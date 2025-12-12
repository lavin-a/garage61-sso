const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { kv } = require('@vercel/kv');
const DEFAULT_TIMEOUT_MS = 8000;

async function request(method, url, { headers = {}, params, data, timeout = DEFAULT_TIMEOUT_MS } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const targetUrl = params ? appendQuery(url, params) : url;
    const normalizedHeaders = {
      Accept: 'application/json',
      ...headers,
    };

    let body = undefined;
    if (data !== undefined) {
      if (data instanceof URLSearchParams) {
        body = data.toString();
        normalizedHeaders['Content-Type'] = normalizedHeaders['Content-Type'] || 'application/x-www-form-urlencoded';
      } else if (typeof data === 'string') {
        body = data;
      } else {
        body = JSON.stringify(data);
        normalizedHeaders['Content-Type'] = normalizedHeaders['Content-Type'] || 'application/json';
      }
    }

    const res = await fetch(targetUrl, {
      method,
      headers: normalizedHeaders,
      body,
      signal: controller.signal,
    });

    const text = await res.text();
    let parsed;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch (err) {
      parsed = text;
    }

    if (!res.ok) {
      const error = new Error(`HTTP ${res.status} ${res.statusText}`);
      error.response = { status: res.status, statusText: res.statusText, data: parsed, headers: Object.fromEntries(res.headers.entries()) };
      error.status = res.status;
      throw error;
    }

    return { status: res.status, data: parsed, headers: Object.fromEntries(res.headers.entries()) };
  } finally {
    clearTimeout(timer);
  }
}

function appendQuery(url, params) {
  const target = new URL(url);
  Object.entries(params || {}).forEach(([key, value]) => {
    if (value === undefined || value === null) return;
    target.searchParams.set(key, value);
  });
  return target.toString();
}

const allowedOrigins = [
  'https://almeidaracingacademy.com',
  'https://aware-amount-178968.framer.app',
];

const allowedReturnUrls = [
  'https://almeidaracingacademy.com/success',
  'https://aware-amount-178968.framer.app/success',
];
const allowedEmailUrls = [
  'https://almeidaracingacademy.com/link-email',
  'https://aware-amount-178968.framer.app/link-email',
];
const DEFAULT_RETURN_URL = allowedReturnUrls[0];
const DEFAULT_EMAIL_PAGE_URL = allowedEmailUrls[0];
const ACCOUNT_CONFLICT_MESSAGE = "This email is already registered. Please sign in using a known method, then link this provider from your account settings.";

const redirectHostAllowlist = new Set([
  ...allowedReturnUrls.map(getHost),
  ...allowedEmailUrls.map(getHost),
  'almeidaracingacademy.com',
  'aware-amount-178968.framer.app',
].filter(Boolean));

function getHost(url) {
  try {
    return new URL(url).host;
  } catch (err) {
    return null;
  }
}

function sanitizeRedirect(targetUrl, fallbackUrl) {
  if (!targetUrl) return fallbackUrl;
  try {
    const parsed = new URL(targetUrl);
    if (parsed.protocol !== 'https:') {
      return fallbackUrl;
    }
    if (allowedReturnUrls.includes(parsed.toString()) || allowedEmailUrls.includes(parsed.toString())) {
      return parsed.toString();
    }
    if (redirectHostAllowlist.has(parsed.host)) {
      return parsed.toString();
    }
  } catch (err) {
    return fallbackUrl;
  }
  return fallbackUrl;
}

// Rate limiting: 10 requests per minute per IP
async function checkRateLimit(ip) {
  const key = `garage61:ratelimit:${ip}`;
  const count = await kv.incr(key);
  if (count === 1) await kv.expire(key, 60);
  return count <= 10;
}

module.exports = async (req, res) => {
  const origin = req.headers.origin || req.headers.referer;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Rate limiting
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.connection?.remoteAddress || 'unknown';
  if (!await checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Too many requests. Please try again later.' });
  }

  const { code, action } = req.query;

  if (req.method === 'POST') {
    if (action === 'complete-registration') {
      return handleCompleteRegistration(req, res);
    }
    if (action === 'send-password-reset') {
      return handleSendPasswordReset(req, res);
    }
    if (action === 'disconnect') {
      return handleDisconnect(req, res);
    }
  }

  if (!code) {
    return handleStart(req, res);
  }

  return handleCallback(req, res, code);
};

async function handleStart(req, res) {
  if (!process.env.GARAGE61_CLIENT_ID) {
    return res.status(500).send('Garage61 client ID not configured');
  }

  const intent = (req.query.intent || 'login').toLowerCase();
  if (!['login', 'link'].includes(intent)) {
    return res.status(400).send('Invalid intent');
  }

  const requestedReturnUrl = req.query.return_url;
  const requestedEmailPageUrl = req.query.email_page_url;

  const returnUrl = sanitizeRedirect(requestedReturnUrl, DEFAULT_RETURN_URL);
  const emailPageUrl = sanitizeRedirect(requestedEmailPageUrl, DEFAULT_EMAIL_PAGE_URL);

  let linkPersonUid = null;
  if (intent === 'link') {
    const linkToken = req.query.link_token;
    const requestedLinkUid = req.query.link_person_uid;

    if (!linkToken || !requestedLinkUid) {
      return res.status(400).send('Missing linking parameters');
    }

    try {
      const profile = await verifyOutsetaAccessToken(linkToken);
      if (profile?.Uid !== requestedLinkUid) {
        return res.status(403).send('Invalid linking session');
      }
    } catch (err) {
      console.error('Failed to verify Outseta token for linking', err.message);
      return res.status(403).send('Invalid linking session');
    }

    linkPersonUid = requestedLinkUid;
  }

  const redirectUri = `${getBaseUrl(req)}/api/auth/garage61`;

  // Store return URL and email page URL in Vercel KV with 10 minute expiration
  const state = crypto.randomBytes(16).toString('hex');
  await kv.set(
    `garage61:state:${state}`,
    { returnUrl, emailPageUrl, intent, linkPersonUid, createdAt: Date.now() },
    { ex: 600 }
  );

  const url =
    'https://garage61.net/app/account/oauth' +
    `?response_type=code` +
    `&client_id=${encodeURIComponent(process.env.GARAGE61_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${encodeURIComponent(state)}` +
    `&scope=${encodeURIComponent('email datapacks_subscriptions driving_data')}`;

  res.writeHead(302, { Location: url });
  res.end();
}

async function handleCallback(req, res, code) {
  try {
    const state = req.query.state;
    const stateData = await kv.get(`garage61:state:${state}`);
    const returnUrl = stateData?.returnUrl;
    const emailPageUrl = stateData?.emailPageUrl;
    const intent = (stateData?.intent || 'login').toLowerCase();
    const linkPersonUid = stateData?.linkPersonUid || null;

    if (!returnUrl) {
      console.error('State not found for Garage61 OAuth');
      return res.send(renderErrorPage('Session expired. Please try again.'));
    }

    await kv.del(`garage61:state:${state}`);

    const redirectUri = `${getBaseUrl(req)}/api/auth/garage61`;

    const tokenResponse = await request('POST', 'https://garage61.net/api/oauth/token', {
      data: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: process.env.GARAGE61_CLIENT_ID,
        client_secret: process.env.GARAGE61_CLIENT_SECRET,
        redirect_uri: redirectUri,
      }),
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 8000,
    });

    // 🔍 TEMPORARY: Log the token response to see what Garage61 provides
    console.log('=== GARAGE61 TOKEN RESPONSE ===');
    console.log(JSON.stringify(tokenResponse.data, null, 2));
    console.log('=== END TOKEN RESPONSE ===');

    const accessToken = tokenResponse.data.access_token;

    const userResponse = await request('GET', 'https://garage61.net/api/oauth/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` },
      timeout: 8000,
    });

    const garageUser = userResponse.data;
    const iRacingData = await fetchGarage61iRacing(accessToken);

    const garage61Id = garageUser.sub || '';
    const normalizedEmail = garageUser.email
      ? String(garageUser.email).trim().toLowerCase()
      : null;

    const existingByGarageId = garage61Id
      ? await findPersonByField('Garage61Id', garage61Id)
      : null;

    if (existingByGarageId) {
      if (intent === 'link') {
        if (!linkPersonUid || existingByGarageId.Uid !== linkPersonUid) {
          return res.send(
            renderRedirectWithError(returnUrl, 'account_exists', ACCOUNT_CONFLICT_MESSAGE, 'garage61')
          );
        }

        // Subscribe to Garage61 data packs after successful linking
        const isPro = isProUser(existingByGarageId);
        await subscribeToGarage61DataPacks(accessToken, isPro);

        return res.send(renderLinkSuccessPage(returnUrl, 'garage61'));
      }

      const outsetaToken = await generateOutsetaToken(existingByGarageId.Email);
      return res.send(renderSuccessPage(outsetaToken, returnUrl));
    }

    if (intent === 'link') {
      if (!linkPersonUid) {
        return res.send(renderErrorPage('Linking session expired.'));
      }

      const person = await getPersonByUid(linkPersonUid);
      if (!person) {
        return res.send(renderErrorPage('Unable to locate your account.'));
      }

      await updatePerson(linkPersonUid, buildGarage61UpdatePayload(person, garageUser, iRacingData));
      
      // Subscribe to Garage61 data packs after successful linking
      const isPro = isProUser(person);
      await subscribeToGarage61DataPacks(accessToken, isPro);
      
      return res.send(renderLinkSuccessPage(returnUrl, 'garage61'));
    }

    if (normalizedEmail) {
      const existingByEmail = await findPersonByEmail(normalizedEmail);
      if (existingByEmail) {
        const existingGarageId = existingByEmail.Garage61Id
          ? String(existingByEmail.Garage61Id).trim()
          : null;
        const newGarageId = garage61Id ? String(garage61Id).trim() : null;
        const garageMatches =
          !existingGarageId || (newGarageId && existingGarageId === newGarageId);

        if (!garageMatches) {
          return res.send(
            renderRedirectWithError(returnUrl, 'account_exists', ACCOUNT_CONFLICT_MESSAGE, 'garage61')
          );
        }

        const hasAccount = personHasAccount(existingByEmail);
        if (!hasAccount) {
          const ensured = await ensurePersonHasAccount(existingByEmail.Email, existingByEmail);
          if (ensured) {
            await updatePerson(existingByEmail.Uid, buildGarage61UpdatePayload(existingByEmail, garageUser, iRacingData));
            const outsetaToken = await generateOutsetaToken(existingByEmail.Email);
            return res.send(renderSuccessPage(outsetaToken, returnUrl));
          }
        }
        return res.send(
          renderRedirectWithError(returnUrl, 'account_exists', ACCOUNT_CONFLICT_MESSAGE, 'garage61')
        );
      }

      const createdPerson = await createGarage61OutsetaUser({
        garageUser,
        iRacingData,
        email: normalizedEmail,
      });

      // Subscribe to Garage61 data packs after successful account creation
      const isPro = isProUser(createdPerson);
      await subscribeToGarage61DataPacks(accessToken, isPro);

      const outsetaToken = await generateOutsetaToken(createdPerson.Email);
      return res.send(renderSuccessPage(outsetaToken, returnUrl));
    }

    const csrfToken = crypto.randomBytes(16).toString('hex');
    const tempToken = jwt.sign(
      {
        garageUser,
        iRacingData,
        returnUrl,
        provider: 'garage61',
        csrf: csrfToken,
      },
      process.env.TEMP_TOKEN_SECRET,
      { expiresIn: '10m' }
    );

    return res.send(renderRedirectToFramer(emailPageUrl, tempToken));
  } catch (err) {
    dumpError('[Garage61SSO]', err);
    return res.send(renderErrorPage('Unable to complete Garage61 sign in.'));
  }
}

async function fetchGarage61iRacing(accessToken) {
  try {
    const response = await request('GET', 'https://garage61.net/api/v1/me/accounts', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
      },
      timeout: 8000,
    });

    const items = response.data?.items;
    if (!Array.isArray(items)) return null;

    const account = items.find((item) => item.platform === 'iracing');
    if (!account) return null;

    return {
      displayName: account.name || '',
      custId: account.id ? String(account.id) : '',
    };
  } catch (err) {
    console.warn('Garage61 linked accounts unavailable:', err.response?.status || err.message);
    return null;
  }
}

async function subscribeToGarage61DataPacks(accessToken, isPro = false) {
  // TODO: Enable this once Garage61 data packs are live
  console.log('[Garage61] Data pack subscription skipped (feature not yet live)');
  console.log(`[Garage61] Would subscribe user (isPro: ${isPro}) to data packs`);
  return true;

  // eslint-disable-next-line no-unreachable
  const FREE_DATA_PACK_GROUP_ID = process.env.GARAGE61_FREE_DATA_PACK_GROUP_ID || '1';
  const PRO_DATA_PACK_GROUP_ID = process.env.GARAGE61_PRO_DATA_PACK_GROUP_ID || '2';

  try {
    // Always subscribe to Free data pack group
    await request('POST', 'https://garage61.net/api/v1/createUserDataPackGroup', {
      data: {
        userDataPackGroupId: FREE_DATA_PACK_GROUP_ID,
      },
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      timeout: 8000,
    });

    console.log('Successfully subscribed user to Free Garage61 data pack group');

    // If Pro user, also subscribe to Pro data pack group
    if (isPro) {
      await request('POST', 'https://garage61.net/api/v1/createUserDataPackGroup', {
        data: {
          userDataPackGroupId: PRO_DATA_PACK_GROUP_ID,
        },
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        timeout: 8000,
      });

      console.log('Successfully subscribed user to Pro Garage61 data pack group');
    }
  } catch (err) {
    // Log but don't fail the authentication flow if data pack subscription fails
    console.warn('Failed to subscribe to Garage61 data pack groups:', err.response?.status || err.message);
    if (err.response?.data) {
      console.warn('Garage61 data pack error details:', err.response.data);
    }
  }
}

function isProUser(person) {
  if (!person) return false;

  // Pro plan UIDs from Outseta
  const PRO_PLAN_UIDS = [
    'aWxroqQV', // Gold
    'z9MzwKW4', // Gold Membership Add-on
  ];

  // Check if user has any Pro plan in their subscriptions
  const subscriptions = person.Account?.Subscriptions || [];
  
  for (const subscription of subscriptions) {
    // Check main plan
    if (subscription.Plan?.Uid && PRO_PLAN_UIDS.includes(subscription.Plan.Uid)) {
      return true;
    }
    
    // Check add-ons
    const addOns = subscription.AddOns || [];
    for (const addOn of addOns) {
      if (addOn.Plan?.Uid && PRO_PLAN_UIDS.includes(addOn.Plan.Uid)) {
        return true;
      }
    }
  }

  return false;
}

function buildGarage61UpdatePayload(person, garageUser, iRacingData) {
  const garageUsername = garageUser.preferred_username || garageUser.name || person.Garage61Username || '';

  const payload = {
    Uid: person.Uid,
    Email: person.Email,
    FirstName: person.FirstName,
    LastName: person.LastName,
    Garage61Username: garageUsername,
    Garage61Id: garageUser.sub || person.Garage61Id || '',
  };

  if (iRacingData?.displayName) {
    payload.iRacingUsername = iRacingData.displayName;
  }
  if (iRacingData?.custId) {
    payload.iRacingId = iRacingData.custId;
  }

  return payload;
}

async function createGarage61OutsetaUser({ garageUser, iRacingData, email }) {
  const firstName = garageUser.given_name || garageUser.name || 'Garage61';
  const lastName = garageUser.family_name || 'User';
  const garageUsername = garageUser.preferred_username || garageUser.name || '';
  const fullName = `${firstName} ${lastName}`.trim();

  const personPayload = {
    Email: email,
    FirstName: firstName,
    LastName: lastName,
    Garage61Username: garageUsername,
    Garage61Id: garageUser.sub || '',
  };

  if (iRacingData?.displayName) {
    personPayload.iRacingUsername = iRacingData.displayName;
  }
  if (iRacingData?.custId) {
    personPayload.iRacingId = iRacingData.custId;
  }

  const registration = await createRegistration({
    Name: fullName || 'Garage61 User',
    PersonAccount: [
      {
        IsPrimary: true,
        Person: personPayload,
      },
    ],
    Subscriptions: [
      {
        Plan: {
          Uid: process.env.OUTSETA_FREE_PLAN_UID,
        },
        BillingRenewalTerm: 1,
      },
    ],
  });

  return registration.PrimaryContact;
}

async function generateOutsetaToken(email) {
  const apiBase = `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
  const authHeader = { Authorization: `Outseta ${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}` };

  try {
    const tokenResponse = await request('POST', `${apiBase}/tokens`, {
      data: { username: email },
      headers: { ...authHeader, 'Content-Type': 'application/json' },
      timeout: 8000,
    });

    return tokenResponse.data.access_token || tokenResponse.data;
  } catch (error) {
    if (isInvalidGrantError(error)) {
      const accountCreated = await ensurePersonHasAccount(email);
      if (accountCreated) {
        return generateOutsetaToken(email);
      }
    }
    throw error;
  }
}

async function handleCompleteRegistration(req, res) {
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    const { tempToken, email, name, csrf } = body;

    if (!tempToken || !email) {
      return res.status(400).json({ error: 'Missing tempToken or email' });
    }

    if (!name || name.trim().length === 0) {
      return res.status(400).json({ error: 'Name is required' });
    }

    // Verify and decode the temporary token
    let tokenData;
    try {
      tokenData = jwt.verify(tempToken, process.env.TEMP_TOKEN_SECRET);
    } catch (err) {
      console.error('Invalid or expired temp token:', err.message);
      return res.status(400).json({ error: 'Invalid or expired token. Please try signing in again.' });
    }

    // CSRF protection
    if (!csrf || tokenData.csrf !== csrf) {
      console.error('CSRF token mismatch');
      return res.status(403).json({ error: 'Invalid request. Please try again.' });
    }

    // Validate and sanitize email
    const sanitizedEmail = email.trim().toLowerCase();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(sanitizedEmail)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    if (sanitizedEmail.length > 254) {
      return res.status(400).json({ error: 'Email address is too long' });
    }

    // Validate and sanitize name
    const sanitizedName = name.trim().replace(/\s+/g, ' '); // Normalize whitespace
    if (sanitizedName.length < 2) {
      return res.status(400).json({ error: 'Name must be at least 2 characters' });
    }
    if (sanitizedName.length > 100) {
      return res.status(400).json({ error: 'Name must be less than 100 characters' });
    }

    // Prevent malicious input
    const dangerousPattern = /<|>|javascript:|on\w+=/i;
    if (dangerousPattern.test(sanitizedName) || dangerousPattern.test(sanitizedEmail)) {
      return res.status(400).json({ error: 'Invalid characters in input' });
    }

    const garageSub = tokenData.garageUser?.sub ? String(tokenData.garageUser.sub) : '';
    const existingByEmail = await findPersonByEmail(sanitizedEmail);
    if (existingByEmail) {
      const existingGarageId = existingByEmail.Garage61Id
        ? String(existingByEmail.Garage61Id)
        : null;

      const garageMatches =
        !existingGarageId ||
        (garageSub && existingGarageId === garageSub);

      if (garageMatches && !personHasAccount(existingByEmail)) {
        const ensured = await ensurePersonHasAccount(existingByEmail.Email, existingByEmail);
        if (ensured) {
          const updatePayload = buildGarage61UpdatePayload(
            existingByEmail,
            tokenData.garageUser,
            tokenData.iRacingData
          );
          await updatePerson(existingByEmail.Uid, updatePayload);

          const outsetaToken = await generateOutsetaToken(existingByEmail.Email);
          return res.status(200).json({
            success: true,
            outsetaToken,
            returnUrl: tokenData.returnUrl,
          });
        }
      }

      return res.status(409).json({ error: ACCOUNT_CONFLICT_MESSAGE });
    }

    const nameParts = sanitizedName.split(/\s+/);
    const firstName = nameParts[0] || 'Garage61';
    const lastName = nameParts.length > 1 ? nameParts.slice(1).join(' ') : 'User';

    const garageUserWithEmail = {
      ...tokenData.garageUser,
      email: sanitizedEmail,
      given_name: firstName,
      family_name: lastName,
    };

    const createdPerson = await createGarage61OutsetaUser({
      garageUser: garageUserWithEmail,
      iRacingData: tokenData.iRacingData,
      email: sanitizedEmail,
    });

    const outsetaToken = await generateOutsetaToken(createdPerson.Email);

    return res.status(200).json({
      success: true,
      outsetaToken,
      returnUrl: tokenData.returnUrl,
    });
  } catch (err) {
    dumpError('[Garage61SSO] complete-registration', err);
    return res.status(500).json({ error: 'Unable to complete registration' });
  }
}

function renderRedirectWithError(returnUrl, code, message, provider) {
  const url = new URL(returnUrl);
  const params = new URLSearchParams(url.hash?.replace(/^#/, '') || '');
  params.set('error', code);
  if (message) {
    params.set('message', message);
  }
  if (provider) {
    params.set('provider', provider);
  }
  url.hash = params.toString();

  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Redirecting...</title>
  </head>
  <body>
    <script>
      window.location.href = ${JSON.stringify(url.toString())};
    </script>
  </body>
</html>`;
}

function renderLinkSuccessPage(returnUrl, provider) {
  const url = new URL(returnUrl);
  const params = new URLSearchParams(url.hash?.replace(/^#/, '') || '');
  params.set('link', 'success');
  params.set('provider', provider);
  url.hash = params.toString();

  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Link Successful</title>
  </head>
  <body>
    <script>
      window.location.href = ${JSON.stringify(url.toString())};
    </script>
  </body>
</html>`;
}

function renderRedirectToFramer(framerUrl, tempToken) {
  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Redirecting...</title>
  </head>
  <body>
    <script>
      const baseUrl = ${JSON.stringify(framerUrl)};
      const separator = baseUrl.includes('?') ? '&' : '?';
      window.location.href = baseUrl + separator + 'popup=false#token=' + ${JSON.stringify(tempToken)};
    </script>
  </body>
</html>`;
}

function renderSuccessPage(token, returnUrl) {
  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Signing in...</title>
  </head>
  <body>
    <script>
      (function() {
        const token = ${JSON.stringify(token)};
        const returnUrl = ${JSON.stringify(returnUrl)};
        
        const url = new URL(returnUrl);
        url.hash = 'garage61_token=' + token;
        window.location.href = url.toString();
      })();
    </script>
  </body>
</html>`;
}

function renderErrorPage(message) {
  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Garage61 Sign In</title>
    <style>
      body { background-color: #0a0a0a; margin: 0; font-family: serif; display: flex; align-items: center; justify-content: center; height: 100vh; }
      p, h1 { color: rgba(255, 255, 255, 0.8); }
    </style>
  </head>
  <body>
    <div style="text-align:center;">
      <h1>Sign in failed</h1>
      <p>${message}</p>
    </div>
  </body>
</html>`;
}

function getBaseUrl(req) {
  const protocol = req.headers['x-forwarded-proto'] || 'https';
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  return `${protocol}://${host}`;
}

function getOutsetaApiBase() {
  if (!process.env.OUTSETA_DOMAIN) {
    throw new Error('OUTSETA_DOMAIN not configured');
  }
  return `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
}

function getOutsetaAuthHeaders() {
  if (!process.env.OUTSETA_API_KEY || !process.env.OUTSETA_SECRET_KEY) {
    throw new Error('Outseta API credentials not configured');
  }

  return {
    Authorization: `Outseta ${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}`,
    'Content-Type': 'application/json',
  };
}

async function verifyOutsetaAccessToken(token) {
  if (!token) {
    throw new Error('Missing Outseta access token');
  }

  const apiBase = getOutsetaApiBase();

  const response = await request('GET', `${apiBase}/profile`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
    timeout: 8000,
  });

  return response.data;
}

async function getPersonByUid(uid) {
  if (!uid) return null;

  const apiBase = getOutsetaApiBase();
  const response = await request('GET', `${apiBase}/crm/people/${uid}`, {
    headers: getOutsetaAuthHeaders(),
    timeout: 8000,
  });

  return response.data;
}

async function findPersonByEmail(email) {
  if (!email) return null;

  const apiBase = getOutsetaApiBase();
  const response = await request('GET', `${apiBase}/crm/people`, {
    headers: getOutsetaAuthHeaders(),
    params: {
      Email: email,
      fields: 'Uid,Email,FirstName,LastName,PersonAccount.Account.Uid',
    },
    timeout: 8000,
  });

  return response.data.items?.[0] ?? null;
}

async function findPersonByField(field, value) {
  if (!field || value == null) return null;

  const apiBase = getOutsetaApiBase();
  const response = await request('GET', `${apiBase}/crm/people`, {
    headers: getOutsetaAuthHeaders(),
    params: { [field]: value },
    timeout: 8000,
  });

  return response.data.items?.[0] ?? null;
}

async function updatePerson(uid, payload) {
  if (!uid) throw new Error('Cannot update person without UID');

  const apiBase = getOutsetaApiBase();
  await request('PUT', `${apiBase}/crm/people/${uid}`, {
    data: payload,
    headers: getOutsetaAuthHeaders(),
    timeout: 8000,
  });
}

async function createRegistration(payload) {
  const apiBase = getOutsetaApiBase();
  const response = await request('POST', `${apiBase}/crm/registrations`, {
    data: payload,
    headers: getOutsetaAuthHeaders(),
    timeout: 8000,
  });

  return response.data;
}

function dumpError(tag, error) {
  const payload = {
    tag,
    message: error?.message,
    stack: error?.stack,
    response: error?.response
      ? {
          status: error.response.status,
          statusText: error.response.statusText,
          data: toJsonSafe(error.response.data),
          headers: error.response.headers,
        }
      : null,
    request: error?.config
      ? {
          method: error.config.method,
          url: error.config.url,
          data: toJsonSafe(error.config.data),
          headers: error.config.headers,
        }
      : null,
  };

  try {
    console.error(`${tag} error`, JSON.stringify(payload, null, 2));
  } catch (serializationError) {
    console.error(`${tag} error (serialization failed)`, payload);
  }
}

function toJsonSafe(value) {
  if (value == null) return null;
  if (typeof value === 'string') return value;
  try {
    return JSON.parse(JSON.stringify(value));
  } catch (err) {
    return String(value);
  }
}

module.exports.config = {
  maxDuration: 30,
  memory: 1024,
};

async function handleDisconnect(req, res) {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader || !authHeader.toLowerCase().startsWith('bearer ')) {
      return res.status(401).json({ error: 'Missing authorization bearer token.' });
    }

    const accessToken = authHeader.slice(7).trim();
    if (!accessToken) {
      return res.status(401).json({ error: 'Missing authorization bearer token.' });
    }

    const profile = await verifyOutsetaAccessToken(accessToken);
    if (!profile?.Uid) {
      return res.status(403).json({ error: 'Unable to validate session.' });
    }

    const person = await getPersonByUid(profile.Uid);
    if (!person) {
      return res.status(404).json({ error: 'Account not found.' });
    }

    if (!hasPassword(person)) {
      return res.status(412).json({
        error: 'Add a password to your account before disconnecting Garage61.',
      });
    }

    const alreadyDisconnected =
      !person.Garage61Id && !person.Garage61Username;

    if (!alreadyDisconnected) {
      await updatePerson(person.Uid, {
        Uid: person.Uid,
        Email: person.Email,
        FirstName: person.FirstName,
        LastName: person.LastName,
        Garage61Id: '',
        Garage61Username: '',
      });
    }

    return res.status(200).json({
      success: true,
      provider: 'garage61',
      disconnected: !alreadyDisconnected,
    });
  } catch (err) {
    dumpError('[Garage61SSO][disconnect]', err);
    return res.status(500).json({ error: 'Unable to disconnect Garage61 at this time.' });
  }
}

function hasPassword(person) {
  if (!person) return false;

  const candidateKeys = [
    'PasswordLastUpdated',
    'PasswordLastUpdatedUtc',
    'PasswordLastUpdatedDate',
    'PasswordLastUpdatedDateUtc',
    'PasswordLastUpdatedDateTime',
    'PasswordLastUpdatedDateTimeUtc',
  ];

  for (const key of candidateKeys) {
    const value = person[key];
    if (!value) continue;
    if (typeof value === 'string' && value.trim().length > 0) return true;
    if (value instanceof Date && !isNaN(value.getTime())) return true;
    if (typeof value === 'number' && value > 0) return true;
  }

  if (person.PasswordMustChange === true) return false;
  if (person.HasPassword === true) return true;

  return false;
}

async function handleSendPasswordReset(req, res) {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader || !authHeader.toLowerCase().startsWith('bearer ')) {
      return res.status(401).json({ error: 'Missing authorization bearer token.' });
    }

    const accessToken = authHeader.slice(7).trim();
    if (!accessToken) {
      return res.status(401).json({ error: 'Missing authorization bearer token.' });
    }

    const profile = await verifyOutsetaAccessToken(accessToken);
    if (!profile?.Uid) {
      return res.status(403).json({ error: 'Unable to validate session.' });
    }

    const person = await getPersonByUid(profile.Uid);
    if (!person?.Email) {
      return res.status(400).json({ error: 'No email found for this account.' });
    }

    await sendPasswordResetEmail(person.Email);

    return res.status(200).json({ success: true });
  } catch (err) {
    dumpError('[Garage61SSO][password-reset]', err);
    return res.status(500).json({ error: 'Unable to send password email. Please try again later.' });
  }
}

async function sendPasswordResetEmail(email) {
  const apiBase = getOutsetaApiBase();
  const config = {
    headers: getOutsetaAuthHeaders(),
    timeout: 8000,
    params: {
      donotlog: 1,
    },
  };

  await request('POST', `${apiBase}/crm/people/forgotPassword`, {
    data: { Email: email },
    headers: config.headers,
    params: config.params,
    timeout: config.timeout,
  });
}

function isInvalidGrantError(error) {
  const status = error?.response?.status;
  const data = typeof error?.response?.data === 'string' ? error.response.data : '';
  return status === 400 && data.toLowerCase().includes('invalid_grant');
}

async function ensurePersonHasAccount(email, existingPerson) {
  try {
    const person = existingPerson ?? (await findPersonByEmail(email));
    if (!person || !person.Uid) {
      return false;
    }

    if (personHasAccount(person)) {
      return false;
    }

    await createAccountForPerson(person);
    return true;
  } catch (error) {
    console.warn('[Garage61SSO] ensurePersonHasAccount failed', error?.message || error);
    return false;
  }
}

async function createAccountForPerson(person) {
  const apiBase = getOutsetaApiBase();
  const freePlanUid = process.env.OUTSETA_FREE_PLAN_UID;
  if (!freePlanUid) {
    throw new Error('OUTSETA_FREE_PLAN_UID not configured');
  }

  const accountName = buildAccountName(person);

  await request('POST', `${apiBase}/crm/accounts`, {
    data: {
      Name: accountName,
      PersonAccount: [
        {
          IsPrimary: true,
          Person: { Uid: person.Uid },
        },
      ],
      Subscriptions: [
        {
          Plan: { Uid: freePlanUid },
          BillingRenewalTerm: 1,
        },
      ],
    },
    headers: getOutsetaAuthHeaders(),
    timeout: 8000,
  });
}

function buildAccountName(person) {
  const first = (person?.FirstName || '').trim();
  const last = (person?.LastName || '').trim();
  const email = person?.Email || 'Account';
  const combined = `${first} ${last}`.trim();
  return combined.length > 0 ? `${combined}'s Account` : `${email} Account`;
}

function personHasAccount(person) {
  const memberships = Array.isArray(person?.PersonAccount) ? person.PersonAccount : [];
  return memberships.some((membership) => membership?.Account?.Uid);
}