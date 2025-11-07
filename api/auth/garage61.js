const axios = require('axios');
const jwt = require('jsonwebtoken');
const { kv } = require('@vercel/kv');

const allowedOrigins = [
  'https://aware-amount-178968.framer.app',
  'https://almeidaracingacademy.com',
  'https://www.almeidaracingacademy.com',
];

const allowedReturnUrls = [
  'https://aware-amount-178968.framer.app/sign-in',
  'https://almeidaracingacademy.com/sign-in',
  'https://www.almeidaracingacademy.com/sign-in',
];
const allowedEmailUrls = [
  'https://aware-amount-178968.framer.app/link-email',
  'https://almeidaracingacademy.com/link-email',
  'https://www.almeidaracingacademy.com/link-email',
];
const DEFAULT_RETURN_URL = allowedReturnUrls[0];
const DEFAULT_EMAIL_PAGE_URL = allowedEmailUrls[0];

const redirectHostAllowlist = new Set([
  ...allowedReturnUrls.map(getHost),
  ...allowedEmailUrls.map(getHost),
  'aware-amount-178968.framer.app',
  'almeidaracingacademy.com',
  'www.almeidaracingacademy.com',
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
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
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

  // Handle complete-registration endpoint (POST)
  if (req.method === 'POST' && action === 'complete-registration') {
    return handleCompleteRegistration(req, res);
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

  const requestedReturnUrl = req.query.return_url;
  const requestedEmailPageUrl = req.query.email_page_url;

  const returnUrl = sanitizeRedirect(requestedReturnUrl, DEFAULT_RETURN_URL);
  const emailPageUrl = sanitizeRedirect(requestedEmailPageUrl, DEFAULT_EMAIL_PAGE_URL);

  const redirectUri = `${getBaseUrl(req)}/api/auth/garage61`;

  // Store return URL and email page URL in Vercel KV with 10 minute expiration
  const state = require('crypto').randomBytes(16).toString('hex');
  await kv.set(`garage61:state:${state}`, { returnUrl, emailPageUrl, createdAt: Date.now() }, { ex: 600 });

  const url =
    'https://garage61.net/app/account/oauth' +
    `?response_type=code` +
    `&client_id=${encodeURIComponent(process.env.GARAGE61_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${encodeURIComponent(state)}` +
    `&scope=email`;

  res.writeHead(302, { Location: url });
  res.end();
}

async function handleCallback(req, res, code) {
  try {
    const state = req.query.state;
    const stateData = await kv.get(`garage61:state:${state}`);
    const returnUrl = stateData?.returnUrl;
    const emailPageUrl = stateData?.emailPageUrl;

    if (!returnUrl) {
      console.error('State not found for Garage61 OAuth');
      return res.send(renderErrorPage('Session expired. Please try again.'));
    }

    await kv.del(`garage61:state:${state}`);

    const redirectUri = `${getBaseUrl(req)}/api/auth/garage61`;

    const tokenResponse = await axios.post(
      'https://garage61.net/api/oauth/token',
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: process.env.GARAGE61_CLIENT_ID,
        client_secret: process.env.GARAGE61_CLIENT_SECRET,
        redirect_uri: redirectUri,
      }),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 8000,
      }
    );

    const accessToken = tokenResponse.data.access_token;

    const userResponse = await axios.get('https://garage61.net/api/oauth/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` },
      timeout: 8000,
    });

    const garageUser = userResponse.data;

    const iRacingData = await fetchGarage61IRacing(accessToken);

    // Check if user already exists by Garage61Id (auto-login)
    const garage61Id = garageUser.sub || '';
    if (garage61Id) {
      const existingUser = await findExistingUserByGarage61Id(garage61Id);
      if (existingUser) {
        const outsetaToken = await generateOutsetaToken(existingUser.Email);
        return res.send(renderSuccessPage(outsetaToken, returnUrl));
      }
    }

    // Check if email is provided
    if (!garageUser.email) {
      // Generate temp token with user data for email collection
      const crypto = require('crypto');
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

      // Redirect to Framer email collection page
      return res.send(renderRedirectToFramer(emailPageUrl, tempToken));
    }

    const outsetaPerson = await findOrCreateOutsetaUser(garageUser, iRacingData);

    const outsetaToken = await generateOutsetaToken(outsetaPerson.Email);

    return res.send(renderSuccessPage(outsetaToken, returnUrl));
  } catch (err) {
    dumpError('[Garage61SSO]', err);
    return res.send(renderErrorPage('Unable to complete Garage61 sign in.'));
  }
}

async function fetchGarage61IRacing(accessToken) {
  try {
    const response = await axios.get('https://garage61.net/api/v1/me/accounts', {
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

async function findExistingUserByGarage61Id(garage61Id) {
  const apiBase = `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
  const authHeader = { Authorization: `Outseta ${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}` };

  try {
    const search = await axios.get(`${apiBase}/crm/people`, {
      headers: authHeader,
      params: { Garage61Id: garage61Id },
      timeout: 8000,
    });

    if (search.data.items && search.data.items.length > 0) {
      return search.data.items[0];
    }
  } catch (err) {
    console.warn('Garage61 ID search failed:', err.message);
  }

  return null;
}

async function findOrCreateOutsetaUser(garageUser, iRacingData) {
  const apiBase = `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
  const authHeader = { Authorization: `Outseta ${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}` };

  const email = garageUser.email;
  const firstName = garageUser.given_name || garageUser.name || 'Garage61';
  const lastName = garageUser.family_name || 'User';
  const desiredGarage = {
    Garage61Username: garageUser.preferred_username || garageUser.name || '',
    Garage61Id: garageUser.sub || '',
  };
  const desiredIRacing = iRacingData
    ? {
        iRacingUsername: iRacingData.displayName || '',
        iRacingId: iRacingData.custId || '',
      }
    : {};

  // Try to find existing person
  try {
    const search = await axios.get(`${apiBase}/crm/people`, {
      headers: authHeader,
      params: { Email: email },
      timeout: 8000,
    });

    if (search.data.items && search.data.items.length > 0) {
      const person = search.data.items[0];
      const needsGarageUpdate =
        person.Garage61Username !== desiredGarage.Garage61Username ||
        person.Garage61Id !== desiredGarage.Garage61Id;
      const needsIRacingUpdate =
        desiredIRacing.iRacingUsername &&
        (person.iRacingUsername !== desiredIRacing.iRacingUsername || person.iRacingId !== desiredIRacing.iRacingId);

      if (needsGarageUpdate || needsIRacingUpdate) {
        await axios.put(
          `${apiBase}/crm/people/${person.Uid}`,
          {
            Uid: person.Uid,
            Email: person.Email,
            FirstName: person.FirstName,
            LastName: person.LastName,
            ...desiredGarage,
            ...desiredIRacing,
          },
          {
            headers: { ...authHeader, 'Content-Type': 'application/json' },
            timeout: 8000,
          }
        );
      }

      return person;
    }
  } catch (err) {
    console.warn('Outseta search failed, will try to create:', err.message);
  }

  // Use /crm/registrations endpoint with free subscription
  const createPayload = {
    Name: `${firstName} ${lastName}`,
    PersonAccount: [
      {
        IsPrimary: true,
        Person: {
          Email: email,
          FirstName: firstName,
          LastName: lastName,
          ...desiredGarage,
          ...desiredIRacing,
        },
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
  };

  const createResponse = await axios.post(
    `${apiBase}/crm/registrations`,
    createPayload,
    {
      headers: {
        ...authHeader,
        'Content-Type': 'application/json',
      },
      timeout: 8000,
    }
  );

  return createResponse.data.PrimaryContact;
}

async function generateOutsetaToken(email) {
  const apiBase = `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
  const authHeader = { Authorization: `Outseta ${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}` };

  const tokenResponse = await axios.post(
    `${apiBase}/tokens`,
    { username: email },
    {
      headers: { ...authHeader, 'Content-Type': 'application/json' },
      timeout: 8000,
    }
  );

  return tokenResponse.data.access_token || tokenResponse.data;
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

    // Split name into first and last name
    const nameParts = sanitizedName.split(/\s+/);
    const firstName = nameParts[0] || 'Garage61';
    const lastName = nameParts.length > 1 ? nameParts.slice(1).join(' ') : 'User';

    // Add email to garageUser data
    const garageUserWithEmail = {
      ...tokenData.garageUser,
      email: sanitizedEmail,
      given_name: firstName,
      family_name: lastName,
    };

    // Create Outseta account
    const outsetaPerson = await findOrCreateOutsetaUser(garageUserWithEmail, tokenData.iRacingData);

    // Generate Outseta token
    const outsetaToken = await generateOutsetaToken(outsetaPerson.Email);

    return res.status(200).json({ 
      success: true, 
      outsetaToken,
      returnUrl: tokenData.returnUrl 
    });
  } catch (err) {
    dumpError('[Garage61SSO] complete-registration', err);
    return res.status(500).json({ error: 'Unable to complete registration' });
  }
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