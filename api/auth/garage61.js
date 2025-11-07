const axios = require('axios');

const allowedOrigins = [
  'https://aware-amount-178968.framer.app',
  'https://almeidaracingacademy.com',
  'https://www.almeidaracingacademy.com',
  'https://almeidaracingacademy.outseta.com',
];

module.exports = async (req, res) => {
  const origin = req.headers.origin || req.headers.referer;
  if (allowedOrigins.includes(origin) || origin?.endsWith('.framer.app')) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const { code } = req.query;

  if (!code) {
    return handleStart(req, res);
  }

  return handleCallback(req, res, code);
};

function handleStart(req, res) {
  if (!process.env.GARAGE61_CLIENT_ID) {
    return res.status(500).send('Garage61 client ID not configured');
  }

  const redirectUri = `${getBaseUrl(req)}/api/auth/garage61`;

  const url =
    'https://garage61.net/app/account/oauth' +
    `?response_type=code` +
    `&client_id=${encodeURIComponent(process.env.GARAGE61_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&scope=email` +
    `&prompt=none`;

  res.writeHead(302, { Location: url });
  res.end();
}

async function handleCallback(req, res, code) {
  try {
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

    const outsetaPerson = await findOrCreateOutsetaUser(garageUser, iRacingData);

    const outsetaToken = await generateOutsetaToken(outsetaPerson.Email);

    return res.send(renderSuccessPage(outsetaToken));
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

function renderSuccessPage(token) {
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
        if (window.opener) {
          window.opener.postMessage({ type: 'GARAGE61_AUTH_SUCCESS', token }, '*');
        }
        window.close();
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
      body { margin: 0; font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; }
      p { color: #555; }
    </style>
  </head>
  <body>
    <div style="text-align:center;">
      <h1>Sign in failed</h1>
      <p>${message}</p>
      <button onclick="window.close()" style="padding: 10px 20px;">Close</button>
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