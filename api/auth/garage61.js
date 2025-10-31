/**
 * GARAGE61 SSO INTEGRATION FOR OUTSETA
 * 
 * OAuth Flow:
 * 1. User clicks "Sign in with Garage61" button
 * 2. Redirected to Garage61 OAuth authorization
 * 3. Garage61 redirects back with authorization code
 * 4. Exchange code for access token
 * 5. Fetch user profile from Garage61
 * 6. Create/update user in Outseta
 * 7. Generate Outseta JWT token
 * 8. Send token to frontend via postMessage
 */

const axios = require('axios');

// CORS Configuration - only allow trusted origins
const ALLOWED_ORIGINS = [
  'https://aware-amount-178968.framer.app',
  'https://almeidaracingacademy.com',
  'https://www.almeidaracingacademy.com',
];

function setCorsHeaders(res, origin) {
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// MAIN HANDLER
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

module.exports = async (req, res) => {
  const origin = req.headers.origin || req.headers.referer;
  setCorsHeaders(res, origin);

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    const { code, state } = req.query;

    if (!code) {
      return handleStart(req, res);
    } else {
      return await handleCallback(req, res, code, state);
    }
  } catch (error) {
    console.error('❌ Garage61 SSO Error:', error);
    return res.status(500).send(getErrorPage('An unexpected error occurred. Please try again.'));
  }
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// STEP 1: START OAUTH FLOW
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

function handleStart(req, res) {
  const redirectUri = process.env.GARAGE61_REDIRECT_URI;
  const clientId = process.env.GARAGE61_CLIENT_ID;

  if (!clientId || !redirectUri) {
    console.error('❌ Missing Garage61 OAuth credentials');
    return res.status(500).send(getErrorPage('Server configuration error. Please contact support.'));
  }

  // Build authorization URL (adjust based on Garage61's OAuth endpoints)
  const params = [
    'response_type=code',
    `client_id=${encodeURIComponent(clientId)}`,
    `redirect_uri=${encodeURIComponent(redirectUri)}`,
    'scope=profile email', // Adjust scopes as needed for Garage61
  ];
  const authUrl = `https://auth.garage61.com/oauth/authorize?${params.join('&')}`;

  // Optimized redirect (302 instead of 307 for faster response)
  res.writeHead(302, { Location: authUrl });
  res.end();
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// STEP 2: HANDLE OAUTH CALLBACK
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function handleCallback(req, res, code, state) {
  console.log('🔄 Processing Garage61 OAuth callback...');

  try {
    // Exchange authorization code for access token
    const tokenResponse = await axios.post(
      'https://auth.garage61.com/oauth/token', // Adjust to actual Garage61 endpoint
      {
        grant_type: 'authorization_code',
        code,
        client_id: process.env.GARAGE61_CLIENT_ID,
        client_secret: process.env.GARAGE61_CLIENT_SECRET,
        redirect_uri: process.env.GARAGE61_REDIRECT_URI,
      },
      {
        headers: { 'Content-Type': 'application/json' },
        timeout: 8000,
      }
    );

    const accessToken = tokenResponse.data.access_token;
    console.log('✓ Garage61 access token obtained');

    // Fetch user profile from Garage61
    const userResponse = await axios.get('https://api.garage61.com/v1/user', {
      headers: { Authorization: `Bearer ${accessToken}` },
      timeout: 8000,
    });

    const garage61User = userResponse.data;
    console.log('✓ Garage61 user data:', {
      email: garage61User.email,
      username: garage61User.username,
      id: garage61User.id,
    });

    // Create or get Outseta user
    const outsetaUser = await findOrCreateOutsetaUser(garage61User);
    console.log('✓ Outseta user:', outsetaUser.Email);

    // Generate Outseta JWT token
    const outsetaToken = await generateOutsetaToken(outsetaUser);
    console.log('✓ Outseta token generated');

    // Send success page with postMessage
    return res.status(200).send(getSuccessPage(outsetaToken.access_token));
  } catch (error) {
    console.error('❌ Callback error:', error.response?.data || error.message);

    // Handle Garage61 OAuth errors (e.g., user denied access)
    if (error.response?.data?.error) {
      const sanitizedError = sanitizeErrorMessage(error.response.data.error_description || error.response.data.error);
      return res.status(400).send(getErrorPage(sanitizedError));
    }

    return res.status(500).send(getErrorPage('Authentication failed. Please try again.'));
  }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// OUTSETA INTEGRATION
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function findOrCreateOutsetaUser(garage61User) {
  const outsetaApiUrl = `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
  const auth = `${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}`;

  // Search for existing user by email
  const searchResponse = await axios.get(
    `${outsetaApiUrl}/crm/people`,
    {
      params: { 
        fields: 'Uid,Email,FirstName,LastName,Garage61Username,Garage61Id',
        Email: garage61User.email 
      },
      headers: { Authorization: `Outseta ${auth}` },
      timeout: 8000,
    }
  );

  // Update existing user if Garage61 fields are missing or changed
  if (searchResponse.data.items && searchResponse.data.items.length > 0) {
    const existingUser = searchResponse.data.items[0];
    const currentGarage61Username = existingUser.Garage61Username;
    const currentGarage61Id = existingUser.Garage61Id;
    const newGarage61Username = garage61User.username || '';
    const newGarage61Id = garage61User.id || '';
    
    if (!currentGarage61Username || !currentGarage61Id || 
        currentGarage61Username !== newGarage61Username || 
        currentGarage61Id !== newGarage61Id) {
      console.log('🔄 Updating existing user Garage61 fields...');
      
      await axios.put(
        `${outsetaApiUrl}/crm/people/${existingUser.Uid}`,
        {
          Uid: existingUser.Uid,
          Email: existingUser.Email,
          FirstName: existingUser.FirstName,
          LastName: existingUser.LastName,
          Garage61Username: newGarage61Username,
          Garage61Id: newGarage61Id
        },
        {
          headers: { Authorization: `Outseta ${auth}`, 'Content-Type': 'application/json' },
          timeout: 8000,
        }
      );
      
      console.log('✓ User Garage61 fields updated');
    }
    
    return existingUser;
  }

  // Create new user
  console.log('🔄 Creating new Outseta user...');
  
  const [firstName = '', lastName = ''] = (garage61User.name || garage61User.username || '').split(' ');

  const createResponse = await axios.post(
    `${outsetaApiUrl}/crm/people`,
    {
      Email: garage61User.email,
      FirstName: firstName || 'Garage61',
      LastName: lastName || 'User',
      Garage61Username: garage61User.username || '',
      Garage61Id: garage61User.id || '',
    },
    {
      headers: { Authorization: `Outseta ${auth}`, 'Content-Type': 'application/json' },
      timeout: 8000,
    }
  );

  return createResponse.data;
}

async function generateOutsetaToken(outsetaUser) {
  const outsetaApiUrl = `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
  const auth = `${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}`;

  const tokenResponse = await axios.post(
    `${outsetaApiUrl}/tokens`,
    {
      username: outsetaUser.Email,
    },
    {
      headers: {
        Authorization: `Outseta ${auth}`,
        'Content-Type': 'application/json',
      },
      timeout: 8000,
    }
  );

  return tokenResponse.data;
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// UI PAGES
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

function getSuccessPage(token) {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Authentication Successful</title>
  <style>
    body { 
      margin: 0; 
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }
    .container {
      background: white;
      padding: 48px;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      text-align: center;
      max-width: 400px;
    }
    .icon {
      font-size: 64px;
      margin-bottom: 24px;
    }
    h1 {
      margin: 0 0 16px 0;
      font-size: 28px;
      color: #1a202c;
    }
    p {
      margin: 0;
      color: #718096;
      font-size: 16px;
      line-height: 1.5;
    }
    .spinner {
      margin: 24px auto 0;
      width: 40px;
      height: 40px;
      border: 4px solid #e2e8f0;
      border-top-color: #667eea;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">🏁</div>
    <h1>Signed in successfully!</h1>
    <p>Redirecting you back to the academy...</p>
    <div class="spinner"></div>
  </div>
  <script>
    const token = ${JSON.stringify(token)};
    const allowedOrigins = ${JSON.stringify(ALLOWED_ORIGINS)};
    
    function sendToken() {
      if (window.opener) {
        allowedOrigins.forEach(origin => {
          try {
            window.opener.postMessage({ 
              type: 'GARAGE61_AUTH_SUCCESS', 
              token 
            }, origin);
          } catch (e) {
            console.warn('Failed to post to', origin);
          }
        });
        
        setTimeout(() => {
          window.close();
          setTimeout(() => {
            document.querySelector('p').textContent = 'You can close this window now.';
            document.querySelector('.spinner').style.display = 'none';
          }, 500);
        }, 1000);
      } else {
        document.querySelector('p').textContent = 'Please close this window and return to the previous page.';
        document.querySelector('.spinner').style.display = 'none';
      }
    }
    
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', sendToken);
    } else {
      sendToken();
    }
  </script>
</body>
</html>
  `.trim();
}

function getErrorPage(message) {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Authentication Failed</title>
  <style>
    body { 
      margin: 0; 
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 20px;
    }
    .container {
      background: white;
      padding: 48px;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      text-align: center;
      max-width: 400px;
    }
    .icon {
      font-size: 64px;
      margin-bottom: 24px;
    }
    h1 {
      margin: 0 0 16px 0;
      font-size: 28px;
      color: #1a202c;
    }
    p {
      margin: 0 0 32px 0;
      color: #718096;
      font-size: 16px;
      line-height: 1.5;
    }
    button {
      background: #667eea;
      color: white;
      border: none;
      padding: 12px 32px;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s;
    }
    button:hover {
      background: #5a67d8;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">⚠️</div>
    <h1>Authentication Failed</h1>
    <p>${escapeHtml(message)}</p>
    <button onclick="window.close()">Close Window</button>
  </div>
</body>
</html>
  `.trim();
}

function sanitizeErrorMessage(message) {
  if (typeof message !== 'string') return 'An error occurred';
  
  // Remove technical details but keep user-friendly messages
  const cleaned = message
    .replace(/https?:\/\/[^\s]+/g, '') // Remove URLs
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, '[email]') // Remove emails
    .replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, '[IP]') // Remove IPs
    .trim();
  
  return cleaned || 'An error occurred during authentication';
}

function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// VERCEL CONFIG
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

module.exports.config = {
  maxDuration: 30,
  memory: 1024,
};

