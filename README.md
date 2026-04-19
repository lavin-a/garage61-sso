# Garage 61 SSO Integration

Secure OAuth integration between Garage 61 and Outseta for the Almeida Racing Academy.

## 🏗️ Architecture

- **Backend**: Vercel serverless function (`api/auth/garage61.js`)
- **Frontend**: Framer component (`Garage61SSOButton.tsx`)
- **User Management**: Outseta CRM with JWT tokens

## 📋 Setup Instructions

### 1. Get Garage 61 OAuth Credentials

Contact Garage 61 support to register your OAuth application:
- **Email**: support@garage61.com (adjust as needed)
- **Required Info**:
  - Application Name: "Almeida Racing Academy"
  - Redirect URI: `https://your-vercel-app.vercel.app/api/auth/garage61`
  - Website: `https://almeidaracingacademy.com`
  - Scopes needed: `profile`, `email`

You'll receive:
- `GARAGE61_CLIENT_ID`
- `GARAGE61_CLIENT_SECRET`

### 2. Configure Outseta Custom Fields

In Outseta dashboard:
1. Go to **CRM** → **Custom Properties**
2. Add these custom fields on **Person** (if not already present):
   - `Garage61Username` (Text)
   - `Garage61Id` (Text)
   - `iRacingUsername` (Text) - Auto-populated if user has iRacing linked to Garage 61
   - `iRacingId` (Text) - Auto-populated if user has iRacing linked to Garage 61

3. Add these custom fields on **Account** (for Discord bot sync):
   - `Garage61AccessToken` (Text) - Stores OAuth access token
   - `Garage61RefreshToken` (Text) - Stores OAuth refresh token
   - `Garage61TokenExpiry` (Date) - Stores token expiry timestamp

### 3. Deploy Backend to Vercel

```bash
cd "Garage 61 SSO"
vercel
```

Set environment variables in Vercel dashboard:
```
GARAGE61_CLIENT_ID=your_client_id
GARAGE61_CLIENT_SECRET=your_client_secret
GARAGE61_REDIRECT_URI=https://your-vercel-app.vercel.app/api/auth/garage61
OUTSETA_DOMAIN=almeidaracingacademy.outseta.com
OUTSETA_API_KEY=your_api_key
OUTSETA_SECRET_KEY=your_secret_key
```

### 4. Add Button to Framer

1. Copy `Garage61SSOButton.tsx` to your Framer project
2. Update the `backendUrl` property to your deployed Vercel URL
3. Add the component to your sign-in page
4. Customize button text and styles as needed

## 🔒 Security Features

✅ Origin validation for postMessage events  
✅ CORS restricted to trusted domains  
✅ XSS protection with input sanitization  
✅ Secure token exchange via backend  
✅ No client-side secrets  
✅ 8-second timeouts on all API calls  
✅ Error messages sanitized before display  

## ✨ Features

- **Unified Identity**: Automatically links Garage 61, iRacing, and Outseta accounts
- **iRacing Auto-Sync**: If user has iRacing linked to Garage 61, their iRacing data is automatically synced to Outseta
- **Field Consistency**: Uses same field names as iRacing SSO (`iRacingUsername`, `iRacingId`) for compatibility
- **Graceful Fallback**: Works perfectly even if iRacing data is not available
- **Smart Updates**: Only updates fields that have changed to minimize API calls
- **OAuth Token Storage**: Stores Garage 61 access/refresh tokens to Outseta Account for Discord bot sync

## 🔄 OAuth Flow

1. User clicks "Sign in with Garage 61" button
2. Popup opens to Garage 61 authorization page
3. User approves access
4. Garage 61 redirects to callback with auth code
5. Backend exchanges code for access token
6. Backend fetches user profile from Garage 61
7. Backend fetches connected accounts (checks for linked iRacing account)
8. Backend creates/updates user in Outseta (includes iRacing data if available)
9. Backend generates Outseta JWT token
10. Token sent to frontend via postMessage
11. Frontend sets Outseta token and redirects

## 🛠️ Testing

1. Deploy backend to Vercel
2. Set all environment variables
3. Click the button in Framer preview
4. Check browser console for logs
5. Verify user created in Outseta dashboard

## 🤖 Discord Bot Token Storage

After successful OAuth, Garage 61 tokens are stored to the Outseta **Account** (not Person) for use by the Discord bot:

| Outseta Account Field | Value |
|-----------------------|-------|
| `Garage61AccessToken` | The OAuth access token |
| `Garage61RefreshToken` | The OAuth refresh token |
| `Garage61TokenExpiry` | ISO timestamp when access token expires |

**Why?** The Discord bot uses these tokens to:
1. Check user's current Garage 61 data pack subscriptions
2. Subscribe/unsubscribe users based on their Outseta plan
3. Auto-refresh expired tokens and write new tokens back to Outseta

**Note:** Data pack subscription is handled entirely by the Discord bot - the OAuth flow only stores tokens.

**Users only need to authenticate once** - the bot handles token refresh automatically.

**Token Lifecycle:**
- Stored on login, link, and new account creation
- Cleared when user disconnects Garage 61 from their account
- Refreshed by Discord bot during sync operations

## 📝 Notes

- **Garage 61 API Endpoints**: The OAuth endpoints in this code (`https://auth.garage61.com`, `https://garage61.net/api/v1/`) are placeholders. Update them based on actual Garage 61 API documentation.
- **iRacing Data Source**: iRacing data is fetched from Garage 61's `/v1/getAccounts` endpoint (see [API docs](https://garage61.net/developer/endpoints/v1/getAccounts))
- **Scopes**: Adjust OAuth scopes based on what data you need from Garage 61.
- **Custom Fields**: The following fields are stored in Outseta:
  - **Person-level:**
  - `Garage61Username` & `Garage61Id` - Always populated from Garage 61
  - `iRacingUsername` & `iRacingId` - Only populated if user has linked iRacing to Garage 61
  - **Account-level (for Discord bot):**
    - `Garage61AccessToken` - OAuth access token
    - `Garage61RefreshToken` - OAuth refresh token  
    - `Garage61TokenExpiry` - Token expiry timestamp (Date field)
- **Field Mapping**: 
  - `iRacingData.displayName` → `iRacingUsername` in Outseta
  - `iRacingData.custId` → `iRacingId` in Outseta

## 🐛 Troubleshooting

**Popup blocked**: Enable popups for your site  
**401 Unauthorized**: Check Outseta API credentials  
**400 Bad Request**: Verify Garage 61 OAuth credentials  
**Token not set**: Check CORS and origin validation  

## 📚 Related Files

- iRacing SSO: `/iRacing SSO/`
- Discord SSO: `/Discord SSO/`
- Framer Components: `/ARA/`

