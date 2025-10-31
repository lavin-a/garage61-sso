# Garage61 SSO Integration

Secure OAuth integration between Garage61 and Outseta for the Almeida Racing Academy.

## 🏗️ Architecture

- **Backend**: Vercel serverless function (`api/auth/garage61.js`)
- **Frontend**: Framer component (`Garage61SSOButton.tsx`)
- **User Management**: Outseta CRM with JWT tokens

## 📋 Setup Instructions

### 1. Get Garage61 OAuth Credentials

Contact Garage61 support to register your OAuth application:
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
2. Add these custom fields (if not already present):
   - `Garage61Username` (Text)
   - `Garage61Id` (Text)

### 3. Deploy Backend to Vercel

```bash
cd "Garage61 SSO"
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

## 🔄 OAuth Flow

1. User clicks "Sign in with Garage61" button
2. Popup opens to Garage61 authorization page
3. User approves access
4. Garage61 redirects to callback with auth code
5. Backend exchanges code for access token
6. Backend fetches user profile from Garage61
7. Backend creates/updates user in Outseta
8. Backend generates Outseta JWT token
9. Token sent to frontend via postMessage
10. Frontend sets Outseta token and redirects

## 🛠️ Testing

1. Deploy backend to Vercel
2. Set all environment variables
3. Click the button in Framer preview
4. Check browser console for logs
5. Verify user created in Outseta dashboard

## 📝 Notes

- **Garage61 API Endpoints**: The OAuth endpoints in this code (`https://auth.garage61.com`, `https://api.garage61.com`) are placeholders. Update them based on actual Garage61 API documentation.
- **Scopes**: Adjust OAuth scopes based on what data you need from Garage61.
- **Custom Fields**: Garage61Username and Garage61Id are stored as custom properties in Outseta.

## 🐛 Troubleshooting

**Popup blocked**: Enable popups for your site  
**401 Unauthorized**: Check Outseta API credentials  
**400 Bad Request**: Verify Garage61 OAuth credentials  
**Token not set**: Check CORS and origin validation  

## 📚 Related Files

- iRacing SSO: `/iRacing SSO/`
- Discord SSO: `/Discord SSO/`
- Framer Components: `/ARA/`

