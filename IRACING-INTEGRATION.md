# iRacing Data Integration via Garage61

## 🎯 Overview

The Garage61 SSO now automatically fetches and syncs iRacing data when users have their iRacing account linked to Garage61. This provides a unified identity across all three platforms: Garage61, iRacing, and Outseta.

## 🔄 How It Works

When a user signs in with Garage61:

1. **Authentication** - User authenticates with Garage61 OAuth
2. **Profile Fetch** - Backend fetches Garage61 user profile
3. **Account Check** - Backend calls Garage61's `/v1/getAccounts` endpoint
4. **iRacing Detection** - If `iRacing` data exists in response, extract it
5. **Sync to Outseta** - Save both Garage61 and iRacing data to Outseta user profile

## 📊 Data Mapping

### Garage61 API Response Structure

According to [Garage61 API docs](https://garage61.net/developer/endpoints/v1/getAccounts):

```json
{
  "iRacing": {
    "custId": 123456,
    "displayName": "John Racer",
    // ... other fields
  }
}
```

### Outseta Field Mapping

| Source | Garage61 Field | Outseta Field |
|--------|----------------|---------------|
| Garage61 | `username` | `Garage61Username` |
| Garage61 | `id` | `Garage61Id` |
| iRacing (via Garage61) | `iRacing.displayName` | `iRacingUsername` |
| iRacing (via Garage61) | `iRacing.custId` | `IRacingId` |

## ✅ Field Consistency

The Outseta fields use **exactly the same names** as the direct iRacing SSO integration:
- `iRacingUsername`
- `IRacingId`

This means:
- ✅ Users can sign in via **either** Garage61 or iRacing SSO
- ✅ iRacing data will be consistent regardless of sign-in method
- ✅ No duplicate or conflicting fields
- ✅ Seamless user experience across both flows

## 🔒 Smart Update Logic

The integration intelligently updates fields:

```javascript
// Only updates if:
1. Field is empty (new user or missing data)
2. Field value has changed (user updated their info)

// This minimizes unnecessary API calls and prevents data thrashing
```

## 🛡️ Graceful Fallback

If iRacing data is not available (e.g., user hasn't linked account, API error), the system:
- ✅ Continues with Garage61 authentication normally
- ✅ Logs warning but doesn't fail
- ✅ Only syncs Garage61 fields
- ✅ Can sync iRacing data on future logins if user links account

## 🧪 Testing

### Test Case 1: User with iRacing Linked
```
1. User has Garage61 account with linked iRacing
2. User signs in via Garage61
3. Check Outseta: Should see all 4 fields populated:
   - Garage61Username: ✓
   - Garage61Id: ✓
   - iRacingUsername: ✓
   - IRacingId: ✓
```

### Test Case 2: User without iRacing Linked
```
1. User has Garage61 account, no iRacing
2. User signs in via Garage61
3. Check Outseta: Should see only Garage61 fields:
   - Garage61Username: ✓
   - Garage61Id: ✓
   - iRacingUsername: (empty)
   - IRacingId: (empty)
```

### Test Case 3: User Links iRacing Later
```
1. User signs in via Garage61 (no iRacing initially)
2. User links iRacing to Garage61 account
3. User signs in again via Garage61
4. Check Outseta: iRacing fields now populated automatically
```

### Test Case 4: Cross-SSO Compatibility
```
1. User signs in via Garage61 (iRacing linked)
2. Check Outseta: iRacing fields populated
3. Same user signs in via direct iRacing SSO
4. Check Outseta: Same iRacing fields, no duplicates
```

## 🔍 Debugging

### Check if iRacing data was fetched

Look for these console logs in Vercel:

```
✓ Garage61 access token obtained
✓ Garage61 user data: { email, username, id }
✓ iRacing account found: { custId, displayName }  ← Look for this!
✓ Outseta user: user@example.com
```

### Verify data in Outseta

```bash
# In browser console on your Framer site:
Outseta.getUser().then(user => {
  console.log({
    garage61: {
      username: user.Garage61Username,
      id: user.Garage61Id
    },
    iracing: {
      username: user.iRacingUsername,
      id: user.IRacingId
    }
  })
})
```

### Common Issues

**iRacing fields empty despite user having linked account:**
- Check Garage61 API endpoint URL is correct (`https://garage61.net/api/v1/getAccounts`)
- Verify OAuth scopes include access to accounts data
- Check Vercel logs for API errors

**Fields not updating on subsequent logins:**
- This is expected if data hasn't changed (optimization)
- Force update by changing data on Garage61/iRacing
- Check `needsIRacingUpdate` logic in code

## 📚 Related Files

- **Main Integration**: `api/auth/garage61.js`
- **iRacing SSO** (for field name reference): `../iRacing SSO/api/auth/iracing.js`
- **Setup Guide**: `README.md`

## 🎉 Benefits

1. **Single Sign-On** - One click sign-in with Garage61 gets iRacing data too
2. **Reduced Friction** - Users don't need separate iRacing SSO if using Garage61
3. **Consistent Identity** - Same user profile across all platforms
4. **Future-Proof** - Easy to add more connected accounts (Steam, ACC, etc.)
5. **Better Analytics** - Track which users are on which platforms

---

**Implementation Date**: October 31, 2025  
**API Reference**: https://garage61.net/developer/endpoints/v1/getAccounts  
**Status**: ✅ Production Ready

