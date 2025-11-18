# Garage61 Data Pack Integration

## Overview

This integration automatically subscribes users to Garage61 data pack groups when they link their Garage61 account to ARA.

## Implementation Details

### When Data Pack Subscription Occurs

The system subscribes users to Garage61 data packs in the following scenarios:

1. **New Account Creation**: When a user signs up with Garage61 for the first time
2. **Account Linking**: When an existing ARA user links their Garage61 account

### Subscription Tiers

- **Free Data Pack Group**: All users are automatically subscribed
  - Provides access to Garage61 challenges
  - Users are automatically enrolled in the challenges training plan
  - Performance tracking begins immediately

- **Pro Data Pack Group**: Only Pro users are subscribed
  - Pro users include those with: Gold, Motorsports, MRC, or RCC plans
  - Prepares for future Pro-specific content and bundling

## Required Environment Variables

Add these to your Vercel project environment variables:

```bash
GARAGE61_FREE_DATA_PACK_GROUP_ID=<free_group_id>
GARAGE61_PRO_DATA_PACK_GROUP_ID=<pro_group_id>
```

**Note**: Get the actual data pack group IDs from the Garage61 developer dashboard.

## Technical Implementation

### API Endpoint Used

- **URL**: `https://garage61.net/api/v1/createUserDataPackGroup`
- **Method**: POST
- **Authentication**: Bearer token (Garage61 access token)
- **Payload**:
  ```json
  {
    "userDataPackGroupId": "<group_id>"
  }
  ```

### Error Handling

- Data pack subscription failures are logged but **do not** block the authentication flow
- Users can still complete sign-in/linking even if data pack subscription fails
- Errors are logged to console with details for debugging

### Pro User Detection

The system checks for these Outseta plan UIDs to determine Pro status:
- `aWxroqQV` - Gold
- `z9MzwKW4` - Gold Membership Add-on
- `496zb49X` - Motorsports
- `7maRGMQE` - MRC
- `496rpB9X` - RCC

## Code Flow

1. User completes Garage61 OAuth flow
2. System creates/updates Outseta account
3. System checks if user has Pro plan
4. System subscribes to Free data pack group (always)
5. System subscribes to Pro data pack group (if applicable)
6. User is redirected to ARA with authentication complete

## Testing

After deployment, check Vercel logs for:
- `"Successfully subscribed user to Free Garage61 data pack group"`
- `"Successfully subscribed user to Pro Garage61 data pack group"` (for Pro users)
- Any warnings about failed subscriptions

## Next Steps

1. Add the environment variables to Vercel
2. Get the correct data pack group IDs from Garage61
3. Deploy the updated function
4. Test with both Free and Pro accounts
5. Verify in Garage61 dashboard that users are being added to the correct groups

