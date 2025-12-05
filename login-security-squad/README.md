# Login Security Squad

Detects and prevents users from sharing login credentials.

## Changelog

### 1.1 (2025-12-05)
* Fixed a fatal error on activation caused by a syntax error.
* Added concurrent session limiting.
* Added IP and device fingerprinting.
* Added OTP verification for suspicious logins.
* Added usage pattern monitoring.
* Added a dashboard widget for flagged accounts.
* Added "Warn," "Suspend," and "Ban" actions to the users list.
* Added a meta box to protect content.
* Added a toggle for geolocation flagging.
* Encrypted sensitive data in the database.

## Installation

1.  Download the `login-security-squad.zip` file.
2.  In your WordPress admin panel, go to **Plugins** > **Add New**.
3.  Click **Upload Plugin** and select the downloaded zip file.
4.  Activate the plugin.
5.  Go to **Settings** > **Login Security** to configure the plugin.

## Test Cases

### Test Case 1: First Shared Login

1.  Log in with a user account from a specific IP address and location.
2.  Log in with the same user account from a different IP address that is geographically distant (e.g., use a VPN).
3.  **Expected Outcome:**
    *   The administrator receives an email notification about the suspicious activity.
    *   The user is immediately logged out.
    *   The user is redirected to the login page with a warning message.
    *   The user is temporarily blocked from logging in for 1 hour.

### Test Case 2: Repeat Shared Login

1.  After the 1-hour temporary block from the first test case has expired, log in again with the same user account from a different IP address.
2.  **Expected Outcome:**
    *   The administrator receives another email notification.
    *   The user's account is permanently blocked (password is changed).
    *   The user can no longer log in with their old password.
    *   The administrator can see the blocked user in the plugin's settings and can manually unblock them.
