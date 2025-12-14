# Login Security Squad

Detects and prevents users from sharing login credentials.

## How It Works

Login Security Squad protects your content by monitoring user activity for signs of account sharing. It uses a combination of session management, IP and device fingerprinting, and behavioral analysis to identify suspicious behavior and block unauthorized access.

### Core Components

*   **Custom Database Tables:**
    *   `wp_login_security_logs`: Records detailed information about each user login, including IP address, user agent, location, session token, and a unique device fingerprint. All sensitive data (IPs, fingerprints) is encrypted.
    *   `wp_lss_content_access_logs`: Tracks when a user accesses a piece of protected content, logging their user ID, the content ID, IP address, and device fingerprint.

*   **Concurrent Session Limiting:**
    *   You can set a limit on the number of simultaneous login sessions a user can have (e.g., 1 or 2).
    *   When a user exceeds this limit, the plugin prompts them to log out of their other sessions before they can proceed, preventing multiple people from using the same account at the same time.

*   **IP & Device Fingerprinting:**
    *   On every login, the plugin captures the user's IP address and generates a unique "fingerprint" for their device based on their browser and other system details.
    *   It flags accounts for suspicious activity if it detects logins from too many unique IPs or devices within a short period (configurable in the settings).
    *   The plugin also uses geolocation to flag logins from distant locations, adding another layer of security.

*   **One-Time Password (OTP) Verification:**
    *   If a user's login is flagged as suspicious, the plugin can be configured to require them to enter a one-time password (OTP) sent to their registered email address.
    *   This ensures that even if someone has a user's password, they won't be able to log in from an unrecognized device or location without access to the user's email.

*   **Content Access Monitoring:**
    *   The plugin monitors how often users access your protected content.
    *   If it detects the same content being accessed from multiple devices in a short time, it will flag the account for suspicious activity, as this can be a sign of link sharing.

*   **Admin Dashboard & Controls:**
    *   **Settings Page:** A comprehensive settings page allows you to configure all of the plugin's features, including session limits, IP and device thresholds, and email templates.
    *   **Dashboard Widget:** A widget on the main WordPress dashboard shows you a list of all flagged accounts, so you can quickly see who might be sharing their account.
    *   **User Management:** You can warn, temporarily suspend, or permanently ban users directly from the WordPress users list or the plugin's dashboard.

## How to Test the Plugin

Follow these steps to test the core features of the Login Security Squad plugin.

### Test 1: Concurrent Session Limiting

1.  **Configure:** Go to **Login Security > Anti-Sharing** in your WordPress admin panel and set the **Session Limit** to `1`.
2.  **Log In (First Session):** Open a browser (e.g., Chrome) and log in to a test user account.
3.  **Log In (Second Session):** Open a different browser (e.g., Firefox) or use a private browsing window and try to log in to the *same* user account.
4.  **Expected Outcome:** You should be redirected to a page asking you to "Log Out Other Devices." Clicking the button should end the first session (in Chrome) and allow you to proceed in the second session (in Firefox).

### Test 2: Suspicious Activity Flagging & OTP Verification

1.  **Configure:**
    *   Go to **Login Security > Anti-Sharing**.
    *   Set the **IP Threshold** to `2`.
    *   Enable **OTP Verification**.
    *   Make sure you have a working email delivery service on your WordPress site.
2.  **Log In (First IP):** Log in to a test user account from your current IP address.
3.  **Log In (Second IP):** Use a VPN or a different network (e.g., your mobile phone's data plan) to change your IP address. Log in to the same account again.
4.  **Log In (Third IP):** Change your IP address one more time and attempt to log in.
5.  **Expected Outcome:**
    *   On the third login attempt, you should be blocked and see a message telling you to enter an OTP.
    *   The user should receive an email with a 6-digit OTP.
    *   Entering the correct OTP should allow you to log in.
    *   The admin should receive an email notification about the suspicious activity.
    *   The user's account should now show up in the "Flagged Accounts" widget on the dashboard.

### Test 3: Content Access Monitoring

1.  **Configure:**
    *   Create a post or page and mark it as protected using the "Protected Content" meta box on the post edit screen.
    *   Go to **Login Security > Anti-Sharing** and set the **Content Access Threshold** to `2`.
2.  **Log In:** Log in to a test user account.
3.  **Access Content:** Visit the protected post you created.
4.  **Access from Another "Device":** This is harder to simulate, but the plugin tracks devices based on browser fingerprint. Try accessing the same protected page from a different browser on the same computer.
5.  **Expected Outcome:** After a few accesses from different "devices," the user's account should be flagged, and the admin should be notified.

### Test 4: Admin Actions (Warn, Suspend, Ban)

1.  **Go to the Users List:** In your WordPress admin panel, go to **Users**.
2.  **Warn:** Find your test user and click the "Warn" link.
    *   **Expected Outcome:** The user should receive a warning email (you can configure the text in the plugin settings).
3.  **Suspend:** Click the "Suspend" link.
    *   **Expected Outcome:** The user should be logged out and unable to log in for one hour.
4.  **Ban:** Click the "Ban" link.
    *   **Expected Outcome:** The user's account should be permanently blocked. They should not be able to log in with their old password, even if they try to log in with their email address. You can unblock them from the **Login Security** settings page.

## Changelog

### 1.2 (2024-07-31)
*   Fixed a bug that prevented admins from unblocking users who were locked out due to too many failed OTP attempts.
*   Enhanced the admin UI by displaying usernames in the login logs and allowing admins to block users by username or user ID.
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
* Patched a critical security vulnerability where a banned user could log in using their email address.

## Installation

1.  Download the `login-security-squad.zip` file.
2.  In your WordPress admin panel, go to **Plugins** > **Add New**.
3.  Click **Upload Plugin** and select the downloaded zip file.
4.  Activate the plugin.
5.  Go to **Login Security > Anti-Sharing** to configure the plugin.
