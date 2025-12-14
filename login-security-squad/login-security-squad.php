<?php
/**
 * Plugin Name:       Login Security Squad
 * Plugin URI:        https://example.com/
 * Description:       Detects and prevents users from sharing login credentials.
 * Version:           1.2
 * Author:            Jules
 * Author URI:        https://example.com/
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       login-security-squad
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly.
}

/**
 * Activate the plugin.
 */
function lss_activate_plugin() {
    if ( ! extension_loaded( 'openssl' ) ) {
        deactivate_plugins( plugin_basename( __FILE__ ) );
        wp_die( 'Login Security Squad requires the OpenSSL PHP extension to be enabled. Please contact your host to enable it.' );
    }
    global $wpdb;
    $table_name = $wpdb->prefix . 'login_security_logs';
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE IF NOT EXISTS $table_name (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        user_id bigint(20) NOT NULL,
        ip_address varchar(100) NOT NULL,
        user_agent text NOT NULL,
        login_time datetime NOT NULL,
        location varchar(255) DEFAULT '' NOT NULL,
        latitude varchar(100) DEFAULT '' NOT NULL,
        longitude varchar(100) DEFAULT '' NOT NULL,
        session_token varchar(255) DEFAULT '' NOT NULL,
        device_fingerprint varchar(255) DEFAULT '' NOT NULL,
        PRIMARY KEY  (id)
    ) $charset_collate;";

    require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
    $result = dbDelta( $sql );
    if ( ! empty( $result ) ) {
        error_log( 'Login Security Squad: Error creating login_security_logs table: ' . print_r( $result, true ) );
    }

    $table_name = $wpdb->prefix . 'lss_content_access_logs';
    $sql = "CREATE TABLE IF NOT EXISTS $table_name (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        user_id bigint(20) NOT NULL,
        post_id bigint(20) NOT NULL,
        access_time datetime NOT NULL,
        ip_address varchar(100) NOT NULL,
        device_fingerprint varchar(255) DEFAULT '' NOT NULL,
        PRIMARY KEY  (id)
    ) $charset_collate;";
    $result = dbDelta( $sql );
    if ( ! empty( $result ) ) {
        error_log( 'Login Security Squad: Error creating lss_content_access_logs table: ' . print_r( $result, true ) );
    }
}
register_activation_hook( __FILE__, 'lss_activate_plugin' );

/**
 * Deactivate the plugin.
 */
function lss_deactivate_plugin() {
    // We don't need to do anything here, but it's good practice to have this function.
}
register_deactivation_hook( __FILE__, 'lss_deactivate_plugin' );

/**
 * Track user logins.
 *
 * @param string  $user_login The user's login name.
 * @param WP_User $user       The WP_User object.
 */
function lss_track_login( $user_login, $user ) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'login_security_logs';

    $ip_address = lss_get_user_ip();
    $user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
    $login_time = current_time( 'mysql' );
    $location_data   = lss_get_location_from_ip( $ip_address );
    $session_token = wp_get_session_token();

    $wpdb->insert(
        $table_name,
        array(
            'user_id'    => $user->ID,
            'ip_address' => lss_encrypt_data( $ip_address ),
            'user_agent' => $user_agent,
            'login_time' => $login_time,
            'location'   => $location_data['location'],
            'latitude'   => $location_data['latitude'],
            'longitude'  => $location_data['longitude'],
            'session_token' => $session_token,
        )
    );

}
add_action( 'wp_login', 'lss_track_login', 10, 2 );

/**
 * Check for suspicious activity on authentication.
 *
 * @param WP_User|WP_Error|null $user     WP_User object if authentication succeeds, WP_Error object or null otherwise.
 * @param string                $username The username.
 * @return WP_User|WP_Error|null
 */
function lss_check_suspicious_activity_on_auth( $user, $username ) {
    if ( is_a( $user, 'WP_User' ) ) {
        $ip_address = lss_get_user_ip();
        $location_data   = lss_get_location_from_ip( $ip_address );
        $result = lss_check_suspicious_activity( $user->ID, $ip_address, $location_data );
        if ( is_wp_error( $result ) ) {
            return $result;
        }
    }
    return $user;
}
add_filter( 'authenticate', 'lss_check_suspicious_activity_on_auth', 25, 2 );

/**
 * Get user IP address.
 *
 * @return string
 */
function lss_get_user_ip() {
    if ( ! empty( $_SERVER['HTTP_CLIENT_IP'] ) ) {
        $ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CLIENT_IP'] ) );
    } elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
        $ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
    } else {
        $ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
    }
    return $ip;
}

/**
 * Get location from IP address using ipapi.co.
 *
 * @param string $ip_address The IP address.
 * @return array
 */
function lss_get_location_from_ip( $ip_address ) {
    $location_data = array(
        'location'  => '',
        'latitude'  => '',
        'longitude' => '',
    );
	if ( ! $ip_address ) {
		return $location_data;
	}

    // Use a transient to cache the API response for 24 hours.
    $transient_key   = 'lss_location_' . md5( $ip_address );
    $cached_location = get_transient( $transient_key );

    if ( false !== $cached_location ) {
        return $cached_location;
    }

    $response = wp_remote_get( "https://ipapi.co/{$ip_address}/json/" );

    if ( is_wp_error( $response ) ) {
        return $location_data;
    }

    $body = wp_remote_retrieve_body( $response );
    $data = json_decode( $body );

    if ( $data && empty( $data->error ) ) {
        $location_data['location']  = $data->city . ', ' . $data->region . ', ' . $data->country_name;
        $location_data['latitude']  = $data->latitude;
        $location_data['longitude'] = $data->longitude;
        // Cache the location for 24 hours.
        set_transient( $transient_key, $location_data, DAY_IN_SECONDS );
    }

    return $location_data;
}

/**
 * Check for suspicious activity.
 *
 * @param int   $user_id       The user ID.
 * @param string $ip_address    The IP address.
 * @param array $location_data The location data.
 */
function lss_check_suspicious_activity( $user_id, $ip_address, $location_data ) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'login_security_logs';

    // Get the last 24 hours of logins for this user.
    $logins = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT * FROM $table_name WHERE user_id = %d AND login_time > DATE_SUB(NOW(), INTERVAL 24 HOUR) ORDER BY login_time DESC",
            $user_id
        )
    );

    // Check for multiple IPs.
    $ip_threshold = (int) get_option( 'lss_ip_threshold', 2 );
    $ip_grace_period = (int) get_option( 'lss_ip_grace_period', 7 );
    $logins_in_grace_period = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT * FROM $table_name WHERE user_id = %d AND login_time > DATE_SUB(NOW(), INTERVAL %d DAY) ORDER BY login_time DESC",
            $user_id,
            $ip_grace_period
        )
    );
    $decrypted_ips = array_map( 'lss_decrypt_data', wp_list_pluck( $logins_in_grace_period, 'ip_address' ) );
    $unique_ips = array_unique( $decrypted_ips );
    if ( count( $unique_ips ) > $ip_threshold ) {
        return lss_handle_suspicious_activity(
            $user_id,
            'Multiple IPs',
            array(
                'IPs' => implode( ', ', $unique_ips ),
            )
        );
    }

    // Check for multiple device fingerprints.
    $fingerprint_threshold = (int) get_option( 'lss_fingerprint_threshold', 2 );
    $decrypted_fingerprints = array_filter( array_map( 'lss_decrypt_data', wp_list_pluck( $logins, 'device_fingerprint' ) ) );
    $unique_fingerprints   = array_unique( $decrypted_fingerprints );
    if ( count( $unique_fingerprints ) > $fingerprint_threshold ) {
        return lss_handle_suspicious_activity(
            $user_id,
            'Multiple Devices',
            array(
                'Devices' => implode( ', ', $unique_fingerprints ),
            )
        );
    }

    // Check for distant locations.
    if ( get_option( 'lss_enable_geolocation' ) ) {
        if ( count( $logins ) > 1 ) {
            $previous_login = $logins[1]; // The one before the current login.
            if ( ! empty( $location_data['latitude'] ) && ! empty( $previous_login->latitude ) ) {
                $distance = lss_calculate_distance(
                    $location_data['latitude'],
                    $location_data['longitude'],
                    $previous_login->latitude,
                    $previous_login->longitude
                );
                // Threshold of 1000km.
                $distance_threshold = (int) get_option( 'lss_distance_threshold', 1000 );
                if ( $distance > $distance_threshold ) {
                    return lss_handle_suspicious_activity(
                        $user_id,
                        'Distant Location',
                        array(
                            'Distance'         => round( $distance ) . ' km',
                            'Current Location'  => $location_data['location'],
                            'Previous Location' => $previous_login->location,
                        )
                    );
                }
            }
        }
    }
}

/**
 * Calculate the distance between two points on Earth.
 *
 * @param float $lat1 Latitude of point 1.
 * @param float $lon1 Longitude of point 1.
 * @param float $lat2 Latitude of point 2.
 * @param float $lon2 Longitude of point 2.
 * @return float The distance in kilometers.
 */
function lss_calculate_distance( $lat1, $lon1, $lat2, $lon2 ) {
    $earth_radius = 6371; // in km

    $dLat = deg2rad( $lat2 - $lat1 );
    $dLon = deg2rad( $lon2 - $lon1 );

    $a = sin( $dLat / 2 ) * sin( $dLat / 2 ) + cos( deg2rad( $lat1 ) ) * cos( deg2rad( $lat2 ) ) * sin( $dLon / 2 ) * sin( $dLon / 2 );
    $c = 2 * atan2( sqrt( $a ), sqrt( 1 - $a ) );

    return $earth_radius * $c;
}

/**
 * Handle suspicious activity.
 *
 * @param int    $user_id       The user ID.
 * @param string $reason        The reason for the suspension.
 * @param array  $details       The details of the suspicious activity.
 */
function lss_handle_suspicious_activity( $user_id, $reason, $details = array() ) {
    // Check if this is a repeat offense.
    $suspicion_count = (int) get_user_meta( $user_id, 'lss_suspicion_count', true );
    $suspicion_count++;
    update_user_meta( $user_id, 'lss_suspicion_count', $suspicion_count );

    // Send email notification to the admin.
    $admin_email = get_option( 'lss_admin_email', get_option( 'admin_email' ) );
    $subject     = 'Suspicious Login Activity Detected';
    $message     = "Suspicious login activity was detected for user ID: {$user_id}.\n\n";
    $message    .= "Reason: {$reason}\n";
    $message    .= "Details:\n";
    foreach ( $details as $key => $value ) {
        $message .= "{$key}: {$value}\n";
    }
    wp_mail( $admin_email, $subject, $message );

    if ( $suspicion_count > 1 ) {
        // This is a repeat offense, permanently block the account.
        wp_update_user(
            array(
                'ID'       => $user_id,
                'role'     => 'no-role',
                'user_pass' => wp_generate_password( 32 ), // Lock out the user.
            )
        );
        update_user_meta( $user_id, 'lss_permanently_blocked', true );
        return new WP_Error( 'lss_blocked', __( '<strong>ERROR</strong>: Your account has been permanently suspended due to suspicious activity.', 'login-security-squad' ) );
    } else {
        if ( get_option( 'lss_enable_otp' ) ) {
            // This is the first offense, require OTP verification.
            $otp = lss_generate_otp();
            update_user_meta( $user_id, 'lss_otp', $otp );
            update_user_meta( $user_id, 'lss_otp_timestamp', time() );

            // Send OTP to the user's email.
            $user    = get_userdata( $user_id );
            $email   = $user->user_email;
            $subject = 'Your One-Time Password';
            $message = "Your one-time password is: {$otp}";
            wp_mail( $email, $subject, $message );

            return new WP_Error( 'lss_otp_required', __( '<strong>ERROR</strong>: Your account has been flagged for suspicious activity. Please enter the one-time password sent to your email address to continue.', 'login-security-squad' ) );
        } else {
            // This is the first offense, temporarily block the account for 1 hour.
            set_transient( 'lss_user_blocked_' . $user_id, true, HOUR_IN_SECONDS );
            return new WP_Error( 'lss_blocked', __( '<strong>ERROR</strong>: Your account has been temporarily suspended due to suspicious activity.', 'login-security-squad' ) );
        }
    }
}

/**
 * Generate a random OTP.
 *
 * @return string
 */
function lss_generate_otp() {
    return (string) random_int( 100000, 999999 );
}

/**
 * Prevent temporarily blocked users from logging in.
 *
 * @param WP_User|WP_Error|null $user     WP_User object if authentication succeeds, WP_Error object or null otherwise.
 * @param string                $username The username.
 * @param string                $password The password.
 * @return WP_User|WP_Error|null
 */
function lss_prevent_blocked_login( $user, $username, $password ) {
    if ( is_wp_error( $user ) ) {
        return $user;
    }

    $user_obj = null;
    if ( ! empty( $username ) ) {
        if ( is_email( $username ) ) {
            $user_obj = get_user_by( 'email', $username );
        } else {
            $user_obj = get_user_by( 'login', $username );
        }
    }

    if ( is_a( $user_obj, 'WP_User' ) ) {
        if ( get_transient( 'lss_user_blocked_' . $user_obj->ID ) ) {
            return new WP_Error( 'lss_blocked', __( '<strong>ERROR</strong>: Your account has been temporarily suspended due to suspicious activity.', 'login-security-squad' ) );
        }
        if ( get_user_meta( $user_obj->ID, 'lss_permanently_blocked', true ) ) {
            return new WP_Error( 'lss_blocked', __( '<strong>ERROR</strong>: Your account has been permanently suspended due to suspicious activity.', 'login-security-squad' ) );
        }
    }

    return $user;
}
add_filter( 'authenticate', 'lss_prevent_blocked_login', 30, 3 );


/**
 * Display a message on the login screen.
 */
function lss_login_message() {
    if ( isset( $_GET['lss_blocked'] ) ) {
        if ( 'permanent' === $_GET['lss_blocked'] ) {
            return '<p class="message">Your account has been permanently suspended due to suspicious activity.</p>';
        } else {
            return '<p class="message">Your account has been temporarily suspended due to suspicious activity.</p>';
        }
    }
}
add_filter( 'login_message', 'lss_login_message' );

/**
 * Display an OTP input field on the login screen.
 */
function lss_otp_login_message() {
    if ( isset( $_GET['lss_otp_required'] ) ) {
        return '<p class="message">Your account has been flagged for suspicious activity. Please enter the one-time password sent to your email address to continue.</p>' .
            '<p><label for="lss_otp">One-Time Password</label><input type="text" name="lss_otp" id="lss_otp" class="input" value="" size="20" /></p>';
    }
}
add_filter( 'login_message', 'lss_otp_login_message' );

/**
 * Verify the OTP.
 *
 * @param WP_User|WP_Error|null $user     WP_User object if authentication succeeds, WP_Error object or null otherwise.
 * @param string                $password The password.
 * @return WP_User|WP_Error|null
 */
function lss_verify_otp( $user, $password ) {
    if ( is_a( $user, 'WP_User' ) && get_user_meta( $user->ID, 'lss_otp', true ) ) {
        $otp     = isset( $_POST['lss_otp'] ) ? sanitize_text_field( wp_unslash( $_POST['lss_otp'] ) ) : '';
        $stored_otp = get_user_meta( $user->ID, 'lss_otp', true );
        $otp_timestamp = (int) get_user_meta( $user->ID, 'lss_otp_timestamp', true );

        if ( ! $stored_otp || $stored_otp !== $otp ) {
            $failed_attempts = (int) get_user_meta( $user->ID, 'lss_otp_failed_attempts', true );
            $failed_attempts++;
            update_user_meta( $user->ID, 'lss_otp_failed_attempts', $failed_attempts );
            if ( $failed_attempts > 5 ) {
                // Lock the account if there are too many failed attempts.
                update_user_meta( $user->ID, 'lss_permanently_blocked', true );
                return new WP_Error( 'lss_blocked', __( '<strong>ERROR</strong>: Your account has been permanently suspended due to too many failed OTP attempts.', 'login-security-squad' ) );
            }
            return new WP_Error( 'lss_otp_invalid', __( '<strong>ERROR</strong>: The one-time password you entered is incorrect.', 'login-security-squad' ) );
        }

        if ( time() - $otp_timestamp > 300 ) { // 5-minute validity.
            return new WP_Error( 'lss_otp_expired', __( '<strong>ERROR</strong>: The one-time password has expired.', 'login-security-squad' ) );
        }

        // OTP is correct, log the user in.
        delete_user_meta( $user->ID, 'lss_otp' );
        delete_user_meta( $user->ID, 'lss_otp_timestamp' );
    }
    return $user;
}
add_filter( 'authenticate', 'lss_verify_otp', 20, 2 );

/**
 * Manage concurrent sessions.
 *
 * @param string  $user_login The user's login name.
 * @param WP_User $user       The WP_User object.
 */
function lss_manage_concurrent_sessions( $user_login, $user ) {
    $session_limit = (int) get_option( 'lss_session_limit', 2 );
    $sessions      = WP_Session_Tokens::get_instance( $user->ID );
    $all_sessions  = $sessions->get_all();

    if ( count( $all_sessions ) >= $session_limit ) {
        wp_safe_redirect(
            add_query_arg(
                'lss_action',
                'confirm_logout',
                home_url()
            )
        );
        exit;
    }
}
add_action( 'wp_login', 'lss_manage_concurrent_sessions', 10, 2 );

/**
 * Enqueue scripts and styles.
 */
function lss_enqueue_scripts() {
    if ( is_user_logged_in() ) {
        wp_enqueue_script(
            'lss-fingerprint',
            plugin_dir_url( __FILE__ ) . 'assets/js/lss-fingerprint.js',
            array(),
            '1.0.0',
            true
        );
        wp_localize_script(
            'lss-fingerprint',
            'lss_fingerprint_ajax',
            array(
                'ajax_url' => admin_url( 'admin-ajax.php' ),
                'nonce'    => wp_create_nonce( 'lss_update_fingerprint' ),
            )
        );
    }
}
add_action( 'wp_enqueue_scripts', 'lss_enqueue_scripts' );

/**
 * AJAX handler to update the device fingerprint.
 */
function lss_update_fingerprint() {
    check_ajax_referer( 'lss_update_fingerprint', 'nonce' );

    if ( ! is_user_logged_in() ) {
        wp_send_json_error( 'Not logged in.' );
    }

    if ( ! isset( $_POST['fingerprint'] ) ) {
        wp_send_json_error( 'Fingerprint not provided.' );
    }

    global $wpdb;
    $table_name    = $wpdb->prefix . 'login_security_logs';
    $user_id       = get_current_user_id();
    $session_token = wp_get_session_token();
    $fingerprint   = sanitize_text_field( wp_unslash( base64_decode( $_POST['fingerprint'] ) ) );

    $wpdb->update(
        $table_name,
        array(
            'device_fingerprint' => lss_encrypt_data( $fingerprint ),
        ),
        array(
            'user_id'       => $user_id,
            'session_token' => $session_token,
        )
    );

    wp_send_json_success();
}
add_action( 'wp_ajax_lss_update_fingerprint', 'lss_update_fingerprint' );

/**
 * Track content access.
 *
 * @param WP_Post $post The post object.
 */
function lss_track_content_access() {
    if ( ! is_user_logged_in() || ! is_singular() ) {
        return;
    }

    $post = get_queried_object();
    // You should add your own logic here to determine if the content is protected.
    // For example, you might check for a specific post meta field or a custom taxonomy.
    $is_protected = get_post_meta( $post->ID, '_is_protected', true );
    if ( ! $is_protected ) {
        return;
    }

    global $wpdb;
    $table_name = $wpdb->prefix . 'lss_content_access_logs';
    $user_id    = get_current_user_id();
    $ip_address = lss_get_user_ip();
    $session_token = wp_get_session_token();

    // Get the device fingerprint from the login logs.
    $login_table_name = $wpdb->prefix . 'login_security_logs';
    $device_fingerprint = $wpdb->get_var(
        $wpdb->prepare(
            "SELECT device_fingerprint FROM $login_table_name WHERE user_id = %d AND session_token = %s",
            $user_id,
            $session_token
        )
    );

    $wpdb->insert(
        $table_name,
        array(
            'user_id'            => $user_id,
            'post_id'            => $post->ID,
            'access_time'        => current_time( 'mysql' ),
            'ip_address'         => lss_encrypt_data( $ip_address ),
            'device_fingerprint' => $device_fingerprint,
        )
    );

    lss_check_content_access_patterns( $user_id, $post->ID );
}
add_action( 'template_redirect', 'lss_track_content_access' );

/**
 * Check for content access patterns.
 *
 * @param int $user_id The user ID.
 * @param int $post_id The post ID.
 */
function lss_check_content_access_patterns( $user_id, $post_id ) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'lss_content_access_logs';

    // Get the last hour of accesses for this user and post.
    $accesses = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT * FROM $table_name WHERE user_id = %d AND post_id = %d AND access_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)",
            $user_id,
            $post_id
        )
    );

    $access_threshold    = (int) get_option( 'lss_access_threshold', 3 );
    $decrypted_fingerprints = array_filter( array_map( 'lss_decrypt_data', wp_list_pluck( $accesses, 'device_fingerprint' ) ) );
    $unique_fingerprints = array_unique( $decrypted_fingerprints );
    if ( count( $unique_fingerprints ) > $access_threshold ) {
        return lss_handle_suspicious_activity(
            $user_id,
            'Suspicious Content Access',
            array(
                'Post ID' => $post_id,
                'Devices' => implode( ', ', $unique_fingerprints ),
            )
        );
    }
}

/**
 * Add a "Report Sharing" button to the footer.
 */
function lss_add_report_sharing_button() {
    if ( is_user_logged_in() ) {
        echo '<a href="' . esc_url( wp_nonce_url( add_query_arg( 'lss_action', 'report_sharing' ), 'lss_report_sharing' ) ) . '" class="lss-report-sharing-button">Report Account Sharing</a>';
    }
}
add_action( 'wp_footer', 'lss_add_report_sharing_button' );

/**
 * Handle the "Report Sharing" action.
 */
function lss_handle_report_sharing_action() {
    if ( isset( $_GET['lss_action'] ) && 'report_sharing' === $_GET['lss_action'] ) {
        if ( isset( $_GET['_wpnonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ), 'lss_report_sharing' ) ) {
            $user_id = get_current_user_id();
            $user    = get_userdata( $user_id );
            $admin_email = get_option( 'lss_admin_email', get_option( 'admin_email' ) );
            $subject     = 'User Report of Account Sharing';
            $message     = "User {$user->user_login} (ID: {$user_id}) has reported that their account may be compromised.";
            wp_mail( $admin_email, $subject, $message );
            add_action( 'wp_footer', 'lss_report_sharing_notice' );
        }
    }
}
add_action( 'init', 'lss_handle_report_sharing_action' );

/**
 * Display a notice when a user reports sharing.
 */
function lss_report_sharing_notice() {
    echo '<div class="lss-notice">Thank you for your report. We will investigate this matter shortly.</div>';
}

/**
 * Encrypt data.
 *
 * @param string $data The data to encrypt.
 * @return string The encrypted data.
 */
function lss_encrypt_data( $data ) {
    $key = wp_salt();
    $iv = openssl_random_pseudo_bytes( openssl_cipher_iv_length( 'aes-256-cbc' ) );
    $encrypted = openssl_encrypt( $data, 'aes-256-cbc', $key, 0, $iv );
    return base64_encode( $encrypted . '::' . $iv );
}

/**
 * Decrypt data.
 *
 * @param string $data The data to decrypt.
 * @return string The decrypted data.
 */
function lss_decrypt_data( $data ) {
    if ( empty( $data ) ) {
        return '';
    }
    $key = wp_salt();
    $decoded_data = base64_decode( $data, true );
    if ( $decoded_data === false || strpos( $decoded_data, '::' ) === false ) {
        return ''; // Or return original data, or false
    }
    list( $encrypted_data, $iv ) = explode( '::', $decoded_data, 2 );
    if ( ! $encrypted_data || ! $iv ) {
        return '';
    }
    $decrypted = openssl_decrypt( $encrypted_data, 'aes-256-cbc', $key, 0, $iv );
    return $decrypted === false ? '' : $decrypted;
}

/**
 * Display a page to confirm logging out other sessions.
 */
function lss_session_management_page() {
    if ( isset( $_GET['lss_action'] ) && 'confirm_logout' === $_GET['lss_action'] ) {
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <title>Confirm Logout</title>
            <?php wp_head(); ?>
            <link rel='stylesheet' id='wp-login-css'  href='<?php echo esc_url( admin_url( 'css/login.min.css' ) ); ?>' type='text/css' media='all' />
            <style>
                body {
                    background: #f1f1f1;
                }
                .login #login {
                    width: 320px;
                    padding: 8% 0 0;
                    margin: auto;
                }
            </style>
        </head>
        <body class="login login-action-login wp-core-ui">
            <div id="login">
            <h1>Log Out Other Devices?</h1>
            <p>You have too many active sessions. Would you like to log out all other devices?</p>
            <form action="" method="post">
                <?php wp_nonce_field( 'lss_confirm_logout' ); ?>
                <input type="submit" name="lss_confirm_logout" value="Log Out Other Devices" />
                <a href="<?php echo esc_url( home_url() ); ?>">Cancel</a>
            </form>
            </div>
            <?php wp_footer(); ?>
        </body>
        </html>
        <?php
        exit;
    }
}
add_action( 'template_redirect', 'lss_session_management_page' );

/**
 * Handle the logout confirmation.
 */
function lss_handle_logout_confirmation() {
    if ( isset( $_POST['lss_confirm_logout'] ) ) {
        check_admin_referer( 'lss_confirm_logout' );
        $user_id       = get_current_user_id();
        $sessions      = WP_Session_Tokens::get_instance( $user_id );
        $sessions->destroy_all_but_current();
        wp_safe_redirect( home_url() );
        exit;
    }
}
add_action( 'init', 'lss_handle_logout_confirmation' );

// Include the admin settings page.
if ( is_admin() ) {
    require_once plugin_dir_path( __FILE__ ) . 'admin/settings-page.php';
}
