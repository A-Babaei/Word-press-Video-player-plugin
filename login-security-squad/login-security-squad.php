<?php
/**
 * Plugin Name:       Login Security Squad
 * Plugin URI:        https://example.com/
 * Description:       Detects and prevents users from sharing login credentials.
 * Version:           1.0.0
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
    global $wpdb;
    $table_name = $wpdb->prefix . 'login_security_logs';
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE $table_name (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        user_id bigint(20) NOT NULL,
        ip_address varchar(100) NOT NULL,
        user_agent text NOT NULL,
        login_time datetime NOT NULL,
        location varchar(255) DEFAULT '' NOT NULL,
        latitude varchar(100) DEFAULT '' NOT NULL,
        longitude varchar(100) DEFAULT '' NOT NULL,
        session_token varchar(255) DEFAULT '' NOT NULL,
        PRIMARY KEY  (id)
    ) $charset_collate;";

    require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
    dbDelta( $sql );
}
register_activation_hook( __FILE__, 'lss_activate_plugin' );

/**
 * Deactivate the plugin.
 */
function lss_deactivate_plugin() {
    // Placeholder for deactivation logic.
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
            'ip_address' => $ip_address,
            'user_agent' => $user_agent,
            'login_time' => $login_time,
            'location'   => $location_data['location'],
            'latitude'   => $location_data['latitude'],
            'longitude'  => $location_data['longitude'],
            'session_token' => $session_token,
        )
    );

    // Check for suspicious activity after logging the new login.
    lss_check_suspicious_activity( $user->ID, $ip_address, $location_data );
}
add_action( 'wp_login', 'lss_track_login', 10, 2 );

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
    $unique_ips = array_unique( wp_list_pluck( $logins, 'ip_address' ) );
    if ( count( $unique_ips ) > $ip_threshold ) {
        lss_handle_suspicious_activity(
            $user_id,
            'Multiple IPs',
            array(
                'IPs' => implode( ', ', $unique_ips ),
            )
        );
    }

    // Check for distant locations.
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
                lss_handle_suspicious_activity(
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

        // Log the user out.
        wp_logout();

        // Redirect to the login page with a warning message.
        wp_safe_redirect(
            add_query_arg(
                'lss_blocked',
                'permanent',
                wp_login_url()
            )
        );
        exit;
    } else {
        // This is the first offense, temporarily block the account for 1 hour.
        set_transient( 'lss_user_blocked_' . $user_id, true, HOUR_IN_SECONDS );

        // Log the user out.
        wp_logout();

        // Redirect to the login page with a warning message.
        wp_safe_redirect(
            add_query_arg(
                'lss_blocked',
                'true',
                wp_login_url()
            )
        );
        exit;
    }
}

/**
 * Prevent temporarily blocked users from logging in.
 *
 * @param WP_User|WP_Error|null $user     WP_User object if authentication succeeds, WP_Error object or null otherwise.
 * @param string                $username The username.
 * @return WP_User|WP_Error|null
 */
function lss_prevent_blocked_login( $user, $username ) {
    if ( is_a( $user, 'WP_User' ) ) {
        if ( get_transient( 'lss_user_blocked_' . $user->ID ) ) {
            return new WP_Error( 'lss_blocked', __( '<strong>ERROR</strong>: Your account has been temporarily suspended due to suspicious activity.', 'login-security-squad' ) );
        }
        if ( get_user_meta( $user->ID, 'lss_permanently_blocked', true ) ) {
            return new WP_Error( 'lss_blocked', __( '<strong>ERROR</strong>: Your account has been permanently suspended due to suspicious activity.', 'login-security-squad' ) );
        }
    }
    return $user;
}
add_filter( 'authenticate', 'lss_prevent_blocked_login', 30, 2 );

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
 * Check for simultaneous sessions.
 */
function lss_check_simultaneous_sessions() {
    if ( ! is_user_logged_in() ) {
        return;
    }

    global $wpdb;
    $table_name = $wpdb->prefix . 'login_security_logs';
    $user_id    = get_current_user_id();

    // Get the last login for this user.
    $last_login = $wpdb->get_row(
        $wpdb->prepare(
            "SELECT * FROM $table_name WHERE user_id = %d ORDER BY login_time DESC",
            $user_id
        )
    );

    if ( $last_login ) {
        $session_token = wp_get_session_token();
        if ( $last_login->session_token !== $session_token ) {
            wp_logout();
            wp_safe_redirect(
                add_query_arg(
                    'lss_session_expired',
                    'true',
                    wp_login_url()
                )
            );
            exit;
        }
    }
}
add_action( 'init', 'lss_check_simultaneous_sessions' );

/**
 * Display a message on the login screen when a session is expired.
 */
function lss_session_expired_message() {
    if ( isset( $_GET['lss_session_expired'] ) ) {
        return '<p class="message">Your session has expired because you logged in from another location.</p>';
    }
}
add_filter( 'login_message', 'lss_session_expired_message' );


// Include the admin settings page.
if ( is_admin() ) {
    require_once plugin_dir_path( __FILE__ ) . 'admin/settings-page.php';
}
