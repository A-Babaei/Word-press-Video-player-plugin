<?php
/**
 * Admin settings page for Login Security Squad.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly.
}

/**
 * Handle manual blocking/unblocking.
 */
function lss_handle_manual_blocking() {
    if ( ! isset( $_POST['lss_manual_block_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['lss_manual_block_nonce'] ) ), 'lss_manual_block_nonce' ) ) {
        return;
    }

    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }

    $user_identifier = isset( $_POST['lss_user_identifier_to_block'] ) ? sanitize_text_field( wp_unslash( $_POST['lss_user_identifier_to_block'] ) ) : '';
    $user = is_numeric( $user_identifier ) ? get_user_by( 'ID', $user_identifier ) : get_user_by( 'login', $user_identifier );

    if ( ! $user ) {
        return;
    }
    $user_id = $user->ID;

    if ( isset( $_POST['lss_block_user'] ) ) {
        update_user_meta( $user_id, 'lss_permanently_blocked', true );
        wp_update_user(
            array(
                'ID'       => $user_id,
                'user_pass' => wp_generate_password( 32 ), // Lock out the user.
            )
        );
        add_action( 'admin_notices', 'lss_manual_block_notice' );
    }

    if ( isset( $_POST['lss_unblock_user'] ) ) {
        delete_user_meta( $user_id, 'lss_permanently_blocked' );
        delete_user_meta( $user_id, 'lss_suspicion_count' );
        delete_user_meta( $user_id, 'lss_otp_failed_attempts' );
        delete_transient( 'lss_user_blocked_' . $user_id );
        add_action( 'admin_notices', 'lss_manual_unblock_notice' );
    }
}
add_action( 'admin_init', 'lss_handle_manual_blocking' );

/**
 * Display a notice when a user is manually blocked.
 */
function lss_manual_block_notice() {
    ?>
    <div class="notice notice-success is-dismissible">
        <p><?php esc_html_e( 'User blocked successfully.', 'login-security-squad' ); ?></p>
    </div>
    <?php
}

/**
 * Add a meta box to the post edit screen.
 */
function lss_add_protected_content_meta_box() {
    add_meta_box(
        'lss_protected_content_meta_box',
        'Protected Content',
        'lss_render_protected_content_meta_box',
        array( 'post', 'page' ),
        'side',
        'default'
    );
}
add_action( 'add_meta_boxes', 'lss_add_protected_content_meta_box' );

/**
 * Render the protected content meta box.
 *
 * @param WP_Post $post The post object.
 */
function lss_render_protected_content_meta_box( $post ) {
    wp_nonce_field( 'lss_save_protected_content_meta_box_data', 'lss_protected_content_meta_box_nonce' );
    $value = get_post_meta( $post->ID, '_is_protected', true );
    ?>
    <label for="lss_is_protected">
        <input type="checkbox" name="lss_is_protected" id="lss_is_protected" value="1" <?php checked( $value, 1 ); ?> />
        <?php esc_html_e( 'Protect this content', 'login-security-squad' ); ?>
    </label>
    <?php
}

/**
 * Save the protected content meta box data.
 *
 * @param int $post_id The post ID.
 */
function lss_save_protected_content_meta_box_data( $post_id ) {
    if ( ! isset( $_POST['lss_protected_content_meta_box_nonce'] ) ) {
        return;
    }
    if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['lss_protected_content_meta_box_nonce'] ) ), 'lss_save_protected_content_meta_box_data' ) ) {
        return;
    }
    if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
        return;
    }
    if ( isset( $_POST['post_type'] ) && 'page' === $_POST['post_type'] ) {
        if ( ! current_user_can( 'edit_page', $post_id ) ) {
            return;
        }
    } else {
        if ( ! current_user_can( 'edit_post', $post_id ) ) {
            return;
        }
    }
    if ( isset( $_POST['lss_is_protected'] ) ) {
        update_post_meta( $post_id, '_is_protected', 1 );
    } else {
        delete_post_meta( $post_id, '_is_protected' );
    }
}
add_action( 'save_post', 'lss_save_protected_content_meta_box_data' );

/**
 * Handle the "Suspend User" action.
 */
function lss_handle_suspend_user_action() {
    if ( isset( $_GET['action'] ) && 'lss_suspend_user' === $_GET['action'] ) {
        check_admin_referer( 'lss_suspend_user' );
        $user_id = isset( $_GET['user'] ) ? absint( $_GET['user'] ) : 0;
        if ( current_user_can( 'edit_user', $user_id ) ) {
            set_transient( 'lss_user_blocked_' . $user_id, true, HOUR_IN_SECONDS );
            add_action( 'admin_notices', 'lss_suspend_user_notice' );
        }
    }
}
add_action( 'admin_init', 'lss_handle_suspend_user_action' );

/**
 * Display a notice when a user is suspended.
 */
function lss_suspend_user_notice() {
    ?>
    <div class="notice notice-success is-dismissible">
        <p><?php esc_html_e( 'User suspended successfully.', 'login-security-squad' ); ?></p>
    </div>
    <?php
}

/**
 * Handle the "Ban User" action.
 */
function lss_handle_ban_user_action() {
    if ( isset( $_GET['action'] ) && 'lss_ban_user' === $_GET['action'] ) {
        check_admin_referer( 'lss_ban_user' );
        $user_id = isset( $_GET['user'] ) ? absint( $_GET['user'] ) : 0;
        if ( current_user_can( 'edit_user', $user_id ) ) {
            update_user_meta( $user_id, 'lss_permanently_blocked', true );
            wp_update_user(
                array(
                    'ID'       => $user_id,
                    'user_pass' => wp_generate_password( 32 ), // Lock out the user.
                )
            );
            add_action( 'admin_notices', 'lss_ban_user_notice' );
        }
    }
}
add_action( 'admin_init', 'lss_handle_ban_user_action' );

/**
 * Display a notice when a user is banned.
 */
function lss_ban_user_notice() {
    ?>
    <div class="notice notice-success is-dismissible">
        <p><?php esc_html_e( 'User banned successfully.', 'login-security-squad' ); ?></p>
    </div>
    <?php
}

/**
 * Add a "Suspicion Score" column to the users table.
 *
 * @param array $columns The existing columns.
 * @return array The modified columns.
 */
function lss_add_suspicion_score_column( $columns ) {
    $columns['suspicion_score'] = 'Suspicion Score';
    return $columns;
}
add_filter( 'manage_users_columns', 'lss_add_suspicion_score_column' );

/**
 * Display the suspicion score in the custom column.
 *
 * @param string $value       The value to display.
 * @param string $column_name The name of the column.
 * @param int    $user_id     The user ID.
 * @return string The modified value.
 */
function lss_display_suspicion_score( $value, $column_name, $user_id ) {
    if ( 'suspicion_score' === $column_name ) {
        return (int) get_user_meta( $user_id, 'lss_suspicion_count', true );
    }
    return $value;
}
add_filter( 'manage_users_custom_column', 'lss_display_suspicion_score', 10, 3 );

/**
 * Add a "Warn User" action to the user row actions.
 *
 * @param array   $actions The existing actions.
 * @param WP_User $user    The user object.
 * @return array The modified actions.
 */
function lss_add_user_row_actions( $actions, $user ) {
    if ( current_user_can( 'edit_user', $user->ID ) ) {
        $actions['warn_user'] = '<a href="' . esc_url( wp_nonce_url( admin_url( 'users.php?action=lss_warn_user&user=' . $user->ID ), 'lss_warn_user' ) ) . '">Warn</a>';
        $actions['suspend_user'] = '<a href="' . esc_url( wp_nonce_url( admin_url( 'users.php?action=lss_suspend_user&user=' . $user->ID ), 'lss_suspend_user' ) ) . '">Suspend</a>';
        $actions['ban_user'] = '<a href="' . esc_url( wp_nonce_url( admin_url( 'users.php?action=lss_ban_user&user=' . $user->ID ), 'lss_ban_user' ) ) . '">Ban</a>';
    }
    return $actions;
}
add_filter( 'user_row_actions', 'lss_add_user_row_actions', 10, 2 );

/**
 * Handle the "Warn User" action.
 */
function lss_handle_warn_user_action() {
    if ( isset( $_GET['action'] ) && 'lss_warn_user' === $_GET['action'] ) {
        check_admin_referer( 'lss_warn_user' );
        $user_id = isset( $_GET['user'] ) ? absint( $_GET['user'] ) : 0;
        if ( current_user_can( 'edit_user', $user_id ) ) {
            $user    = get_userdata( $user_id );
            $email   = $user->user_email;
            $subject = get_option( 'lss_warn_email_subject', 'A Warning About Your Account' );
            $message = get_option( 'lss_warn_email_body', 'We have detected suspicious activity on your account. Please be aware that account sharing is not permitted.' );
            wp_mail( $email, $subject, $message );
            add_action( 'admin_notices', 'lss_warn_user_notice' );
        }
    }
}
add_action( 'admin_init', 'lss_handle_warn_user_action' );

/**
 * Display a notice when a user is warned.
 */
function lss_warn_user_notice() {
    ?>
    <div class="notice notice-success is-dismissible">
        <p><?php esc_html_e( 'User warned successfully.', 'login-security-squad' ); ?></p>
    </div>
    <?php
}

/**
 * Add a dashboard widget to display flagged accounts.
 */
function lss_add_dashboard_widget() {
    wp_add_dashboard_widget(
        'lss_flagged_accounts_widget',
        'Flagged Accounts',
        'lss_render_flagged_accounts_widget'
    );
}
add_action( 'wp_dashboard_setup', 'lss_add_dashboard_widget' );

/**
 * Render the flagged accounts dashboard widget.
 */
function lss_render_flagged_accounts_widget() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'usermeta';
    $flagged_users = $wpdb->get_results(
        "SELECT user_id, meta_value FROM $table_name WHERE meta_key = 'lss_suspicion_count' AND meta_value > 0 ORDER BY meta_value DESC"
    );

    if ( ! empty( $flagged_users ) ) {
        echo '<ul>';
        foreach ( $flagged_users as $flagged_user ) {
            $user = get_userdata( $flagged_user->user_id );
            echo '<li>';
            echo esc_html( $user->user_login ) . ' (' . esc_html( $flagged_user->meta_value ) . ' flags)';
            echo ' <a href="' . esc_url( wp_nonce_url( admin_url( 'users.php?action=lss_warn_user&user=' . $user->ID ), 'lss_warn_user' ) ) . '">Warn</a>';
            echo ' | <a href="' . esc_url( wp_nonce_url( admin_url( 'users.php?action=lss_suspend_user&user=' . $user->ID ), 'lss_suspend_user' ) ) . '">Suspend</a>';
            echo ' | <a href="' . esc_url( wp_nonce_url( admin_url( 'users.php?action=lss_ban_user&user=' . $user->ID ), 'lss_ban_user' ) ) . '">Ban</a>';
            echo '</li>';
        }
        echo '</ul>';
    } else {
        echo '<p>No flagged accounts.</p>';
    }
}

/**
 * Display a notice when a user is manually unblocked.
 */
function lss_manual_unblock_notice() {
    ?>
    <div class="notice notice-success is-dismissible">
        <p><?php esc_html_e( 'User unblocked successfully.', 'login-security-squad' ); ?></p>
    </div>
    <?php
}

/**
 * Add the settings page to the admin menu.
 */
function lss_add_settings_page() {
    add_menu_page(
        'Login Security Squad',
        'Login Security',
        'manage_options',
        'login-security-squad',
        'lss_render_settings_page',
        'dashicons-shield-alt'
    );
    add_submenu_page(
        'login-security-squad',
        'Anti-Sharing Settings',
        'Anti-Sharing',
        'manage_options',
        'lss-anti-sharing',
        'lss_render_anti_sharing_page'
    );
}
add_action( 'admin_menu', 'lss_add_settings_page' );

/**
 * Register the settings.
 */
function lss_register_settings() {
    // Anti-sharing settings.
    register_setting( 'lss_anti_sharing_settings_group', 'lss_enable_anti_sharing' );
    register_setting( 'lss_anti_sharing_settings_group', 'lss_suspicion_email_subject' );
    register_setting( 'lss_anti_sharing_settings_group', 'lss_suspicion_email_body' );
    register_setting( 'lss_anti_sharing_settings_group', 'lss_warn_email_subject' );
    register_setting( 'lss_anti_sharing_settings_group', 'lss_warn_email_body' );
    register_setting( 'lss_anti_sharing_settings_group', 'lss_ip_threshold' );
    register_setting( 'lss_anti_sharing_settings_group', 'lss_distance_threshold' );
    register_setting( 'lss_anti_sharing_settings_group', 'lss_admin_email' );
    register_setting( 'lss_anti_sharing_settings_group', 'lss_session_limit' );
    register_setting( 'lss_anti_sharing_settings_group', 'lss_fingerprint_threshold' );
    register_setting( 'lss_anti_sharing_settings_group', 'lss_access_threshold' );
    register_setting( 'lss_anti_sharing_settings_group', 'lss_ip_grace_period' );
    register_setting( 'lss_anti_sharing_settings_group', 'lss_enable_geolocation' );
    register_setting( 'lss_anti_sharing_settings_group', 'lss_enable_otp' );
}
add_action( 'admin_init', 'lss_register_settings' );

/**
 * Render the anti-sharing settings page.
 */
function lss_render_anti_sharing_page() {
    ?>
    <div class="wrap">
        <h1>Anti-Sharing Settings</h1>
        <form action="options.php" method="post">
            <?php
            settings_fields( 'lss_anti_sharing_settings_group' );
            do_settings_sections( 'lss-anti-sharing' );
            ?>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row">Enable Anti-Sharing Features</th>
                    <td><input type="checkbox" name="lss_enable_anti_sharing" value="1" <?php checked( get_option( 'lss_enable_anti_sharing' ), 1 ); ?> /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Enable Geolocation Flagging</th>
                    <td><input type="checkbox" name="lss_enable_geolocation" value="1" <?php checked( get_option( 'lss_enable_geolocation' ), 1 ); ?> /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Enable OTP Verification</th>
                    <td><input type="checkbox" name="lss_enable_otp" value="1" <?php checked( get_option( 'lss_enable_otp' ), 1 ); ?> /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">IP Threshold</th>
                    <td><input type="number" name="lss_ip_threshold" value="<?php echo esc_attr( get_option( 'lss_ip_threshold', 2 ) ); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Distance Threshold (km)</th>
                    <td><input type="number" name="lss_distance_threshold" value="<?php echo esc_attr( get_option( 'lss_distance_threshold', 1000 ) ); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Admin Notification Email</th>
                    <td><input type="email" name="lss_admin_email" value="<?php echo esc_attr( get_option( 'lss_admin_email', get_option( 'admin_email' ) ) ); ?>" /></td>
                </tr>
                 <tr valign="top">
                    <th scope="row">Session Limit</th>
                    <td><input type="number" name="lss_session_limit" value="<?php echo esc_attr( get_option( 'lss_session_limit', 2 ) ); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Device Fingerprint Threshold</th>
                    <td><input type="number" name="lss_fingerprint_threshold" value="<?php echo esc_attr( get_option( 'lss_fingerprint_threshold', 2 ) ); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Content Access Threshold</th>
                    <td><input type="number" name="lss_access_threshold" value="<?php echo esc_attr( get_option( 'lss_access_threshold', 3 ) ); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">IP Grace Period (days)</th>
                    <td><input type="number" name="lss_ip_grace_period" value="<?php echo esc_attr( get_option( 'lss_ip_grace_period', 7 ) ); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Suspicion Email Subject</th>
                    <td><input type="text" name="lss_suspicion_email_subject" value="<?php echo esc_attr( get_option( 'lss_suspicion_email_subject', 'Suspicious Login Activity Detected' ) ); ?>" class="regular-text" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Suspicion Email Body</th>
                    <td><textarea name="lss_suspicion_email_body" rows="10" cols="50" class="large-text"><?php echo esc_textarea( get_option( 'lss_suspicion_email_body', "Suspicious login activity was detected for your account.\n\nPlease verify your account to continue." ) ); ?></textarea></td>
                </tr>
                <tr valign="top">
                    <th scope="row">"Warn User" Email Subject</th>
                    <td><input type="text" name="lss_warn_email_subject" value="<?php echo esc_attr( get_option( 'lss_warn_email_subject', 'A Warning About Your Account' ) ); ?>" class="regular-text" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">"Warn User" Email Body</th>
                    <td><textarea name="lss_warn_email_body" rows="10" cols="50" class="large-text"><?php echo esc_textarea( get_option( 'lss_warn_email_body', 'We have detected suspicious activity on your account. Please be aware that account sharing is not permitted.' ) ); ?></textarea></td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
    </div>
    <?php
}

/**
 * Render the settings page.
 */
function lss_render_settings_page() {
    ?>
    <div class="wrap">
        <h1><?php echo esc_html( get_admin_page_title() ); ?></h1>

        <h2>Login Logs</h2>
        <?php
        global $wpdb;
        $table_name = $wpdb->prefix . 'login_security_logs';
        $logs       = $wpdb->get_results( "SELECT * FROM $table_name ORDER BY login_time DESC LIMIT 100" );
        ?>
        <table class="widefat fixed" cellspacing="0">
            <thead>
                <tr>
                    <th id="columnname" class="manage-column column-columnname" scope="col">Username</th>
                    <th id="columnname" class="manage-column column-columnname" scope="col">IP Address</th>
                    <th id="columnname" class="manage-column column-columnname" scope="col">User Agent</th>
                    <th id="columnname" class="manage-column column-columnname" scope="col">Login Time</th>
                    <th id="columnname" class="manage-column column-columnname" scope="col">Location</th>
                    <th id="columnname" class="manage-column column-columnname" scope="col">Status</th>
                </tr>
            </thead>
            <tbody>
                <?php if ( ! empty( $logs ) ) : ?>
                    <?php foreach ( $logs as $log ) : ?>
                        <?php
                        $user = get_userdata( $log->user_id );
                        $status = 'Active';
                        if ( get_transient( 'lss_user_blocked_' . $log->user_id ) ) {
                            $status = 'Suspended';
                        } elseif ( get_user_meta( $log->user_id, 'lss_permanently_blocked', true ) ) {
                            $status = 'Banned';
                        }
                        ?>
                        <tr>
                            <td><?php echo esc_html( $user ? $user->user_login : 'N/A' ); ?></td>
                            <td><?php echo esc_html( lss_decrypt_data( $log->ip_address ) ); ?></td>
                            <td><?php echo esc_html( $log->user_agent ); ?></td>
                            <td><?php echo esc_html( $log->login_time ); ?></td>
                            <td><?php echo esc_html( $log->location ); ?></td>
                            <td><?php echo esc_html( $status ); ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php else : ?>
                    <tr>
                        <td colspan="6">No login logs found.</td>
                    </tr>
                <?php endif; ?>
            </tbody>
        </table>

        <h2>Manual Blocking</h2>
        <form action="" method="post">
            <?php wp_nonce_field( 'lss_manual_block_nonce' ); ?>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row">User ID or Username</th>
                    <td><input type="text" name="lss_user_identifier_to_block" /></td>
                </tr>
            </table>
            <input type="submit" name="lss_block_user" class="button button-primary" value="Block User" />
            <input type="submit" name="lss_unblock_user" class="button" value="Unblock User" />
        </form>
    </div>
    <?php
}
