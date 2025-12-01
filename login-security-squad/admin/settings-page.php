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

    $user_id = isset( $_POST['lss_user_id_to_block'] ) ? absint( $_POST['lss_user_id_to_block'] ) : 0;

    if ( ! $user_id ) {
        return;
    }

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
    add_options_page(
        'Login Security Squad Settings',
        'Login Security',
        'manage_options',
        'login-security-squad',
        'lss_render_settings_page'
    );
}
add_action( 'admin_menu', 'lss_add_settings_page' );

/**
 * Register the settings.
 */
function lss_register_settings() {
    register_setting( 'lss_settings_group', 'lss_ip_threshold' );
    register_setting( 'lss_settings_group', 'lss_distance_threshold' );
    register_setting( 'lss_settings_group', 'lss_admin_email' );
}
add_action( 'admin_init', 'lss_register_settings' );

/**
 * Render the settings page.
 */
function lss_render_settings_page() {
    ?>
    <div class="wrap">
        <h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
        <form action="options.php" method="post">
            <?php
            settings_fields( 'lss_settings_group' );
            do_settings_sections( 'login-security-squad' );
            ?>
            <table class="form-table">
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
            </table>
            <?php submit_button(); ?>
        </form>

        <h2>Login Logs</h2>
        <?php
        global $wpdb;
        $table_name = $wpdb->prefix . 'login_security_logs';
        $logs       = $wpdb->get_results( "SELECT * FROM $table_name ORDER BY login_time DESC LIMIT 100" );
        ?>
        <table class="widefat fixed" cellspacing="0">
            <thead>
                <tr>
                    <th id="columnname" class="manage-column column-columnname" scope="col">User ID</th>
                    <th id="columnname" class="manage-column column-columnname" scope="col">IP Address</th>
                    <th id="columnname" class="manage-column column-columnname" scope="col">User Agent</th>
                    <th id="columnname" class="manage-column column-columnname" scope="col">Login Time</th>
                    <th id="columnname" class="manage-column column-columnname" scope="col">Location</th>
                </tr>
            </thead>
            <tbody>
                <?php if ( ! empty( $logs ) ) : ?>
                    <?php foreach ( $logs as $log ) : ?>
                        <tr>
                            <td><?php echo esc_html( $log->user_id ); ?></td>
                            <td><?php echo esc_html( $log->ip_address ); ?></td>
                            <td><?php echo esc_html( $log->user_agent ); ?></td>
                            <td><?php echo esc_html( $log->login_time ); ?></td>
                            <td><?php echo esc_html( $log->location ); ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php else : ?>
                    <tr>
                        <td colspan="5">No login logs found.</td>
                    </tr>
                <?php endif; ?>
            </tbody>
        </table>

        <h2>Manual Blocking</h2>
        <form action="" method="post">
            <?php wp_nonce_field( 'lss_manual_block_nonce' ); ?>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row">User ID</th>
                    <td><input type="number" name="lss_user_id_to_block" /></td>
                </tr>
            </table>
            <input type="submit" name="lss_block_user" class="button button-primary" value="Block User" />
            <input type="submit" name="lss_unblock_user" class="button" value="Unblock User" />
        </form>
    </div>
    <?php
}
