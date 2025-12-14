<?php

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

/**
 * Helper function to unban a user.
 *
 * @param int $user_id The ID of the user to unban.
 */
function lss_unban_user($user_id) {
    delete_user_meta($user_id, '_lss_is_banned');
    delete_user_meta($user_id, 'lss_permanently_blocked');
    delete_transient('lss_temp_suspend_' . $user_id);
    delete_user_meta($user_id, '_lss_login_attempts'); // Clear OTP failures

    // Restore user role to default
    wp_update_user(['ID' => $user_id, 'role' => get_option('default_role')]);

    // Reset password and send notification
    wp_send_new_user_notifications($user_id, 'both');
}


/**
 * Handle manual user blocking from the settings page.
 */
function lss_handle_manual_blocking() {
    if (isset($_POST['lss_manual_block_user_nonce']) && wp_verify_nonce($_POST['lss_manual_block_user_nonce'], 'lss_manual_block_user_action')) {
        $user_identifier = sanitize_text_field($_POST['user_identifier']);
        $action = sanitize_text_field($_POST['block_action']);

        if (empty($user_identifier)) {
            add_settings_error('lss_messages', 'lss_error', __('Please enter a User ID or Username.', 'login-security-squad'), 'error');
            return;
        }

        if (filter_var($user_identifier, FILTER_VALIDATE_INT)) {
            $user = get_user_by('ID', $user_identifier);
        } else {
            $user = get_user_by('login', $user_identifier);
        }

        if (!$user) {
            add_settings_error('lss_messages', 'lss_error', __('User not found.', 'login-security-squad'), 'error');
            return;
        }

        if (current_user_can('edit_user', $user->ID) && get_current_user_id() !== $user->ID) {
            if ($action === 'block') {
                update_user_meta($user->ID, '_lss_is_banned', true);
                wp_update_user(['ID' => $user->ID, 'role' => 'no-role']);
                add_settings_error('lss_messages', 'lss_success', sprintf(__('User %s has been banned successfully.', 'login-security-squad'), esc_html($user->user_login)), 'updated');
            } elseif ($action === 'unblock') {
                lss_unban_user($user->ID);
                add_settings_error('lss_messages', 'lss_success', sprintf(__('User %s has been unbanned. Their role has been restored and a password reset link has been sent to their email.', 'login-security-squad'), esc_html($user->user_login)), 'updated');
            }
        } else {
            add_settings_error('lss_messages', 'lss_error', __('You do not have permission to modify this user.', 'login-security-squad'), 'error');
        }
    }
}
add_action('admin_init', 'lss_handle_manual_blocking');


/**
 * Handle user actions from the log table (ban/unban).
 */
function lss_handle_log_actions() {
    if (isset($_GET['action'], $_GET['user_id'], $_GET['_wpnonce'])) {
        $user_id = intval($_GET['user_id']);
        $action = sanitize_key($_GET['action']);
        $nonce = $_GET['_wpnonce'];

        if (!wp_verify_nonce($nonce, 'lss_' . $action . '_user_' . $user_id)) {
            wp_die(__('Security check failed.', 'login-security-squad'));
        }

        if (!current_user_can('edit_user', $user_id) || get_current_user_id() === $user_id) {
            wp_die(__('You do not have permission to perform this action.', 'login-security-squad'));
        }

        $user = get_user_by('ID', $user_id);
        if (!$user) {
            wp_die(__('User not found.', 'login-security-squad'));
        }

        if ($action === 'ban_user') {
            update_user_meta($user_id, '_lss_is_banned', true);
            wp_update_user(['ID' => $user_id, 'role' => 'no-role']);
            $redirect_url = add_query_arg('lss_message', 'user_banned', wp_get_referer());
        } elseif ($action === 'unban_user') {
            lss_unban_user($user_id);
            $redirect_url = add_query_arg('lss_message', 'user_unbanned', wp_get_referer());
        }

        if (isset($redirect_url)) {
            wp_safe_redirect($redirect_url);
            exit;
        }
    }
}
add_action('admin_init', 'lss_handle_log_actions');

/**
 * Display admin notices for log actions.
 */
function lss_display_log_action_notices() {
    if (isset($_GET['lss_message'])) {
        $message = '';
        $type = 'success';
        switch ($_GET['lss_message']) {
            case 'user_banned':
                $message = __('User has been banned successfully.', 'login-security-squad');
                break;
            case 'user_unbanned':
                $message = __('User has been unbanned. Their role has been restored and a password reset link has been sent.', 'login-security-squad');
                break;
        }
        if ($message) {
            echo '<div class="notice notice-' . esc_attr($type) . ' is-dismissible"><p>' . esc_html($message) . '</p></div>';
        }
    }
}
add_action('admin_notices', 'lss_display_log_action_notices');


/**
 * Add the settings page to the admin menu.
 */
function lss_add_admin_menu() {
    add_menu_page(
        __('Login Security Squad', 'login-security-squad'),
        __('Login Security', 'login-security-squad'),
        'manage_options',
        'login-security-squad',
        'lss_settings_page_html',
        'dashicons-shield-alt',
        80
    );
}
add_action('admin_menu', 'lss_add_admin_menu');

/**
 * Register plugin settings.
 */
function lss_register_settings() {
    register_setting('lss_settings_group', 'lss_settings', 'lss_settings_sanitize');

    $sections = [
        'lss_section_session' => __('Concurrent Session Management', 'login-security-squad'),
        'lss_section_ip' => __('IP & Device Fingerprinting', 'login-security-squad'),
        'lss_section_otp' => __('Email OTP Verification', 'login-security-squad'),
        'lss_section_monitoring' => __('Usage Pattern Monitoring', 'login-security-squad'),
        'lss_section_notifications' => __('Email Notifications', 'login-security-squad'),
        'lss_section_manual_block' => __('Manual User Blocking', 'login-security-squad'),
    ];

    foreach ($sections as $id => $title) {
        add_settings_section($id, $title, null, 'login-security-squad');
    }

    $fields = [
        'lss_section_session' => [
            'concurrent_sessions_limit' => __('Max Concurrent Sessions', 'login-security-squad'),
            'force_logout' => __('Force Logout', 'login-security-squad'),
        ],
        'lss_section_ip' => [
            'max_ips' => __('Max Unique IPs per 24h', 'login-security-squad'),
            'enable_otp_ip_flag' => __('Require OTP on IP Flag', 'login-security-squad'),
        ],
        'lss_section_otp' => [
            'otp_max_attempts' => __('OTP Max Attempts', 'login-security-squad'),
            'otp_temp_lockout_duration' => __('OTP Temporary Lockout (minutes)', 'login-security-squad'),
        ],
        'lss_section_monitoring' => [
            'content_access_limit' => __('Content Access Limit', 'login-security-squad'),
            'content_access_window' => __('Content Access Time Window (minutes)', 'login-security-squad'),
            'auto_suspend_on_flag' => __('Auto-suspend on Flag', 'login-security-squad'),
        ],
        'lss_section_notifications' => [
            'admin_notification_email' => __('Admin Notification Email', 'login-security-squad'),
            'email_subject_flagged' => __('Suspicious Activity Email Subject', 'login-security-squad'),
            'email_body_flagged' => __('Suspicious Activity Email Body', 'login-security-squad'),
            'email_subject_suspended' => __('Account Suspended Email Subject', 'login-security-squad'),
            'email_body_suspended' => __('Account Suspended Email Body', 'login-security-squad'),
            'email_subject_otp' => __('Email OTP Subject', 'login-security-squad'),
            'email_body_otp' => __('Email OTP Body', 'login-security-squad'),
        ]
    ];

    foreach ($fields as $section => $field_group) {
        foreach ($field_group as $id => $title) {
            add_settings_field(
                $id,
                $title,
                'lss_render_field',
                'login-security-squad',
                $section,
                ['id' => $id, 'label_for' => $id]
            );
        }
    }
}
add_action('admin_init', 'lss_register_settings');

/**
 * Render a settings field.
 *
 * @param array $args Field arguments.
 */
function lss_render_field($args) {
    $options = get_option('lss_settings');
    $id = $args['id'];
    $value = isset($options[$id]) ? $options[$id] : '';

    switch ($id) {
        case 'force_logout':
        case 'enable_otp_ip_flag':
        case 'auto_suspend_on_flag':
            echo '<input type="checkbox" id="' . esc_attr($id) . '" name="lss_settings[' . esc_attr($id) . ']" value="1"' . checked(1, $value, false) . '>';
            break;
        case 'email_body_flagged':
        case 'email_body_suspended':
        case 'email_body_otp':
             wp_editor(
                $value,
                esc_attr($id),
                [
                    'textarea_name' => 'lss_settings[' . esc_attr($id) . ']',
                    'textarea_rows' => 10,
                ]
            );
            echo '<p class="description">' . __('Available placeholders: {username}, {display_name}, {otp_code}, {ip_address}', 'login-security-squad') . '</p>';
            break;
        case 'concurrent_sessions_limit':
        case 'max_ips':
        case 'content_access_limit':
        case 'content_access_window':
        case 'otp_max_attempts':
        case 'otp_temp_lockout_duration':
            echo '<input type="number" id="' . esc_attr($id) . '" name="lss_settings[' . esc_attr($id) . ']" value="' . esc_attr($value) . '" min="1" class="small-text">';
            break;
        default:
            echo '<input type="text" id="' . esc_attr($id) . '" name="lss_settings[' . esc_attr($id) . ']" value="' . esc_attr($value) . '" class="regular-text">';
            break;
    }
}

/**
 * Sanitize settings values.
 *
 * @param array $input The input array.
 * @return array The sanitized array.
 */
function lss_settings_sanitize($input) {
    $sanitized_input = [];
    $options = get_option('lss_settings');

    if (empty($input)) {
        return $options;
    }

    foreach ($input as $key => $value) {
        switch ($key) {
            case 'concurrent_sessions_limit':
            case 'max_ips':
            case 'content_access_limit':
            case 'content_access_window':
            case 'otp_max_attempts':
            case 'otp_temp_lockout_duration':
                $sanitized_input[$key] = absint($value);
                break;
            case 'force_logout':
            case 'enable_otp_ip_flag':
            case 'auto_suspend_on_flag':
                $sanitized_input[$key] = ($value == '1' ? 1 : 0);
                break;
            case 'admin_notification_email':
                $sanitized_input[$key] = sanitize_email($value);
                break;
            case 'email_body_flagged':
            case 'email_body_suspended':
            case 'email_body_otp':
                $sanitized_input[$key] = wp_kses_post($value);
                break;
            default:
                $sanitized_input[$key] = sanitize_text_field($value);
                break;
        }
    }

    return $sanitized_input;
}


/**
 * Render the main settings page HTML.
 */
function lss_settings_page_html() {
    if (!current_user_can('manage_options')) {
        return;
    }

    // Manual block form handling
    lss_handle_manual_blocking();

    // Display any settings errors
    settings_errors('lss_messages');
    ?>
    <div class="wrap">
        <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

        <h2 class="nav-tab-wrapper">
            <a href="#settings" class="nav-tab nav-tab-active"><?php _e('Settings', 'login-security-squad'); ?></a>
            <a href="#logs" class="nav-tab"><?php _e('Activity Logs', 'login-security-squad'); ?></a>
        </h2>

        <div id="settings" class="tab-content">
            <form action="options.php" method="post">
                <?php
                settings_fields('lss_settings_group');
                do_settings_sections('login-security-squad');
                submit_button(__('Save Settings', 'login-security-squad'));
                ?>
            </form>
             <!-- Manual Block Form -->
            <div id="lss_manual_block_form" class="card">
                <h2><?php _e('Manual User Actions', 'login-security-squad'); ?></h2>
                <p><?php _e('Manually ban or unban a user by their User ID or Username.', 'login-security-squad'); ?></p>
                <form method="post" action="">
                    <?php wp_nonce_field('lss_manual_block_user_action', 'lss_manual_block_user_nonce'); ?>
                    <table class="form-table">
                        <tr valign="top">
                            <th scope="row">
                                <label for="user_identifier"><?php _e('User ID or Username', 'login-security-squad'); ?></label>
                            </th>
                            <td>
                                <input type="text" id="user_identifier" name="user_identifier" class="regular-text" required />
                            </td>
                        </tr>
                        <tr valign="top">
                            <th scope="row">
                                <label for="block_action"><?php _e('Action', 'login-security-squad'); ?></label>
                            </th>
                            <td>
                                <select id="block_action" name="block_action">
                                    <option value="block"><?php _e('Ban', 'login-security-squad'); ?></option>
                                    <option value="unblock"><?php _e('Unban', 'login-security-squad'); ?></option>
                                </select>
                            </td>
                        </tr>
                    </table>
                    <?php submit_button(__('Apply Action', 'login-security-squad'), 'primary', 'lss_manual_block_submit'); ?>
                </form>
            </div>
        </div>

        <div id="logs" class="tab-content" style="display:none;">
            <h2><?php _e('User Login & Security Logs', 'login-security-squad'); ?></h2>
            <?php
            require_once plugin_dir_path(__FILE__) . '../includes/class-lss-logs-list-table.php';
            $log_table = new LSS_Logs_List_Table();
            $log_table->prepare_items();
            $log_table->display();
            ?>
        </div>

    </div>
    <script>
    jQuery(document).ready(function($) {
        // Simple tabs
        $('.nav-tab-wrapper a').on('click', function(e) {
            e.preventDefault();
            var target = $(this).attr('href');
            $('.nav-tab').removeClass('nav-tab-active');
            $(this).addClass('nav-tab-active');
            $('.tab-content').hide();
            $(target).show();
        });

        // Handle hash in URL for active tab
        if(window.location.hash) {
            $('.nav-tab-wrapper a[href="' + window.location.hash + '"]').click();
        }
    });
    </script>
    <?php
}
