<?php
/**
 * Admin Access Control
 *
 * Controls which administrator accounts can access the WordPress admin dashboard.
 * Even if a hacker creates an admin account via exploit, they won't be able to
 * access the admin panel unless their account is explicitly authorized.
 *
 * @package VietShield_WAF
 */

namespace VietShield\Integrations;

if (!defined('ABSPATH')) {
    exit;
}

class AdminAccessControl {

    /**
     * Plugin options
     */
    private $options = [];

    /**
     * Allowed user IDs
     */
    private $allowed_user_ids = [];

    /**
     * Constructor
     */
    public function __construct() {
        $this->options = get_option('vietshield_options', []);
        $this->allowed_user_ids = $this->options['admin_access_allowed_users'] ?? [];

        // If no users are configured yet, skip enforcement
        if (empty($this->allowed_user_ids)) {
            return;
        }

        // Check admin access on admin_init (runs before any admin page loads)
        add_action('admin_init', [$this, 'check_admin_access'], 1);

        // Remove admin bar for unauthorized admin users on frontend
        add_action('init', [$this, 'maybe_hide_admin_bar'], 1);

        // Filter user capabilities for unauthorized admins
        add_filter('user_has_cap', [$this, 'filter_capabilities'], 10, 4);
    }

    /**
     * Check if current user is allowed to access admin
     */
    public function check_admin_access() {
        // Skip AJAX requests to avoid breaking functionality
        if (wp_doing_ajax()) {
            return;
        }

        // Skip if not logged in
        if (!is_user_logged_in()) {
            return;
        }

        $current_user = wp_get_current_user();

        // Only enforce for users with administrator role
        if (!in_array('administrator', (array) $current_user->roles, true)) {
            return;
        }

        // Check if this admin is in the allowed list
        if ($this->is_user_allowed($current_user->ID)) {
            return;
        }

        // Allow access to profile.php so user can see their own profile
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $request_uri = isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : '';
        if (strpos($request_uri, 'profile.php') !== false) {
            return;
        }

        // Block unauthorized admin - show forbidden page
        $this->block_unauthorized_admin($current_user);
    }

    /**
     * Check if user ID is in the allowed list
     */
    private function is_user_allowed($user_id) {
        return in_array((int) $user_id, array_map('intval', $this->allowed_user_ids), true);
    }

    /**
     * Hide admin bar for unauthorized admin users
     */
    public function maybe_hide_admin_bar() {
        if (!is_user_logged_in()) {
            return;
        }

        $current_user = wp_get_current_user();

        if (!in_array('administrator', (array) $current_user->roles, true)) {
            return;
        }

        if (!$this->is_user_allowed($current_user->ID)) {
            show_admin_bar(false);
        }
    }

    /**
     * Filter capabilities for unauthorized admin users
     * Removes sensitive capabilities while keeping basic ones
     */
    public function filter_capabilities($allcaps, $caps, $args, $user) {
        // Only filter for administrators
        if (!in_array('administrator', (array) $user->roles, true)) {
            return $allcaps;
        }

        // If user is allowed, don't filter
        if ($this->is_user_allowed($user->ID)) {
            return $allcaps;
        }

        // Remove dangerous capabilities from unauthorized admins
        $restricted_caps = [
            'switch_themes',
            'edit_themes',
            'activate_plugins',
            'edit_plugins',
            'edit_users',
            'delete_users',
            'create_users',
            'unfiltered_upload',
            'edit_dashboard',
            'update_plugins',
            'delete_plugins',
            'install_plugins',
            'update_themes',
            'install_themes',
            'delete_themes',
            'update_core',
            'manage_options',
            'edit_files',
            'unfiltered_html',
            'export',
            'import',
            'manage_network',
            'manage_sites',
            'manage_network_users',
            'manage_network_plugins',
            'manage_network_themes',
            'manage_network_options',
            'promote_users',
            'remove_users',
            'list_users',
        ];

        foreach ($restricted_caps as $cap) {
            $allcaps[$cap] = false;
        }

        return $allcaps;
    }

    /**
     * Block unauthorized admin access (with static HTML caching)
     */
    private function block_unauthorized_admin($user) {
        // Log this attempt before serving cached/rendered page
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
        error_log(sprintf(
            'VietShield: Unauthorized admin access blocked - User: %s (ID: %d), IP: %s',
            $user->user_login,
            $user->ID,
            $this->get_client_ip()
        ));

        require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';

        $message = __('Access Denied - Your administrator account is not authorized to access this area. Contact the site owner for access.', 'vietshield-waf');

        \VietShield_Helpers::send_blocked_response('ADMIN_ACCESS', $this->get_client_ip(), $message);
    }

    /**
     * Get client IP address
     */
    private function get_client_ip() {
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            return sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_CONNECTING_IP']));
        }
        if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
            return sanitize_text_field(wp_unslash($_SERVER['HTTP_X_REAL_IP']));
        }
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR'])));
            return trim($ips[0]);
        }
        return isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
    }

    /**
     * Get all admin users for settings UI
     */
    public static function get_admin_users() {
        $admins = get_users([
            'role' => 'administrator',
            'orderby' => 'ID',
            'order' => 'ASC',
        ]);

        $result = [];
        foreach ($admins as $admin) {
            $result[] = [
                'id' => $admin->ID,
                'login' => $admin->user_login,
                'email' => $admin->user_email,
                'display_name' => $admin->display_name,
            ];
        }

        return $result;
    }
}
