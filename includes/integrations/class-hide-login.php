<?php
/**
 * Hide Admin Login
 *
 * Hides the default WordPress login URL (wp-login.php, wp-admin) and replaces it
 * with a custom slug defined by the user. Unauthorized access to default login URLs
 * returns a 403 Forbidden response.
 *
 * @package VietShield_WAF
 */

namespace VietShield\Integrations;

if (!defined('ABSPATH')) {
    exit;
}

class HideLogin {

    /**
     * Custom login slug
     */
    private $login_slug = '';

    /**
     * Plugin options
     */
    private $options = [];

    /**
     * Constructor
     */
    public function __construct() {
        $this->options = get_option('vietshield_options', []);
        $this->login_slug = $this->options['hide_login_slug'] ?? '';

        if (empty($this->login_slug)) {
            return;
        }

        // Don't interfere with admin-ajax.php, cron, or REST API
        if ($this->is_excluded_request()) {
            return;
        }

        add_filter('site_url', [$this, 'filter_site_url'], 10, 4);
        add_filter('wp_redirect', [$this, 'filter_wp_redirect'], 10, 2);
        add_filter('login_url', [$this, 'filter_login_url'], 10, 3);
        add_filter('logout_url', [$this, 'filter_logout_url'], 10, 2);
        add_filter('register_url', [$this, 'filter_register_url'], 10, 1);
        add_filter('lostpassword_url', [$this, 'filter_lostpassword_url'], 10, 2);

        // Handle the custom login slug
        add_action('init', [$this, 'handle_custom_login'], 1);

        // Block default login URLs for non-logged-in users
        add_action('init', [$this, 'block_default_login'], 2);

        // Prevent wp-admin redirect for non-logged-in users
        remove_action('template_redirect', 'wp_redirect_admin_locations', 1000);
    }

    /**
     * Check if current request should be excluded from hide login logic
     */
    private function is_excluded_request() {
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $request_uri = isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : '';

        // Exclude AJAX requests
        if (strpos($request_uri, '/wp-admin/admin-ajax.php') !== false) {
            return true;
        }

        // Exclude admin-post.php
        if (strpos($request_uri, '/wp-admin/admin-post.php') !== false) {
            return true;
        }

        // Exclude WP Cron
        if (strpos($request_uri, '/wp-cron.php') !== false) {
            return true;
        }

        // Exclude REST API
        if (strpos($request_uri, '/wp-json/') !== false) {
            return true;
        }

        // Exclude XML-RPC
        if (strpos($request_uri, '/xmlrpc.php') !== false) {
            return true;
        }

        return false;
    }

    /**
     * Get the custom login URL
     */
    private function get_custom_login_url($scheme = 'login') {
        return home_url('/' . $this->login_slug . '/', $scheme);
    }

    /**
     * Filter site_url to replace wp-login.php references
     */
    public function filter_site_url($url, $path, $scheme, $blog_id) {
        return $this->replace_login_url($url);
    }

    /**
     * Filter wp_redirect to replace wp-login.php in redirects
     */
    public function filter_wp_redirect($location, $status) {
        return $this->replace_login_url($location);
    }

    /**
     * Filter login_url
     */
    public function filter_login_url($login_url, $redirect, $force_reauth) {
        $login_url = $this->get_custom_login_url();

        if (!empty($redirect)) {
            $login_url = add_query_arg('redirect_to', urlencode($redirect), $login_url);
        }

        if ($force_reauth) {
            $login_url = add_query_arg('reauth', '1', $login_url);
        }

        return $login_url;
    }

    /**
     * Filter logout_url
     */
    public function filter_logout_url($logout_url, $redirect) {
        // Parse the original logout URL to get the nonce
        $parsed = wp_parse_url($logout_url);
        $query = [];
        if (!empty($parsed['query'])) {
            parse_str($parsed['query'], $query);
        }

        $new_logout_url = $this->get_custom_login_url();
        $new_logout_url = add_query_arg('action', 'logout', $new_logout_url);

        if (isset($query['_wpnonce'])) {
            $new_logout_url = add_query_arg('_wpnonce', $query['_wpnonce'], $new_logout_url);
        }

        if (!empty($redirect)) {
            $new_logout_url = add_query_arg('redirect_to', urlencode($redirect), $new_logout_url);
        }

        return $new_logout_url;
    }

    /**
     * Filter register_url
     */
    public function filter_register_url($register_url) {
        return add_query_arg('action', 'register', $this->get_custom_login_url());
    }

    /**
     * Filter lostpassword_url
     */
    public function filter_lostpassword_url($lostpassword_url, $redirect) {
        $url = add_query_arg('action', 'lostpassword', $this->get_custom_login_url());

        if (!empty($redirect)) {
            $url = add_query_arg('redirect_to', urlencode($redirect), $url);
        }

        return $url;
    }

    /**
     * Replace wp-login.php in any URL with custom slug
     */
    private function replace_login_url($url) {
        if (strpos($url, 'wp-login.php') !== false) {
            // Parse query string from original URL
            $parsed = wp_parse_url($url);
            $query_string = !empty($parsed['query']) ? '?' . $parsed['query'] : '';

            $url = $this->get_custom_login_url() . ltrim($query_string, '/');
        }

        return $url;
    }

    /**
     * Handle requests to the custom login slug
     */
    public function handle_custom_login() {
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $request_uri = isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : '';
        $request_path = wp_parse_url($request_uri, PHP_URL_PATH);
        $request_path = rtrim($request_path, '/');

        $custom_slug = '/' . $this->login_slug;

        if ($request_path === $custom_slug) {
            // Set the flag so block_default_login doesn't interfere
            define('VIETSHIELD_CUSTOM_LOGIN', true);

            // Internally rewrite to wp-login.php so WordPress handles it natively
            // Preserve query string (e.g. ?action=logout&_wpnonce=xxx)
            $query_string = wp_parse_url($request_uri, PHP_URL_QUERY);
            $_SERVER['REQUEST_URI'] = '/wp-login.php' . ($query_string ? '?' . $query_string : '');

            // Load wp-login.php as WordPress expects it (fresh global scope)
            global $action, $error, $errors, $interim_login, $redirect_to, $user_login;
            require ABSPATH . 'wp-login.php';
            exit;
        }
    }

    /**
     * Block access to default login URLs for non-logged-in users
     */
    public function block_default_login() {
        // If already handled by custom login, skip
        if (defined('VIETSHIELD_CUSTOM_LOGIN')) {
            return;
        }

        // If user is already logged in, allow access to wp-admin
        if (is_user_logged_in()) {
            return;
        }

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $request_uri = isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : '';
        $request_path = wp_parse_url($request_uri, PHP_URL_PATH);
        $request_path = rtrim($request_path, '/');

        $blocked_paths = [
            '/wp-login.php',
            '/wp-login',
        ];

        // Also block /wp-admin (but not /wp-admin/admin-ajax.php, etc.)
        $is_wp_admin = (strpos($request_path, '/wp-admin') === 0 || $request_path === '/wp-admin');
        $is_wp_admin_allowed = (
            strpos($request_path, '/wp-admin/admin-ajax.php') !== false ||
            strpos($request_path, '/wp-admin/admin-post.php') !== false ||
            strpos($request_path, '/wp-admin/css/') !== false ||
            strpos($request_path, '/wp-admin/js/') !== false ||
            strpos($request_path, '/wp-admin/images/') !== false
        );

        $should_block = false;

        foreach ($blocked_paths as $blocked_path) {
            if (strpos($request_path, $blocked_path) !== false) {
                $should_block = true;
                break;
            }
        }

        if (!$should_block && $is_wp_admin && !$is_wp_admin_allowed) {
            $should_block = true;
        }

        if ($should_block) {
            // Return 403 or custom page
            $this->send_forbidden_response();
        }
    }

    /**
     * Send 403 Forbidden response (with static HTML caching)
     */
    private function send_forbidden_response() {
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';

        $client_ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : 'unknown';
        $message = __('You are not allowed to access this page.', 'vietshield-waf');

        \VietShield_Helpers::send_blocked_response('HIDE_LOGIN', $client_ip, $message);
    }
}
