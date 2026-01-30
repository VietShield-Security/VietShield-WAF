<?php
/**
 * CAPTCHA Handler
 * 
 * Handles CAPTCHA challenge for suspicious requests instead of blocking
 * Supports: Google reCAPTCHA v2/v3, Cloudflare Turnstile, hCaptcha
 * 
 * @package VietShield_WAF
 */

namespace VietShield\WAF;

if (!defined('ABSPATH')) {
    exit;
}

class CaptchaHandler {
    
    /**
     * Captcha options
     */
    private $options;
    
    /**
     * Supported providers
     */
    const PROVIDERS = ['recaptcha_v2', 'recaptcha_v3', 'turnstile', 'hcaptcha'];
    
    /**
     * Provider configurations
     */
    private $provider_configs = [
        'recaptcha_v2' => [
            'name' => 'Google reCAPTCHA v2',
            'script' => 'https://www.google.com/recaptcha/api.js',
            'verify_url' => 'https://www.google.com/recaptcha/api/siteverify',
            'response_field' => 'g-recaptcha-response',
        ],
        'recaptcha_v3' => [
            'name' => 'Google reCAPTCHA v3',
            'script' => 'https://www.google.com/recaptcha/api.js?render=',
            'verify_url' => 'https://www.google.com/recaptcha/api/siteverify',
            'response_field' => 'g-recaptcha-response',
        ],
        'turnstile' => [
            'name' => 'Cloudflare Turnstile',
            'script' => 'https://challenges.cloudflare.com/turnstile/v0/api.js',
            'verify_url' => 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            'response_field' => 'cf-turnstile-response',
        ],
        'hcaptcha' => [
            'name' => 'hCaptcha',
            'script' => 'https://js.hcaptcha.com/1/api.js',
            'verify_url' => 'https://hcaptcha.com/siteverify',
            'response_field' => 'h-captcha-response',
        ],
    ];
    
    /**
     * Constructor
     */
    public function __construct() {
        $this->options = get_option('vietshield_options', []);
    }
    
    /**
     * Check if captcha challenge is enabled
     */
    public function is_enabled() {
        return !empty($this->options['captcha_enabled']) && 
               !empty($this->options['captcha_provider']) &&
               !empty($this->options['captcha_site_key']) &&
               !empty($this->options['captcha_secret_key']);
    }
    
    /**
     * Get current provider
     */
    public function get_provider() {
        return $this->options['captcha_provider'] ?? '';
    }
    
    /**
     * Get site key
     */
    public function get_site_key() {
        return $this->options['captcha_site_key'] ?? '';
    }
    
    /**
     * Get secret key
     */
    public function get_secret_key() {
        return $this->options['captcha_secret_key'] ?? '';
    }
    
    /**
     * Check if attack type should use captcha challenge
     * Threat intelligence attacks are excluded from captcha
     */
    public function should_challenge($attack_type) {
        // Check if captcha is enabled first
        if (!$this->is_enabled()) {
            return false;
        }
        
        // Empty attack type should not be challenged
        if (empty($attack_type)) {
            return false;
        }
        
        // Excluded attack types - always block, never captcha
        // These are high-severity threats that should always be blocked
        $excluded_types = [
            'threat_intelligence',
            'threat_intel', // backward compatibility
            'ip_blacklist',
            'auto_blocked',
            'temp_block',
        ];
        
        if (in_array($attack_type, $excluded_types, true)) {
            return false;
        }
        
        // Get configured attack types for captcha challenge
        $captcha_types = $this->options['captcha_attack_types'] ?? [];
        
        // If no specific types configured (empty or not set),
        // apply captcha to ALL attack types except excluded ones above
        if (empty($captcha_types)) {
            return true; // Apply captcha challenge for all non-excluded attack types
        }
        
        // If specific types are configured, only apply to those
        return in_array($attack_type, $captcha_types, true);
    }
    
    /**
     * Generate challenge token
     */
    public function generate_challenge_token($ip, $attack_type, $request_uri) {
        $data = [
            'ip' => $ip,
            'attack_type' => $attack_type,
            'request_uri' => $request_uri,
            'timestamp' => time(),
            'nonce' => wp_generate_password(16, false),
        ];
        
        $token = base64_encode(wp_json_encode($data));
        $signature = hash_hmac('sha256', $token, $this->get_token_secret());
        
        return $token . '.' . $signature;
    }
    
    /**
     * Validate challenge token
     */
    public function validate_challenge_token($token) {
        $parts = explode('.', $token);
        if (count($parts) !== 2) {
            return false;
        }
        
        list($data_encoded, $signature) = $parts;
        
        // Verify signature
        $expected_signature = hash_hmac('sha256', $data_encoded, $this->get_token_secret());
        if (!hash_equals($expected_signature, $signature)) {
            return false;
        }
        
        // Decode data
        $data = json_decode(base64_decode($data_encoded), true);
        if (!$data) {
            return false;
        }
        
        // Check expiration (5 minutes)
        if (time() - $data['timestamp'] > 300) {
            return false;
        }
        
        return $data;
    }
    
    /**
     * Get token secret key
     */
    private function get_token_secret() {
        $secret = get_option('vietshield_captcha_secret');
        if (!$secret) {
            $secret = wp_generate_password(32, true, true);
            update_option('vietshield_captcha_secret', $secret);
        }
        return $secret;
    }
    
    /**
     * Verify captcha response
     */
    public function verify_response($response, $ip = null) {
        if (empty($response)) {
            return ['success' => false, 'error' => 'No captcha response'];
        }
        
        $provider = $this->get_provider();
        if (!isset($this->provider_configs[$provider])) {
            return ['success' => false, 'error' => 'Invalid provider'];
        }
        
        $config = $this->provider_configs[$provider];
        $secret = $this->get_secret_key();
        
        // Build request body
        $body = [
            'secret' => $secret,
            'response' => $response,
        ];
        
        // Add IP if provided (optional for most providers)
        if ($ip) {
            $body['remoteip'] = $ip;
        }
        
        // Make verification request
        $result = wp_remote_post($config['verify_url'], [
            'body' => $body,
            'timeout' => 10,
        ]);
        
        if (is_wp_error($result)) {
            return ['success' => false, 'error' => $result->get_error_message()];
        }
        
        $response_body = json_decode(wp_remote_retrieve_body($result), true);
        
        if (!$response_body) {
            return ['success' => false, 'error' => 'Invalid verification response'];
        }
        
        // Check success
        if (!empty($response_body['success'])) {
            // For reCAPTCHA v3, also check score
            if ($provider === 'recaptcha_v3') {
                $score = $response_body['score'] ?? 0;
                $min_score = $this->options['recaptcha_v3_min_score'] ?? 0.5;
                if ($score < $min_score) {
                    return ['success' => false, 'error' => 'Score too low', 'score' => $score];
                }
            }
            return ['success' => true, 'data' => $response_body];
        }
        
        $error_codes = $response_body['error-codes'] ?? ['unknown'];
        return ['success' => false, 'error' => implode(', ', $error_codes)];
    }
    
    /**
     * Store verified session
     */
    public function store_verified_session($ip) {
        $session_key = 'vietshield_captcha_verified_' . md5($ip);
        $duration = $this->options['captcha_session_duration'] ?? 3600; // 1 hour default
        
        set_transient($session_key, time(), $duration);
    }
    
    /**
     * Check if IP has verified session
     */
    public function has_verified_session($ip) {
        $session_key = 'vietshield_captcha_verified_' . md5($ip);
        return get_transient($session_key) !== false;
    }
    
    /**
     * Show challenge page
     */
    public function show_challenge_page($data) {
        if (!$this->is_enabled()) {
            return;
        }
        
        $provider = $this->get_provider();
        $site_key = $this->get_site_key();
        $config = $this->provider_configs[$provider] ?? null;
        
        if (!$config) {
            return;
        }
        
        // Generate challenge token
        $challenge_token = $this->generate_challenge_token(
            $data['ip'] ?? '',
            $data['attack_type'] ?? '',
            $data['request_uri'] ?? ''
        );
        
        // Get the challenge page HTML
        $html = $this->get_challenge_page_html($data, $challenge_token, $provider, $site_key, $config);
        
        // Set appropriate headers
        status_header(403);
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-cache, no-store, must-revalidate');
        header('X-VietShield-Challenge: captcha');
        
        // Output and exit
        echo $html;
        exit;
    }
    
    /**
     * Get challenge page HTML
     */
    private function get_challenge_page_html($data, $challenge_token, $provider, $site_key, $config) {
        $attack_type = $data['attack_type'] ?? 'unknown';
        $block_id = $data['block_id'] ?? substr(md5(uniqid()), 0, 8);
        
        // Get custom CSS if exists
        $custom_css_file = VIETSHIELD_PLUGIN_DIR . 'assets/css/captcha-page.css';
        $custom_css = file_exists($custom_css_file) ? file_get_contents($custom_css_file) : '';
        
        // Build script URL
        $script_url = $config['script'];
        if ($provider === 'recaptcha_v3') {
            $script_url .= $site_key;
        }
        
        // Generate form action URL
        $form_action = add_query_arg([
            'vietshield_captcha_verify' => 1,
            'token' => urlencode($challenge_token),
        ], home_url('/'));
        
        ob_start();
        ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Security Check Required</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .captcha-container {
            background: #fff;
            border-radius: 16px;
            padding: 40px;
            max-width: 480px;
            width: 100%;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
        }
        .shield-icon {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 24px;
        }
        .shield-icon svg {
            width: 40px;
            height: 40px;
            fill: white;
        }
        h1 {
            color: #1f2937;
            font-size: 24px;
            margin-bottom: 12px;
            font-weight: 600;
        }
        .description {
            color: #6b7280;
            margin-bottom: 24px;
            line-height: 1.6;
        }
        .captcha-widget {
            display: flex;
            justify-content: center;
            margin-bottom: 24px;
            min-height: 78px;
        }
        .submit-btn {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
            border: none;
            padding: 14px 32px;
            font-size: 16px;
            font-weight: 600;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            width: 100%;
        }
        .submit-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(16, 185, 129, 0.4);
        }
        .submit-btn:disabled {
            background: #9ca3af;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        .info-box {
            background: #fef3c7;
            border: 1px solid #f59e0b;
            border-radius: 8px;
            padding: 12px 16px;
            margin-top: 20px;
            font-size: 13px;
            color: #92400e;
        }
        .block-id {
            color: #9ca3af;
            font-size: 12px;
            margin-top: 16px;
        }
        .error-message {
            background: #fef2f2;
            border: 1px solid #ef4444;
            color: #dc2626;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 16px;
            display: none;
        }
        @media (max-width: 480px) {
            .captcha-container { padding: 24px; }
            h1 { font-size: 20px; }
        }
        <?php echo $custom_css; ?>
    </style>
    <script src="<?php echo esc_url($script_url); ?>" async defer></script>
</head>
<body>
    <div class="captcha-container">
        <div class="shield-icon">
            <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
        </div>
        
        <h1>Security Check Required</h1>
        <p class="description">
            Our security system has detected unusual activity from your connection. 
            Please complete the verification below to continue.
        </p>
        
        <div id="error-message" class="error-message"></div>
        
        <form id="captcha-form" method="POST" action="<?php echo esc_url($form_action); ?>">
            <input type="hidden" name="vietshield_challenge_token" value="<?php echo esc_attr($challenge_token); ?>">
            <input type="hidden" name="vietshield_original_uri" value="<?php echo esc_attr($data['request_uri'] ?? '/'); ?>">
            
            <div class="captcha-widget">
                <?php if ($provider === 'recaptcha_v2'): ?>
                    <div class="g-recaptcha" data-sitekey="<?php echo esc_attr($site_key); ?>" data-callback="onCaptchaSuccess"></div>
                <?php elseif ($provider === 'recaptcha_v3'): ?>
                    <input type="hidden" name="g-recaptcha-response" id="g-recaptcha-response">
                <?php elseif ($provider === 'turnstile'): ?>
                    <div class="cf-turnstile" data-sitekey="<?php echo esc_attr($site_key); ?>" data-callback="onCaptchaSuccess"></div>
                <?php elseif ($provider === 'hcaptcha'): ?>
                    <div class="h-captcha" data-sitekey="<?php echo esc_attr($site_key); ?>" data-callback="onCaptchaSuccess"></div>
                <?php endif; ?>
            </div>
            
            <button type="submit" id="submit-btn" class="submit-btn" <?php echo $provider !== 'recaptcha_v3' ? 'disabled' : ''; ?>>
                Verify & Continue
            </button>
        </form>
        
        <div class="info-box">
            <strong>Why am I seeing this?</strong><br>
            This security check helps protect the website from automated attacks and malicious traffic.
        </div>
        
        <p class="block-id">Reference: <?php echo esc_html($block_id); ?></p>
    </div>
    
    <script>
        function onCaptchaSuccess(token) {
            document.getElementById('submit-btn').disabled = false;
        }
        
        <?php if ($provider === 'recaptcha_v3'): ?>
        grecaptcha.ready(function() {
            grecaptcha.execute('<?php echo esc_js($site_key); ?>', {action: 'verify'}).then(function(token) {
                document.getElementById('g-recaptcha-response').value = token;
            });
        });
        <?php endif; ?>
        
        document.getElementById('captcha-form').addEventListener('submit', function(e) {
            var btn = document.getElementById('submit-btn');
            btn.disabled = true;
            btn.textContent = 'Verifying...';
        });
    </script>
</body>
</html>
        <?php
        return ob_get_clean();
    }
    
    /**
     * Handle captcha verification callback
     */
    public function handle_verification() {
        // Check if this is a captcha verification request
        if (empty($_GET['vietshield_captcha_verify']) && empty($_POST['vietshield_challenge_token'])) {
            return false;
        }
        
        // Get the challenge token
        $challenge_token = '';
        if (!empty($_GET['token'])) {
            $challenge_token = sanitize_text_field(wp_unslash($_GET['token']));
        } elseif (!empty($_POST['vietshield_challenge_token'])) {
            $challenge_token = sanitize_text_field(wp_unslash($_POST['vietshield_challenge_token']));
        }
        
        // Validate challenge token
        $token_data = $this->validate_challenge_token($challenge_token);
        if (!$token_data) {
            $this->show_error_page('Invalid or expired security token. Please try again.');
            return true;
        }
        
        // Get captcha response
        $provider = $this->get_provider();
        $response_field = $this->provider_configs[$provider]['response_field'] ?? 'g-recaptcha-response';
        
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Captcha verification doesn't use nonce
        $captcha_response = isset($_POST[$response_field]) ? sanitize_text_field(wp_unslash($_POST[$response_field])) : '';
        
        if (empty($captcha_response)) {
            $this->show_error_page('Please complete the captcha verification.');
            return true;
        }
        
        // Verify captcha response
        $verification = $this->verify_response($captcha_response, $token_data['ip']);
        
        if (!$verification['success']) {
            $this->show_error_page('Captcha verification failed: ' . ($verification['error'] ?? 'Unknown error'));
            return true;
        }
        
        // Store verified session
        $this->store_verified_session($token_data['ip']);
        
        // Log successful verification
        $this->log_verification($token_data);
        
        // Redirect to original URI
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Captcha verification doesn't use nonce
        $original_uri = isset($_POST['vietshield_original_uri']) ? sanitize_text_field(wp_unslash($_POST['vietshield_original_uri'])) : '/';
        $redirect_url = home_url($original_uri);
        
        wp_safe_redirect($redirect_url);
        exit;
    }
    
    /**
     * Show error page
     */
    private function show_error_page($message) {
        status_header(400);
        header('Content-Type: text/html; charset=utf-8');
        ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verification Failed</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #1a1a2e; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .container { background: #fff; border-radius: 16px; padding: 40px; max-width: 480px; text-align: center; }
        .error-icon { width: 60px; height: 60px; background: #fef2f2; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 20px; }
        .error-icon svg { width: 30px; height: 30px; fill: #ef4444; }
        h1 { color: #1f2937; font-size: 20px; margin-bottom: 12px; }
        p { color: #6b7280; margin-bottom: 24px; }
        a { display: inline-block; background: #3b82f6; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 8px; }
        a:hover { background: #2563eb; }
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">
            <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
        </div>
        <h1>Verification Failed</h1>
        <p><?php echo esc_html($message); ?></p>
        <a href="javascript:history.back()">Try Again</a>
    </div>
</body>
</html>
        <?php
        exit;
    }
    
    /**
     * Log successful verification
     */
    private function log_verification($token_data) {
        global $wpdb;
        
        $table = $wpdb->prefix . 'vietshield_logs';
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- WAF logging
        $wpdb->insert($table, [
            'timestamp' => current_time('mysql'),
            'ip' => $token_data['ip'] ?? '',
            'request_method' => 'POST',
            'request_uri' => $token_data['request_uri'] ?? '',
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '',
            'action' => 'captcha_verified',
            'rule_id' => 'captcha',
            'rule_matched' => 'Captcha verification passed',
            'severity' => 'info',
            'attack_type' => $token_data['attack_type'] ?? '',
            'response_code' => 200,
        ]);
    }
    
    /**
     * Get provider list for settings
     */
    public static function get_provider_list() {
        return [
            'recaptcha_v2' => 'Google reCAPTCHA v2 (Checkbox)',
            'recaptcha_v3' => 'Google reCAPTCHA v3 (Invisible)',
            'turnstile' => 'Cloudflare Turnstile',
            'hcaptcha' => 'hCaptcha',
        ];
    }
}
