<?php
/**
 * Response Handler - Handle blocked/allowed responses
 * 
 * @package VietShield_WAF
 */

namespace VietShield\WAF;

if (!defined('ABSPATH')) {
    exit;
}

class ResponseHandler {
    
    /**
     * Block the request
     * 
     * @param array $data Block information
     */
    public function block($data) {
        // Set HTTP response code
        $status_code = $this->get_status_code($data['severity'] ?? 'medium');
        
        // Check if headers already sent
        if (!headers_sent()) {
            http_response_code($status_code);
            header('X-VietShield-Block: ' . ($data['rule_id'] ?? 'unknown'));
            header('X-Content-Type-Options: nosniff');
            header('X-Frame-Options: DENY');
        }
        
        // Determine response type
        if ($this->is_ajax_request()) {
            $this->json_response($data, $status_code);
        } elseif ($this->is_rest_request()) {
            $this->json_response($data, $status_code);
        } else {
            $this->html_response($data, $status_code);
        }
        
        exit;
    }
    
    /**
     * Get HTTP status code based on severity
     */
    private function get_status_code($severity) {
        switch ($severity) {
            case 'critical':
            case 'high':
                return 403; // Forbidden
            case 'medium':
                return 403;
            case 'low':
                return 403;
            default:
                return 403;
        }
    }
    
    /**
     * JSON response for AJAX/REST requests
     */
    private function json_response($data, $status_code) {
        header('Content-Type: application/json; charset=utf-8');
        
        $response = [
            'error' => true,
            'code' => $status_code,
            'message' => $this->get_block_message($data),
            'blocked_by' => 'VietShield WAF',
        ];
        
        // Add debug info only for admins
        if (defined('WP_DEBUG') && WP_DEBUG && current_user_can('manage_options')) {
            $response['debug'] = [
                'rule_id' => $data['rule_id'] ?? '',
                'attack_type' => $data['attack_type'] ?? '',
            ];
        }
        
        echo json_encode($response);
    }
    
    /**
     * HTML response for browser requests
     */
    private function html_response($data, $status_code) {
        $message = $this->get_block_message($data);
        // Use provided Block ID or generate one
        $block_id = $data['block_id'] ?? substr(md5(time() . ($data['ip'] ?? '')), 0, 12);
        
        // Beautiful block page
        $html = $this->get_block_page_html([
            'status_code' => $status_code,
            'message' => $message,
            'block_id' => $block_id,
            'severity' => $data['severity'] ?? 'medium',
            'attack_type' => $data['attack_type'] ?? '',
        ]);
        
        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- HTML is fully escaped in get_block_page_html
        echo $html;
    }
    
    /**
     * Get block message based on attack type
     */
    private function get_block_message($data) {
        $attack_type = $data['attack_type'] ?? '';
        
        $messages = [
            'sqli' => 'SQL Injection attack detected and blocked.',
            'xss' => 'Cross-Site Scripting (XSS) attack detected and blocked.',
            'rce' => 'Remote Code Execution attempt detected and blocked.',
            'lfi' => 'Local File Inclusion attempt detected and blocked.',
            'bad_bot' => 'Automated scanner/bot blocked.',
            'enumeration' => 'User enumeration attempt blocked.',
            'xmlrpc' => 'XML-RPC access is disabled.',
            'rate_limited' => 'Too many requests. Please slow down.',
            'ip_blacklisted' => 'Your IP address has been blocked.',
        ];
        
        return $messages[$attack_type] ?? 'Your request has been blocked for security reasons.';
    }
    
    /**
     * Generate block page HTML
     */
    private function get_block_page_html($data) {
        $status = $data['status_code'];
        $message = htmlspecialchars($data['message']);
        $block_id = htmlspecialchars($data['block_id']);
        $severity = $data['severity'];
        
        // Get timezone info
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
        $options = get_option('vietshield_options', []);
        $timezone = $options['log_timezone'] ?? get_option('timezone_string') ?: 'UTC';
        
        // Get timezone name for display
        try {
            $tz = new \DateTimeZone($timezone);
            $dt = new \DateTime('now', $tz);
            $offset = $dt->getOffset();
            $hours = intval($offset / 3600);
            $minutes = abs(intval(($offset % 3600) / 60));
            $sign = $hours >= 0 ? '+' : '-';
            $offset_str = sprintf('%s%02d:%02d', $sign, abs($hours), $minutes);
            $timezone_label = str_replace('_', ' ', $timezone) . ' (GMT' . $offset_str . ')';
        } catch (\Exception $e) {
            $timezone_label = 'UTC';
        }
        
        // Get current time in configured timezone
        $current_time = \VietShield_Helpers::get_current_timestamp();
        
        // Escape for output
        $timezone_label = htmlspecialchars($timezone_label, ENT_QUOTES, 'UTF-8');
        $current_time = htmlspecialchars($current_time, ENT_QUOTES, 'UTF-8');
        
        // Color based on severity
        $colors = [
            'critical' => '#dc2626',
            'high' => '#ea580c',
            'medium' => '#ca8a04',
            'low' => '#65a30d',
        ];
        $accent_color = $colors[$severity] ?? '#dc2626';
        
        // Use template file instead of heredoc
        ob_start();
        include VIETSHIELD_PLUGIN_DIR . 'templates/block-page.php';
        return ob_get_clean();
    }
    
    /**
     * Check if AJAX request
     */
    private function is_ajax_request() {
        if (defined('DOING_AJAX') && DOING_AJAX) {
            return true;
        }
        
        if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && 
            strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if REST API request
     */
    private function is_rest_request() {
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        
        if (strpos($uri, '/wp-json/') !== false) {
            return true;
        }
        
        if (defined('REST_REQUEST') && REST_REQUEST) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Send rate limit response
     */
    public function rate_limit($data) {
        $retry_after = $data['retry_after'] ?? 60;
        
        if (!headers_sent()) {
            http_response_code(429);
            header('Retry-After: ' . $retry_after);
            header('X-RateLimit-Limit: ' . ($data['limit'] ?? 0));
            header('X-RateLimit-Remaining: 0');
        }
        
        $data['severity'] = 'medium';
        $data['attack_type'] = 'rate_limited';
        
        if ($this->is_ajax_request() || $this->is_rest_request()) {
            $this->json_response($data, 429);
        } else {
            $this->html_response($data, 429);
        }
        
        exit;
    }
}
