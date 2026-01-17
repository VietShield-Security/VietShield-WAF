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
        
        // phpcs:ignore PluginCheck.CodeAnalysis.Heredoc.NotAllowed -- Block page HTML requires heredoc for readability
        return <<<HTML
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>{$status} - Request Blocked | VietShield WAF</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f0f23 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            color: #e2e8f0;
        }
        
        .container {
            max-width: 600px;
            width: 100%;
            text-align: center;
        }
        
        .shield-icon {
            width: 120px;
            height: 120px;
            margin: 0 auto 30px;
            position: relative;
        }
        
        .shield-icon svg {
            width: 100%;
            height: 100%;
            filter: drop-shadow(0 0 30px {$accent_color}40);
        }
        
        .status-code {
            font-size: 72px;
            font-weight: 800;
            color: {$accent_color};
            text-shadow: 0 0 40px {$accent_color}60;
            margin-bottom: 10px;
        }
        
        .status-text {
            font-size: 24px;
            font-weight: 600;
            color: #f8fafc;
            margin-bottom: 30px;
        }
        
        .message-box {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-left: 4px solid {$accent_color};
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 30px;
            backdrop-filter: blur(10px);
        }
        
        .message-box p {
            font-size: 16px;
            line-height: 1.6;
            color: #cbd5e1;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .info-item {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            padding: 15px;
        }
        
        .info-item .label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #64748b;
            margin-bottom: 5px;
        }
        
        .info-item .value {
            font-size: 14px;
            font-family: 'Monaco', 'Consolas', monospace;
            color: #94a3b8;
        }
        
        .action-btn {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: linear-gradient(135deg, {$accent_color}dd, {$accent_color});
            color: white;
            text-decoration: none;
            padding: 14px 28px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 15px;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px {$accent_color}40;
        }
        
        .action-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 25px {$accent_color}50;
        }
        
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .footer p {
            font-size: 13px;
            color: #475569;
        }
        
        .footer a {
            color: #64748b;
            text-decoration: none;
        }
        
        @media (max-width: 480px) {
            .status-code {
                font-size: 48px;
            }
            .status-text {
                font-size: 18px;
            }
            .info-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="shield-icon">
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2L3 7V12C3 17.55 6.84 22.74 12 24C17.16 22.74 21 17.55 21 12V7L12 2Z" 
                      fill="{$accent_color}" fill-opacity="0.2" stroke="{$accent_color}" stroke-width="1.5"/>
                <path d="M12 8V12M12 16H12.01" stroke="{$accent_color}" stroke-width="2" stroke-linecap="round"/>
            </svg>
        </div>
        
        <div class="status-code">{$status}</div>
        <div class="status-text">Access Denied</div>
        
        <div class="message-box">
            <p>{$message}</p>
        </div>
        
        <div class="info-grid">
            <div class="info-item">
                <div class="label">Block ID</div>
                <div class="value">{$block_id}</div>
            </div>
            <div class="info-item">
                <div class="label">Time ({$timezone_label})</div>
                <div class="value" id="time">{$current_time}</div>
            </div>
        </div>
        
        <a href="/" class="action-btn">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/>
                <polyline points="9,22 9,12 15,12 15,22"/>
            </svg>
            Go to Homepage
        </a>
        
        <div class="footer">
            <p>Protected by <strong>VietShield WAF</strong></p>
        </div>
    </div>
    
</body>
</html>
HTML;
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
