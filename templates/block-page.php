<?php
/**
 * Block page template
 * 
 * @package VietShield_WAF
 * 
 * Variables available:
 * - $status: HTTP status code
 * - $message: Block message
 * - $block_id: Block ID for reference
 * - $current_time: Current timestamp
 * - $timezone_label: Timezone label
 * - $accent_color: Color based on severity
 */

if (!defined('ABSPATH')) {
    exit;
}
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title><?php echo esc_html($status); ?> - Request Blocked | VietShield WAF</title>
    <link rel="stylesheet" href="<?php echo esc_url(VIETSHIELD_PLUGIN_URL . 'assets/css/block-page.css'); ?>">
    <style>
        /* Dynamic colors injected here because they depend on PHP variables */
        .shield-icon svg {
            filter: drop-shadow(0 0 30px <?php echo esc_attr($accent_color); ?>40);
        }
        .status-code {
            color: <?php echo esc_attr($accent_color); ?>;
            text-shadow: 0 0 40px <?php echo esc_attr($accent_color); ?>60;
        }
        .message-box {
            border-left: 4px solid <?php echo esc_attr($accent_color); ?>;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="shield-icon">
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2L3 7V12C3 17.55 6.84 22.74 12 24C17.16 22.74 21 17.55 21 12V7L12 2Z" 
                      fill="<?php echo esc_attr($accent_color); ?>" fill-opacity="0.2" stroke="<?php echo esc_attr($accent_color); ?>" stroke-width="1.5"/>
                <path d="M12 8V12M12 16H12.01" stroke="<?php echo esc_attr($accent_color); ?>" stroke-width="2" stroke-linecap="round"/>
            </svg>
        </div>
        
        <div class="status-code"><?php echo esc_html($status); ?></div>
        <div class="status-text">Access Denied</div>
        
        <div class="message-box">
            <p><?php echo esc_html($message); ?></p>
        </div>
        
        <div class="info-grid">
            <div class="info-item">
                <div class="label">Block ID</div>
                <div class="value"><?php echo esc_html($block_id); ?></div>
            </div>
            <div class="info-item">
                <div class="label">Time (<?php echo esc_html($timezone_label); ?>)</div>
                <div class="value" id="time"><?php echo esc_html($current_time); ?></div>
            </div>
        </div>
        
        <div class="footer">
            <p>Protected by <strong><a href="https://vietshield.org" target="_blank" rel="noopener noreferrer">VietShield WAF</a></strong></p>
        </div>
    </div>
    
</body>
</html>
