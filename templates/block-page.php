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
            filter: drop-shadow(0 0 30px <?php echo esc_attr($accent_color); ?>40);
        }
        
        .status-code {
            font-size: 72px;
            font-weight: 800;
            color: <?php echo esc_attr($accent_color); ?>;
            text-shadow: 0 0 40px <?php echo esc_attr($accent_color); ?>60;
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
            border-left: 4px solid <?php echo esc_attr($accent_color); ?>;
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
            transition: color 0.3s;
        }

        .footer a:hover {
            color: #94a3b8;
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
                      fill="<?php echo esc_attr($accent_color); ?>" fill-opacity="0.2" stroke="<?php echo esc_attr($accent_color); ?>" stroke-width="1.5"/>
                <path d="M12 8V12M12 16H12.01" stroke="<?php echo esc_attr($accent_color); ?>" stroke-width="2" stroke-linecap="round"/>
            </svg>
        </div>
        
        <div class="status-code"><?php echo esc_html($status); ?></div>
        <div class="status-text">Access Denied</div>
        
        <div class="message-box">
            <p><?php esc_html_e('Sorry, you have been blocked for security reasons.', 'vietshield-waf'); ?></p>
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
