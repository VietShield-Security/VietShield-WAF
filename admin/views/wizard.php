<?php
if (!defined('ABSPATH')) {
    exit;
}

$vswaf_current_step = isset($current_step) ? (int) $current_step : 1;
$vswaf_webserver = isset($webserver) ? $webserver : 'apache';
$vswaf_config_method = $this->get_webserver_config_method($vswaf_webserver);
$vswaf_total_steps = 3;
?>
<div class="wrap vietshield-wizard-wrap">
    <div class="wizard-header">
        <div class="wizard-logo">
            <span class="dashicons dashicons-shield-alt"></span>
            <h1><?php esc_html_e('VietShield WAF Setup Wizard', 'vietshield-waf'); ?> <span style="font-size: 13px; color: #666; font-weight: 400; margin-left: 8px;">v<?php echo esc_html(VIETSHIELD_VERSION); ?></span></h1>
        </div>
        <div class="wizard-progress">
            <div class="progress-bar">
                <div class="progress-fill" style="width: <?php echo esc_attr(($vswaf_current_step / $vswaf_total_steps) * 100); ?>%"></div>
            </div>
            <div class="progress-text">
                <?php 
                /* translators: 1: current step number, 2: total steps number */
                printf(esc_html__('Step %1$d of %2$d', 'vietshield-waf'), intval($vswaf_current_step), intval($vswaf_total_steps)); 
                ?>
            </div>
        </div>
    </div>

    <div class="wizard-content">
        <?php if ($vswaf_current_step == 1): ?>
            <!-- Step 1: Web Server Detection -->
            <div class="wizard-step">
                <h2><?php esc_html_e('Web Server Detection', 'vietshield-waf'); ?></h2>
                <p class="wizard-description">
                    <?php esc_html_e('We\'ve automatically detected your web server configuration. This helps us optimize the firewall settings for your environment.', 'vietshield-waf'); ?>
                </p>
                
                <div class="wizard-card">
                    <div class="detection-result">
                        <div class="detection-icon">
                            <?php if ($vswaf_webserver === 'apache'): ?>
                                <span class="dashicons dashicons-admin-tools"></span>
                            <?php elseif ($vswaf_webserver === 'nginx'): ?>
                                <span class="dashicons dashicons-networking"></span>
                            <?php else: ?>
                                <span class="dashicons dashicons-admin-settings"></span>
                            <?php endif; ?>
                        </div>
                        <div class="detection-info">
                            <h3><?php esc_html_e('Detected Configuration', 'vietshield-waf'); ?></h3>
                            <p class="server-type">
                                <strong><?php esc_html_e('Server Type:', 'vietshield-waf'); ?></strong>
                                <?php
                                $vswaf_server_names = [
                                    'apache' => 'Apache',
                                    'apache-fpm' => 'Apache with PHP-FPM',
                                    'nginx' => 'Nginx',
                                    'php-fpm' => 'PHP-FPM'
                                ];
                                echo esc_html($vswaf_server_names[$vswaf_webserver] ?? 'Apache');
                                ?>
                            </p>
                            <p class="config-method">
                                <strong><?php esc_html_e('Configuration Method:', 'vietshield-waf'); ?></strong>
                                <code><?php echo esc_html($vswaf_config_method); ?></code>
                            </p>
                            <p class="description">
                                <?php
                                if ($vswaf_config_method === '.user.ini') {
                                    esc_html_e('Your server uses PHP-FPM, so we\'ll configure early blocking using .user.ini file.', 'vietshield-waf');
                                } else {
                                    esc_html_e('Your server uses Apache, so we\'ll configure early blocking using .htaccess file.', 'vietshield-waf');
                                }
                                ?>
                            </p>
                        </div>
                    </div>
                </div>
                
                <div class="wizard-actions">
                    <button type="button" class="button button-primary wizard-next" data-step="1">
                        <?php esc_html_e('Continue', 'vietshield-waf'); ?>
                        <span class="dashicons dashicons-arrow-right-alt"></span>
                    </button>
                </div>
            </div>

        <?php elseif ($vswaf_current_step == 2): ?>
            <!-- Step 2: Firewall Mode -->
            <div class="wizard-step">
                <h2><?php esc_html_e('Choose Firewall Mode', 'vietshield-waf'); ?></h2>
                <p class="wizard-description">
                    <?php esc_html_e('Select how you want the firewall to operate. We recommend Block Mode for maximum protection.', 'vietshield-waf'); ?>
                </p>
                
                <div class="wizard-options">
                    <div class="option-card recommended" data-value="protecting">
                        <div class="option-header">
                            <input type="radio" name="firewall_mode" value="protecting" id="mode-protecting" checked>
                            <label for="mode-protecting">
                                <span class="option-title"><?php esc_html_e('Protecting Mode - Block threats and Logging (Recommended)', 'vietshield-waf'); ?></span>
                                <span class="option-badge"><?php esc_html_e('Recommended', 'vietshield-waf'); ?></span>
                            </label>
                        </div>
                        <div class="option-content">
                            <p><?php esc_html_e('Blocks malicious requests immediately and provides the highest level of protection.', 'vietshield-waf'); ?></p>
                            <ul>
                                <li><?php esc_html_e('Block threats before WordPress loads', 'vietshield-waf'); ?></li>
                                <li><?php esc_html_e('Real-time threat detection and logging', 'vietshield-waf'); ?></li>
                                <li><?php esc_html_e('Maximum performance optimization', 'vietshield-waf'); ?></li>
                            </ul>
                        </div>
                    </div>
                    
                    <div class="option-card" data-value="learning">
                        <div class="option-header">
                            <input type="radio" name="firewall_mode" value="learning" id="mode-learning">
                            <label for="mode-learning">
                                <span class="option-title"><?php esc_html_e('Learning Mode - Log only, no blocking', 'vietshield-waf'); ?></span>
                            </label>
                        </div>
                        <div class="option-content">
                            <p><?php esc_html_e('Monitors and logs threats without blocking. Useful for testing.', 'vietshield-waf'); ?></p>
                            <ul>
                                <li><?php esc_html_e('Logs all threats for analysis', 'vietshield-waf'); ?></li>
                                <li><?php esc_html_e('No blocking of requests', 'vietshield-waf'); ?></li>
                                <li><?php esc_html_e('Safe for testing environments', 'vietshield-waf'); ?></li>
                            </ul>
                        </div>
                    </div>
                </div>
                
                <div class="wizard-actions">
                    <button type="button" class="button wizard-prev" data-step="2">
                        <span class="dashicons dashicons-arrow-left-alt"></span>
                        <?php esc_html_e('Back', 'vietshield-waf'); ?>
                    </button>
                    <button type="button" class="button button-primary wizard-next" data-step="2">
                        <?php esc_html_e('Continue', 'vietshield-waf'); ?>
                        <span class="dashicons dashicons-arrow-right-alt"></span>
                    </button>
                </div>
            </div>

        <?php elseif ($vswaf_current_step == 3): ?>
            <!-- Step 3: Auto-Optimize -->
            <div class="wizard-step">
                <h2><?php esc_html_e('Auto-Optimize Settings', 'vietshield-waf'); ?></h2>
                <p class="wizard-description">
                    <?php esc_html_e('We can automatically configure all recommended security features for you. This is the fastest way to get started.', 'vietshield-waf'); ?>
                </p>
                
                <div class="wizard-card">
                    <div class="optimize-option">
                        <label>
                            <input type="checkbox" name="auto_optimize" value="1" checked>
                            <span class="checkbox-label">
                                <strong><?php esc_html_e('Enable Auto-Optimization', 'vietshield-waf'); ?></strong>
                                <span class="description"><?php esc_html_e('Automatically configure all recommended security features', 'vietshield-waf'); ?></span>
                            </span>
                        </label>
                    </div>
                    
                    <div class="optimize-features" id="optimize-features">
                        <h3><?php esc_html_e('Features that will be enabled:', 'vietshield-waf'); ?></h3>
                        <ul>
                            <li><span class="dashicons dashicons-yes"></span> <?php esc_html_e('WAF Engine', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes"></span> <?php esc_html_e('Login Security & Brute Force Protection', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes"></span> <?php esc_html_e('Threat Intelligence', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes"></span> <?php esc_html_e('Threats Sharing', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes"></span> <?php esc_html_e('Country Blocking', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes"></span> <?php esc_html_e('IP Whitelist', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes"></span> <?php esc_html_e('Rate Limiting', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes"></span> <?php esc_html_e('File Scanner', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes"></span> <?php esc_html_e('Malware Scanner', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes"></span> <?php esc_html_e('Scheduled Tasks', 'vietshield-waf'); ?></li>
                            <?php if (isset($vswaf_webserver) && $vswaf_webserver !== 'apache'): ?>
                            <li><span class="dashicons dashicons-yes"></span> <?php esc_html_e('Early Blocking (.user.ini)', 'vietshield-waf'); ?></li>
                            <?php else: ?>
                            <li><span class="dashicons dashicons-yes"></span> <?php esc_html_e('Early Blocking (.htaccess)', 'vietshield-waf'); ?></li>
                            <?php endif; ?>
                        </ul>
                    </div>
                </div>
                
                <div class="wizard-actions">
                    <button type="button" class="button wizard-prev" data-step="3">
                        <span class="dashicons dashicons-arrow-left-alt"></span>
                        <?php esc_html_e('Back', 'vietshield-waf'); ?>
                    </button>
                    <button type="button" class="button button-primary wizard-complete" data-step="3">
                        <span class="dashicons dashicons-yes"></span>
                        <?php esc_html_e('Complete Setup', 'vietshield-waf'); ?>
                    </button>
                </div>
            </div>
        <?php endif; ?>
    </div>
</div>

<script>
var vswafWizardData = {
    webserver: '<?php echo esc_js($vswaf_webserver); ?>',
    configMethod: '<?php echo esc_js($vswaf_config_method); ?>'
};
</script>


