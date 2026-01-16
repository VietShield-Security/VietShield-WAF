<?php
if (!defined('ABSPATH')) {
    exit;
}

$current_step = isset($current_step) ? $current_step : 1;
$webserver = isset($webserver) ? $webserver : 'apache';
$config_method = $this->get_webserver_config_method($webserver);
$total_steps = 3;
?>
<div class="wrap vietshield-wizard-wrap">
    <div class="wizard-header">
        <div class="wizard-logo">
            <span class="dashicons dashicons-shield-alt"></span>
            <h1><?php _e('VietShield WAF Setup Wizard', 'vietshield-waf'); ?> <span style="font-size: 13px; color: #666; font-weight: 400; margin-left: 8px;">v<?php echo VIETSHIELD_VERSION; ?></span></h1>
        </div>
        <div class="wizard-progress">
            <div class="progress-bar">
                <div class="progress-fill" style="width: <?php echo ($current_step / $total_steps) * 100; ?>%"></div>
            </div>
            <div class="progress-text">
                <?php printf(__('Step %d of %d', 'vietshield-waf'), $current_step, $total_steps); ?>
            </div>
        </div>
    </div>

    <div class="wizard-content">
        <?php if ($current_step == 1): ?>
            <!-- Step 1: Web Server Detection -->
            <div class="wizard-step">
                <h2><?php _e('Web Server Detection', 'vietshield-waf'); ?></h2>
                <p class="wizard-description">
                    <?php _e('We\'ve automatically detected your web server configuration. This helps us optimize the firewall settings for your environment.', 'vietshield-waf'); ?>
                </p>
                
                <div class="wizard-card">
                    <div class="detection-result">
                        <div class="detection-icon">
                            <?php if ($webserver === 'apache'): ?>
                                <span class="dashicons dashicons-admin-tools"></span>
                            <?php elseif ($webserver === 'nginx'): ?>
                                <span class="dashicons dashicons-networking"></span>
                            <?php else: ?>
                                <span class="dashicons dashicons-admin-settings"></span>
                            <?php endif; ?>
                        </div>
                        <div class="detection-info">
                            <h3><?php _e('Detected Configuration', 'vietshield-waf'); ?></h3>
                            <p class="server-type">
                                <strong><?php _e('Server Type:', 'vietshield-waf'); ?></strong>
                                <?php
                                $server_names = [
                                    'apache' => 'Apache',
                                    'apache-fpm' => 'Apache with PHP-FPM',
                                    'nginx' => 'Nginx',
                                    'php-fpm' => 'PHP-FPM'
                                ];
                                echo esc_html($server_names[$webserver] ?? 'Apache');
                                ?>
                            </p>
                            <p class="config-method">
                                <strong><?php _e('Configuration Method:', 'vietshield-waf'); ?></strong>
                                <code><?php echo esc_html($config_method); ?></code>
                            </p>
                            <p class="description">
                                <?php
                                if ($config_method === '.user.ini') {
                                    _e('Your server uses PHP-FPM, so we\'ll configure early blocking using .user.ini file.', 'vietshield-waf');
                                } else {
                                    _e('Your server uses Apache, so we\'ll configure early blocking using .htaccess file.', 'vietshield-waf');
                                }
                                ?>
                            </p>
                        </div>
                    </div>
                </div>
                
                <div class="wizard-actions">
                    <button type="button" class="button button-primary wizard-next" data-step="1">
                        <?php _e('Continue', 'vietshield-waf'); ?>
                        <span class="dashicons dashicons-arrow-right-alt"></span>
                    </button>
                </div>
            </div>

        <?php elseif ($current_step == 2): ?>
            <!-- Step 2: Firewall Mode -->
            <div class="wizard-step">
                <h2><?php _e('Choose Firewall Mode', 'vietshield-waf'); ?></h2>
                <p class="wizard-description">
                    <?php _e('Select how you want the firewall to operate. We recommend Block Mode for maximum protection.', 'vietshield-waf'); ?>
                </p>
                
                <div class="wizard-options">
                    <div class="option-card recommended" data-value="protecting">
                        <div class="option-header">
                            <input type="radio" name="firewall_mode" value="protecting" id="mode-protecting" checked>
                            <label for="mode-protecting">
                                <span class="option-title"><?php _e('Protecting Mode - Block threats and Logging (Recommended)', 'vietshield-waf'); ?></span>
                                <span class="option-badge"><?php _e('Recommended', 'vietshield-waf'); ?></span>
                            </label>
                        </div>
                        <div class="option-content">
                            <p><?php _e('Blocks malicious requests immediately and provides the highest level of protection.', 'vietshield-waf'); ?></p>
                            <ul>
                                <li><?php _e('Block threats before WordPress loads', 'vietshield-waf'); ?></li>
                                <li><?php _e('Real-time threat detection and logging', 'vietshield-waf'); ?></li>
                                <li><?php _e('Maximum performance optimization', 'vietshield-waf'); ?></li>
                            </ul>
                        </div>
                    </div>
                    
                    <div class="option-card" data-value="learning">
                        <div class="option-header">
                            <input type="radio" name="firewall_mode" value="learning" id="mode-learning">
                            <label for="mode-learning">
                                <span class="option-title"><?php _e('Learning Mode - Log only, no blocking', 'vietshield-waf'); ?></span>
                            </label>
                        </div>
                        <div class="option-content">
                            <p><?php _e('Monitors and logs threats without blocking. Useful for testing.', 'vietshield-waf'); ?></p>
                            <ul>
                                <li><?php _e('Logs all threats for analysis', 'vietshield-waf'); ?></li>
                                <li><?php _e('No blocking of requests', 'vietshield-waf'); ?></li>
                                <li><?php _e('Safe for testing environments', 'vietshield-waf'); ?></li>
                            </ul>
                        </div>
                    </div>
                </div>
                
                <div class="wizard-actions">
                    <button type="button" class="button wizard-prev" data-step="2">
                        <span class="dashicons dashicons-arrow-left-alt"></span>
                        <?php _e('Back', 'vietshield-waf'); ?>
                    </button>
                    <button type="button" class="button button-primary wizard-next" data-step="2">
                        <?php _e('Continue', 'vietshield-waf'); ?>
                        <span class="dashicons dashicons-arrow-right-alt"></span>
                    </button>
                </div>
            </div>

        <?php elseif ($current_step == 3): ?>
            <!-- Step 3: Auto-Optimize -->
            <div class="wizard-step">
                <h2><?php _e('Auto-Optimize Settings', 'vietshield-waf'); ?></h2>
                <p class="wizard-description">
                    <?php _e('We can automatically configure all recommended security features for you. This is the fastest way to get started.', 'vietshield-waf'); ?>
                </p>
                
                <div class="wizard-card">
                    <div class="optimize-option">
                        <label>
                            <input type="checkbox" name="auto_optimize" value="1" checked>
                            <span class="checkbox-label">
                                <strong><?php _e('Enable Auto-Optimization', 'vietshield-waf'); ?></strong>
                                <span class="description"><?php _e('Automatically configure all recommended security features', 'vietshield-waf'); ?></span>
                            </span>
                        </label>
                    </div>
                    
                    <div class="optimize-features" id="optimize-features">
                        <h3><?php _e('Features that will be enabled:', 'vietshield-waf'); ?></h3>
                        <ul>
                            <li><span class="dashicons dashicons-yes"></span> <?php _e('WAF Engine', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes"></span> <?php _e('Login Security & Brute Force Protection', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes"></span> <?php _e('Threat Intelligence', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes"></span> <?php _e('Threats Sharing', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes"></span> <?php _e('Country Blocking', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes"></span> <?php _e('IP Whitelist', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes"></span> <?php _e('Rate Limiting', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes"></span> <?php _e('File Scanner', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes"></span> <?php _e('Malware Scanner', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes"></span> <?php _e('Scheduled Tasks', 'vietshield-waf'); ?></li>
                            <?php if (isset($webserver) && $webserver !== 'apache'): ?>
                            <li><span class="dashicons dashicons-yes"></span> <?php _e('Early Blocking (.user.ini)', 'vietshield-waf'); ?></li>
                            <?php else: ?>
                            <li><span class="dashicons dashicons-yes"></span> <?php _e('Early Blocking (.htaccess)', 'vietshield-waf'); ?></li>
                            <?php endif; ?>
                        </ul>
                    </div>
                </div>
                
                <div class="wizard-actions">
                    <button type="button" class="button wizard-prev" data-step="3">
                        <span class="dashicons dashicons-arrow-left-alt"></span>
                        <?php _e('Back', 'vietshield-waf'); ?>
                    </button>
                    <button type="button" class="button button-primary wizard-complete" data-step="3">
                        <span class="dashicons dashicons-yes"></span>
                        <?php _e('Complete Setup', 'vietshield-waf'); ?>
                    </button>
                </div>
            </div>
        <?php endif; ?>
    </div>
</div>

<script>
jQuery(document).ready(function($) {
    var currentStep = <?php echo $current_step; ?>;
    var wizardData = {
        webserver: '<?php echo esc_js($webserver); ?>',
        config_method: '<?php echo esc_js($config_method); ?>'
    };
    
    // Save step data
    function saveStep(step, data) {
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'vietshield_wizard_save',
                nonce: '<?php echo wp_create_nonce('vietshield_wizard'); ?>',
                step: step,
                data: data
            }
        });
    }
    
    // Next button
    $('.wizard-next').on('click', function() {
        var step = parseInt($(this).data('step'));
        var data = {};
        
        if (step === 1) {
            // Step 1: Web server (already detected)
            saveStep(1, wizardData);
            window.location.href = '<?php echo admin_url('admin.php?page=vietshield-wizard&step=2'); ?>';
        } else if (step === 2) {
            // Step 2: Firewall mode
            var firewallMode = $('input[name="firewall_mode"]:checked').val();
            // Map old values for backward compatibility
            if (firewallMode === 'extended') {
                firewallMode = 'protecting';
            }
            data.firewall_mode = firewallMode;
            saveStep(2, data);
            window.location.href = '<?php echo admin_url('admin.php?page=vietshield-wizard&step=3'); ?>';
        }
    });
    
    // Previous button
    $('.wizard-prev').on('click', function() {
        var step = parseInt($(this).data('step'));
        if (step === 2) {
            window.location.href = '<?php echo admin_url('admin.php?page=vietshield-wizard&step=1'); ?>';
        } else if (step === 3) {
            window.location.href = '<?php echo admin_url('admin.php?page=vietshield-wizard&step=2'); ?>';
        }
    });
    
    // Complete wizard
    $('.wizard-complete').on('click', function() {
        var firewallMode = $('input[name="firewall_mode"]:checked').val() || 'protecting';
        // Map old values for backward compatibility
        if (firewallMode === 'extended') {
            firewallMode = 'protecting';
        }
        var data = {
            firewall_mode: firewallMode,
            auto_optimize: $('input[name="auto_optimize"]:checked').length > 0 ? 1 : 0,
            webserver: wizardData.webserver
        };
        
        $(this).prop('disabled', true).text('<?php _e('Setting up...', 'vietshield-waf'); ?>');
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'vietshield_wizard_complete',
                nonce: '<?php echo wp_create_nonce('vietshield_wizard'); ?>',
                data: data
            },
            success: function(response) {
                if (response.success) {
                    window.location.href = response.data.redirect;
                } else {
                    alert(response.data.message || '<?php _e('An error occurred', 'vietshield-waf'); ?>');
                    $('.wizard-complete').prop('disabled', false);
                }
            },
            error: function() {
                alert('<?php _e('An error occurred', 'vietshield-waf'); ?>');
                $('.wizard-complete').prop('disabled', false);
            }
        });
    });
    
    // Option card selection
    $('.option-card').on('click', function() {
        $('.option-card').removeClass('selected');
        $(this).addClass('selected');
        $(this).find('input[type="radio"]').prop('checked', true);
    });
    
    // Auto-optimize checkbox
    $('input[name="auto_optimize"]').on('change', function() {
        if ($(this).is(':checked')) {
            $('#optimize-features').slideDown();
        } else {
            $('#optimize-features').slideUp();
        }
    });
});
</script>
