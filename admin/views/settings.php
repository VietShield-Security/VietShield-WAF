<?php
if (!defined('ABSPATH')) {
    exit;
}

$options = get_option('vietshield_options', []);

// Auto-set defaults for new options in existing installations
$needs_update = false;
if (!isset($options['whitelist_googlebot'])) {
    $options['whitelist_googlebot'] = true;
    $needs_update = true;
}
if (!isset($options['block_bad_useragents'])) {
    $options['block_bad_useragents'] = true;
    $needs_update = true;
}
if (!isset($options['block_empty_useragent'])) {
    $options['block_empty_useragent'] = true;
    $needs_update = true;
}
if (!isset($options['advanced_injection_detection'])) {
    $options['advanced_injection_detection'] = true;
    $needs_update = true;
}
if ($needs_update) {
    update_option('vietshield_options', $options);
}
?>
<div class="wrap vietshield-wrap">
    <div class="vietshield-header">
        <div class="vietshield-logo">
            <span class="dashicons dashicons-shield"></span>
            <h1><?php _e('VietShield WAF Settings', 'vietshield-waf'); ?> <span style="font-size: 13px; color: #666; font-weight: 400; margin-left: 8px;">v<?php echo VIETSHIELD_VERSION; ?></span></h1>
        </div>
        <div class="vietshield-header-actions">
            <button type="submit" form="vietshield-settings-form" class="button button-primary">
                <span class="dashicons dashicons-yes"></span>
                <?php _e('Save Settings', 'vietshield-waf'); ?>
            </button>
        </div>
    </div>

    <form method="post" action="options.php" class="vietshield-settings-form" id="vietshield-settings-form">
        <?php settings_fields('vietshield_options'); ?>
        
        <!-- General Settings -->
        <div class="vietshield-card">
            <div class="card-header">
                <h2>
                    <span class="dashicons dashicons-admin-generic"></span>
                    <?php _e('General Settings', 'vietshield-waf'); ?>
                </h2>
            </div>
            <div class="card-body">
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Enable WAF', 'vietshield-waf'); ?></th>
                        <td>
                            <label class="vietshield-switch">
                                <input type="checkbox" name="vietshield_options[waf_enabled]" value="1" 
                                       <?php checked($options['waf_enabled'] ?? true); ?>
                                       id="waf-enabled-toggle" class="waf-main-toggle">
                                <span class="slider"></span>
                            </label>
                            <p class="description">
                                <?php _e('Enable or disable the Web Application Firewall. When disabled, all WAF features including logging and blocking will be inactive.', 'vietshield-waf'); ?>
                            </p>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        <!-- WAF Settings (Hidden when WAF is disabled) -->
        <div id="waf-settings-container" style="<?php echo empty($options['waf_enabled']) ? 'display: none;' : ''; ?>">
        <div class="vietshield-card">
            <div class="card-header">
                <h2>
                    <span class="dashicons dashicons-shield-alt"></span>
                    <?php _e('Firewall Mode', 'vietshield-waf'); ?>
                </h2>
            </div>
            <div class="card-body">
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Firewall Mode', 'vietshield-waf'); ?></th>
                        <td>
                            <?php
                            // Detect web server for dynamic description
                            require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-early-blocker.php';
                            $early_blocker = new \VietShield\Firewall\EarlyBlocker();
                            $reflection = new ReflectionClass($early_blocker);
                            $method = $reflection->getMethod('detect_web_server');
                            $method->setAccessible(true);
                            $web_server = $method->invoke($early_blocker);
                            
                            $server_names = [
                                'apache' => 'Apache',
                                'nginx' => 'Nginx',
                                'php-fpm' => 'PHP-FPM',
                            ];
                            $server_name = $server_names[$web_server] ?? ucfirst($web_server);
                            
                            // Determine early blocking method description
                            $early_blocking_desc = '';
                            if ($web_server === 'apache') {
                                $early_blocking_desc = __('Block via .htaccess/.user.ini (recommended)', 'vietshield-waf');
                            } elseif ($web_server === 'nginx') {
                                $early_blocking_desc = __('Block via .user.ini (recommended)', 'vietshield-waf');
                            } else {
                                $early_blocking_desc = __('Block via .user.ini (recommended)', 'vietshield-waf');
                            }
                            ?>
                            <select name="vietshield_options[firewall_mode]" class="regular-text" id="firewall-mode-select">
                                <option value="learning" <?php selected($options['firewall_mode'] ?? 'protecting', 'learning'); ?>>
                                    <?php _e('Learning Mode - Log only, no blocking', 'vietshield-waf'); ?>
                                </option>
                                <option value="protecting" <?php selected($options['firewall_mode'] ?? 'protecting', 'protecting'); ?>>
                                    <?php _e('Protecting Mode - Block threats and Logging', 'vietshield-waf'); ?>
                                </option>
                            </select>
                            <p class="description">
                                <?php 
                                printf(
                                    __('Detected web server: <strong>%s</strong>. Protecting Mode blocks threats before WordPress loads for maximum performance.', 'vietshield-waf'),
                                    esc_html($server_name)
                                );
                                ?>
                            </p>
                        </td>
                    </tr>
                    <?php
                    require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-early-blocker.php';
                    $early_blocker = new \VietShield\Firewall\EarlyBlocker();
                    $early_stats = $early_blocker->get_stats();
                    // Get firewall mode and early blocking status
                    $firewall_mode = $options['firewall_mode'] ?? 'protecting';
                    $early_blocking_enabled = $options['early_blocking_enabled'] ?? ($firewall_mode === 'protecting');
                    ?>
                    <tr>
                        <th scope="row"><?php _e('Status', 'vietshield-waf'); ?></th>
                        <td>
                            <div id="early-blocking-status">
                                <?php if ($early_blocking_enabled): ?>
                                    <p style="margin-top: 0;">
                                        <strong><?php _e('Web Server:', 'vietshield-waf'); ?></strong> 
                                        <?php 
                                        $server_names = [
                                            'apache' => 'Apache',
                                            'nginx' => 'Nginx',
                                            'php-fpm' => 'PHP-FPM',
                                        ];
                                        echo esc_html($server_names[$early_stats['web_server']] ?? ucfirst($early_stats['web_server']));
                                        ?>
                                    </p>
                                    <p>
                                        <strong><?php _e('Configuration:', 'vietshield-waf'); ?></strong>
                                        <ul style="list-style: disc; margin-left: 20px; margin-top: 5px;">
                                            <li>
                                                <?php if ($early_stats['user_ini_configured']): ?>
                                                    <span style="color: #46b450;">✓</span> 
                                                <?php else: ?>
                                                    <span style="color: #dc3232;">✗</span> 
                                                <?php endif; ?>
                                                .user.ini (PHP-FPM - works with Apache & Nginx)
                                            </li>
                                            <?php if ($early_stats['web_server'] === 'apache'): ?>
                                            <li>
                                                <?php if ($early_stats['htaccess_configured']): ?>
                                                    <span style="color: #46b450;">✓</span> 
                                                <?php else: ?>
                                                    <span style="color: #dc3232;">✗</span> 
                                                <?php endif; ?>
                                                .htaccess (Apache only)
                                            </li>
                                            <?php endif; ?>
                                        </ul>
                                    </p>
                                    <p>
                                        <strong><?php _e('Files:', 'vietshield-waf'); ?></strong>
                                        <?php if ($early_stats['blocker_file_exists']): ?>
                                            <span style="color: #46b450;">✓</span> Blocker file
                                        <?php else: ?>
                                            <span style="color: #dc3232;">✗</span> Blocker file missing
                                        <?php endif; ?>
                                        <?php if ($early_stats['blocked_ips_file_exists']): ?>
                                            <span style="color: #46b450;">✓</span> IPs file
                                        <?php else: ?>
                                            <span style="color: #dc3232;">✗</span> IPs file missing
                                        <?php endif; ?>
                                    </p>
                                <?php else: ?>
                                    <p>
                                        <strong><?php _e('Status:', 'vietshield-waf'); ?></strong> 
                                        <span style="color: #dc3232;"><?php _e('Disabled', 'vietshield-waf'); ?></span>
                                    </p>
                                    <p class="description">
                                        <?php _e('Early blocking is disabled. Enable "Protecting Mode - Block threats and Logging" above to activate.', 'vietshield-waf'); ?>
                                    </p>
                                <?php endif; ?>
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Whitelist Admins', 'vietshield-waf'); ?></th>
                        <td>
                            <label class="vietshield-switch">
                                <input type="checkbox" name="vietshield_options[whitelist_admins]" value="1" 
                                       <?php checked($options['whitelist_admins'] ?? true); ?>
                                       <?php echo empty($options['waf_enabled']) ? 'disabled' : ''; ?>
                                       class="waf-dependent"
                                       id="whitelist-admins-toggle">
                                <span class="slider"></span>
                            </label>
                            <p class="description"><?php _e('Automatically whitelist logged-in administrators.', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        <!-- Protection Settings -->
        <div class="vietshield-card">
            <div class="card-header">
                <h2>
                    <span class="dashicons dashicons-shield-alt"></span>
                    <?php _e('Protection Settings', 'vietshield-waf'); ?>
                </h2>
            </div>
            <div class="card-body">
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Block SQL Injection', 'vietshield-waf'); ?></th>
                        <td>
                            <label class="vietshield-switch">
                                <input type="checkbox" name="vietshield_options[block_sqli]" value="1" 
                                       <?php checked($options['block_sqli'] ?? true); ?>>
                                <span class="slider"></span>
                            </label>
                            <p class="description"><?php _e('Block SQL injection attacks including UNION SELECT, time-based, and error-based injection attempts.', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Block XSS Attacks', 'vietshield-waf'); ?></th>
                        <td>
                            <label class="vietshield-switch">
                                <input type="checkbox" name="vietshield_options[block_xss]" value="1" 
                                       <?php checked($options['block_xss'] ?? true); ?>>
                                <span class="slider"></span>
                            </label>
                            <p class="description"><?php _e('Block Cross-Site Scripting attacks including script injection, event handlers, and JavaScript protocol attacks.', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Block Remote Code Execution', 'vietshield-waf'); ?></th>
                        <td>
                            <label class="vietshield-switch">
                                <input type="checkbox" name="vietshield_options[block_rce]" value="1" 
                                       <?php checked($options['block_rce'] ?? true); ?>>
                                <span class="slider"></span>
                            </label>
                            <p class="description"><?php _e('Block remote code execution attempts including shell commands, PHP functions (eval, system), and reverse shells.', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Block Local File Inclusion', 'vietshield-waf'); ?></th>
                        <td>
                            <label class="vietshield-switch">
                                <input type="checkbox" name="vietshield_options[block_lfi]" value="1" 
                                       <?php checked($options['block_lfi'] ?? true); ?>>
                                <span class="slider"></span>
                            </label>
                            <p class="description"><?php _e('Block path traversal and local file inclusion attacks targeting /etc/passwd, wp-config.php, and PHP wrappers.', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Block Bad Bots', 'vietshield-waf'); ?></th>
                        <td>
                            <label class="vietshield-switch">
                                <input type="checkbox" name="vietshield_options[block_bad_bots]" value="1" 
                                       <?php checked($options['block_bad_bots'] ?? true); ?>>
                                <span class="slider"></span>
                            </label>
                            <p class="description"><?php _e('Block known malicious bots and vulnerability scanners using pattern matching rules.', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Block Malicious User-Agents', 'vietshield-waf'); ?></th>
                        <td>
                            <label class="vietshield-switch">
                                <input type="checkbox" name="vietshield_options[block_bad_useragents]" value="1" 
                                       <?php checked($options['block_bad_useragents'] ?? true); ?>>
                                <span class="slider"></span>
                            </label>
                            <p class="description"><?php _e('Block requests from security scanners (sqlmap, nikto, nuclei), recon services (shodan, censys), and automated tools (curl, wget, python-requests).', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Block Empty User-Agent', 'vietshield-waf'); ?></th>
                        <td>
                            <label class="vietshield-switch">
                                <input type="checkbox" name="vietshield_options[block_empty_useragent]" value="1" 
                                       <?php checked($options['block_empty_useragent'] ?? true); ?>>
                                <span class="slider"></span>
                            </label>
                            <p class="description"><?php _e('Block requests without a User-Agent header. Most bots and scanners don\'t send User-Agent.', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Advanced Injection Detection', 'vietshield-waf'); ?></th>
                        <td>
                            <label class="vietshield-switch">
                                <input type="checkbox" name="vietshield_options[advanced_injection_detection]" value="1" 
                                       <?php checked($options['advanced_injection_detection'] ?? true); ?>>
                                <span class="slider"></span>
                            </label>
                            <p class="description"><?php _e('Enhanced detection for command injection, OGNL injection, protocol smuggling, and advanced SQL/LFI attacks in POST, Cookies, and URL parameters.', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Block XML-RPC', 'vietshield-waf'); ?></th>
                        <td>
                            <label class="vietshield-switch">
                                <input type="checkbox" name="vietshield_options[block_xmlrpc]" value="1" 
                                       <?php checked($options['block_xmlrpc'] ?? false); ?>>
                                <span class="slider"></span>
                            </label>
                            <p class="description"><?php _e('Block all XML-RPC requests. Disable if you use mobile apps or Jetpack.', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Block Author Enumeration', 'vietshield-waf'); ?></th>
                        <td>
                            <label class="vietshield-switch">
                                <input type="checkbox" name="vietshield_options[block_author_scan]" value="1" 
                                       <?php checked($options['block_author_scan'] ?? true); ?>>
                                <span class="slider"></span>
                            </label>
                            <p class="description"><?php _e('Block attempts to enumerate users via ?author=N queries and REST API.', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        <!-- Login Security -->
        <div class="vietshield-card">
            <div class="card-header">
                <h2>
                    <span class="dashicons dashicons-lock"></span>
                    <?php _e('Login Security', 'vietshield-waf'); ?>
                </h2>
            </div>
            <div class="card-body">
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Enable Login Security', 'vietshield-waf'); ?></th>
                        <td>
                            <label class="vietshield-switch">
                                <input type="checkbox" name="vietshield_options[login_security_enabled]" value="1" 
                                       <?php checked($options['login_security_enabled'] ?? true); ?>>
                                <span class="slider"></span>
                            </label>
                            <p class="description"><?php _e('Protect WordPress login page from brute force attacks.', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Max Login Attempts', 'vietshield-waf'); ?></th>
                        <td>
                            <input type="number" name="vietshield_options[login_max_attempts]" 
                                   value="<?php echo esc_attr($options['login_max_attempts'] ?? 5); ?>" 
                                   class="small-text" min="1" max="20">
                            <span class="description"><?php _e('Maximum failed login attempts before blocking IP', 'vietshield-waf'); ?></span>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Time Window', 'vietshield-waf'); ?></th>
                        <td>
                            <input type="number" name="vietshield_options[login_time_window]" 
                                   value="<?php echo esc_attr($options['login_time_window'] ?? 900); ?>" 
                                   class="small-text" min="60" max="3600">
                            <span class="description"><?php _e('Time window in seconds to count attempts (default: 900 = 15 minutes)', 'vietshield-waf'); ?></span>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Lockout Duration', 'vietshield-waf'); ?></th>
                        <td>
                            <select name="vietshield_options[login_lockout_duration]">
                                <option value="300" <?php selected($options['login_lockout_duration'] ?? 900, 300); ?>>5 minutes</option>
                                <option value="900" <?php selected($options['login_lockout_duration'] ?? 900, 900); ?>>15 minutes</option>
                                <option value="1800" <?php selected($options['login_lockout_duration'] ?? 900, 1800); ?>>30 minutes</option>
                                <option value="3600" <?php selected($options['login_lockout_duration'] ?? 900, 3600); ?>>1 hour</option>
                                <option value="7200" <?php selected($options['login_lockout_duration'] ?? 900, 7200); ?>>2 hours</option>
                                <option value="86400" <?php selected($options['login_lockout_duration'] ?? 900, 86400); ?>>24 hours</option>
                            </select>
                            <p class="description"><?php _e('How long to block IP after max attempts reached', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Enable Honeypot', 'vietshield-waf'); ?></th>
                        <td>
                            <label class="vietshield-switch">
                                <input type="checkbox" name="vietshield_options[login_honeypot_enabled]" value="1" 
                                       <?php checked($options['login_honeypot_enabled'] ?? true); ?>>
                                <span class="slider"></span>
                            </label>
                            <p class="description"><?php _e('Add hidden honeypot field to catch bots', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Enable Email Notifications', 'vietshield-waf'); ?></th>
                        <td>
                            <label class="vietshield-switch">
                                <input type="checkbox" name="vietshield_options[login_notifications_enabled]" value="1" 
                                       <?php checked($options['login_notifications_enabled'] ?? false); ?>>
                                <span class="slider"></span>
                            </label>
                            <p class="description"><?php _e('Send email alerts for failed login attempts', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Notification Threshold', 'vietshield-waf'); ?></th>
                        <td>
                            <input type="number" name="vietshield_options[login_notification_threshold]" 
                                   value="<?php echo esc_attr($options['login_notification_threshold'] ?? 3); ?>" 
                                   class="small-text" min="1" max="10">
                            <span class="description"><?php _e('Send email after this many failed attempts', 'vietshield-waf'); ?></span>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        <!-- Scanner -->
        <div class="vietshield-card">
            <div class="card-header">
                <h2>
                    <span class="dashicons dashicons-search"></span>
                    <?php _e('Scanner', 'vietshield-waf'); ?>
                </h2>
            </div>
            <div class="card-body">
                <!-- WP Core Scanner -->
                <div style="margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid #ddd;">
                    <h3 style="margin-top: 0; margin-bottom: 15px; font-size: 16px; font-weight: 600;">
                        <span class="dashicons dashicons-admin-tools" style="font-size: 18px; vertical-align: middle;"></span>
                        <?php _e('WP Core Scanner', 'vietshield-waf'); ?>
                    </h3>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php _e('Enable WP Core Scanner', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="hidden" name="vietshield_options[file_scanner_enabled]" value="0">
                                    <input type="checkbox" name="vietshield_options[file_scanner_enabled]" value="1" 
                                           <?php checked($options['file_scanner_enabled'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php _e('Scan WordPress core files for modifications, missing files, and unknown files.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php _e('Scan Schedule', 'vietshield-waf'); ?></th>
                            <td>
                                <select name="vietshield_options[file_scan_schedule]">
                                    <option value="manual" <?php selected($options['file_scan_schedule'] ?? 'weekly', 'manual'); ?>>
                                        <?php _e('Manual Only', 'vietshield-waf'); ?>
                                    </option>
                                    <option value="daily" <?php selected($options['file_scan_schedule'] ?? 'weekly', 'daily'); ?>>
                                        <?php _e('Daily', 'vietshield-waf'); ?>
                                    </option>
                                    <option value="weekly" <?php selected($options['file_scan_schedule'] ?? 'weekly', 'weekly'); ?>>
                                        <?php _e('Weekly', 'vietshield-waf'); ?>
                                    </option>
                                </select>
                                <p class="description"><?php _e('Scheduled scans will run automatically based on this interval.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>

                <!-- Malware Scanner -->
                <div>
                    <h3 style="margin-top: 0; margin-bottom: 15px; font-size: 16px; font-weight: 600;">
                        <span class="dashicons dashicons-shield-alt" style="font-size: 18px; vertical-align: middle;"></span>
                        <?php _e('Malware Scanner', 'vietshield-waf'); ?>
                    </h3>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php _e('Enable Malware Scanner', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="hidden" name="vietshield_options[malware_scanner_enabled]" value="0">
                                    <input type="checkbox" name="vietshield_options[malware_scanner_enabled]" value="1" 
                                           <?php checked($options['malware_scanner_enabled'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php _e('Scan themes, plugins, and uploads for malware, backdoors, and suspicious code.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php _e('Scan Schedule', 'vietshield-waf'); ?></th>
                            <td>
                                <select name="vietshield_options[malware_scan_schedule]">
                                    <option value="manual" <?php selected($options['malware_scan_schedule'] ?? 'weekly', 'manual'); ?>>
                                        <?php _e('Manual Only', 'vietshield-waf'); ?>
                                    </option>
                                    <option value="daily" <?php selected($options['malware_scan_schedule'] ?? 'weekly', 'daily'); ?>>
                                        <?php _e('Daily', 'vietshield-waf'); ?>
                                    </option>
                                    <option value="weekly" <?php selected($options['malware_scan_schedule'] ?? 'weekly', 'weekly'); ?>>
                                        <?php _e('Weekly', 'vietshield-waf'); ?>
                                    </option>
                                </select>
                                <p class="description"><?php _e('Scheduled scans will run automatically based on this interval.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php _e('Scan Scope', 'vietshield-waf'); ?></th>
                            <td>
                                <select name="vietshield_options[malware_scan_scope]">
                                    <option value="all" <?php selected($options['malware_scan_scope'] ?? 'all', 'all'); ?>>
                                        <?php _e('All (Themes, Plugins, Uploads)', 'vietshield-waf'); ?>
                                    </option>
                                    <option value="themes" <?php selected($options['malware_scan_scope'] ?? 'all', 'themes'); ?>>
                                        <?php _e('Themes Only', 'vietshield-waf'); ?>
                                    </option>
                                    <option value="plugins" <?php selected($options['malware_scan_scope'] ?? 'all', 'plugins'); ?>>
                                        <?php _e('Plugins Only', 'vietshield-waf'); ?>
                                    </option>
                                    <option value="uploads" <?php selected($options['malware_scan_scope'] ?? 'all', 'uploads'); ?>>
                                        <?php _e('Uploads Only', 'vietshield-waf'); ?>
                                    </option>
                                </select>
                                <p class="description"><?php _e('Select which directories to scan for malware.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>

        <!-- Rate Limiting -->
        <div class="vietshield-card">
            <div class="card-header">
                <h2>
                    <span class="dashicons dashicons-clock"></span>
                    <?php _e('Rate Limiting', 'vietshield-waf'); ?>
                </h2>
            </div>
            <div class="card-body">
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Enable Rate Limiting', 'vietshield-waf'); ?></th>
                        <td>
                            <label class="vietshield-switch">
                                <input type="checkbox" name="vietshield_options[rate_limiting_enabled]" value="1" 
                                       <?php checked($options['rate_limiting_enabled'] ?? true); ?>>
                                <span class="slider"></span>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Global Rate Limit', 'vietshield-waf'); ?></th>
                        <td>
                            <input type="number" name="vietshield_options[rate_limit_global]" 
                                   value="<?php echo esc_attr($options['rate_limit_global'] ?? 100); ?>" 
                                   class="small-text" min="10" max="1000">
                            <span class="description"><?php _e('requests per minute', 'vietshield-waf'); ?></span>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Login Rate Limit', 'vietshield-waf'); ?></th>
                        <td>
                            <input type="number" name="vietshield_options[rate_limit_login]" 
                                   value="<?php echo esc_attr($options['rate_limit_login'] ?? 20); ?>" 
                                   class="small-text" min="1" max="100">
                            <span class="description"><?php _e('attempts per 5 minutes', 'vietshield-waf'); ?></span>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('XML-RPC Rate Limit', 'vietshield-waf'); ?></th>
                        <td>
                            <input type="number" name="vietshield_options[rate_limit_xmlrpc]" 
                                   value="<?php echo esc_attr($options['rate_limit_xmlrpc'] ?? 20); ?>" 
                                   class="small-text" min="1" max="100">
                            <span class="description"><?php _e('requests per minute', 'vietshield-waf'); ?></span>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        <!-- Auto Block -->
        <div class="vietshield-card">
            <div class="card-header">
                <h2>
                    <span class="dashicons dashicons-dismiss"></span>
                    <?php _e('Auto Block', 'vietshield-waf'); ?>
                </h2>
            </div>
            <div class="card-body">
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Auto Block Threshold', 'vietshield-waf'); ?></th>
                        <td>
                            <input type="number" name="vietshield_options[auto_block_threshold]" 
                                   value="<?php echo esc_attr($options['auto_block_threshold'] ?? 10); ?>" 
                                   class="small-text" min="0" max="100">
                            <span class="description"><?php _e('blocked requests before auto-blocking IP (0 to disable)', 'vietshield-waf'); ?></span>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Auto Block Duration', 'vietshield-waf'); ?></th>
                        <td>
                            <select name="vietshield_options[auto_block_duration]">
                                <option value="3600" <?php selected($options['auto_block_duration'] ?? 3600, 3600); ?>>1 hour</option>
                                <option value="7200" <?php selected($options['auto_block_duration'] ?? 3600, 7200); ?>>2 hours</option>
                                <option value="21600" <?php selected($options['auto_block_duration'] ?? 3600, 21600); ?>>6 hours</option>
                                <option value="43200" <?php selected($options['auto_block_duration'] ?? 3600, 43200); ?>>12 hours</option>
                                <option value="86400" <?php selected($options['auto_block_duration'] ?? 3600, 86400); ?>>24 hours</option>
                                <option value="604800" <?php selected($options['auto_block_duration'] ?? 3600, 604800); ?>>7 days</option>
                            </select>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        <!-- Logging -->
        <div class="vietshield-card">
            <div class="card-header">
                <h2>
                    <span class="dashicons dashicons-media-text"></span>
                    <?php _e('Logging', 'vietshield-waf'); ?>
                </h2>
            </div>
            <div class="card-body">
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Log All Traffic', 'vietshield-waf'); ?></th>
                        <td>
                            <label class="vietshield-switch">
                                <input type="checkbox" name="vietshield_options[log_all_traffic]" value="1" 
                                       <?php checked($options['log_all_traffic'] ?? false); ?>>
                                <span class="slider"></span>
                            </label>
                            <p class="description"><?php _e('Log all requests, not just blocked ones. May increase database size.', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Log Retention', 'vietshield-waf'); ?></th>
                        <td>
                            <input type="number" name="vietshield_options[log_retention_days]" 
                                   value="<?php echo esc_attr($options['log_retention_days'] ?? 30); ?>" 
                                   class="small-text" min="1" max="365">
                            <span class="description"><?php _e('days to keep logs', 'vietshield-waf'); ?></span>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Log Timezone', 'vietshield-waf'); ?></th>
                        <td>
                            <?php
                            require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
                            $timezone_groups = VietShield_Helpers::get_timezone_groups();
                            $current_timezone = $options['log_timezone'] ?? get_option('timezone_string') ?: 'UTC';
                            ?>
                            <select name="vietshield_options[log_timezone]" class="regular-text">
                                <?php foreach ($timezone_groups as $region => $zones): ?>
                                    <?php if (!empty($zones)): ?>
                                        <optgroup label="<?php echo esc_attr($region); ?>">
                                            <?php foreach ($zones as $tz => $label): ?>
                                                <option value="<?php echo esc_attr($tz); ?>" 
                                                        <?php selected($current_timezone, $tz); ?>>
                                                    <?php echo esc_html($label); ?>
                                                </option>
                                            <?php endforeach; ?>
                                        </optgroup>
                                    <?php endif; ?>
                                <?php endforeach; ?>
                            </select>
                            <p class="description">
                                <?php _e('Timezone for log timestamps. Current server time:', 'vietshield-waf'); ?>
                                <strong><?php echo date('Y-m-d H:i:s T'); ?></strong>
                            </p>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        <!-- Country Blocking -->
        <div class="vietshield-card">
            <div class="card-header">
                <h2>
                    <span class="dashicons dashicons-admin-site-alt"></span>
                    <?php _e('Country Blocking', 'vietshield-waf'); ?>
                </h2>
            </div>
            <div class="card-body">
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Enable Country Blocking', 'vietshield-waf'); ?></th>
                        <td>
                            <label class="vietshield-switch">
                                <input type="checkbox" name="vietshield_options[country_blocking_enabled]" value="1" 
                                       <?php checked($options['country_blocking_enabled'] ?? false); ?>>
                                <span class="slider"></span>
                            </label>
                            <p class="description"><?php _e('Block requests from specific countries based on IP geolocation.', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Block Unknown Countries', 'vietshield-waf'); ?></th>
                        <td>
                            <label class="vietshield-switch">
                                <input type="checkbox" name="vietshield_options[block_unknown_countries]" value="1" 
                                       <?php checked($options['block_unknown_countries'] ?? false); ?>>
                                <span class="slider"></span>
                            </label>
                            <p class="description"><?php _e('Block requests when country cannot be determined.', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Blocked Countries', 'vietshield-waf'); ?></th>
                        <td>
                            <?php
                            require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-country-blocker.php';
                            $country_blocker = new \VietShield\Firewall\CountryBlocker();
                            $countries = $country_blocker->get_countries_list();
                            $blocked_countries = $options['blocked_countries'] ?? [];
                            ?>
                            <div style="max-height: 300px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; border-radius: 4px; background: #f9f9f9;">
                                <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 8px;">
                                    <?php foreach ($countries as $code => $name): ?>
                                        <label style="display: flex; align-items: center; gap: 6px; font-size: 13px;">
                                            <input type="checkbox" 
                                                   name="vietshield_options[blocked_countries][]" 
                                                   value="<?php echo esc_attr($code); ?>"
                                                   <?php checked(in_array($code, $blocked_countries)); ?>>
                                            <span><?php echo esc_html($name); ?> (<?php echo esc_html($code); ?>)</span>
                                        </label>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                            <p class="description"><?php _e('Select countries to block. Use Ctrl/Cmd+Click to select multiple.', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        <!-- Threat Intelligence -->
        <div class="vietshield-card">
            <div class="card-header">
                <h2>
                    <span class="dashicons dashicons-shield"></span>
                    <?php _e('Threat Intelligence', 'vietshield-waf'); ?>
                </h2>
            </div>
            <div class="card-body">
                <?php
                require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-threat-intelligence.php';
                $threat_intel = new \VietShield\Firewall\ThreatIntelligence();
                $sync_status = $threat_intel->get_sync_status();
                $is_syncing = get_transient('vietshield_threat_intel_syncing');
                ?>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Enable Threat Intelligence', 'vietshield-waf'); ?></th>
                        <td>
                            <label class="vietshield-switch">
                                <input type="checkbox" name="vietshield_options[threat_intel_enabled]" value="1" 
                                       <?php checked($options['threat_intel_enabled'] ?? false); ?>
                                       id="threat-intel-enabled">
                                <span class="slider"></span>
                            </label>
                            <p class="description"><?php _e('Automatically block IPs from VietShield Threat Intelligence feed.', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Feed Category', 'vietshield-waf'); ?></th>
                        <td>
                            <select name="vietshield_options[threat_intel_category]" 
                                    id="threat-intel-category" 
                                    class="regular-text"
                                    <?php disabled($is_syncing); ?>>
                                <option value=""><?php _e('-- Select Category --', 'vietshield-waf'); ?></option>
                                <option value="1d" <?php selected($options['threat_intel_category'] ?? '', '1d'); ?>>
                                    <?php _e('1 Day (Most Recent Threats)', 'vietshield-waf'); ?>
                                </option>
                                <option value="3d" <?php selected($options['threat_intel_category'] ?? '', '3d'); ?>>
                                    <?php _e('3 Days', 'vietshield-waf'); ?>
                                </option>
                                <option value="7d" <?php selected($options['threat_intel_category'] ?? '', '7d'); ?>>
                                    <?php _e('7 Days', 'vietshield-waf'); ?>
                                </option>
                                <option value="14d" <?php selected($options['threat_intel_category'] ?? '', '14d'); ?>>
                                    <?php _e('14 Days', 'vietshield-waf'); ?>
                                </option>
                                <option value="30d" <?php selected($options['threat_intel_category'] ?? '', '30d'); ?>>
                                    <?php _e('30 Days (Largest List)', 'vietshield-waf'); ?>
                                </option>
                            </select>
                            <p class="description">
                                <?php _e('Select threat intelligence feed category. Only one category can be active at a time.', 'vietshield-waf'); ?>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Sync Status', 'vietshield-waf'); ?></th>
                        <td>
                            <div id="threat-intel-status">
                                <?php if ($sync_status['count'] > 0): ?>
                                    <p>
                                        <strong><?php _e('IPs in Database:', 'vietshield-waf'); ?></strong> 
                                        <?php echo number_format($sync_status['count']); ?>
                                    </p>
                                    <?php if ($sync_status['last_sync']): ?>
                                        <p>
                                            <strong><?php _e('Last Sync:', 'vietshield-waf'); ?></strong> 
                                            <?php 
                                            require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
                                            echo esc_html(\VietShield_Helpers::format_timestamp($sync_status['last_sync'], 'Y-m-d H:i:s'));
                                            ?>
                                        </p>
                                    <?php endif; ?>
                                    <?php if ($sync_status['category']): ?>
                                        <p>
                                            <strong><?php _e('Category:', 'vietshield-waf'); ?></strong> 
                                            <?php echo esc_html(strtoupper($sync_status['category'])); ?>
                                        </p>
                                    <?php endif; ?>
                                    <?php if (!empty($sync_status['next_sync'])): ?>
                                        <p>
                                            <strong><?php _e('Next Auto-Sync:', 'vietshield-waf'); ?></strong> 
                                            <?php 
                                            require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
                                            echo esc_html(\VietShield_Helpers::format_timestamp($sync_status['next_sync'], 'Y-m-d H:i:s'));
                                            ?>
                                        </p>
                                    <?php endif; ?>
                                <?php else: ?>
                                    <p class="description"><?php _e('No threat intelligence data synced yet.', 'vietshield-waf'); ?></p>
                                <?php endif; ?>
                            </div>
                            <p>
                                <button type="button" 
                                        id="threat-intel-sync-btn" 
                                        class="button button-secondary"
                                        <?php disabled($is_syncing); ?>>
                                    <span class="dashicons dashicons-update"></span>
                                    <?php _e('Sync Now', 'vietshield-waf'); ?>
                                </button>
                                <button type="button" 
                                        id="threat-intel-clear-btn" 
                                        class="button button-secondary"
                                        <?php disabled($is_syncing); ?>
                                        style="<?php echo $sync_status['count'] > 0 ? '' : 'display:none;'; ?>">
                                    <span class="dashicons dashicons-trash"></span>
                                    <?php _e('Clear Data', 'vietshield-waf'); ?>
                                </button>
                            </p>
                            <?php if ($is_syncing): ?>
                            <p class="description" style="color: #f59e0b;">
                                <span class="dashicons dashicons-update spin"></span>
                                <?php _e('Sync in progress... Please wait.', 'vietshield-waf'); ?>
                            </p>
                            <?php endif; ?>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        <!-- Threats Sharing -->
        <div class="vietshield-card">
            <div class="card-header">
                <h2>
                    <span class="dashicons dashicons-share"></span>
                    <?php _e('Threats Sharing', 'vietshield-waf'); ?>
                </h2>
            </div>
            <div class="card-body">
                <?php
                require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-threats-sharing.php';
                $threats_stats = \VietShield\Firewall\ThreatsSharing::get_stats();
                $next_submit = wp_next_scheduled('vietshield_submit_threats');
                ?>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Status', 'vietshield-waf'); ?></th>
                        <td>
                            <p>
                                <strong style="color: #46b450;"><?php _e('Always Enabled', 'vietshield-waf'); ?></strong>
                                <span class="description"><?php _e('This feature cannot be disabled. Blocked IPs are automatically shared with the VietShield Intelligence community to help protect other websites.', 'vietshield-waf'); ?></span>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Queue Statistics', 'vietshield-waf'); ?></th>
                        <td>
                            <ul style="list-style: disc; margin-left: 20px;">
                                <li>
                                    <strong><?php _e('Pending:', 'vietshield-waf'); ?></strong> 
                                    <?php echo number_format($threats_stats['pending']); ?>
                                    <span class="description"><?php _e('IPs waiting to be submitted', 'vietshield-waf'); ?></span>
                                </li>
                                <li>
                                    <strong><?php _e('Submitted:', 'vietshield-waf'); ?></strong> 
                                    <?php echo number_format($threats_stats['submitted']); ?>
                                    <span class="description"><?php _e('IPs successfully shared', 'vietshield-waf'); ?></span>
                                </li>
                                <?php if ($threats_stats['failed'] > 0): ?>
                                <li>
                                    <strong style="color: #dc3232;"><?php _e('Failed:', 'vietshield-waf'); ?></strong> 
                                    <?php echo number_format($threats_stats['failed']); ?>
                                    <span class="description"><?php _e('IPs that failed to submit (max retries reached)', 'vietshield-waf'); ?></span>
                                </li>
                                <?php endif; ?>
                                <?php if ($threats_stats['last_submission']): ?>
                                <li>
                                    <strong><?php _e('Last Submission:', 'vietshield-waf'); ?></strong> 
                                    <?php 
                                    require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
                                    echo esc_html(\VietShield_Helpers::format_timestamp($threats_stats['last_submission'], 'Y-m-d H:i:s'));
                                    ?>
                                </li>
                                <?php endif; ?>
                            </ul>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Auto-Submit Schedule', 'vietshield-waf'); ?></th>
                        <td>
                            <p>
                                <strong><?php _e('Next Submission:', 'vietshield-waf'); ?></strong> 
                                <?php 
                                if ($next_submit) {
                                    echo date('Y-m-d H:i:s', $next_submit);
                                } else {
                                    _e('Not scheduled', 'vietshield-waf');
                                }
                                ?>
                                <span class="description"> (<?php _e('Every 5 minutes', 'vietshield-waf'); ?>)</span>
                            </p>
                            <p class="description">
                                <?php _e('Blocked IPs are automatically queued and submitted to the Intelligence API every 5 minutes. This helps protect the entire community by sharing threat data.', 'vietshield-waf'); ?>
                            </p>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        <!-- Scheduled Tasks -->
        <div class="vietshield-card">
            <div class="card-header">
                <h2>
                    <span class="dashicons dashicons-clock"></span>
                    <?php _e('Scheduled Tasks', 'vietshield-waf'); ?>
                </h2>
            </div>
            <div class="card-body">
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Log Retention', 'vietshield-waf'); ?></th>
                        <td>
                            <input type="number" name="vietshield_options[log_retention_days]" 
                                   value="<?php echo esc_attr($options['log_retention_days'] ?? 30); ?>" 
                                   class="small-text" min="0" max="365">
                            <span class="description"><?php _e('days (0 = keep all logs)', 'vietshield-waf'); ?></span>
                            <p class="description"><?php _e('Old logs will be automatically deleted after this period. Logs older than this will be cleaned up daily.', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Scheduled Tasks Status', 'vietshield-waf'); ?></th>
                        <td>
                            <ul style="list-style: disc; margin-left: 20px;">
                                <li>
                                    <strong><?php _e('Log Cleanup:', 'vietshield-waf'); ?></strong> 
                                    <?php 
                                    $next_cleanup = wp_next_scheduled('vietshield_cleanup_logs');
                                    echo $next_cleanup ? date('Y-m-d H:i:s', $next_cleanup) : __('Not scheduled', 'vietshield-waf');
                                    ?>
                                    <span class="description"> (<?php _e('Daily', 'vietshield-waf'); ?>)</span>
                                </li>
                                <li>
                                    <strong><?php _e('Stats Aggregation:', 'vietshield-waf'); ?></strong> 
                                    <?php 
                                    $next_stats = wp_next_scheduled('vietshield_aggregate_stats');
                                    echo $next_stats ? date('Y-m-d H:i:s', $next_stats) : __('Not scheduled', 'vietshield-waf');
                                    ?>
                                    <span class="description"> (<?php _e('Hourly', 'vietshield-waf'); ?>)</span>
                                </li>
                                <li>
                                    <strong><?php _e('Maintenance:', 'vietshield-waf'); ?></strong> 
                                    <?php 
                                    $next_maintenance = wp_next_scheduled('vietshield_maintenance');
                                    echo $next_maintenance ? date('Y-m-d H:i:s', $next_maintenance) : __('Not scheduled', 'vietshield-waf');
                                    ?>
                                    <span class="description"> (<?php _e('Weekly', 'vietshield-waf'); ?>)</span>
                                </li>
                                <li>
                                    <strong><?php _e('Threats Sharing:', 'vietshield-waf'); ?></strong> 
                                    <?php 
                                    $next_threats = wp_next_scheduled('vietshield_submit_threats');
                                    echo $next_threats ? date('Y-m-d H:i:s', $next_threats) : __('Not scheduled', 'vietshield-waf');
                                    ?>
                                    <span class="description"> (<?php _e('Every 5 minutes', 'vietshield-waf'); ?>)</span>
                                </li>
                                <li>
                                    <strong><?php _e('Googlebot IP Whitelist:', 'vietshield-waf'); ?></strong> 
                                    <?php 
                                    $next_whitelist = wp_next_scheduled('vietshield_ip_whitelist_sync');
                                    echo $next_whitelist ? date('Y-m-d H:i:s', $next_whitelist) : __('Not scheduled', 'vietshield-waf');
                                    ?>
                                    <span class="description"> (<?php _e('Daily', 'vietshield-waf'); ?>)</span>
                                </li>
                            </ul>
                            <p class="description"><?php _e('These tasks run automatically to keep your site optimized and secure.', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        <!-- IP Whitelist -->
        <div class="vietshield-card">
            <div class="card-header">
                <h2>
                    <span class="dashicons dashicons-list-view"></span>
                    <?php _e('IP Whitelist', 'vietshield-waf'); ?>
                </h2>
            </div>
            <div class="card-body">
                <?php
                // Get auto-whitelist sync status
                require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-ip-whitelist-sync.php';
                $whitelist_status = \VietShield\Firewall\IPWhitelistSync::get_sync_status();
                ?>
                <h3 style="margin-top: 0; margin-bottom: 15px; font-size: 16px; font-weight: 600;">
                    <span class="dashicons dashicons-update" style="font-size: 18px; vertical-align: middle;"></span>
                    <?php _e('Auto-Whitelist Trusted Services', 'vietshield-waf'); ?>
                </h3>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Whitelist Googlebot', 'vietshield-waf'); ?></th>
                        <td>
                            <label class="vietshield-switch">
                                <input type="checkbox" name="vietshield_options[whitelist_googlebot]" value="1" 
                                       <?php checked($options['whitelist_googlebot'] ?? true); ?>>
                                <span class="slider"></span>
                            </label>
                            <p class="description">
                                <?php _e('Auto-whitelist Google crawler IP ranges (Googlebot, AdsBot, etc.). Updated daily from Google.', 'vietshield-waf'); ?>
                                <?php if ($whitelist_status['googlebot_count'] > 0): ?>
                                    <br><strong><?php printf(__('Currently whitelisted: %d IP ranges', 'vietshield-waf'), $whitelist_status['googlebot_count']); ?></strong>
                                <?php endif; ?>
                            </p>
                        </td>
                    </tr>

                    <tr>
                        <th scope="row"><?php _e('Sync Status', 'vietshield-waf'); ?></th>
                        <td>
                            <div id="ip-whitelist-status">
                                <?php if ($whitelist_status['last_sync']): ?>
                                    <p>
                                        <strong><?php _e('Last Sync:', 'vietshield-waf'); ?></strong> 
                                        <?php echo esc_html($whitelist_status['last_sync']); ?>
                                    </p>
                                    <p>
                                        <strong><?php _e('Googlebot:', 'vietshield-waf'); ?></strong> 
                                        <?php echo number_format($whitelist_status['googlebot_count']); ?> <?php _e('IP ranges', 'vietshield-waf'); ?>
                                    </p>
                                <?php else: ?>
                                    <p class="description"><?php _e('Not synced yet. Click "Sync Now" to fetch IP ranges.', 'vietshield-waf'); ?></p>
                                <?php endif; ?>
                            </div>
                            <button type="button" id="ip-whitelist-sync-btn" class="button button-secondary">
                                <span class="dashicons dashicons-update"></span>
                                <?php _e('Sync Now', 'vietshield-waf'); ?>
                            </button>
                        </td>
                    </tr>
                </table>
                
                <hr style="margin: 30px 0;">
                
                <h3 style="margin-top: 0; margin-bottom: 15px; font-size: 16px; font-weight: 600;">
                    <span class="dashicons dashicons-edit" style="font-size: 18px; vertical-align: middle;"></span>
                    <?php _e('Manual IP Lists', 'vietshield-waf'); ?>
                </h3>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Whitelisted IPs', 'vietshield-waf'); ?></th>
                        <td>
                            <textarea name="vietshield_options[whitelisted_ips]" rows="5" class="large-text code"><?php 
                                echo esc_textarea(implode("\n", $options['whitelisted_ips'] ?? [])); 
                            ?></textarea>
                            <p class="description"><?php _e('One IP per line. Supports CIDR notation (e.g., 192.168.1.0/24)', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Blacklisted IPs', 'vietshield-waf'); ?></th>
                        <td>
                            <textarea name="vietshield_options[blacklisted_ips]" rows="5" class="large-text code"><?php 
                                echo esc_textarea(implode("\n", $options['blacklisted_ips'] ?? [])); 
                            ?></textarea>
                            <p class="description"><?php _e('One IP per line. These IPs will be permanently blocked.', 'vietshield-waf'); ?></p>
                        </td>
                    </tr>
                </table>
            </div>
        </div>
        </div> <!-- End WAF Settings Container -->

        <?php submit_button(__('Save Settings', 'vietshield-waf'), 'primary', 'submit', true); ?>
    </form>
    
    <?php include VIETSHIELD_PLUGIN_DIR . 'admin/views/partials/footer.php'; ?>
</div>

<script>
jQuery(document).ready(function($) {
    // IP Whitelist Sync Button
    $('#ip-whitelist-sync-btn').on('click', function() {
        var $btn = $(this);
        var $status = $('#ip-whitelist-status');
        var originalText = $btn.html();
        
        $btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> Syncing...');
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'vietshield_sync_ip_whitelist',
                nonce: vietshieldAdmin.nonce
            },
            success: function(response) {
                if (response.success) {
                    var status = response.data.status;
                    var html = '<p><strong><?php _e('Last Sync:', 'vietshield-waf'); ?></strong> ' + status.last_sync + '</p>';
                    if (status.googlebot_count > 0) {
                        html += '<p>Googlebot: ' + status.googlebot_count + ' IP ranges</p>';
                    }
                    if (status.cloudflare_count > 0) {
                        html += '<p>Cloudflare: ' + status.cloudflare_count + ' IP ranges</p>';
                    }
                    $status.html(html);
                    alert('<?php _e('IP whitelist synced successfully!', 'vietshield-waf'); ?>');
                } else {
                    alert('<?php _e('Sync failed:', 'vietshield-waf'); ?> ' + response.data);
                }
            },
            error: function() {
                alert('<?php _e('An error occurred during sync.', 'vietshield-waf'); ?>');
            },
            complete: function() {
                $btn.prop('disabled', false).html(originalText);
            }
        });
    });
});
</script>
