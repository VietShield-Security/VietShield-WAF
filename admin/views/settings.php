<?php
if (!defined('ABSPATH')) {
    exit;
}

// Get options
$vswaf_options = get_option('vietshield_options', []);
$vswaf_needs_update = false;

// Initialize Early Blocker (logic only, no UI stats needed)
// Early Blocker is handled internally by the firewall based on settings

// Ensure default values for new options
if (!isset($vswaf_options['firewall_mode'])) {
    $vswaf_options['firewall_mode'] = 'protecting';
    $vswaf_needs_update = true;
}

if (!isset($vswaf_options['early_blocking_enabled'])) {
    $vswaf_options['early_blocking_enabled'] = false; 
    $vswaf_needs_update = true;
}

// Update options if needed
if ($vswaf_needs_update) {
    update_option('vietshield_options', $vswaf_options);
}

// Get firewall mode for display logic
$vswaf_firewall_mode = $vswaf_options['firewall_mode'];
$vswaf_early_blocking_enabled = $vswaf_options['early_blocking_enabled'];
?>
<div class="wrap vietshield-wrap">
    <div class="vietshield-header">
        <div class="vietshield-logo">
            <span class="dashicons dashicons-shield"></span>
            <h1><?php esc_html_e('VietShield WAF Settings', 'vietshield-waf'); ?> <span style="font-size: 13px; color: #666; font-weight: 400; margin-left: 8px;">v<?php echo esc_html(VIETSHIELD_VERSION); ?></span></h1>
        </div>
        <div class="vietshield-header-actions">
            <button type="submit" form="vietshield-settings-form" class="button button-primary">
                <span class="dashicons dashicons-yes"></span>
                <?php esc_html_e('Save Settings', 'vietshield-waf'); ?>
            </button>
        </div>
    </div>

    <div class="vietshield-tabs">
        <a href="#general" class="tab-btn active">
            <span class="dashicons dashicons-admin-settings"></span>
            <?php esc_html_e('General', 'vietshield-waf'); ?>
        </a>
        <a href="#firewall" class="tab-btn">
            <span class="dashicons dashicons-shield"></span>
            <?php esc_html_e('Firewall', 'vietshield-waf'); ?>
        </a>
        <a href="#captcha" class="tab-btn">
            <span class="dashicons dashicons-lock"></span>
            <?php esc_html_e('CAPTCHA', 'vietshield-waf'); ?>
        </a>
        <a href="#login" class="tab-btn">
            <span class="dashicons dashicons-admin-users"></span>
            <?php esc_html_e('Login Security', 'vietshield-waf'); ?>
        </a>
        <a href="#scanner" class="tab-btn">
            <span class="dashicons dashicons-search"></span>
            <?php esc_html_e('Scanners', 'vietshield-waf'); ?>
        </a>
        <a href="#advanced" class="tab-btn">
            <span class="dashicons dashicons-admin-tools"></span>
            <?php esc_html_e('Advanced', 'vietshield-waf'); ?>
        </a>
        <a href="#threat-intel" class="tab-btn">
            <span class="dashicons dashicons-admin-site-alt3"></span>
            <?php esc_html_e('Threat Intel', 'vietshield-waf'); ?>
        </a>
        <a href="#about" class="tab-btn">
            <span class="dashicons dashicons-info"></span>
            <?php esc_html_e('About', 'vietshield-waf'); ?>
        </a>
    </div>

    <form method="post" action="options.php" id="vietshield-settings-form">
        <?php settings_fields('vietshield_options'); ?>
        
        <!-- General Settings -->
        <div class="vietshield-tab-content active" id="general">
            <div class="vietshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-admin-settings"></span>
                        <?php esc_html_e('General Configuration', 'vietshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('WAF Status', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[waf_enabled]" value="1" 
                                           <?php checked($vswaf_options['waf_enabled'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Enable or disable the entire Web Application Firewall.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Firewall Mode', 'vietshield-waf'); ?></th>
                            <td>
                                <div class="vietshield-radio-group">
                                    <label class="radio-card <?php echo $vswaf_firewall_mode === 'protecting' ? 'active' : ''; ?>">
                                        <input type="radio" name="vietshield_options[firewall_mode]" value="protecting" 
                                               <?php checked($vswaf_firewall_mode, 'protecting'); ?>>
                                        <div class="radio-icon">
                                            <span class="dashicons dashicons-shield"></span>
                                        </div>
                                        <div class="radio-content">
                                            <div class="radio-header">
                                                <strong><?php esc_html_e('Protection Mode', 'vietshield-waf'); ?></strong>
                                                <span class="badge badge-pro">Pro</span>
                                                <span class="radio-check dashicons dashicons-yes"></span>
                                            </div>
                                            <p><?php esc_html_e('Blocks known attacks and malicious traffic. Recommended for live sites.', 'vietshield-waf'); ?></p>
                                        </div>
                                    </label>
                                    <label class="radio-card <?php echo $vswaf_firewall_mode === 'learning' ? 'active' : ''; ?>">
                                        <input type="radio" name="vietshield_options[firewall_mode]" value="learning" 
                                               <?php checked($vswaf_firewall_mode, 'learning'); ?>>
                                        <div class="radio-icon">
                                            <span class="dashicons dashicons-welcome-learn-more"></span>
                                        </div>
                                        <div class="radio-content">
                                            <div class="radio-header">
                                                <strong><?php esc_html_e('Learning Mode', 'vietshield-waf'); ?></strong>
                                                <span class="radio-check dashicons dashicons-yes"></span>
                                            </div>
                                            <p><?php esc_html_e('Logs attacks but does not block them. Use this to test for false positives.', 'vietshield-waf'); ?></p>
                                        </div>
                                    </label>
                                </div>
                                </div>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php esc_html_e('Email Alerts', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[email_alerts]" value="1" 
                                           <?php checked($vswaf_options['email_alerts'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Receive email notifications for critical security events.', 'vietshield-waf'); ?></p>
                                
                                <div class="dependent-field" style="margin-top: 10px;">
                                    <input type="email" name="vietshield_options[alert_email]" 
                                           value="<?php echo esc_attr($vswaf_options['alert_email'] ?? get_option('admin_email')); ?>" 
                                           class="regular-text" placeholder="admin@example.com">
                                    <p class="description"><?php esc_html_e('Email address to send alerts to.', 'vietshield-waf'); ?></p>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Whitelist Admins', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[whitelist_admins]" value="1" 
                                           <?php checked($vswaf_options['whitelist_admins'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Automatically whitelist logged-in administrators (recommended).', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>

        <!-- Firewall Protection -->
        <div class="vietshield-tab-content" id="firewall">
            <div class="vietshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-shield-alt"></span>
                        <?php esc_html_e('Attack Protection', 'vietshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <p class="description mb-20">
                        <?php esc_html_e('Configure which types of attacks VietShield should block.', 'vietshield-waf'); ?>
                    </p>
                    
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('SQL Injection (SQLi)', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[block_sqli]" value="1" 
                                           <?php checked($vswaf_options['block_sqli'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Block attempts to inject malicious SQL commands.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Cross-Site Scripting (XSS)', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[block_xss]" value="1" 
                                           <?php checked($vswaf_options['block_xss'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Block attempts to inject malicious scripts.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Remote Code Execution (RCE)', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[block_rce]" value="1" 
                                           <?php checked($vswaf_options['block_rce'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description">
                                    <?php esc_html_e('Block attempts to execute arbitrary code on the server.', 'vietshield-waf'); ?>
                                    <strong><?php esc_html_e('Note:', 'vietshield-waf'); ?></strong>
                                    <?php esc_html_e('This is disabled by default to avoid false positives with Google Ads. Enable with caution and configure whitelist patterns below.', 'vietshield-waf'); ?>
                                </p>
                                
                                <div class="dependent-field" style="margin-top: 15px; <?php echo empty($vswaf_options['block_rce']) ? 'display: none;' : ''; ?>" id="rce-whitelist-section">
                                    <h4 style="margin-top: 0; margin-bottom: 10px;"><?php esc_html_e('RCE Whitelist Patterns', 'vietshield-waf'); ?></h4>
                                    <p class="description" style="margin-bottom: 10px;"><?php esc_html_e('Add regex patterns to whitelist legitimate traffic (e.g., Google Ads parameters). One pattern per line.', 'vietshield-waf'); ?></p>
                                    <textarea name="vietshield_options[rce_whitelist_patterns]" 
                                              rows="8" 
                                              class="large-text code" 
                                              placeholder="/gclid=/i&#10;/utm_source=/i&#10;/safeframe\.googlesyndication\.com/i"><?php 
                                        $rce_patterns = $vswaf_options['rce_whitelist_patterns'] ?? [];
                                        if (is_array($rce_patterns)) {
                                            echo esc_textarea(implode("\n", $rce_patterns));
                                        }
                                    ?></textarea>
                                    <p class="description" style="margin-top: 5px;">
                                        <?php esc_html_e('Default patterns include Google Ads (gclid, utm_*, gad_*), Google SafeFrame, and common tracking parameters.', 'vietshield-waf'); ?>
                                    </p>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Local File Inclusion (LFI)', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[block_lfi]" value="1" 
                                           <?php checked($vswaf_options['block_lfi'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Block attempts to access local files (e.g., /etc/passwd).', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Bad Bots & Crawlers', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[block_bad_bots]" value="1" 
                                           <?php checked($vswaf_options['block_bad_bots'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Block known bad bots, scrapers, and aggressive crawlers.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('XML-RPC Protection', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[block_xmlrpc]" value="1" 
                                           <?php checked($vswaf_options['block_xmlrpc'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Block all XML-RPC requests (pingbacks, remote publishing). Recommended if you don\'t use the WordPress app or Jetpack.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Block Author Enumeration', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[block_author_scan]" value="1" 
                                           <?php checked($vswaf_options['block_author_scan'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Block attempts to enumerate users via ?author=N queries and REST API.', 'vietshield-waf'); ?></p>
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
                        <?php esc_html_e('Country Blocking', 'vietshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <p class="description mb-20">
                        <?php esc_html_e('Block or allow requests based on geographic location. Uses IP geolocation to determine visitor country.', 'vietshield-waf'); ?>
                    </p>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable Country Blocking', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[country_blocking_enabled]" value="1"
                                           <?php checked($vswaf_options['country_blocking_enabled'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Block requests from specific countries based on IP geolocation.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Blocking Mode', 'vietshield-waf'); ?></th>
                            <td>
                                <?php $vswaf_country_mode = $vswaf_options['country_blocking_mode'] ?? 'block_selected'; ?>
                                <div class="vietshield-radio-group" style="flex-direction: column; gap: 10px;">
                                    <label class="radio-card <?php echo $vswaf_country_mode === 'block_selected' ? 'active' : ''; ?>" style="padding: 15px;">
                                        <input type="radio" name="vietshield_options[country_blocking_mode]" value="block_selected"
                                               <?php checked($vswaf_country_mode, 'block_selected'); ?>>
                                        <div class="radio-content">
                                            <div class="radio-header">
                                                <strong><?php esc_html_e('Block Selected Countries', 'vietshield-waf'); ?></strong>
                                                <span class="radio-check dashicons dashicons-yes"></span>
                                            </div>
                                            <p style="margin: 5px 0 0;"><?php esc_html_e('Block only the countries you select below. All other countries are allowed.', 'vietshield-waf'); ?></p>
                                        </div>
                                    </label>
                                    <label class="radio-card <?php echo $vswaf_country_mode === 'allow_selected' ? 'active' : ''; ?>" style="padding: 15px;">
                                        <input type="radio" name="vietshield_options[country_blocking_mode]" value="allow_selected"
                                               <?php checked($vswaf_country_mode, 'allow_selected'); ?>>
                                        <div class="radio-content">
                                            <div class="radio-header">
                                                <strong><?php esc_html_e('Allow Selected Countries Only', 'vietshield-waf'); ?></strong>
                                                <span class="radio-check dashicons dashicons-yes"></span>
                                            </div>
                                            <p style="margin: 5px 0 0;"><?php esc_html_e('Allow only the countries you select below. All other countries are blocked.', 'vietshield-waf'); ?></p>
                                        </div>
                                    </label>
                                </div>
                                <div id="country-mode-warning" class="notice notice-warning inline" style="margin-top: 10px; padding: 10px; display: none;">
                                    <p><strong><?php esc_html_e('Warning:', 'vietshield-waf'); ?></strong> <?php esc_html_e('You have selected "Allow Selected Countries Only" mode but no countries are selected. This will block ALL traffic!', 'vietshield-waf'); ?></p>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Block Unknown Countries', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[block_unknown_countries]" value="1"
                                           <?php checked($vswaf_options['block_unknown_countries'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Block requests when country cannot be determined.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <span id="countries-list-label">
                                    <?php echo $vswaf_country_mode === 'allow_selected' ? esc_html__('Allowed Countries', 'vietshield-waf') : esc_html__('Blocked Countries', 'vietshield-waf'); ?>
                                </span>
                            </th>
                            <td>
                                <?php
                                require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-country-blocker.php';
                                $vswaf_country_blocker = new \VietShield\Firewall\CountryBlocker();
                                $vswaf_countries = $vswaf_country_blocker->get_countries_list();
                                $vswaf_blocked_countries = $vswaf_options['blocked_countries'] ?? [];
                                ?>
                                <div style="max-height: 300px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; border-radius: 4px; background: #f9f9f9;">
                                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 8px;">
                                        <?php foreach ($vswaf_countries as $vswaf_code => $vswaf_name): ?>
                                            <label style="display: flex; align-items: center; gap: 6px; font-size: 13px;">
                                                <input type="checkbox"
                                                       name="vietshield_options[blocked_countries][]"
                                                       value="<?php echo esc_attr($vswaf_code); ?>"
                                                       <?php checked(in_array($vswaf_code, $vswaf_blocked_countries)); ?>>
                                                <span><?php echo esc_html($vswaf_name); ?> (<?php echo esc_html($vswaf_code); ?>)</span>
                                            </label>
                                        <?php endforeach; ?>
                                    </div>
                                </div>
                                <p class="description"><?php esc_html_e('Select countries to block. Use Ctrl/Cmd+Click to select multiple.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>

        </div>

        <!-- CAPTCHA Settings -->
        <div class="vietshield-tab-content" id="captcha">
            <div class="vietshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-lock"></span>
                        <?php esc_html_e('CAPTCHA Challenge', 'vietshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <p class="description mb-20">
                        <?php esc_html_e('Show CAPTCHA challenge instead of blocking. Allows legitimate users to verify themselves while stopping automated attacks.', 'vietshield-waf'); ?>
                    </p>
                    
                    <?php
                    require_once VIETSHIELD_PLUGIN_DIR . 'includes/waf/class-captcha-handler.php';
                    $vswaf_captcha_providers = \VietShield\WAF\CaptchaHandler::get_provider_list();
                    ?>
                    
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable CAPTCHA Challenge', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[captcha_enabled]" value="1"
                                           <?php checked($vswaf_options['captcha_enabled'] ?? false); ?>
                                           id="captcha-enabled-toggle">
                                    <span class="slider"></span>
                                </label>
                                <p class="description">
                                    <?php esc_html_e('When enabled, suspicious requests will be shown a CAPTCHA challenge instead of being blocked immediately.', 'vietshield-waf'); ?>
                                    <br><strong><?php esc_html_e('Note:', 'vietshield-waf'); ?></strong>
                                    <?php esc_html_e('Threat Intelligence blocks are always immediate (no CAPTCHA).', 'vietshield-waf'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('CAPTCHA Provider', 'vietshield-waf'); ?></th>
                            <td>
                                <select name="vietshield_options[captcha_provider]" id="captcha-provider-select" class="regular-text">
                                    <option value=""><?php esc_html_e('-- Select Provider --', 'vietshield-waf'); ?></option>
                                    <?php foreach ($vswaf_captcha_providers as $vswaf_provider_key => $vswaf_provider_name): ?>
                                        <option value="<?php echo esc_attr($vswaf_provider_key); ?>"
                                                <?php selected($vswaf_options['captcha_provider'] ?? '', $vswaf_provider_key); ?>>
                                            <?php echo esc_html($vswaf_provider_name); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                                <p class="description">
                                    <?php esc_html_e('Choose your CAPTCHA provider. You will need to configure API keys from your provider dashboard.', 'vietshield-waf'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Site Key', 'vietshield-waf'); ?></th>
                            <td>
                                <input type="text" name="vietshield_options[captcha_site_key]"
                                       value="<?php echo esc_attr($vswaf_options['captcha_site_key'] ?? ''); ?>"
                                       class="regular-text" placeholder="Enter your site key">
                                <p class="description">
                                    <?php esc_html_e('The public site key from your CAPTCHA provider.', 'vietshield-waf'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Secret Key', 'vietshield-waf'); ?></th>
                            <td>
                                <input type="password" name="vietshield_options[captcha_secret_key]"
                                       value="<?php echo esc_attr($vswaf_options['captcha_secret_key'] ?? ''); ?>"
                                       class="regular-text" placeholder="Enter your secret key">
                                <p class="description">
                                    <?php esc_html_e('The private secret key from your CAPTCHA provider. Keep this secure.', 'vietshield-waf'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Session Duration', 'vietshield-waf'); ?></th>
                            <td>
                                <select name="vietshield_options[captcha_session_duration]">
                                    <option value="1800" <?php selected($vswaf_options['captcha_session_duration'] ?? 3600, 1800); ?>><?php esc_html_e('30 minutes', 'vietshield-waf'); ?></option>
                                    <option value="3600" <?php selected($vswaf_options['captcha_session_duration'] ?? 3600, 3600); ?>><?php esc_html_e('1 hour', 'vietshield-waf'); ?></option>
                                    <option value="7200" <?php selected($vswaf_options['captcha_session_duration'] ?? 3600, 7200); ?>><?php esc_html_e('2 hours', 'vietshield-waf'); ?></option>
                                    <option value="14400" <?php selected($vswaf_options['captcha_session_duration'] ?? 3600, 14400); ?>><?php esc_html_e('4 hours', 'vietshield-waf'); ?></option>
                                    <option value="28800" <?php selected($vswaf_options['captcha_session_duration'] ?? 3600, 28800); ?>><?php esc_html_e('8 hours', 'vietshield-waf'); ?></option>
                                    <option value="86400" <?php selected($vswaf_options['captcha_session_duration'] ?? 3600, 86400); ?>><?php esc_html_e('24 hours', 'vietshield-waf'); ?></option>
                                </select>
                                <p class="description">
                                    <?php esc_html_e('How long a verified session lasts before requiring another CAPTCHA.', 'vietshield-waf'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr id="recaptcha-v3-score-row" style="<?php echo ($vswaf_options['captcha_provider'] ?? '') === 'recaptcha_v3' ? '' : 'display: none;'; ?>">
                            <th scope="row"><?php esc_html_e('reCAPTCHA v3 Min Score', 'vietshield-waf'); ?></th>
                            <td>
                                <input type="number" name="vietshield_options[recaptcha_v3_min_score]"
                                       value="<?php echo esc_attr($vswaf_options['recaptcha_v3_min_score'] ?? '0.5'); ?>"
                                       class="small-text" min="0" max="1" step="0.1">
                                <p class="description">
                                    <?php esc_html_e('Minimum score (0.0-1.0) to pass verification. Lower = more permissive. Default: 0.5', 'vietshield-waf'); ?>
                                </p>
                            </td>
                        </tr>
                    </table>
                    
                    <div class="notice notice-info inline" style="margin: 20px 0 10px;">
                        <p>
                            <strong><?php esc_html_e('Provider Setup Links:', 'vietshield-waf'); ?></strong><br>
                            • <a href="https://www.google.com/recaptcha/admin" target="_blank">Google reCAPTCHA</a> -
                            <?php esc_html_e('Free, widely supported', 'vietshield-waf'); ?><br>
                            • <a href="https://dash.cloudflare.com/?to=/:account/turnstile" target="_blank">Cloudflare Turnstile</a> -
                            <?php esc_html_e('Free, privacy-focused, no puzzles', 'vietshield-waf'); ?><br>
                            • <a href="https://dashboard.hcaptcha.com/" target="_blank">hCaptcha</a> -
                            <?php esc_html_e('Privacy-first alternative', 'vietshield-waf'); ?>
                        </p>
                    </div>
                    
                    <!-- Attack Types Section (inside CAPTCHA card) -->
                    <hr style="margin: 25px 0;">
                    <h3 style="margin-top: 0; margin-bottom: 15px; font-size: 16px; font-weight: 600;">
                        <span class="dashicons dashicons-shield-alt" style="font-size: 18px; vertical-align: middle;"></span>
                        <?php esc_html_e('Attack Types for CAPTCHA', 'vietshield-waf'); ?>
                    </h3>
                    <p class="description mb-20">
                        <?php esc_html_e('Select which attack types should trigger CAPTCHA challenge. If none selected, CAPTCHA will apply to all attack types.', 'vietshield-waf'); ?>
                    </p>
                    
                    <?php
                    $vswaf_captcha_types = $vswaf_options['captcha_types'] ?? [];
                    $vswaf_available_types = [
                        'sqli' => __('SQL Injection (SQLi)', 'vietshield-waf'),
                        'xss' => __('Cross-Site Scripting (XSS)', 'vietshield-waf'),
                        'rce' => __('Remote Code Execution (RCE)', 'vietshield-waf'),
                        'lfi' => __('Local File Inclusion (LFI)', 'vietshield-waf'),
                        'bad_bot' => __('Bad Bots & Crawlers', 'vietshield-waf'),
                        'author_scan' => __('Author Enumeration', 'vietshield-waf'),
                        'rate_limit' => __('Rate Limiting', 'vietshield-waf'),
                    ];
                    ?>
                    
                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 10px;">
                        <?php foreach ($vswaf_available_types as $vswaf_type_key => $vswaf_type_label): ?>
                            <label style="display: flex; align-items: center; gap: 8px; padding: 10px; background: #f9f9f9; border-radius: 4px;">
                                <input type="checkbox"
                                       name="vietshield_options[captcha_types][]"
                                       value="<?php echo esc_attr($vswaf_type_key); ?>"
                                       <?php checked(in_array($vswaf_type_key, $vswaf_captcha_types)); ?>>
                                <span><?php echo esc_html($vswaf_type_label); ?></span>
                            </label>
                        <?php endforeach; ?>
                    </div>
                    
                    <p class="description" style="margin-top: 15px;">
                        <strong><?php esc_html_e('Excluded from CAPTCHA:', 'vietshield-waf'); ?></strong>
                        <?php esc_html_e('Threat Intelligence, Country Blocking, and XML-RPC attacks are always blocked immediately (no CAPTCHA option).', 'vietshield-waf'); ?>
                    </p>
                </div>
            </div>
        </div>

        <!-- Login Security -->
        <div class="vietshield-tab-content" id="login">
            <div class="vietshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-lock"></span>
                        <?php esc_html_e('Login Security', 'vietshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable Login Security', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[login_security_enabled]" value="1" 
                                           <?php checked($vswaf_options['login_security_enabled'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Protect WordPress login page from brute force attacks.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Max Login Attempts', 'vietshield-waf'); ?></th>
                            <td>
                                <input type="number" name="vietshield_options[login_max_attempts]" 
                                       value="<?php echo esc_attr($vswaf_options['login_max_attempts'] ?? 5); ?>" 
                                       class="small-text" min="1" max="20">
                                <span class="description"><?php esc_html_e('Maximum failed login attempts before blocking IP', 'vietshield-waf'); ?></span>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Time Window', 'vietshield-waf'); ?></th>
                            <td>
                                <input type="number" name="vietshield_options[login_time_window]" 
                                       value="<?php echo esc_attr($vswaf_options['login_time_window'] ?? 900); ?>" 
                                       class="small-text" min="60" max="3600">
                                <span class="description"><?php esc_html_e('Time window in seconds to count attempts (default: 900 = 15 minutes)', 'vietshield-waf'); ?></span>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Lockout Duration', 'vietshield-waf'); ?></th>
                            <td>
                                <select name="vietshield_options[login_lockout_duration]">
                                    <option value="300" <?php selected($vswaf_options['login_lockout_duration'] ?? 900, 300); ?>>5 minutes</option>
                                    <option value="900" <?php selected($vswaf_options['login_lockout_duration'] ?? 900, 900); ?>>15 minutes</option>
                                    <option value="1800" <?php selected($vswaf_options['login_lockout_duration'] ?? 900, 1800); ?>>30 minutes</option>
                                    <option value="3600" <?php selected($vswaf_options['login_lockout_duration'] ?? 900, 3600); ?>>1 hour</option>
                                    <option value="7200" <?php selected($vswaf_options['login_lockout_duration'] ?? 900, 7200); ?>>2 hours</option>
                                    <option value="86400" <?php selected($vswaf_options['login_lockout_duration'] ?? 900, 86400); ?>>24 hours</option>
                                </select>
                                <p class="description"><?php esc_html_e('How long to block IP after max attempts reached', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable Honeypot', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[login_honeypot_enabled]" value="1" 
                                           <?php checked($vswaf_options['login_honeypot_enabled'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Add hidden honeypot field to catch bots', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable Email Notifications', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[login_notifications_enabled]" value="1" 
                                           <?php checked($vswaf_options['login_notifications_enabled'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Send email alerts for failed login attempts', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Notification Threshold', 'vietshield-waf'); ?></th>
                            <td>
                                <input type="number" name="vietshield_options[login_notification_threshold]" 
                                       value="<?php echo esc_attr($vswaf_options['login_notification_threshold'] ?? 3); ?>" 
                                       class="small-text" min="1" max="10">
                                <span class="description"><?php esc_html_e('Send email after this many failed attempts', 'vietshield-waf'); ?></span>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>
        <!-- Scanner -->
        <div class="vietshield-tab-content" id="scanner">
            <!-- File Scanner Card -->
            <div class="vietshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-media-text"></span>
                        <?php esc_html_e('File Scanner (Core Integrity)', 'vietshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <p class="description mb-20">
                        <?php esc_html_e('Compare WordPress core files against official checksums to detect unauthorized modifications.', 'vietshield-waf'); ?>
                    </p>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable File Scanner', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[file_scanner_enabled]" value="1"
                                           <?php checked($vswaf_options['file_scanner_enabled'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Monitor WordPress core files for unauthorized changes.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Scan Schedule', 'vietshield-waf'); ?></th>
                            <td>
                                <select name="vietshield_options[file_scan_schedule]">
                                    <option value="manual" <?php selected($vswaf_options['file_scan_schedule'] ?? 'manual', 'manual'); ?>>
                                        <?php esc_html_e('Manual Only', 'vietshield-waf'); ?>
                                    </option>
                                    <option value="daily" <?php selected($vswaf_options['file_scan_schedule'] ?? 'manual', 'daily'); ?>>
                                        <?php esc_html_e('Daily', 'vietshield-waf'); ?>
                                    </option>
                                    <option value="weekly" <?php selected($vswaf_options['file_scan_schedule'] ?? 'manual', 'weekly'); ?>>
                                        <?php esc_html_e('Weekly', 'vietshield-waf'); ?>
                                    </option>
                                </select>
                                <p class="description"><?php esc_html_e('How often to check core files.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>

            <!-- Malware Scanner Card -->
            <div class="vietshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-shield-alt"></span>
                        <?php esc_html_e('Malware Scanner', 'vietshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <p class="description mb-20">
                        <?php esc_html_e('Scan your themes, plugins, and uploads for malware, backdoors, and suspicious code patterns.', 'vietshield-waf'); ?>
                    </p>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable Malware Scanner', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="hidden" name="vietshield_options[malware_scanner_enabled]" value="0">
                                    <input type="checkbox" name="vietshield_options[malware_scanner_enabled]" value="1"
                                           <?php checked($vswaf_options['malware_scanner_enabled'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Scan themes, plugins, and uploads for malware, backdoors, and suspicious code.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Scan Schedule', 'vietshield-waf'); ?></th>
                            <td>
                                <select name="vietshield_options[malware_scan_schedule]">
                                    <option value="manual" <?php selected($vswaf_options['malware_scan_schedule'] ?? 'weekly', 'manual'); ?>>
                                        <?php esc_html_e('Manual Only', 'vietshield-waf'); ?>
                                    </option>
                                    <option value="daily" <?php selected($vswaf_options['malware_scan_schedule'] ?? 'weekly', 'daily'); ?>>
                                        <?php esc_html_e('Daily', 'vietshield-waf'); ?>
                                    </option>
                                    <option value="weekly" <?php selected($vswaf_options['malware_scan_schedule'] ?? 'weekly', 'weekly'); ?>>
                                        <?php esc_html_e('Weekly', 'vietshield-waf'); ?>
                                    </option>
                                </select>
                                <p class="description"><?php esc_html_e('Scheduled scans will run automatically based on this interval.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Scan Scope', 'vietshield-waf'); ?></th>
                            <td>
                                <select name="vietshield_options[malware_scan_scope]">
                                    <option value="all" <?php selected($vswaf_options['malware_scan_scope'] ?? 'all', 'all'); ?>>
                                        <?php esc_html_e('All (Themes, Plugins, Uploads)', 'vietshield-waf'); ?>
                                    </option>
                                    <option value="themes" <?php selected($vswaf_options['malware_scan_scope'] ?? 'all', 'themes'); ?>>
                                        <?php esc_html_e('Themes Only', 'vietshield-waf'); ?>
                                    </option>
                                    <option value="plugins" <?php selected($vswaf_options['malware_scan_scope'] ?? 'all', 'plugins'); ?>>
                                        <?php esc_html_e('Plugins Only', 'vietshield-waf'); ?>
                                    </option>
                                    <option value="uploads" <?php selected($vswaf_options['malware_scan_scope'] ?? 'all', 'uploads'); ?>>
                                        <?php esc_html_e('Uploads Only', 'vietshield-waf'); ?>
                                    </option>
                                </select>
                                <p class="description"><?php esc_html_e('Select which directories to scan for malware.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>

        <!-- Advanced -->
        <div class="vietshield-tab-content" id="advanced">
            <!-- Rate Limiting -->
            <div class="vietshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-clock"></span>
                        <?php esc_html_e('Rate Limiting', 'vietshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable Rate Limiting', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[rate_limiting_enabled]" value="1" 
                                           <?php checked($vswaf_options['rate_limiting_enabled'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Global Rate Limit', 'vietshield-waf'); ?></th>
                            <td>
                                <input type="number" name="vietshield_options[rate_limit_global]"
                                       value="<?php echo esc_attr($vswaf_options['rate_limit_global'] ?? 250); ?>"
                                       class="small-text" min="10" max="1000">
                                <span class="description"><?php esc_html_e('requests per minute', 'vietshield-waf'); ?></span>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Login Rate Limit', 'vietshield-waf'); ?></th>
                            <td>
                                <input type="number" name="vietshield_options[rate_limit_login]" 
                                       value="<?php echo esc_attr($vswaf_options['rate_limit_login'] ?? 20); ?>" 
                                       class="small-text" min="1" max="100">
                                <span class="description"><?php esc_html_e('attempts per 5 minutes', 'vietshield-waf'); ?></span>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('XML-RPC Rate Limit', 'vietshield-waf'); ?></th>
                            <td>
                                <input type="number" name="vietshield_options[rate_limit_xmlrpc]" 
                                       value="<?php echo esc_attr($vswaf_options['rate_limit_xmlrpc'] ?? 20); ?>" 
                                       class="small-text" min="1" max="100">
                                <span class="description"><?php esc_html_e('requests per minute', 'vietshield-waf'); ?></span>
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
                        <?php esc_html_e('Auto Block', 'vietshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Auto Block Threshold', 'vietshield-waf'); ?></th>
                            <td>
                                <input type="number" name="vietshield_options[auto_block_threshold]" 
                                       value="<?php echo esc_attr($vswaf_options['auto_block_threshold'] ?? 10); ?>" 
                                       class="small-text" min="0" max="100">
                                <span class="description"><?php esc_html_e('blocked requests before auto-blocking IP (0 to disable)', 'vietshield-waf'); ?></span>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Auto Block Duration', 'vietshield-waf'); ?></th>
                            <td>
                                <select name="vietshield_options[auto_block_duration]">
                                    <option value="3600" <?php selected($vswaf_options['auto_block_duration'] ?? 3600, 3600); ?>>1 hour</option>
                                    <option value="7200" <?php selected($vswaf_options['auto_block_duration'] ?? 3600, 7200); ?>>2 hours</option>
                                    <option value="21600" <?php selected($vswaf_options['auto_block_duration'] ?? 3600, 21600); ?>>6 hours</option>
                                    <option value="43200" <?php selected($vswaf_options['auto_block_duration'] ?? 3600, 43200); ?>>12 hours</option>
                                    <option value="86400" <?php selected($vswaf_options['auto_block_duration'] ?? 3600, 86400); ?>>24 hours</option>
                                    <option value="604800" <?php selected($vswaf_options['auto_block_duration'] ?? 3600, 604800); ?>>7 days</option>
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
                        <?php esc_html_e('Logging', 'vietshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Log All Traffic', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[log_all_traffic]" value="1" 
                                           <?php checked($vswaf_options['log_all_traffic'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Log all requests, not just blocked ones. May increase database size.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Log Retention', 'vietshield-waf'); ?></th>
                            <td>
                                <input type="number" name="vietshield_options[log_retention_days]" 
                                       value="<?php echo esc_attr($vswaf_options['log_retention_days'] ?? 30); ?>" 
                                       class="small-text" min="1" max="365">
                                <span class="description"><?php esc_html_e('days to keep logs', 'vietshield-waf'); ?></span>
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
                        <?php esc_html_e('IP Whitelist', 'vietshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <?php
                    // Get auto-whitelist sync status
                    require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-ip-whitelist-sync.php';
                    $vswaf_whitelist_status = \VietShield\Firewall\IPWhitelistSync::get_sync_status();
                    ?>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Whitelist Googlebot', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[whitelist_googlebot]" value="1" 
                                           <?php checked($vswaf_options['whitelist_googlebot'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description">
                                    <?php esc_html_e('Auto-whitelist Google crawler IP ranges (Googlebot, AdsBot, etc.). Updated daily from Google.', 'vietshield-waf'); ?>
                                    <?php if ($vswaf_whitelist_status['googlebot_count'] > 0): ?>
                                        <br><strong><?php 
                                        /* translators: %d: number of IP ranges */
                                        printf(esc_html__('Currently whitelisted: %d IP ranges', 'vietshield-waf'), intval($vswaf_whitelist_status['googlebot_count'])); 
                                        ?></strong>
                                    <?php endif; ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable Cloudflare Support', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[cloudflare_enabled]" value="1" 
                                           <?php checked($vswaf_options['cloudflare_enabled'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Auto-whitelist Cloudflare IP ranges. Enable this if your site is behind Cloudflare.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>

                    </table>
                    
                    <div style="margin: 15px 0 20px;">
                        <button type="button" id="ip-whitelist-sync-btn" class="button button-secondary">
                            <span class="dashicons dashicons-update"></span>
                            <?php esc_html_e('Sync Now', 'vietshield-waf'); ?>
                        </button>
                        <span id="ip-whitelist-message" style="margin-left: 10px; font-style: italic;"></span>
                    </div>

                    <hr style="margin: 30px 0;">
                    <h3 style="margin-top: 0; margin-bottom: 15px; font-size: 16px; font-weight: 600;">
                        <span class="dashicons dashicons-edit" style="font-size: 18px; vertical-align: middle;"></span>
                        <?php esc_html_e('Manual IP Lists', 'vietshield-waf'); ?>
                    </h3>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Whitelisted IPs', 'vietshield-waf'); ?></th>
                            <td>
                                <textarea name="vietshield_options[whitelisted_ips]" rows="5" class="large-text code"><?php 
                                    echo esc_textarea(implode("\n", $vswaf_options['whitelisted_ips'] ?? [])); 
                                ?></textarea>
                                <p class="description"><?php esc_html_e('One IP per line. Supports CIDR notation (e.g., 192.168.1.0/24)', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Trusted Proxies', 'vietshield-waf'); ?></th>
                            <td>
                                <textarea name="vietshield_options[trusted_proxies]" rows="5" class="large-text code"><?php 
                                    echo esc_textarea(implode("\n", $vswaf_options['trusted_proxies'] ?? [])); 
                                ?></textarea>
                                <p class="description"><?php esc_html_e('One IP or CIDR per line. These IPs will be trusted to provide the real client IP via X-Forwarded-For headers.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Blacklisted IPs', 'vietshield-waf'); ?></th>
                            <td>
                                <textarea name="vietshield_options[blacklisted_ips]" rows="5" class="large-text code"><?php 
                                    echo esc_textarea(implode("\n", $vswaf_options['blacklisted_ips'] ?? [])); 
                                ?></textarea>
                                <p class="description"><?php esc_html_e('One IP per line. These IPs will be permanently blocked.', 'vietshield-waf'); ?></p>
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
                        <?php esc_html_e('Scheduled Tasks', 'vietshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Scheduled Tasks Status', 'vietshield-waf'); ?></th>
                            <td>
                                <ul style="list-style: disc; margin-left: 20px;">
                                    <li>
                                        <strong><?php esc_html_e('Log Cleanup:', 'vietshield-waf'); ?></strong> 
                                        <?php 
                                        $vswaf_next_cleanup = wp_next_scheduled('vietshield_cleanup_logs');
                                        echo $vswaf_next_cleanup ? esc_html(wp_date('Y-m-d H:i:s', $vswaf_next_cleanup)) : esc_html__('Not scheduled', 'vietshield-waf');
                                        ?>
                                        <span class="description"> (<?php esc_html_e('Daily', 'vietshield-waf'); ?>)</span>
                                    </li>
                                    <li>
                                        <strong><?php esc_html_e('Stats Aggregation:', 'vietshield-waf'); ?></strong> 
                                        <?php 
                                        $vswaf_next_stats = wp_next_scheduled('vietshield_aggregate_stats');
                                        echo $vswaf_next_stats ? esc_html(wp_date('Y-m-d H:i:s', $vswaf_next_stats)) : esc_html__('Not scheduled', 'vietshield-waf');
                                        ?>
                                        <span class="description"> (<?php esc_html_e('Hourly', 'vietshield-waf'); ?>)</span>
                                    </li>
                                    <li>
                                        <strong><?php esc_html_e('Maintenance:', 'vietshield-waf'); ?></strong> 
                                        <?php 
                                        $vswaf_next_maintenance = wp_next_scheduled('vietshield_maintenance');
                                        echo $vswaf_next_maintenance ? esc_html(wp_date('Y-m-d H:i:s', $vswaf_next_maintenance)) : esc_html__('Not scheduled', 'vietshield-waf');
                                        ?>
                                        <span class="description"> (<?php esc_html_e('Weekly', 'vietshield-waf'); ?>)</span>
                                    </li>
                                    <li>
                                        <strong><?php esc_html_e('Threats Sharing:', 'vietshield-waf'); ?></strong> 
                                        <?php 
                                        $vswaf_next_threats = wp_next_scheduled('vietshield_submit_threats');
                                        echo $vswaf_next_threats ? esc_html(wp_date('Y-m-d H:i:s', $vswaf_next_threats)) : esc_html__('Not scheduled', 'vietshield-waf');
                                        ?>
                                        <span class="description"> (<?php esc_html_e('Every 5 minutes', 'vietshield-waf'); ?>)</span>
                                    </li>
                                    <li>
                                        <strong><?php esc_html_e('Googlebot IP Whitelist:', 'vietshield-waf'); ?></strong> 
                                        <?php 
                                        $vswaf_next_whitelist = wp_next_scheduled('vietshield_ip_whitelist_sync');
                                        echo $vswaf_next_whitelist ? esc_html(wp_date('Y-m-d H:i:s', $vswaf_next_whitelist)) : esc_html__('Not scheduled', 'vietshield-waf');
                                        ?>
                                        <span class="description"> (<?php esc_html_e('Daily', 'vietshield-waf'); ?>)</span>
                                    </li>
                                </ul>
                                <p class="description"><?php esc_html_e('These tasks run automatically to keep your site optimized and secure.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>

        <!-- Threat Intelligence -->
        <div class="vietshield-tab-content" id="threat-intel">
            <div class="vietshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-shield"></span>
                        <?php esc_html_e('Threat Intelligence', 'vietshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <?php
                    require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-threat-intelligence.php';
                    $vswaf_threat_intel = new \VietShield\Firewall\ThreatIntelligence();
                    $vswaf_sync_status = $vswaf_threat_intel->get_sync_status();
                    $vswaf_is_syncing = get_transient('vietshield_threat_intel_syncing');
                    ?>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable Threat Intelligence', 'vietshield-waf'); ?></th>
                            <td>
                                <label class="vietshield-switch">
                                    <input type="checkbox" name="vietshield_options[threat_intel_enabled]" value="1" 
                                           <?php checked($vswaf_options['threat_intel_enabled'] ?? false); ?>
                                           id="threat-intel-enabled">
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Automatically block IPs from VietShield Threat Intelligence feed.', 'vietshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Feed Category', 'vietshield-waf'); ?></th>
                            <td>
                                <select name="vietshield_options[threat_intel_category]" 
                                        id="threat-intel-category" 
                                        class="regular-text"
                                        <?php disabled($vswaf_is_syncing); ?>>
                                    <option value=""><?php esc_html_e('-- Select Category --', 'vietshield-waf'); ?></option>
                                    <option value="1d" <?php selected($vswaf_options['threat_intel_category'] ?? '', '1d'); ?>>
                                        <?php esc_html_e('1 Day (Most Recent Threats)', 'vietshield-waf'); ?>
                                    </option>
                                    <option value="3d" <?php selected($vswaf_options['threat_intel_category'] ?? '', '3d'); ?>>
                                        <?php esc_html_e('3 Days', 'vietshield-waf'); ?>
                                    </option>
                                    <option value="7d" <?php selected($vswaf_options['threat_intel_category'] ?? '', '7d'); ?>>
                                        <?php esc_html_e('7 Days', 'vietshield-waf'); ?>
                                    </option>
                                    <option value="14d" <?php selected($vswaf_options['threat_intel_category'] ?? '', '14d'); ?>>
                                        <?php esc_html_e('14 Days', 'vietshield-waf'); ?>
                                    </option>
                                    <option value="30d" <?php selected($vswaf_options['threat_intel_category'] ?? '', '30d'); ?>>
                                        <?php esc_html_e('30 Days (Largest List)', 'vietshield-waf'); ?>
                                    </option>
                                </select>
                                <p class="description">
                                    <?php esc_html_e('Select threat intelligence feed category. Only one category can be active at a time.', 'vietshield-waf'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Sync Status', 'vietshield-waf'); ?></th>
                            <td>
                                <div id="threat-intel-status">
                                    <?php if ($vswaf_sync_status['count'] > 0): ?>
                                        <p>
                                            <strong><?php esc_html_e('IPs in Database:', 'vietshield-waf'); ?></strong> 
                                            <?php echo number_format($vswaf_sync_status['count']); ?>
                                        </p>
                                        <?php if ($vswaf_sync_status['last_sync']): ?>
                                            <p>
                                                <strong><?php esc_html_e('Last Sync:', 'vietshield-waf'); ?></strong> 
                                                <?php 
                                                require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
                                                echo esc_html(\VietShield_Helpers::format_timestamp($vswaf_sync_status['last_sync'], 'Y-m-d H:i:s'));
                                                ?>
                                            </p>
                                        <?php endif; ?>
                                        <?php if ($vswaf_sync_status['category']): ?>
                                            <p>
                                                <strong><?php esc_html_e('Category:', 'vietshield-waf'); ?></strong> 
                                                <?php echo esc_html(strtoupper($vswaf_sync_status['category'])); ?>
                                            </p>
                                        <?php endif; ?>
                                        <?php if (!empty($vswaf_sync_status['next_sync'])): ?>
                                            <p>
                                                <strong><?php esc_html_e('Next Auto-Sync:', 'vietshield-waf'); ?></strong> 
                                                <?php 
                                                require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
                                                echo esc_html(\VietShield_Helpers::format_timestamp($vswaf_sync_status['next_sync'], 'Y-m-d H:i:s'));
                                                ?>
                                            </p>
                                        <?php endif; ?>
                                    <?php else: ?>
                                        <p class="description"><?php esc_html_e('No threat intelligence data synced yet.', 'vietshield-waf'); ?></p>
                                    <?php endif; ?>
                                </div>
                                <p>
                                    <button type="button" 
                                            id="threat-intel-sync-btn" 
                                            class="button button-secondary"
                                            <?php disabled($vswaf_is_syncing); ?>>
                                        <span class="dashicons dashicons-update"></span>
                                        <?php esc_html_e('Sync Now', 'vietshield-waf'); ?>
                                    </button>
                                    <button type="button" 
                                            id="threat-intel-clear-btn" 
                                            class="button button-secondary"
                                            <?php disabled($vswaf_is_syncing); ?>
                                            style="<?php echo $vswaf_sync_status['count'] > 0 ? '' : 'display:none;'; ?>">
                                        <span class="dashicons dashicons-trash"></span>
                                        <?php esc_html_e('Clear Data', 'vietshield-waf'); ?>
                                    </button>
                                </p>
                                <?php if ($vswaf_is_syncing): ?>
                                <p class="description" style="color: #f59e0b;">
                                    <span class="dashicons dashicons-update spin"></span>
                                    <?php esc_html_e('Sync in progress... Please wait.', 'vietshield-waf'); ?>
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
                        <?php esc_html_e('Threats Sharing', 'vietshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <?php
                    require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-threats-sharing.php';
                    $vswaf_threats_stats = \VietShield\Firewall\ThreatsSharing::get_stats();
                    $vswaf_next_submit = wp_next_scheduled('vietshield_submit_threats');
                    ?>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Status', 'vietshield-waf'); ?></th>
                            <td>
                                <p>
                                    <strong style="color: #46b450;"><?php esc_html_e('Always Enabled', 'vietshield-waf'); ?></strong>
                                    <span class="description"><?php esc_html_e('This feature cannot be disabled. Blocked IPs are automatically shared with the VietShield Intelligence community to help protect other websites.', 'vietshield-waf'); ?></span>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Queue Statistics', 'vietshield-waf'); ?></th>
                            <td>
                                <ul style="list-style: disc; margin-left: 20px;">
                                    <li>
                                        <strong><?php esc_html_e('Pending:', 'vietshield-waf'); ?></strong> 
                                        <?php echo number_format($vswaf_threats_stats['pending']); ?>
                                        <span class="description"><?php esc_html_e('IPs waiting to be submitted', 'vietshield-waf'); ?></span>
                                    </li>
                                    <li>
                                        <strong><?php esc_html_e('Submitted:', 'vietshield-waf'); ?></strong> 
                                        <?php echo number_format($vswaf_threats_stats['submitted']); ?>
                                        <span class="description"><?php esc_html_e('IPs successfully shared', 'vietshield-waf'); ?></span>
                                    </li>
                                    <?php if ($vswaf_threats_stats['failed'] > 0): ?>
                                    <li>
                                        <strong style="color: #dc3232;"><?php esc_html_e('Failed:', 'vietshield-waf'); ?></strong> 
                                        <?php echo number_format($vswaf_threats_stats['failed']); ?>
                                        <span class="description"><?php esc_html_e('IPs that failed to submit (max retries reached)', 'vietshield-waf'); ?></span>
                                    </li>
                                    <?php endif; ?>
                                    <?php if ($vswaf_threats_stats['last_submission']): ?>
                                    <li>
                                        <strong><?php esc_html_e('Last Submission:', 'vietshield-waf'); ?></strong> 
                                        <?php 
                                        require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
                                        echo esc_html(\VietShield_Helpers::format_timestamp($vswaf_threats_stats['last_submission'], 'Y-m-d H:i:s'));
                                        ?>
                                    </li>
                                    <?php endif; ?>
                                </ul>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Auto-Submit Schedule', 'vietshield-waf'); ?></th>
                            <td>
                                <p>
                                    <strong><?php esc_html_e('Next Submission:', 'vietshield-waf'); ?></strong> 
                                    <?php 
                                    if ($vswaf_next_submit) {
                                        echo esc_html(wp_date('Y-m-d H:i:s', $vswaf_next_submit));
                                    } else {
                                        esc_html_e('Not scheduled', 'vietshield-waf');
                                    }
                                    ?>
                                    <span class="description"> (<?php esc_html_e('Every 5 minutes', 'vietshield-waf'); ?>)</span>
                                </p>
                                <p class="description">
                                    <?php esc_html_e('Blocked IPs are automatically queued and submitted to the Intelligence API every 5 minutes. This helps protect the entire community by sharing threat data.', 'vietshield-waf'); ?>
                                </p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>

        <!-- About -->
        <div class="vietshield-tab-content" id="about">
            <!-- Plugin Information -->
            <div class="vietshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-info"></span>
                        <?php esc_html_e('Plugin Information', 'vietshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 20px;">
                        <div style="background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%); width: 48px; height: 48px; min-width: 48px; border-radius: 8px; display: flex; align-items: center; justify-content: center;">
                            <span class="dashicons dashicons-shield" style="font-size: 24px; width: 24px; height: 24px; color: white;"></span>
                        </div>
                        <div>
                            <h3 style="margin: 0 0 3px; font-size: 18px; font-weight: 600;"><?php esc_html_e('VietShield WAF', 'vietshield-waf'); ?></h3>
                            <p style="margin: 0; color: #666; font-size: 13px;"><?php esc_html_e('Web Application Firewall for WordPress', 'vietshield-waf'); ?></p>
                        </div>
                    </div>
                    
                    <table class="form-table" style="margin-top: 0;">
                        <tr>
                            <th scope="row"><?php esc_html_e('Version', 'vietshield-waf'); ?></th>
                            <td><strong>v<?php echo esc_html(VIETSHIELD_VERSION); ?></strong></td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Author', 'vietshield-waf'); ?></th>
                            <td>
                                <a href="https://github.com/VietShield-Security" target="_blank">VietShield Security</a>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('License', 'vietshield-waf'); ?></th>
                            <td>GPL v2 or later</td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('PHP Version', 'vietshield-waf'); ?></th>
                            <td><?php echo esc_html(PHP_VERSION); ?></td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('WordPress Version', 'vietshield-waf'); ?></th>
                            <td><?php echo esc_html(get_bloginfo('version')); ?></td>
                        </tr>
                    </table>
                </div>
            </div>

            <!-- Plugin Updates -->
            <div class="vietshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-update"></span>
                        <?php esc_html_e('Plugin Updates', 'vietshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <?php
                    // Get update info from transient
                    $vswaf_update_transient = get_site_transient('update_plugins');
                    $vswaf_plugin_file = 'vietshield-waf/vietshield-waf.php';
                    $vswaf_has_update = isset($vswaf_update_transient->response[$vswaf_plugin_file]);
                    $vswaf_update_info = $vswaf_has_update ? $vswaf_update_transient->response[$vswaf_plugin_file] : null;
                    ?>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Current Version', 'vietshield-waf'); ?></th>
                            <td>
                                <strong>v<?php echo esc_html(VIETSHIELD_VERSION); ?></strong>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Update Status', 'vietshield-waf'); ?></th>
                            <td>
                                <div id="vietshield-update-status">
                                    <?php if ($vswaf_has_update && $vswaf_update_info): ?>
                                        <p style="color: #f59e0b; margin: 0 0 10px;">
                                            <span class="dashicons dashicons-warning"></span>
                                            <strong><?php
                                            /* translators: %s: new version number */
                                            printf(esc_html__('New version available: v%s', 'vietshield-waf'), esc_html($vswaf_update_info->new_version));
                                            ?></strong>
                                        </p>
                                        <a href="<?php echo esc_url(admin_url('update-core.php')); ?>" class="button button-primary">
                                            <span class="dashicons dashicons-update"></span>
                                            <?php esc_html_e('Update Now', 'vietshield-waf'); ?>
                                        </a>
                                    <?php else: ?>
                                        <p style="color: #46b450; margin: 0;">
                                            <span class="dashicons dashicons-yes-alt"></span>
                                            <?php esc_html_e('You are running the latest version.', 'vietshield-waf'); ?>
                                        </p>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Check for Updates', 'vietshield-waf'); ?></th>
                            <td>
                                <button type="button" id="vietshield-check-update-btn" class="button button-secondary">
                                    <span class="dashicons dashicons-update"></span>
                                    <?php esc_html_e('Check Now', 'vietshield-waf'); ?>
                                </button>
                                <span id="vietshield-update-message" style="margin-left: 10px; font-style: italic;"></span>
                                <p class="description">
                                    <?php esc_html_e('Manually check for new versions from GitHub Releases.', 'vietshield-waf'); ?>
                                </p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>

            <!-- Support & Links -->
            <div class="vietshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-sos"></span>
                        <?php esc_html_e('Support & Resources', 'vietshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 15px;">
                        <a href="https://github.com/VietShield-Security/vietshield-waf" target="_blank" class="button button-secondary" style="display: flex; align-items: center; gap: 8px; justify-content: center; padding: 12px 15px; height: auto;">
                            <span class="dashicons dashicons-editor-code"></span>
                            <?php esc_html_e('GitHub Repository', 'vietshield-waf'); ?>
                        </a>
                        <a href="https://github.com/VietShield-Security/vietshield-waf/issues" target="_blank" class="button button-secondary" style="display: flex; align-items: center; gap: 8px; justify-content: center; padding: 12px 15px; height: auto;">
                            <span class="dashicons dashicons-flag"></span>
                            <?php esc_html_e('Report an Issue', 'vietshield-waf'); ?>
                        </a>
                        <a href="https://github.com/VietShield-Security/vietshield-waf/releases" target="_blank" class="button button-secondary" style="display: flex; align-items: center; gap: 8px; justify-content: center; padding: 12px 15px; height: auto;">
                            <span class="dashicons dashicons-download"></span>
                            <?php esc_html_e('Release Notes', 'vietshield-waf'); ?>
                        </a>
                        <a href="https://github.com/VietShield-Security/vietshield-waf/wiki" target="_blank" class="button button-secondary" style="display: flex; align-items: center; gap: 8px; justify-content: center; padding: 12px 15px; height: auto;">
                            <span class="dashicons dashicons-book"></span>
                            <?php esc_html_e('Documentation', 'vietshield-waf'); ?>
                        </a>
                    </div>
                    
                    <div class="notice notice-info inline" style="margin: 20px 0 0;">
                        <p>
                            <strong><?php esc_html_e('Need help?', 'vietshield-waf'); ?></strong>
                            <?php esc_html_e('If you encounter any issues or have feature requests, please create an issue on our GitHub repository. We respond to all issues within 24-48 hours.', 'vietshield-waf'); ?>
                        </p>
                    </div>
                </div>
            </div>

            <!-- Credits -->
            <div class="vietshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-heart"></span>
                        <?php esc_html_e('Credits', 'vietshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <p><?php esc_html_e('VietShield WAF is an open-source project developed with ❤️ by the VietShield Security team.', 'vietshield-waf'); ?></p>
                    <p><?php esc_html_e('This plugin uses the following technologies and services:', 'vietshield-waf'); ?></p>
                    <ul style="list-style: disc; margin-left: 20px;">
                        <li><?php esc_html_e('VietShield Threat Intelligence API - Community-powered threat feed', 'vietshield-waf'); ?></li>
                        <li><?php esc_html_e('MaxMind GeoLite2 - IP geolocation data', 'vietshield-waf'); ?></li>
                        <li><?php esc_html_e('Google reCAPTCHA / Cloudflare Turnstile / hCaptcha - CAPTCHA providers', 'vietshield-waf'); ?></li>
                    </ul>
                    
                    <div style="margin-top: 20px; padding: 15px; background: #f0f0f1; border-radius: 6px; text-align: center;">
                        <p style="margin: 0 0 10px; font-size: 14px;">
                            <?php esc_html_e('If you find VietShield WAF useful, please consider:', 'vietshield-waf'); ?>
                        </p>
                        <a href="https://github.com/VietShield-Security/vietshield-waf" target="_blank" class="button button-primary">
                            <span class="dashicons dashicons-star-filled"></span>
                            <?php esc_html_e('Star us on GitHub', 'vietshield-waf'); ?>
                        </a>
                    </div>
                </div>
            </div>
        </div>

        <?php submit_button(__('Save Settings', 'vietshield-waf'), 'primary', 'submit', true); ?>
    </form>
    
    <?php include VIETSHIELD_PLUGIN_DIR . 'admin/views/partials/footer.php'; ?>
</div>


