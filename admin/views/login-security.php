<?php
if (!defined('ABSPATH')) {
    exit;
}

$vswaf_stats = isset($stats) ? $stats : [];
$vswaf_recent_failed = isset($recent_failed) ? $recent_failed : [];
$vswaf_top_ips = isset($top_ips) ? $top_ips : [];
$vswaf_options = get_option('vietshield_options', []);
?>
<div class="wrap vietshield-wrap">
    <div class="vietshield-header">
        <div class="vietshield-logo">
            <span class="dashicons dashicons-lock"></span>
            <h1><?php esc_html_e('Login Security', 'vietshield-waf'); ?> <span style="font-size: 13px; color: #666; font-weight: 400; margin-left: 8px;">v<?php echo esc_html(VIETSHIELD_VERSION); ?></span></h1>
        </div>
        <div class="vietshield-status">
            <?php 
            if ($vswaf_options['login_security_enabled'] ?? true): 
            ?>
                <span class="status-badge status-active">
                    <span class="dashicons dashicons-yes-alt"></span>
                    <?php esc_html_e('Protection Active', 'vietshield-waf'); ?>
                </span>
            <?php else: ?>
                <span class="status-badge status-inactive">
                    <span class="dashicons dashicons-dismiss"></span>
                    <?php esc_html_e('Protection Disabled', 'vietshield-waf'); ?>
                </span>
            <?php endif; ?>
        </div>
    </div>

    <!-- Stats Cards -->
    <div class="vietshield-stats-grid">
        <?php
        $vswaf_total_attempts = 0;
        $vswaf_total_successful = 0;
        $vswaf_total_failed = 0;
        $vswaf_unique_ips = 0;
        
        foreach ($vswaf_stats as $vswaf_stat) {
            $vswaf_total_attempts += $vswaf_stat['total_attempts'];
            $vswaf_total_successful += $vswaf_stat['successful'];
            $vswaf_total_failed += $vswaf_stat['failed'];
            $vswaf_unique_ips += $vswaf_stat['unique_ips'];
        }
        ?>
        <div class="stat-card stat-total">
            <div class="stat-icon">
                <span class="dashicons dashicons-admin-users"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value"><?php echo number_format($vswaf_total_attempts); ?></div>
                <div class="stat-label"><?php esc_html_e('Total Login Attempts', 'vietshield-waf'); ?></div>
            </div>
        </div>
        
        <div class="stat-card stat-success">
            <div class="stat-icon">
                <span class="dashicons dashicons-yes-alt"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value"><?php echo number_format($vswaf_total_successful); ?></div>
                <div class="stat-label"><?php esc_html_e('Successful Logins', 'vietshield-waf'); ?></div>
            </div>
        </div>
        
        <div class="stat-card stat-blocked">
            <div class="stat-icon">
                <span class="dashicons dashicons-dismiss"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value"><?php echo number_format($vswaf_total_failed); ?></div>
                <div class="stat-label"><?php esc_html_e('Failed Attempts', 'vietshield-waf'); ?></div>
            </div>
        </div>
        
        <div class="stat-card stat-ips">
            <div class="stat-icon">
                <span class="dashicons dashicons-networking"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value"><?php echo number_format($vswaf_unique_ips); ?></div>
                <div class="stat-label"><?php esc_html_e('Unique IPs', 'vietshield-waf'); ?></div>
            </div>
        </div>
    </div>

    <!-- Main Content Grid -->
    <div class="vietshield-content-grid">
        <!-- Recent Failed Attempts -->
        <div class="vietshield-card">
            <div class="card-header">
                <h2>
                    <span class="dashicons dashicons-warning"></span>
                    <?php esc_html_e('Recent Failed Login Attempts', 'vietshield-waf'); ?>
                </h2>
            </div>
            <div class="card-body">
                <?php if (empty($vswaf_recent_failed)): ?>
                    <div class="empty-state">
                        <span class="dashicons dashicons-yes-alt"></span>
                        <p><?php esc_html_e('No failed login attempts recently.', 'vietshield-waf'); ?></p>
                    </div>
                <?php else: ?>
                    <table class="vietshield-table">
                        <thead>
                            <tr>
                                <th><?php esc_html_e('Time', 'vietshield-waf'); ?></th>
                                <th><?php esc_html_e('IP Address', 'vietshield-waf'); ?></th>
                                <th><?php esc_html_e('Username', 'vietshield-waf'); ?></th>
                                <th><?php esc_html_e('User Agent', 'vietshield-waf'); ?></th>
                                <th><?php esc_html_e('Action', 'vietshield-waf'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($vswaf_recent_failed as $vswaf_attempt): ?>
                                <tr>
                                    <td>
                                        <?php 
                                        require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
                                        echo esc_html(\VietShield_Helpers::format_timestamp($vswaf_attempt['timestamp'], 'Y-m-d H:i:s'));
                                        ?>
                                    </td>
                                    <td><code><?php echo esc_html($vswaf_attempt['ip']); ?></code></td>
                                    <td><?php echo esc_html($vswaf_attempt['username'] ?: '-'); ?></td>
                                    <td class="user-agent-col">
                                        <?php echo esc_html(substr($vswaf_attempt['user_agent'] ?? '', 0, 50)); ?>
                                    </td>
                                    <td>
                                        <button class="button button-small block-ip-btn" 
                                                data-ip="<?php echo esc_attr($vswaf_attempt['ip']); ?>">
                                            <?php esc_html_e('Block IP', 'vietshield-waf'); ?>
                                        </button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        </div>

        <!-- Top Attacking IPs -->
        <div class="vietshield-card">
            <div class="card-header">
                <h2>
                    <span class="dashicons dashicons-admin-users"></span>
                    <?php esc_html_e('Top Attacking IPs', 'vietshield-waf'); ?>
                </h2>
            </div>
            <div class="card-body">
                <?php if (empty($vswaf_top_ips)): ?>
                    <div class="empty-state">
                        <span class="dashicons dashicons-yes-alt"></span>
                        <p><?php esc_html_e('No attacking IPs detected.', 'vietshield-waf'); ?></p>
                    </div>
                <?php else: ?>
                    <table class="vietshield-table">
                        <thead>
                            <tr>
                                <th><?php esc_html_e('IP Address', 'vietshield-waf'); ?></th>
                                <th><?php esc_html_e('Failed Attempts', 'vietshield-waf'); ?></th>
                                <th><?php esc_html_e('Usernames Tried', 'vietshield-waf'); ?></th>
                                <th><?php esc_html_e('Last Attempt', 'vietshield-waf'); ?></th>
                                <th><?php esc_html_e('Action', 'vietshield-waf'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($vswaf_top_ips as $vswaf_ip_data): ?>
                                <tr>
                                    <td><code><?php echo esc_html($vswaf_ip_data['ip']); ?></code></td>
                                    <td><strong><?php echo esc_html($vswaf_ip_data['attempt_count']); ?></strong></td>
                                    <td>
                                        <?php 
                                        $vswaf_usernames = explode(',', $vswaf_ip_data['usernames']);
                                        echo esc_html(implode(', ', array_slice($vswaf_usernames, 0, 3)));
                                        if (count($vswaf_usernames) > 3) {
                                            /* translators: %d: number of additional usernames */
                                            printf(esc_html__(' +%d more', 'vietshield-waf'), count($vswaf_usernames) - 3);
                                        }
                                        ?>
                                    </td>
                                    <td>
                                        <?php 
                                        require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
                                        echo esc_html(\VietShield_Helpers::format_timestamp($vswaf_ip_data['last_attempt'], 'Y-m-d H:i:s'));
                                        ?>
                                    </td>
                                    <td>
                                        <button class="button button-small block-ip-btn" 
                                                data-ip="<?php echo esc_attr($vswaf_ip_data['ip']); ?>">
                                            <?php esc_html_e('Block IP', 'vietshield-waf'); ?>
                                        </button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <?php include VIETSHIELD_PLUGIN_DIR . 'admin/views/partials/footer.php'; ?>
</div>
