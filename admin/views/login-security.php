<?php
if (!defined('ABSPATH')) {
    exit;
}
?>
<div class="wrap vietshield-wrap">
    <div class="vietshield-header">
        <div class="vietshield-logo">
            <span class="dashicons dashicons-lock"></span>
            <h1><?php _e('Login Security', 'vietshield-waf'); ?> <span style="font-size: 13px; color: #666; font-weight: 400; margin-left: 8px;">v<?php echo VIETSHIELD_VERSION; ?></span></h1>
        </div>
        <div class="vietshield-status">
            <?php 
            $options = get_option('vietshield_options', []);
            if ($options['login_security_enabled'] ?? true): 
            ?>
                <span class="status-badge status-active">
                    <span class="dashicons dashicons-yes-alt"></span>
                    <?php _e('Protection Active', 'vietshield-waf'); ?>
                </span>
            <?php else: ?>
                <span class="status-badge status-inactive">
                    <span class="dashicons dashicons-dismiss"></span>
                    <?php _e('Protection Disabled', 'vietshield-waf'); ?>
                </span>
            <?php endif; ?>
        </div>
    </div>

    <!-- Stats Cards -->
    <div class="vietshield-stats-grid">
        <?php
        $total_attempts = 0;
        $total_successful = 0;
        $total_failed = 0;
        $unique_ips = 0;
        
        foreach ($stats as $stat) {
            $total_attempts += $stat['total_attempts'];
            $total_successful += $stat['successful'];
            $total_failed += $stat['failed'];
            $unique_ips += $stat['unique_ips'];
        }
        ?>
        <div class="stat-card stat-total">
            <div class="stat-icon">
                <span class="dashicons dashicons-admin-users"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value"><?php echo number_format($total_attempts); ?></div>
                <div class="stat-label"><?php _e('Total Login Attempts', 'vietshield-waf'); ?></div>
            </div>
        </div>
        
        <div class="stat-card stat-success">
            <div class="stat-icon">
                <span class="dashicons dashicons-yes-alt"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value"><?php echo number_format($total_successful); ?></div>
                <div class="stat-label"><?php _e('Successful Logins', 'vietshield-waf'); ?></div>
            </div>
        </div>
        
        <div class="stat-card stat-blocked">
            <div class="stat-icon">
                <span class="dashicons dashicons-dismiss"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value"><?php echo number_format($total_failed); ?></div>
                <div class="stat-label"><?php _e('Failed Attempts', 'vietshield-waf'); ?></div>
            </div>
        </div>
        
        <div class="stat-card stat-ips">
            <div class="stat-icon">
                <span class="dashicons dashicons-networking"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value"><?php echo number_format($unique_ips); ?></div>
                <div class="stat-label"><?php _e('Unique IPs', 'vietshield-waf'); ?></div>
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
                    <?php _e('Recent Failed Login Attempts', 'vietshield-waf'); ?>
                </h2>
            </div>
            <div class="card-body">
                <?php if (empty($recent_failed)): ?>
                    <div class="empty-state">
                        <span class="dashicons dashicons-yes-alt"></span>
                        <p><?php _e('No failed login attempts recently.', 'vietshield-waf'); ?></p>
                    </div>
                <?php else: ?>
                    <table class="vietshield-table">
                        <thead>
                            <tr>
                                <th><?php _e('Time', 'vietshield-waf'); ?></th>
                                <th><?php _e('IP Address', 'vietshield-waf'); ?></th>
                                <th><?php _e('Username', 'vietshield-waf'); ?></th>
                                <th><?php _e('User Agent', 'vietshield-waf'); ?></th>
                                <th><?php _e('Action', 'vietshield-waf'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($recent_failed as $attempt): ?>
                                <tr>
                                    <td>
                                        <?php 
                                        require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
                                        echo esc_html(\VietShield_Helpers::format_timestamp($attempt['timestamp'], 'Y-m-d H:i:s'));
                                        ?>
                                    </td>
                                    <td><code><?php echo esc_html($attempt['ip']); ?></code></td>
                                    <td><?php echo esc_html($attempt['username'] ?: '-'); ?></td>
                                    <td class="user-agent-col">
                                        <?php echo esc_html(substr($attempt['user_agent'] ?? '', 0, 50)); ?>
                                    </td>
                                    <td>
                                        <button class="button button-small block-ip-btn" 
                                                data-ip="<?php echo esc_attr($attempt['ip']); ?>">
                                            <?php _e('Block IP', 'vietshield-waf'); ?>
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
                    <?php _e('Top Attacking IPs', 'vietshield-waf'); ?>
                </h2>
            </div>
            <div class="card-body">
                <?php if (empty($top_ips)): ?>
                    <div class="empty-state">
                        <span class="dashicons dashicons-yes-alt"></span>
                        <p><?php _e('No attacking IPs detected.', 'vietshield-waf'); ?></p>
                    </div>
                <?php else: ?>
                    <table class="vietshield-table">
                        <thead>
                            <tr>
                                <th><?php _e('IP Address', 'vietshield-waf'); ?></th>
                                <th><?php _e('Failed Attempts', 'vietshield-waf'); ?></th>
                                <th><?php _e('Usernames Tried', 'vietshield-waf'); ?></th>
                                <th><?php _e('Last Attempt', 'vietshield-waf'); ?></th>
                                <th><?php _e('Action', 'vietshield-waf'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($top_ips as $ip_data): ?>
                                <tr>
                                    <td><code><?php echo esc_html($ip_data['ip']); ?></code></td>
                                    <td><strong><?php echo esc_html($ip_data['attempt_count']); ?></strong></td>
                                    <td>
                                        <?php 
                                        $usernames = explode(',', $ip_data['usernames']);
                                        echo esc_html(implode(', ', array_slice($usernames, 0, 3)));
                                        if (count($usernames) > 3) {
                                            echo ' +' . (count($usernames) - 3) . ' more';
                                        }
                                        ?>
                                    </td>
                                    <td>
                                        <?php 
                                        require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
                                        echo esc_html(\VietShield_Helpers::format_timestamp($ip_data['last_attempt'], 'Y-m-d H:i:s'));
                                        ?>
                                    </td>
                                    <td>
                                        <button class="button button-small block-ip-btn" 
                                                data-ip="<?php echo esc_attr($ip_data['ip']); ?>">
                                            <?php _e('Block IP', 'vietshield-waf'); ?>
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
