<?php
if (!defined('ABSPATH')) {
    exit;
}

$totals = $stats['totals'] ?? [];
?>
<div class="wrap vietshield-wrap">
    <div class="vietshield-header">
        <div class="vietshield-logo">
            <span class="dashicons dashicons-shield"></span>
            <h1><?php _e('VietShield WAF', 'vietshield-waf'); ?> <span style="font-size: 13px; color: #666; font-weight: 400; margin-left: 8px;">v<?php echo VIETSHIELD_VERSION; ?></span></h1>
        </div>
        <div class="vietshield-status">
            <?php if ($this->options['waf_enabled'] ?? true): ?>
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
            <span class="firewall-mode">
                <?php 
                $mode = $this->options['firewall_mode'] ?? 'protecting';
                // Backward compatibility: map old values to new
                if ($mode === 'extended') {
                    $mode = 'protecting';
                }
                $mode_labels = [
                    'learning' => __('Learning Mode', 'vietshield-waf'),
                    'protecting' => __('Protecting Mode - Block threats and Logging', 'vietshield-waf'),
                ];
                echo esc_html($mode_labels[$mode] ?? $mode);
                ?>
            </span>
        </div>
    </div>

    <!-- Stats Cards -->
    <div class="vietshield-stats-grid">
        <div class="stat-card stat-total">
            <div class="stat-icon">
                <span class="dashicons dashicons-visibility"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value"><?php echo number_format($totals['total_requests'] ?? 0); ?></div>
                <div class="stat-label"><?php _e('Total Requests', 'vietshield-waf'); ?></div>
            </div>
        </div>
        
        <div class="stat-card stat-blocked">
            <div class="stat-icon">
                <span class="dashicons dashicons-shield-alt"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value"><?php echo number_format($totals['blocked'] ?? 0); ?></div>
                <div class="stat-label"><?php _e('Attacks Blocked', 'vietshield-waf'); ?></div>
            </div>
        </div>
        
        <div class="stat-card stat-intelligence">
            <div class="stat-icon">
                <span class="dashicons dashicons-networking"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value"><?php echo number_format($threat_intel_synced ?? 0); ?></div>
                <div class="stat-label"><?php _e('Intelligence Threats', 'vietshield-waf'); ?></div>
            </div>
        </div>
        
        <div class="stat-card stat-intelligence-blocked">
            <div class="stat-icon">
                <span class="dashicons dashicons-shield"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value"><?php echo number_format($threat_intel_blocked ?? 0); ?></div>
                <div class="stat-label"><?php _e('Intelligence Blocked', 'vietshield-waf'); ?></div>
            </div>
        </div>
    </div>

    <!-- Main Content Grid -->
    <div class="vietshield-content-grid">
        <!-- Recent Attacks -->
        <div class="vietshield-card">
            <div class="card-header">
                <h2>
                    <span class="dashicons dashicons-warning"></span>
                    <?php _e('Recent Attacks', 'vietshield-waf'); ?>
                </h2>
                <a href="<?php echo admin_url('admin.php?page=vietshield-traffic'); ?>" class="button button-small">
                    <?php _e('View All', 'vietshield-waf'); ?>
                </a>
            </div>
            <div class="card-body">
                <?php if (empty($recent_attacks)): ?>
                    <div class="empty-state">
                        <span class="dashicons dashicons-yes-alt"></span>
                        <p><?php _e('No attacks detected recently. Your site is safe!', 'vietshield-waf'); ?></p>
                    </div>
                <?php else: ?>
                    <table class="vietshield-table">
                        <thead>
                            <tr>
                                <th><?php _e('Time', 'vietshield-waf'); ?></th>
                                <th><?php _e('IP', 'vietshield-waf'); ?></th>
                                <th><?php _e('Type', 'vietshield-waf'); ?></th>
                                <th><?php _e('Severity', 'vietshield-waf'); ?></th>
                                <th><?php _e('Action', 'vietshield-waf'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($recent_attacks as $attack): ?>
                                <tr>
                                    <td class="time-col">
                                        <?php 
                                        require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
                                        $formatted_time = VietShield_Helpers::format_timestamp($attack['timestamp'], 'Y-m-d H:i:s');
                                        echo esc_html($formatted_time);
                                        ?>
                                    </td>
                                    <td class="ip-col">
                                        <code><?php echo esc_html($attack['ip']); ?></code>
                                    </td>
                                    <td class="type-col">
                                        <?php 
                                        $attack_type = $attack['attack_type'];
                                        // For rate_limited with no attack_type, show the action
                                        if (empty($attack_type) && $attack['action'] === 'rate_limited') {
                                            $attack_type = 'rate_limit';
                                        }
                                        ?>
                                        <span class="attack-type type-<?php echo esc_attr($attack_type ?: 'unknown'); ?>">
                                            <?php echo esc_html(strtoupper($attack_type ?: 'UNKNOWN')); ?>
                                        </span>
                                    </td>
                                    <td class="severity-col">
                                        <span class="severity severity-<?php echo esc_attr($attack['severity']); ?>">
                                            <?php echo esc_html(ucfirst($attack['severity'])); ?>
                                        </span>
                                    </td>
                                    <td class="action-col">
                                        <button class="button button-small block-ip-btn" 
                                                data-ip="<?php echo esc_attr($attack['ip']); ?>">
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

        <!-- Top Blocked IPs -->
        <div class="vietshield-card">
            <div class="card-header">
                <h2>
                    <span class="dashicons dashicons-admin-users"></span>
                    <?php _e('Top Blocked IPs', 'vietshield-waf'); ?>
                </h2>
            </div>
            <div class="card-body">
                <?php if (empty($top_ips)): ?>
                    <div class="empty-state">
                        <span class="dashicons dashicons-yes-alt"></span>
                        <p><?php _e('No IPs have been blocked yet.', 'vietshield-waf'); ?></p>
                    </div>
                <?php else: ?>
                    <table class="vietshield-table">
                        <thead>
                            <tr>
                                <th><?php _e('IP Address', 'vietshield-waf'); ?></th>
                                <th><?php _e('Blocks', 'vietshield-waf'); ?></th>
                                <th><?php _e('Attack Types', 'vietshield-waf'); ?></th>
                                <th><?php _e('Action', 'vietshield-waf'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($top_ips as $ip_data): ?>
                                <tr>
                                    <td class="ip-col">
                                        <code><?php echo esc_html($ip_data['ip']); ?></code>
                                    </td>
                                    <td class="count-col">
                                        <strong><?php echo esc_html($ip_data['block_count']); ?></strong>
                                    </td>
                                    <td class="types-col">
                                        <?php 
                                        $types = array_filter(explode(',', $ip_data['attack_types'] ?? ''));
                                        $actions = array_filter(explode(',', $ip_data['actions'] ?? ''));
                                        
                                        // If no attack types but has rate_limited action
                                        if (empty($types) && in_array('rate_limited', $actions)) {
                                            $types = ['rate_limit'];
                                        }
                                        
                                        if (empty($types)) {
                                            $types = ['unknown'];
                                        }
                                        
                                        foreach ($types as $type): 
                                        ?>
                                            <span class="attack-type type-<?php echo esc_attr($type); ?>">
                                                <?php echo esc_html(strtoupper($type)); ?>
                                            </span>
                                        <?php endforeach; ?>
                                    </td>
                                    <td class="action-col">
                                        <button class="button button-small block-ip-btn" 
                                                data-ip="<?php echo esc_attr($ip_data['ip']); ?>">
                                            <?php _e('Permanent Block', 'vietshield-waf'); ?>
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

    <!-- Quick Actions -->
    <div class="vietshield-card">
        <div class="card-header">
            <h2>
                <span class="dashicons dashicons-admin-tools"></span>
                <?php _e('Quick Actions', 'vietshield-waf'); ?>
            </h2>
        </div>
        <div class="card-body">
            <div class="quick-actions">
                <a href="<?php echo admin_url('admin.php?page=vietshield-settings'); ?>" class="quick-action">
                    <span class="dashicons dashicons-admin-settings"></span>
                    <span><?php _e('Configure Settings', 'vietshield-waf'); ?></span>
                </a>
                <a href="<?php echo admin_url('admin.php?page=vietshield-firewall'); ?>" class="quick-action">
                    <span class="dashicons dashicons-list-view"></span>
                    <span><?php _e('Manage IP Lists', 'vietshield-waf'); ?></span>
                </a>
                <a href="<?php echo admin_url('admin.php?page=vietshield-traffic'); ?>" class="quick-action">
                    <span class="dashicons dashicons-chart-area"></span>
                    <span><?php _e('View Live Traffic', 'vietshield-waf'); ?></span>
                </a>
                <button class="quick-action" id="clear-logs-btn">
                    <span class="dashicons dashicons-trash"></span>
                    <span><?php _e('Clear All Logs', 'vietshield-waf'); ?></span>
                </button>
            </div>
        </div>
    </div>
    
    <?php include VIETSHIELD_PLUGIN_DIR . 'admin/views/partials/footer.php'; ?>
</div>
