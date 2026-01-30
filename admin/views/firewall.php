<?php
if (!defined('ABSPATH')) {
    exit;
}

// Get Googlebot whitelist status from IPWhitelistSync
require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-ip-whitelist-sync.php';
$vswaf_whitelist_sync_status = \VietShield\Firewall\IPWhitelistSync::get_sync_status();
$vswaf_googlebot_count = $vswaf_whitelist_sync_status['googlebot_count'] ?? 0;

// Check if user wants to show Googlebot IPs
// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Just reading display preference
$vswaf_show_googlebot = isset($_GET['show_googlebot']) && $_GET['show_googlebot'] === '1';

// Separate Googlebot IPs from custom IPs
$vswaf_whitelist_all = isset($vswaf_whitelist) && is_array($vswaf_whitelist) ? $vswaf_whitelist : [];
$vswaf_whitelist_custom = array_filter($vswaf_whitelist_all, function($vswaf_entry) {
    return strpos($vswaf_entry['reason'] ?? '', '[Googlebot]') === false;
});
$vswaf_whitelist_googlebot = array_filter($vswaf_whitelist_all, function($vswaf_entry) {
    return strpos($vswaf_entry['reason'] ?? '', '[Googlebot]') !== false;
});

// Get options
$vswaf_options = get_option('vietshield_options', []);
$vswaf_googlebot_enabled = !empty($vswaf_options['whitelist_googlebot']);

// Show based on user preference
if ($vswaf_show_googlebot) {
    // Show all whitelist including Googlebot
    $vswaf_whitelist = $vswaf_whitelist_all;
} else {
    // Hide Googlebot IPs
    $vswaf_whitelist = $vswaf_whitelist_custom;
}
?>
<div class="wrap vietshield-wrap">
    <div class="vietshield-header">
        <div class="vietshield-logo">
            <span class="dashicons dashicons-shield"></span>
            <h1><?php esc_html_e('Firewall Management', 'vietshield-waf'); ?> <span style="font-size: 13px; color: #666; font-weight: 400; margin-left: 8px;">v<?php echo esc_html(VIETSHIELD_VERSION); ?></span></h1>
        </div>
    </div>

    <!-- Add IP Form -->
    <div class="vietshield-card">
        <div class="card-header">
            <h2>
                <span class="dashicons dashicons-plus-alt"></span>
                <?php esc_html_e('Add IP to List', 'vietshield-waf'); ?>
            </h2>
        </div>
        <div class="card-body">
            <form id="add-ip-form" class="ip-add-form">
                <div class="form-row">
                    <div class="form-group">
                        <label for="ip-address"><?php esc_html_e('IP Address', 'vietshield-waf'); ?></label>
                        <input type="text" id="ip-address" name="ip" placeholder="192.168.1.1 or 192.168.1.0/24" required>
                    </div>
                    <div class="form-group">
                        <label for="list-type"><?php esc_html_e('List Type', 'vietshield-waf'); ?></label>
                        <select id="list-type" name="list_type">
                            <option value="whitelist"><?php esc_html_e('Whitelist (Allow)', 'vietshield-waf'); ?></option>
                            <option value="blacklist"><?php esc_html_e('Blacklist (Block)', 'vietshield-waf'); ?></option>
                            <option value="temporary"><?php esc_html_e('Temporary Block', 'vietshield-waf'); ?></option>
                        </select>
                    </div>
                    <div class="form-group duration-group" style="display:none;">
                        <label for="duration"><?php esc_html_e('Duration', 'vietshield-waf'); ?></label>
                        <select id="duration" name="duration">
                            <option value="3600">1 hour</option>
                            <option value="7200">2 hours</option>
                            <option value="21600">6 hours</option>
                            <option value="43200">12 hours</option>
                            <option value="86400">24 hours</option>
                            <option value="604800">7 days</option>
                            <option value="2592000">30 days</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="reason"><?php esc_html_e('Reason', 'vietshield-waf'); ?></label>
                        <input type="text" id="reason" name="reason" placeholder="Optional reason">
                    </div>
                    <div class="form-group">
                        <label>&nbsp;</label>
                        <button type="submit" class="button button-primary"><?php esc_html_e('Add IP', 'vietshield-waf'); ?></button>
                    </div>
                </div>
            </form>
        </div>
    </div>

    <!-- Googlebot Whitelist Card -->
    <div class="vietshield-card" style="margin-bottom: 20px;">
        <div class="card-header">
            <h2>
                <span class="dashicons dashicons-google"></span>
                <?php esc_html_e('Googlebot Whitelist', 'vietshield-waf'); ?>
            </h2>
        </div>
        <div class="card-body">
            <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 15px;">
                <div>
                    <p style="margin: 0 0 5px 0;">
                        <?php esc_html_e('Auto-whitelist Google crawler IP ranges (Googlebot, AdsBot, etc.) to ensure your site is properly indexed.', 'vietshield-waf'); ?>
                    </p>
                    <?php if ($vswaf_googlebot_count > 0): ?>
                        <p style="margin: 0; color: #00a32a;">
                            <span class="dashicons dashicons-yes-alt" style="color: #00a32a;"></span>
                            <strong><?php printf(esc_html__('%d IP ranges synced', 'vietshield-waf'), $vswaf_googlebot_count); ?></strong>
                            <?php if (!empty($vswaf_whitelist_sync_status['last_sync'])): ?>
                                <span style="color: #666; margin-left: 10px;">
                                    <?php
                                    /* translators: %s: date time */
                                    printf(esc_html__('Last sync: %s', 'vietshield-waf'), esc_html($vswaf_whitelist_sync_status['last_sync']));
                                    ?>
                                </span>
                            <?php endif; ?>
                        </p>
                    <?php elseif ($vswaf_googlebot_enabled): ?>
                        <p style="margin: 0; color: #d63638;">
                            <span class="dashicons dashicons-warning" style="color: #d63638;"></span>
                            <strong><?php esc_html_e('Not synced yet. Click "Sync Now" to fetch Googlebot IPs.', 'vietshield-waf'); ?></strong>
                        </p>
                    <?php else: ?>
                        <p style="margin: 0; color: #666;">
                            <span class="dashicons dashicons-info"></span>
                            <?php esc_html_e('Googlebot whitelist is disabled. Enable it in Settings.', 'vietshield-waf'); ?>
                        </p>
                    <?php endif; ?>
                </div>
                <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                    <?php if ($vswaf_googlebot_count > 0): ?>
                        <?php if ($vswaf_show_googlebot): ?>
                            <a href="<?php echo esc_url(admin_url('admin.php?page=vietshield-firewall')); ?>" class="button">
                                <span class="dashicons dashicons-hidden" style="font-size: 16px; width: 16px; height: 16px; margin-right: 3px; vertical-align: middle;"></span>
                                <?php esc_html_e('Hide IPs', 'vietshield-waf'); ?>
                            </a>
                        <?php else: ?>
                            <a href="<?php echo esc_url(admin_url('admin.php?page=vietshield-firewall&show_googlebot=1')); ?>" class="button">
                                <span class="dashicons dashicons-visibility" style="font-size: 16px; width: 16px; height: 16px; margin-right: 3px; vertical-align: middle;"></span>
                                <?php esc_html_e('Show IPs', 'vietshield-waf'); ?>
                            </a>
                        <?php endif; ?>
                    <?php endif; ?>
                    <?php if ($vswaf_googlebot_enabled): ?>
                        <button type="button" id="sync-googlebot-btn" class="button button-primary">
                            <span class="dashicons dashicons-update" style="font-size: 16px; width: 16px; height: 16px; margin-right: 3px; vertical-align: middle;"></span>
                            <?php esc_html_e('Sync Now', 'vietshield-waf'); ?>
                        </button>
                    <?php else: ?>
                        <a href="<?php echo esc_url(admin_url('admin.php?page=vietshield-settings#firewall')); ?>" class="button button-primary">
                            <?php esc_html_e('Enable in Settings', 'vietshield-waf'); ?>
                        </a>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <!-- Tabs -->
    <div class="vietshield-tabs">
        <button class="tab-btn active" data-tab="whitelist">
            <span class="dashicons dashicons-yes"></span>
            <?php esc_html_e('Whitelist', 'vietshield-waf'); ?>
            <span class="count"><?php echo count($vswaf_whitelist); ?></span>
        </button>
        <button class="tab-btn" data-tab="blacklist">
            <span class="dashicons dashicons-no"></span>
            <?php esc_html_e('Blacklist', 'vietshield-waf'); ?>
            <span class="count"><?php echo count($vswaf_blacklist); ?></span>
        </button>
        <button class="tab-btn" data-tab="temporary">
            <span class="dashicons dashicons-clock"></span>
            <?php esc_html_e('Temporary Blocks', 'vietshield-waf'); ?>
            <span class="count"><?php echo count($vswaf_temporary); ?></span>
        </button>
    </div>

    <!-- Whitelist Tab -->
    <div class="tab-content active" id="tab-whitelist">
        <div class="vietshield-card">
            <div class="card-body">
                <?php if ($vswaf_googlebot_count > 0): ?>
                    <div class="notice notice-info inline" style="margin: 0 0 15px 0;">
                        <p style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                            <span style="display: flex; align-items: center; gap: 5px;">
                                <span class="dashicons dashicons-google"></span>
                                <?php
                                /* translators: %s: number of Googlebot IP ranges */
                                printf(esc_html__('%s Googlebot IP ranges are whitelisted.', 'vietshield-waf'), '<strong>' . esc_html($vswaf_googlebot_count) . '</strong>');
                                ?>
                            </span>
                            <?php if ($vswaf_show_googlebot): ?>
                                <a href="<?php echo esc_url(admin_url('admin.php?page=vietshield-firewall')); ?>" class="button button-small">
                                    <span class="dashicons dashicons-hidden" style="font-size: 14px; width: 14px; height: 14px; margin-right: 3px;"></span>
                                    <?php esc_html_e('Hide Googlebot IPs', 'vietshield-waf'); ?>
                                </a>
                            <?php else: ?>
                                <a href="<?php echo esc_url(admin_url('admin.php?page=vietshield-firewall&show_googlebot=1')); ?>" class="button button-small">
                                    <span class="dashicons dashicons-visibility" style="font-size: 14px; width: 14px; height: 14px; margin-right: 3px;"></span>
                                    <?php esc_html_e('Show Googlebot IPs', 'vietshield-waf'); ?>
                                </a>
                            <?php endif; ?>
                            <a href="<?php echo esc_url(admin_url('admin.php?page=vietshield-settings')); ?>"><?php esc_html_e('Manage in Settings', 'vietshield-waf'); ?></a>
                        </p>
                    </div>
                <?php endif; ?>

                <?php if (empty($vswaf_whitelist)): ?>
                    <div class="empty-state">
                        <span class="dashicons dashicons-info"></span>
                        <p><?php esc_html_e('No IPs in whitelist.', 'vietshield-waf'); ?></p>
                    </div>
                <?php else: ?>
                    <table class="vietshield-table">
                        <thead>
                            <tr>
                                <th><?php esc_html_e('IP Address', 'vietshield-waf'); ?></th>
                                <th><?php esc_html_e('Reason', 'vietshield-waf'); ?></th>
                                <th><?php esc_html_e('Added', 'vietshield-waf'); ?></th>
                                <th><?php esc_html_e('Actions', 'vietshield-waf'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($vswaf_whitelist as $vswaf_entry): ?>
                                <tr>
                                    <td><code><?php echo esc_html($vswaf_entry['ip_address'] ?: $vswaf_entry['ip_range']); ?></code></td>
                                    <td><?php echo esc_html($vswaf_entry['reason'] ?: '-'); ?></td>
                                    <td>
                                        <?php 
                                        require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
                                        echo esc_html(VietShield_Helpers::format_timestamp($vswaf_entry['created_at'], 'Y-m-d H:i:s'));
                                        ?>
                                    </td>
                                    <td>
                                        <button class="button button-small remove-ip-btn" 
                                                data-id="<?php echo esc_attr($vswaf_entry['id']); ?>">
                                            <?php esc_html_e('Remove', 'vietshield-waf'); ?>
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

    <!-- Blacklist Tab -->
    <div class="tab-content" id="tab-blacklist">
        <div class="vietshield-card">
            <div class="card-body">
                <?php if (empty($vswaf_blacklist)): ?>
                    <div class="empty-state">
                        <span class="dashicons dashicons-info"></span>
                        <p><?php esc_html_e('No IPs in blacklist.', 'vietshield-waf'); ?></p>
                    </div>
                <?php else: ?>
                    <table class="vietshield-table">
                        <thead>
                            <tr>
                                <th><?php esc_html_e('IP Address', 'vietshield-waf'); ?></th>
                                <th><?php esc_html_e('Reason', 'vietshield-waf'); ?></th>
                                <th><?php esc_html_e('Hit Count', 'vietshield-waf'); ?></th>
                                <th><?php esc_html_e('Added', 'vietshield-waf'); ?></th>
                                <th><?php esc_html_e('Actions', 'vietshield-waf'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($vswaf_blacklist as $vswaf_entry): ?>
                                <tr>
                                    <td><code><?php echo esc_html($vswaf_entry['ip_address'] ?: $vswaf_entry['ip_range']); ?></code></td>
                                    <td><?php echo esc_html($vswaf_entry['reason'] ?: '-'); ?></td>
                                    <td><?php echo esc_html($vswaf_entry['hit_count']); ?></td>
                                    <td>
                                        <?php 
                                        require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
                                        echo esc_html(VietShield_Helpers::format_timestamp($vswaf_entry['created_at'], 'Y-m-d H:i:s'));
                                        ?>
                                    </td>
                                    <td>
                                        <button class="button button-small remove-ip-btn" 
                                                data-id="<?php echo esc_attr($vswaf_entry['id']); ?>">
                                            <?php esc_html_e('Unblock', 'vietshield-waf'); ?>
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

    <!-- Temporary Tab -->
    <div class="tab-content" id="tab-temporary">
        <div class="vietshield-card">
            <div class="card-body">
                <?php if (empty($vswaf_temporary)): ?>
                    <div class="empty-state">
                        <span class="dashicons dashicons-info"></span>
                        <p><?php esc_html_e('No temporary blocks.', 'vietshield-waf'); ?></p>
                    </div>
                <?php else: ?>
                    <table class="vietshield-table">
                        <thead>
                            <tr>
                                <th><?php esc_html_e('IP Address', 'vietshield-waf'); ?></th>
                                <th><?php esc_html_e('Reason', 'vietshield-waf'); ?></th>
                                <th><?php esc_html_e('Expires', 'vietshield-waf'); ?></th>
                                <th><?php esc_html_e('Actions', 'vietshield-waf'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($vswaf_temporary as $vswaf_entry): ?>
                                <tr>
                                    <td><code><?php echo esc_html($vswaf_entry['ip_address'] ?: $vswaf_entry['ip_range']); ?></code></td>
                                    <td><?php echo esc_html($vswaf_entry['reason'] ?: '-'); ?></td>
                                    <td>
                                        <?php 
                                        if ($vswaf_entry['expires_at']) {
                                            $vswaf_expires = strtotime($vswaf_entry['expires_at']);
                                            if ($vswaf_expires > time()) {
                                                echo 'in ' . esc_html(human_time_diff($vswaf_expires));
                                            } else {
                                                echo '<span class="expired">Expired</span>';
                                            }
                                        }
                                        ?>
                                    </td>
                                    <td>
                                        <button class="button button-small remove-ip-btn" 
                                                data-id="<?php echo esc_attr($vswaf_entry['id']); ?>">
                                            <?php esc_html_e('Unblock', 'vietshield-waf'); ?>
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
</div>



    <?php include VIETSHIELD_PLUGIN_DIR . 'admin/views/partials/footer.php'; ?>
</div>
