<?php
if (!defined('ABSPATH')) {
    exit;
}

// Filter out auto-synced Googlebot IPs for cleaner display
if (isset($whitelist) && is_array($whitelist)) {
    $whitelist_custom = array_filter($whitelist, function($entry) {
        return strpos($entry['reason'] ?? '', '[Googlebot]') === false;
    });
    // Keep original for referencing if needed, but use filtered for display
    $googlebot_count = count($whitelist) - count($whitelist_custom);
    $whitelist = $whitelist_custom;
} else {
    $whitelist = [];
    $googlebot_count = 0;
}
?>
<div class="wrap vietshield-wrap">
    <div class="vietshield-header">
        <div class="vietshield-logo">
            <span class="dashicons dashicons-shield"></span>
            <h1><?php _e('Firewall Management', 'vietshield-waf'); ?> <span style="font-size: 13px; color: #666; font-weight: 400; margin-left: 8px;">v<?php echo VIETSHIELD_VERSION; ?></span></h1>
        </div>
    </div>

    <!-- Add IP Form -->
    <div class="vietshield-card">
        <div class="card-header">
            <h2>
                <span class="dashicons dashicons-plus-alt"></span>
                <?php _e('Add IP to List', 'vietshield-waf'); ?>
            </h2>
        </div>
        <div class="card-body">
            <form id="add-ip-form" class="ip-add-form">
                <div class="form-row">
                    <div class="form-group">
                        <label for="ip-address"><?php _e('IP Address', 'vietshield-waf'); ?></label>
                        <input type="text" id="ip-address" name="ip" placeholder="192.168.1.1 or 192.168.1.0/24" required>
                    </div>
                    <div class="form-group">
                        <label for="list-type"><?php _e('List Type', 'vietshield-waf'); ?></label>
                        <select id="list-type" name="list_type">
                            <option value="whitelist"><?php _e('Whitelist (Allow)', 'vietshield-waf'); ?></option>
                            <option value="blacklist"><?php _e('Blacklist (Block)', 'vietshield-waf'); ?></option>
                            <option value="temporary"><?php _e('Temporary Block', 'vietshield-waf'); ?></option>
                        </select>
                    </div>
                    <div class="form-group duration-group" style="display:none;">
                        <label for="duration"><?php _e('Duration', 'vietshield-waf'); ?></label>
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
                        <label for="reason"><?php _e('Reason', 'vietshield-waf'); ?></label>
                        <input type="text" id="reason" name="reason" placeholder="Optional reason">
                    </div>
                    <div class="form-group">
                        <label>&nbsp;</label>
                        <button type="submit" class="button button-primary"><?php _e('Add IP', 'vietshield-waf'); ?></button>
                    </div>
                </div>
            </form>
        </div>
    </div>

    <!-- Tabs -->
    <div class="vietshield-tabs">
        <button class="tab-btn active" data-tab="whitelist">
            <span class="dashicons dashicons-yes"></span>
            <?php _e('Whitelist', 'vietshield-waf'); ?>
            <span class="count"><?php echo count($whitelist); ?></span>
        </button>
        <button class="tab-btn" data-tab="blacklist">
            <span class="dashicons dashicons-no"></span>
            <?php _e('Blacklist', 'vietshield-waf'); ?>
            <span class="count"><?php echo count($blacklist); ?></span>
        </button>
        <button class="tab-btn" data-tab="temporary">
            <span class="dashicons dashicons-clock"></span>
            <?php _e('Temporary Blocks', 'vietshield-waf'); ?>
            <span class="count"><?php echo count($temporary); ?></span>
        </button>
    </div>

    <!-- Whitelist Tab -->
    <div class="tab-content active" id="tab-whitelist">
        <div class="vietshield-card">
            <div class="card-body">
                <?php if ($googlebot_count > 0): ?>
                    <div class="notice notice-info inline" style="margin: 0 0 15px 0;">
                        <p>
                            <span class="dashicons dashicons-google"></span> 
                            <?php printf(__('%s Googlebot IP ranges are whitelisted and hidden from this view.', 'vietshield-waf'), '<strong>' . $googlebot_count . '</strong>'); ?>
                            <a href="<?php echo admin_url('admin.php?page=vietshield-settings'); ?>"><?php _e('Manage in Settings', 'vietshield-waf'); ?></a>
                        </p>
                    </div>
                <?php endif; ?>

                <?php if (empty($whitelist)): ?>
                    <div class="empty-state">
                        <span class="dashicons dashicons-info"></span>
                        <p><?php _e('No IPs in whitelist.', 'vietshield-waf'); ?></p>
                    </div>
                <?php else: ?>
                    <table class="vietshield-table">
                        <thead>
                            <tr>
                                <th><?php _e('IP Address', 'vietshield-waf'); ?></th>
                                <th><?php _e('Reason', 'vietshield-waf'); ?></th>
                                <th><?php _e('Added', 'vietshield-waf'); ?></th>
                                <th><?php _e('Actions', 'vietshield-waf'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($whitelist as $entry): ?>
                                <tr>
                                    <td><code><?php echo esc_html($entry['ip_address'] ?: $entry['ip_range']); ?></code></td>
                                    <td><?php echo esc_html($entry['reason'] ?: '-'); ?></td>
                                    <td>
                                        <?php 
                                        require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
                                        echo esc_html(VietShield_Helpers::format_timestamp($entry['created_at'], 'Y-m-d H:i:s'));
                                        ?>
                                    </td>
                                    <td>
                                        <button class="button button-small remove-ip-btn" 
                                                data-id="<?php echo esc_attr($entry['id']); ?>">
                                            <?php _e('Remove', 'vietshield-waf'); ?>
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
                <?php if (empty($blacklist)): ?>
                    <div class="empty-state">
                        <span class="dashicons dashicons-info"></span>
                        <p><?php _e('No IPs in blacklist.', 'vietshield-waf'); ?></p>
                    </div>
                <?php else: ?>
                    <table class="vietshield-table">
                        <thead>
                            <tr>
                                <th><?php _e('IP Address', 'vietshield-waf'); ?></th>
                                <th><?php _e('Reason', 'vietshield-waf'); ?></th>
                                <th><?php _e('Hit Count', 'vietshield-waf'); ?></th>
                                <th><?php _e('Added', 'vietshield-waf'); ?></th>
                                <th><?php _e('Actions', 'vietshield-waf'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($blacklist as $entry): ?>
                                <tr>
                                    <td><code><?php echo esc_html($entry['ip_address'] ?: $entry['ip_range']); ?></code></td>
                                    <td><?php echo esc_html($entry['reason'] ?: '-'); ?></td>
                                    <td><?php echo esc_html($entry['hit_count']); ?></td>
                                    <td>
                                        <?php 
                                        require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
                                        echo esc_html(VietShield_Helpers::format_timestamp($entry['created_at'], 'Y-m-d H:i:s'));
                                        ?>
                                    </td>
                                    <td>
                                        <button class="button button-small remove-ip-btn" 
                                                data-id="<?php echo esc_attr($entry['id']); ?>">
                                            <?php _e('Unblock', 'vietshield-waf'); ?>
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
                <?php if (empty($temporary)): ?>
                    <div class="empty-state">
                        <span class="dashicons dashicons-info"></span>
                        <p><?php _e('No temporary blocks.', 'vietshield-waf'); ?></p>
                    </div>
                <?php else: ?>
                    <table class="vietshield-table">
                        <thead>
                            <tr>
                                <th><?php _e('IP Address', 'vietshield-waf'); ?></th>
                                <th><?php _e('Reason', 'vietshield-waf'); ?></th>
                                <th><?php _e('Expires', 'vietshield-waf'); ?></th>
                                <th><?php _e('Actions', 'vietshield-waf'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($temporary as $entry): ?>
                                <tr>
                                    <td><code><?php echo esc_html($entry['ip_address'] ?: $entry['ip_range']); ?></code></td>
                                    <td><?php echo esc_html($entry['reason'] ?: '-'); ?></td>
                                    <td>
                                        <?php 
                                        if ($entry['expires_at']) {
                                            $expires = strtotime($entry['expires_at']);
                                            if ($expires > time()) {
                                                echo 'in ' . human_time_diff($expires);
                                            } else {
                                                echo '<span class="expired">Expired</span>';
                                            }
                                        }
                                        ?>
                                    </td>
                                    <td>
                                        <button class="button button-small remove-ip-btn" 
                                                data-id="<?php echo esc_attr($entry['id']); ?>">
                                            <?php _e('Unblock', 'vietshield-waf'); ?>
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

<script>
jQuery(document).ready(function($) {
    // Tab switching
    $('.tab-btn').on('click', function() {
        var tab = $(this).data('tab');
        
        $('.tab-btn').removeClass('active');
        $(this).addClass('active');
        
        $('.tab-content').removeClass('active');
        $('#tab-' + tab).addClass('active');
    });
    
    // Show/hide duration field
    $('#list-type').on('change', function() {
        if ($(this).val() === 'temporary') {
            $('.duration-group').show();
        } else {
            $('.duration-group').hide();
        }
    });
});
</script>

    <?php include VIETSHIELD_PLUGIN_DIR . 'admin/views/partials/footer.php'; ?>
</div>
