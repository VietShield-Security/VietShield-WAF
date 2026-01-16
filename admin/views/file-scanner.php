<?php
if (!defined('ABSPATH')) {
    exit;
}

$options = get_option('vietshield_options', []);
$enabled = $options['file_scanner_enabled'] ?? true;
$schedule = $options['file_scan_schedule'] ?? 'weekly';
?>
<div class="wrap vietshield-wrap" id="vietshield-file-scanner">
    <div class="vietshield-header">
        <div class="vietshield-logo">
            <span class="dashicons dashicons-shield-alt"></span>
            <h1><?php _e('File Scanner', 'vietshield-waf'); ?> <span style="font-size: 13px; color: #666; font-weight: 400; margin-left: 8px;">v<?php echo VIETSHIELD_VERSION; ?></span></h1>
        </div>
        <div class="vietshield-status">
            <?php if ($enabled): ?>
                <span class="status-badge status-active">
                    <span class="dashicons dashicons-yes-alt"></span>
                    <?php _e('Scanner Enabled', 'vietshield-waf'); ?>
                </span>
            <?php else: ?>
                <span class="status-badge status-inactive">
                    <span class="dashicons dashicons-dismiss"></span>
                    <?php _e('Scanner Disabled', 'vietshield-waf'); ?>
                </span>
            <?php endif; ?>
        </div>
    </div>

    <div class="vietshield-card">
        <div class="card-header">
            <h2>
                <span class="dashicons dashicons-search"></span>
                <?php _e('Core Integrity Scan', 'vietshield-waf'); ?>
            </h2>
            <div class="header-actions">
                <button id="vietshield-run-scan" class="button button-primary" <?php disabled(!$enabled); ?>>
                    <span class="dashicons dashicons-update"></span>
                    <?php _e('Run Scan', 'vietshield-waf'); ?>
                </button>
                <button id="vietshield-clear-file-history" class="button button-secondary">
                    <span class="dashicons dashicons-trash"></span>
                    <?php _e('Clear History', 'vietshield-waf'); ?>
                </button>
            </div>
        </div>
        <div class="card-body">
            <p class="description">
                <?php _e('This scan checks WordPress core files against official checksums to detect modifications or unknown files in core directories (wp-admin, wp-includes).', 'vietshield-waf'); ?>
            </p>
            <div class="scan-meta">
                <div><strong><?php _e('Schedule:', 'vietshield-waf'); ?></strong> <?php echo esc_html(ucfirst($schedule)); ?></div>
                <div><strong><?php _e('Last Scan:', 'vietshield-waf'); ?></strong>
                    <?php
                    if (!empty($latest_scan['finished_at'])) {
                        require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
                        echo esc_html(\VietShield_Helpers::format_timestamp($latest_scan['finished_at'], 'Y-m-d H:i:s'));
                    } else {
                        echo esc_html__('Never', 'vietshield-waf');
                    }
                    ?>
                </div>
            </div>
        </div>
    </div>

    <div class="vietshield-stats-grid" id="vietshield-scan-stats">
        <div class="stat-card stat-total">
            <div class="stat-icon">
                <span class="dashicons dashicons-forms"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value" id="scan-total-files">0</div>
                <div class="stat-label"><?php _e('Total Core Files', 'vietshield-waf'); ?></div>
            </div>
        </div>
        <div class="stat-card stat-success">
            <div class="stat-icon">
                <span class="dashicons dashicons-yes-alt"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value" id="scan-ok-files">0</div>
                <div class="stat-label"><?php _e('Files OK', 'vietshield-waf'); ?></div>
            </div>
        </div>
        <div class="stat-card stat-blocked">
            <div class="stat-icon">
                <span class="dashicons dashicons-warning"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value" id="scan-modified-files">0</div>
                <div class="stat-label"><?php _e('Modified Files', 'vietshield-waf'); ?></div>
            </div>
        </div>
        <div class="stat-card stat-info" title="<?php esc_attr_e('Missing files are counted but not logged (most are intentionally removed)', 'vietshield-waf'); ?>">
            <div class="stat-icon">
                <span class="dashicons dashicons-info"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value" id="scan-missing-files">0</div>
                <div class="stat-label"><?php _e('Missing (Info Only)', 'vietshield-waf'); ?></div>
            </div>
        </div>
        <div class="stat-card stat-ips">
            <div class="stat-icon">
                <span class="dashicons dashicons-visibility"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value" id="scan-unknown-files">0</div>
                <div class="stat-label"><?php _e('Unknown Files', 'vietshield-waf'); ?></div>
            </div>
        </div>
    </div>

    <div class="vietshield-card">
        <div class="card-header">
            <h2>
                <span class="dashicons dashicons-list-view"></span>
                <?php _e('Scan Results', 'vietshield-waf'); ?>
            </h2>
            <div class="header-actions">
                <select id="scan-status-filter">
                    <option value=""><?php _e('All Issues', 'vietshield-waf'); ?></option>
                    <option value="modified"><?php _e('Modified', 'vietshield-waf'); ?></option>
                    <option value="unknown"><?php _e('Unknown', 'vietshield-waf'); ?></option>
                </select>
            </div>
        </div>
        <div class="card-body">
            <table class="vietshield-table" id="scan-results-table">
                <thead>
                    <tr>
                        <th><?php _e('Status', 'vietshield-waf'); ?></th>
                        <th><?php _e('File Path', 'vietshield-waf'); ?></th>
                        <th><?php _e('Expected Hash', 'vietshield-waf'); ?></th>
                        <th><?php _e('Actual Hash', 'vietshield-waf'); ?></th>
                        <th><?php _e('Size', 'vietshield-waf'); ?></th>
                        <th><?php _e('Modified Time', 'vietshield-waf'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <tr class="empty-row">
                        <td colspan="6"><?php _e('No scan results yet. Run a scan to view findings.', 'vietshield-waf'); ?></td>
                    </tr>
                </tbody>
            </table>
            <div class="scan-pagination" id="scan-pagination"></div>
        </div>
    </div>
    
    <?php include VIETSHIELD_PLUGIN_DIR . 'admin/views/partials/footer.php'; ?>
</div>
