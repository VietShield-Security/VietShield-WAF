<?php
if (!defined('ABSPATH')) {
    exit;
}
?>
<div class="wrap vietshield-wrap">
    <div class="vietshield-header">
        <div class="vietshield-logo">
            <span class="dashicons dashicons-shield"></span>
            <h1><?php esc_html_e('Live Traffic', 'vietshield-waf'); ?> <span style="font-size: 13px; color: #666; font-weight: 400; margin-left: 8px;">v<?php echo esc_html(VIETSHIELD_VERSION); ?></span></h1>
        </div>
        <div class="header-actions">
            <button id="toggle-live" class="button button-primary">
                <span class="dashicons dashicons-controls-pause"></span>
                <?php esc_html_e('Pause', 'vietshield-waf'); ?>
            </button>
            <button id="clear-logs-btn" class="button">
                <span class="dashicons dashicons-trash"></span>
                <?php esc_html_e('Clear Logs', 'vietshield-waf'); ?>
            </button>
        </div>
    </div>

    <!-- Filters -->
    <div class="vietshield-card">
        <div class="card-body">
            <div class="traffic-filters">
                <div class="filter-group">
                    <label for="filter-action"><?php esc_html_e('Action', 'vietshield-waf'); ?></label>
                    <select id="filter-action">
                        <option value=""><?php esc_html_e('All', 'vietshield-waf'); ?></option>
                        <option value="blocked"><?php esc_html_e('Blocked', 'vietshield-waf'); ?></option>
                        <option value="allowed"><?php esc_html_e('Allowed', 'vietshield-waf'); ?></option>
                        <option value="monitored"><?php esc_html_e('Monitored', 'vietshield-waf'); ?></option>
                        <option value="rate_limited"><?php esc_html_e('Rate Limited', 'vietshield-waf'); ?></option>
                    </select>
                </div>
                <div class="filter-group">
                    <label for="filter-type"><?php esc_html_e('Attack Type', 'vietshield-waf'); ?></label>
                    <select id="filter-type">
                        <option value=""><?php esc_html_e('All', 'vietshield-waf'); ?></option>
                        <option value="sqli"><?php esc_html_e('SQL Injection', 'vietshield-waf'); ?></option>
                        <option value="xss"><?php esc_html_e('XSS', 'vietshield-waf'); ?></option>
                        <option value="rce"><?php esc_html_e('RCE', 'vietshield-waf'); ?></option>
                        <option value="lfi"><?php esc_html_e('LFI', 'vietshield-waf'); ?></option>
                        <option value="bad_bot"><?php esc_html_e('Bad Bot', 'vietshield-waf'); ?></option>
                        <option value="brute_force"><?php esc_html_e('Brute Force', 'vietshield-waf'); ?></option>
                        <option value="threat_intel"><?php esc_html_e('Threat Intelligence', 'vietshield-waf'); ?></option>
                        <option value="enumeration"><?php esc_html_e('Enumeration', 'vietshield-waf'); ?></option>
                        <option value="rate_limit"><?php esc_html_e('Rate Limit', 'vietshield-waf'); ?></option>
                        <option value="xmlrpc"><?php esc_html_e('XML-RPC', 'vietshield-waf'); ?></option>
                        <option value="ssrf"><?php esc_html_e('SSRF', 'vietshield-waf'); ?></option>
                    </select>
                </div>
                <div class="filter-group">
                    <label for="filter-ip"><?php esc_html_e('IP Address', 'vietshield-waf'); ?></label>
                    <input type="text" id="filter-ip" placeholder="<?php esc_attr_e('Filter by IP', 'vietshield-waf'); ?>">
                </div>
                <div class="filter-group">
                    <label for="filter-block-id"><?php esc_html_e('Block ID', 'vietshield-waf'); ?></label>
                    <input type="text" id="filter-block-id" placeholder="<?php esc_attr_e('Filter by Block ID', 'vietshield-waf'); ?>">
                </div>
                <div class="filter-group">
                    <label for="filter-search"><?php esc_html_e('Search', 'vietshield-waf'); ?></label>
                    <input type="text" id="filter-search" placeholder="<?php esc_attr_e('Search in URI, UA...', 'vietshield-waf'); ?>">
                </div>
                <div class="filter-group">
                    <label>&nbsp;</label>
                    <button id="apply-filters" class="button"><?php esc_html_e('Apply Filters', 'vietshield-waf'); ?></button>
                </div>
            </div>
        </div>
    </div>

    <!-- Traffic Table -->
    <div class="vietshield-card">
        <div class="card-body">
            <div id="live-traffic-status" class="live-status">
                <span class="status-dot live"></span>
                <span class="status-text"><?php esc_html_e('Live - Auto-refreshing every 5 seconds', 'vietshield-waf'); ?></span>
            </div>
            
            <div class="table-responsive">
                <table class="vietshield-table traffic-table" id="traffic-table">
                    <thead>
                        <tr>
                            <th class="col-time"><?php esc_html_e('Time', 'vietshield-waf'); ?></th>
                            <th class="col-ip"><?php esc_html_e('IP', 'vietshield-waf'); ?></th>
                            <th class="col-country"><?php esc_html_e('Country', 'vietshield-waf'); ?></th>
                            <th class="col-asn-number"><?php esc_html_e('ASN Number', 'vietshield-waf'); ?></th>
                            <th class="col-asn-name"><?php esc_html_e('ASN Name', 'vietshield-waf'); ?></th>
                            <th class="col-method"><?php esc_html_e('Method', 'vietshield-waf'); ?></th>
                            <th class="col-uri"><?php esc_html_e('URI', 'vietshield-waf'); ?></th>
                            <th class="col-action"><?php esc_html_e('Action', 'vietshield-waf'); ?></th>
                            <th class="col-type"><?php esc_html_e('Type', 'vietshield-waf'); ?></th>
                            <th class="col-block-id"><?php esc_html_e('Block ID', 'vietshield-waf'); ?></th>
                            <th class="col-actions"><?php esc_html_e('Actions', 'vietshield-waf'); ?></th>
                        </tr>
                    </thead>
                    <tbody id="traffic-body">
                        <tr class="loading-row">
                            <td colspan="11">
                                <span class="spinner is-active"></span>
                                <?php esc_html_e('Loading traffic data...', 'vietshield-waf'); ?>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <!-- Pagination -->
            <div class="traffic-pagination">
                <button id="prev-page" class="button" disabled>&laquo; <?php esc_html_e('Previous', 'vietshield-waf'); ?></button>
                <span id="page-info"><?php esc_html_e('Page 1', 'vietshield-waf'); ?></span>
                <button id="next-page" class="button"><?php esc_html_e('Next', 'vietshield-waf'); ?> &raquo;</button>
            </div>
        </div>
    </div>

    <!-- Request Details Modal -->
    <div id="request-modal" class="vietshield-modal" style="display:none;">
        <div class="modal-overlay"></div>
        <div class="modal-content">
            <div class="modal-header">
                <h3><?php esc_html_e('Request Details', 'vietshield-waf'); ?></h3>
                <button class="modal-close" type="button">&times;</button>
            </div>
            <div class="modal-body" id="request-details">
                <!-- Details loaded via AJAX -->
            </div>
        </div>
    </div>
</div>



    <?php include VIETSHIELD_PLUGIN_DIR . 'admin/views/partials/footer.php'; ?>
</div>
