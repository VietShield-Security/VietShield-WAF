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

<script>
jQuery(document).ready(function($) {
    var currentPage = 1;
    var isLive = true;
    var refreshInterval;
    
    function loadTraffic() {
        var filters = {
            action: 'vietshield_get_logs',
            nonce: vietshieldAdmin.nonce,
            page: currentPage,
            per_page: 50,
            action_filter: $('#filter-action').val(),
            attack_type: $('#filter-type').val(),
            ip: $('#filter-ip').val(),
            block_id: $('#filter-block-id').val(),
            search: $('#filter-search').val()
        };
        
        $.post(vietshieldAdmin.ajaxUrl, filters, function(response) {
            if (response.success) {
                renderTraffic(response.data);
            }
        });
    }
    
    function renderTraffic(data) {
        var tbody = $('#traffic-body');
        tbody.empty();
        
        if (data.logs.length === 0) {
            tbody.append('<tr><td colspan="11" class="empty-cell">' + vietshieldAdmin.strings.noData + '</td></tr>');
            return;
        }
        
        data.logs.forEach(function(log) {
            var safeAction = escapeHtml(log.action || '');
            var safeMethod = escapeHtml(log.request_method || 'GET');
            var safeAttackType = escapeHtml(log.attack_type || '');
            var safeIp = escapeHtml(log.ip || '');
            var safeBlockId = escapeHtml(log.block_id || '');
            var countryCode = escapeHtml(log.country_code || '');
            var asNumber = escapeHtml(log.as_number || '');
            var asName = escapeHtml(log.as_name || '');
            
            var actionButtons = '<button class="button button-small view-details" data-id="' + parseInt(log.id) + '">View</button> ';
            
            if (log.ip_status === 'blacklisted') {
                 // Already blacklisted - show Unblock
                 actionButtons += '<button class="button button-small unblock-ip-btn button-link-delete" data-ip="' + safeIp + '" title="<?php esc_attr_e('Unblock IP', 'vietshield-waf'); ?>">Unblock</button>';
            } else if (log.ip_status === 'temporary') {
                 // Temporary block - show Unblock (remove temp) or Blacklist (make permanent)
                 actionButtons += '<button class="button button-small unblock-ip-btn button-link-delete" data-ip="' + safeIp + '" title="<?php esc_attr_e('Unblock IP', 'vietshield-waf'); ?>">Unblock</button> ';
                 actionButtons += '<button class="button button-small block-ip-btn" data-ip="' + safeIp + '" title="<?php esc_attr_e('Permanently Blacklist', 'vietshield-waf'); ?>">Blacklist</button>';
            } else if (log.ip_status === 'whitelisted') {
                 // Whitelisted - show indicator
                 actionButtons += '<span class="dashicons dashicons-yes" title="<?php esc_attr_e('IP is Whitelisted', 'vietshield-waf'); ?>" style="color: #46b450; font-size: 20px; vertical-align: middle;"></span>';
            } else {
                 // Clean IP - show Block
                 actionButtons += '<button class="button button-small block-ip-btn" data-ip="' + safeIp + '" title="<?php esc_attr_e('Block IP', 'vietshield-waf'); ?>">Block</button>';
            }

            var row = '<tr class="action-' + safeAction + '">' +
                '<td class="col-time">' + formatTime(log.timestamp) + '</td>' +
                '<td class="col-ip"><code>' + safeIp + '</code>' + (log.ip_status_label ? ' <span class="ip-label ' + log.ip_status + '">' + log.ip_status_label + '</span>' : '') + '</td>' +
                '<td class="col-country">' + (countryCode ? '<span class="country-flag" title="' + countryCode + '">' + countryCode + '</span>' : '-') + '</td>' +
                '<td class="col-asn-number">' + (asNumber ? '<code>' + asNumber + '</code>' : '-') + '</td>' +
                '<td class="col-asn-name">' + (asName ? truncate(asName, 30) : '-') + '</td>' +
                '<td class="col-method"><span class="method-' + safeMethod.toLowerCase() + '">' + safeMethod + '</span></td>' +
                '<td class="col-uri" title="' + escapeHtml(log.request_uri || '') + '">' + truncate(log.request_uri, 50) + '</td>' +
                '<td class="col-action"><span class="action-badge ' + safeAction + '">' + safeAction + '</span></td>' +
                '<td class="col-type">' + (safeAttackType ? '<span class="attack-type type-' + safeAttackType + '">' + safeAttackType.toUpperCase() + '</span>' : '-') + '</td>' +
                '<td class="col-block-id">' + (safeBlockId ? '<code>' + safeBlockId + '</code>' : '-') + '</td>' +
                '<td class="col-actions">' + actionButtons + '</td>' +
            '</tr>';
            tbody.append(row);
        });
        
        // Update pagination
        // vietshieldAdmin.strings.page + ' ' + data.page + ' ' + vietshieldAdmin.strings.of + ' ' + data.pages
        var pageText = vietshieldAdmin.strings.page + ' ' + data.page + ' ' + vietshieldAdmin.strings.of + ' ' + data.pages;
        $('#page-info').text(pageText);
        $('#prev-page').prop('disabled', data.page <= 1);
        $('#next-page').prop('disabled', data.page >= data.pages);
    }
    
    function formatTime(timestamp) {
        // Parse MySQL timestamp (assumes it's already in configured timezone)
        var date = new Date(timestamp);
        if (isNaN(date.getTime())) {
            return timestamp; // Return original if invalid
        }
        // Format: YYYY-MM-DD HH:MM:SS
        var year = date.getFullYear();
        var month = String(date.getMonth() + 1).padStart(2, '0');
        var day = String(date.getDate()).padStart(2, '0');
        var hours = String(date.getHours()).padStart(2, '0');
        var minutes = String(date.getMinutes()).padStart(2, '0');
        var seconds = String(date.getSeconds()).padStart(2, '0');
        return year + '-' + month + '-' + day + ' ' + hours + ':' + minutes + ':' + seconds;
    }
    
    function escapeHtml(text) {
        if (!text) return '';
        return $('<div>').text(text).html();
    }
    
    function truncate(str, len) {
        if (!str) return '';
        // Escape HTML first, then truncate
        var escaped = escapeHtml(str);
        return escaped.length > len ? escaped.substring(0, len) + '...' : escaped;
    }
    
    // Start live refresh
    function startLive() {
        refreshInterval = setInterval(loadTraffic, 5000);
        isLive = true;
        $('#toggle-live').html('<span class="dashicons dashicons-controls-pause"></span> ' + vietshieldAdmin.strings.pause);
        $('#live-traffic-status .status-dot').addClass('live');
        $('#live-traffic-status .status-text').text(vietshieldAdmin.strings.liveStatus);
    }
    
    function stopLive() {
        clearInterval(refreshInterval);
        isLive = false;
        $('#toggle-live').html('<span class="dashicons dashicons-controls-play"></span> ' + vietshieldAdmin.strings.resume);
        $('#live-traffic-status .status-dot').removeClass('live');
        $('#live-traffic-status .status-text').text(vietshieldAdmin.strings.pausedStatus);
    }
    
    $('#toggle-live').on('click', function() {
        if (isLive) {
            stopLive();
        } else {
            startLive();
        }
    });
    
    // Pagination
    $('#prev-page').on('click', function() {
        if (currentPage > 1) {
            currentPage--;
            loadTraffic();
        }
    });
    
    $('#next-page').on('click', function() {
        currentPage++;
        loadTraffic();
    });
    
    // Filters
    $('#apply-filters').on('click', function() {
        currentPage = 1;
        loadTraffic();
    });
    
    // Modal close
    $(document).on('click', '.modal-close, .modal-close-btn, .modal-overlay', function(e) {
        // Don't close if clicking inside modal content (except close buttons)
        if ($(e.target).closest('.modal-content').length && 
            !$(e.target).hasClass('modal-close') && 
            !$(e.target).hasClass('modal-close-btn') &&
            !$(e.target).closest('.modal-close').length &&
            !$(e.target).closest('.modal-close-btn').length) {
            return;
        }
        $('#request-modal').hide();
    });
    
    // Initial load
    loadTraffic();
    startLive();
});
</script>

    <?php include VIETSHIELD_PLUGIN_DIR . 'admin/views/partials/footer.php'; ?>
</div>
