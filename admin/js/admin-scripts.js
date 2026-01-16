/**
 * VietShield WAF Admin Scripts
 */
(function($) {
    'use strict';
    
    // Block IP button handler
    $(document).on('click', '.block-ip-btn', function(e) {
        e.preventDefault();
        
        var ip = $(this).data('ip');
        var $btn = $(this);
        
        // Skip if already blocked
        if ($btn.hasClass('button-disabled')) {
            return;
        }
        $btn.prop('disabled', true).text('Blocking...');
        
        $.post(vietshieldAdmin.ajaxUrl, {
            action: 'vietshield_block_ip',
            nonce: vietshieldAdmin.nonce,
            ip: ip,
            reason: 'Manually blocked from admin',
            duration: 0
        }, function(response) {
            if (response.success) {
                $btn.text('Blocked').removeClass('button-primary').addClass('button-disabled').prop('disabled', true);
                showNotice('success', 'IP ' + ip + ' has been blocked successfully.');
            } else {
                $btn.prop('disabled', false).text('Block IP');
                showNotice('error', response.data || 'Failed to block IP.');
            }
        }).fail(function() {
            $btn.prop('disabled', false).text('Block IP');
            showNotice('error', 'Request failed. Please try again.');
        });
    });
    
    // Unblock IP button handler
    $(document).on('click', '.unblock-ip-btn, .remove-ip-btn', function(e) {
        e.preventDefault();
        
        var ip = $(this).data('ip');
        var id = $(this).data('id');
        var $btn = $(this);
        var $row = $btn.closest('tr');
        $btn.prop('disabled', true).text('Removing...');
        
        $.post(vietshieldAdmin.ajaxUrl, {
            action: 'vietshield_unblock_ip',
            nonce: vietshieldAdmin.nonce,
            ip: ip,
            id: id
        }, function(response) {
            if (response.success) {
                $row.fadeOut(300, function() {
                    $(this).remove();
                });
                showNotice('success', 'IP has been removed from the list.');
            } else {
                $btn.prop('disabled', false).text('Remove');
                showNotice('error', response.data || 'Failed to remove IP.');
            }
        }).fail(function() {
            $btn.prop('disabled', false).text('Remove');
            showNotice('error', 'Request failed. Please try again.');
        });
    });
    
    // Clear logs button handler
    $('#clear-logs-btn').on('click', function(e) {
        e.preventDefault();
        
        if (!confirm(vietshieldAdmin.strings.confirmClearLogs)) {
            return;
        }
        
        var $btn = $(this);
        $btn.prop('disabled', true);
        
        $.post(vietshieldAdmin.ajaxUrl, {
            action: 'vietshield_clear_logs',
            nonce: vietshieldAdmin.nonce
        }, function(response) {
            if (response.success) {
                showNotice('success', 'All logs have been cleared.');
                // Reload page after 1 second
                setTimeout(function() {
                    location.reload();
                }, 1000);
            } else {
                $btn.prop('disabled', false);
                showNotice('error', response.data || 'Failed to clear logs.');
            }
        }).fail(function() {
            $btn.prop('disabled', false);
            showNotice('error', 'Request failed. Please try again.');
        });
    });
    
    // Add IP form handler
    $('#add-ip-form').on('submit', function(e) {
        e.preventDefault();
        
        var $form = $(this);
        var $btn = $form.find('button[type="submit"]');
        var formData = {
            action: 'vietshield_block_ip',
            nonce: vietshieldAdmin.nonce,
            ip: $('#ip-address').val(),
            reason: $('#reason').val(),
            duration: $('#list-type').val() === 'temporary' ? $('#duration').val() : 0,
            list_type: $('#list-type').val()
        };
        
        // For whitelist, use different action
        if (formData.list_type === 'whitelist') {
            formData.action = 'vietshield_whitelist_ip';
        }
        
        $btn.prop('disabled', true).text('Adding...');
        
        $.post(vietshieldAdmin.ajaxUrl, formData, function(response) {
            $btn.prop('disabled', false).text('Add IP');
            
            if (response.success) {
                showNotice('success', 'IP has been added to the list.');
                $form[0].reset();
                // Reload page after 1 second
                setTimeout(function() {
                    location.reload();
                }, 1000);
            } else {
                showNotice('error', response.data || 'Failed to add IP.');
            }
        }).fail(function() {
            $btn.prop('disabled', false).text('Add IP');
            showNotice('error', 'Request failed. Please try again.');
        });
    });
    
    // Show WordPress-style notice
    function showNotice(type, message) {
        var noticeClass = 'notice-error';
        if (type === 'success') noticeClass = 'notice-success';
        else if (type === 'warning') noticeClass = 'notice-warning';
        var $notice = $('<div class="notice ' + noticeClass + ' is-dismissible"><p>' + message + '</p><button type="button" class="notice-dismiss"><span class="screen-reader-text">Dismiss this notice.</span></button></div>');
        
        // Remove existing notices
        $('.vietshield-wrap > .notice').remove();
        
        // Add new notice after header
        $('.vietshield-header').after($notice);
        
        // Handle dismiss button click
        $notice.on('click', '.notice-dismiss', function() {
            $notice.fadeOut(300, function() {
                $(this).remove();
            });
        });
        
        // Auto dismiss after 5 seconds
        setTimeout(function() {
            $notice.fadeOut(300, function() {
                $(this).remove();
            });
        }, 5000);
    }
    
    // View request details
    $(document).on('click', '.view-details', function(e) {
        e.preventDefault();
        
        var id = $(this).data('id');
        var $modal = $('#request-modal');
        var $details = $('#request-details');
        
        $details.html('<div class="loading"><span class="spinner is-active"></span> Loading...</div>');
        $modal.show();
        
        // Fetch log details via AJAX
        $.post(vietshieldAdmin.ajaxUrl, {
            action: 'vietshield_get_log_details',
            nonce: vietshieldAdmin.nonce,
            log_id: id
        }, function(response) {
            if (response.success && response.data) {
                renderLogDetails(response.data, $details);
            } else {
                $details.html('<div class="error-message">Failed to load request details. ' + (response.data || '') + '</div>');
            }
        }).fail(function() {
            $details.html('<div class="error-message">Request failed. Please try again.</div>');
        });
    });
    
    // Render log details in modal
    function renderLogDetails(log, $container) {
        var html = '<div class="log-details">';
        
        // Basic Info Section
        html += '<div class="detail-section">';
        html += '<h4><span class="dashicons dashicons-info"></span> Basic Information</h4>';
        html += '<div class="detail-grid">';
        html += '<div class="detail-item"><label>Timestamp:</label><span>' + escapeHtml(log.formatted_timestamp || log.timestamp) + '</span></div>';
        html += '<div class="detail-item"><label>IP Address:</label><span><code>' + escapeHtml(log.ip) + '</code></span></div>';
        if (log.country) {
            html += '<div class="detail-item"><label>Country:</label><span>' + escapeHtml(log.country) + '</span></div>';
        }
        html += '<div class="detail-item"><label>Action:</label><span><span class="action-badge ' + escapeHtml(log.action) + '">' + escapeHtml(log.action) + '</span></span></div>';
        html += '<div class="detail-item"><label>Response Code:</label><span>' + escapeHtml(log.response_code) + '</span></div>';
        html += '</div>';
        html += '</div>';
        
        // Request Info Section
        html += '<div class="detail-section">';
        html += '<h4><span class="dashicons dashicons-admin-links"></span> Request Information</h4>';
        html += '<div class="detail-grid">';
        html += '<div class="detail-item"><label>Method:</label><span><span class="method-' + escapeHtml(log.request_method.toLowerCase()) + '">' + escapeHtml(log.request_method) + '</span></span></div>';
        html += '<div class="detail-item full-width"><label>Request URI:</label><span><code class="uri-display">' + escapeHtml(log.request_uri) + '</code></span></div>';
        
        // Parse and display GET parameters if URI contains query string
        var uri = log.request_uri || '';
        var queryIndex = uri.indexOf('?');
        if (queryIndex !== -1 && queryIndex < uri.length - 1) {
            var queryString = uri.substring(queryIndex + 1);
            try {
                var params = {};
                var pairs = queryString.split('&');
                for (var i = 0; i < pairs.length; i++) {
                    var pair = pairs[i].split('=');
                    var key = decodeURIComponent(pair[0] || '');
                    var value = decodeURIComponent(pair[1] || '');
                    if (key) {
                        params[key] = value;
                    }
                }
                if (Object.keys(params).length > 0) {
                    html += '<div class="detail-item full-width"><label>GET Parameters:</label>';
                    html += '<pre class="get-params">' + escapeHtml(JSON.stringify(params, null, 2)) + '</pre>';
                    html += '</div>';
                }
            } catch(e) {
                // If parsing fails, show raw query string
                html += '<div class="detail-item full-width"><label>Query String:</label><span><code>' + escapeHtml(queryString) + '</code></span></div>';
            }
        }
        
        if (log.referer) {
            html += '<div class="detail-item full-width"><label>Referer:</label><span><code>' + escapeHtml(log.referer) + '</code></span></div>';
        }
        html += '</div>';
        html += '</div>';
        
        // Attack Info Section (if blocked)
        if (log.action === 'blocked' || log.action === 'monitored' || log.action === 'rate_limited') {
            html += '<div class="detail-section">';
            html += '<h4><span class="dashicons dashicons-shield-alt"></span> Security Information</h4>';
            html += '<div class="detail-grid">';
            
            // Rate Limited - show rate info
            if (log.action === 'rate_limited' && log.rule_matched) {
                try {
                    var rateInfo = JSON.parse(log.rule_matched);
                    var endpointLabels = {
                        'global': 'Global Rate Limit',
                        'login': 'Login Rate Limit',
                        'xmlrpc': 'XML-RPC Rate Limit',
                        'api': 'API Rate Limit',
                        '404': '404 Rate Limit'
                    };
                    var endpointLabel = endpointLabels[rateInfo.endpoint] || rateInfo.endpoint;
                    
                    html += '<div class="detail-item"><label>Limit Type:</label><span><strong>' + escapeHtml(endpointLabel) + '</strong></span></div>';
                    html += '<div class="detail-item"><label>Request Count:</label><span class="rate-exceeded"><strong>' + rateInfo.current + '</strong> / ' + rateInfo.limit + '</span></div>';
                    html += '<div class="detail-item"><label>Time Window:</label><span>' + rateInfo.window + ' seconds</span></div>';
                } catch(e) {
                    // Fallback if not JSON
                    html += '<div class="detail-item full-width"><label>Details:</label><span>' + escapeHtml(log.rule_matched) + '</span></div>';
                }
            } else {
                // Normal attack info
                if (log.attack_type) {
                    html += '<div class="detail-item"><label>Attack Type:</label><span><span class="attack-type type-' + escapeHtml(log.attack_type) + '">' + escapeHtml(log.attack_type.toUpperCase()) + '</span></span></div>';
                }
                if (log.rule_matched && log.action !== 'rate_limited') {
                    html += '<div class="detail-item full-width"><label>Matched Pattern:</label><span><code class="matched-pattern">' + escapeHtml(log.rule_matched) + '</code></span></div>';
                }
            }
            
            if (log.severity) {
                html += '<div class="detail-item"><label>Severity:</label><span><span class="severity severity-' + escapeHtml(log.severity) + '">' + escapeHtml(log.severity.charAt(0).toUpperCase() + log.severity.slice(1)) + '</span></span></div>';
            }
            if (log.rule_id) {
                html += '<div class="detail-item"><label>Rule ID:</label><span><code>' + escapeHtml(log.rule_id) + '</code></span></div>';
            }
            if (log.block_id) {
                html += '<div class="detail-item"><label>Block ID:</label><span><code>' + escapeHtml(log.block_id) + '</code></span></div>';
            }
            html += '</div>';
            html += '</div>';
        }
        
        // User Agent Section
        if (log.user_agent) {
            html += '<div class="detail-section">';
            html += '<h4><span class="dashicons dashicons-admin-users"></span> User Agent</h4>';
            html += '<div class="detail-item full-width"><code class="user-agent">' + escapeHtml(log.user_agent) + '</code></div>';
            html += '</div>';
        }
        
        // POST Data Section - Always show for POST requests
        if (log.request_method === 'POST') {
            html += '<div class="detail-section">';
            html += '<h4><span class="dashicons dashicons-edit"></span> POST Data</h4>';
            
            if (!log.post_data || log.post_data === '' || log.post_data === '[]' || log.post_data.trim() === '') {
                html += '<p class="empty-data">No POST data captured (request may have empty body or data was filtered)</p>';
            } else {
                try {
                    // Try to parse as JSON
                    var postData = typeof log.post_data_parsed !== 'undefined' && log.post_data_parsed !== null 
                        ? log.post_data_parsed 
                        : JSON.parse(log.post_data);
                    
                    // Check if it's an empty array or object
                    if (Array.isArray(postData) && postData.length === 0) {
                        html += '<p class="empty-data">No POST data (empty array)</p>';
                    } else if (typeof postData === 'object' && postData !== null && Object.keys(postData).length === 0) {
                        html += '<p class="empty-data">No POST data (empty object)</p>';
                    } else {
                        // Format and display
                        html += '<pre class="post-data">' + escapeHtml(JSON.stringify(postData, null, 2)) + '</pre>';
                    }
                } catch(e) {
                    // If not JSON, display as raw text
                    html += '<pre class="post-data">' + escapeHtml(log.post_data) + '</pre>';
                }
            }
            html += '</div>';
        }
        
        html += '</div>';
        
        // Actions - outside of log-details div
        html += '<div class="detail-actions">';
        
        // Block IP button - check if already blocked
        var isBlocked = log.is_blocked || false;
        if (isBlocked) {
            html += '<button class="button button-disabled" disabled>Blocked</button>';
        } else {
            html += '<button class="button button-primary block-ip-btn" data-ip="' + escapeHtml(log.ip) + '">Block IP</button>';
        }
        
        html += '<button class="button button-secondary modal-close-btn" type="button">Close</button>';
        html += '</div>';
        
        $container.html(html);
    }
    
    function escapeHtml(text) {
        if (!text) return '';
        return $('<div>').text(text).html();
    }

    // Shared utility function for formatting bytes
    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        var sizes = ['B', 'KB', 'MB', 'GB'];
        var i = Math.floor(Math.log(bytes) / Math.log(1024));
        var value = (bytes / Math.pow(1024, i)).toFixed(2);
        return value + ' ' + sizes[i];
    }

    // Format number with commas
    function number_format(num) {
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    }
    
    // Initialize tooltips
    $('[data-tooltip]').each(function() {
        $(this).attr('title', $(this).data('tooltip'));
    });

    // File Scanner
    if ($('#vietshield-file-scanner').length) {
        var scanState = {
            scanId: null,
            page: 1,
            perPage: 50,
            status: ''
        };

        function loadScanResults() {
            var requestData = {
                action: 'vietshield_get_file_scan',
                nonce: vietshieldAdmin.nonce,
                page: scanState.page,
                per_page: scanState.perPage,
                status: scanState.status
            };
            if (scanState.scanId) {
                requestData.scan_id = scanState.scanId;
            }

            $.post(vietshieldAdmin.ajaxUrl, requestData, function(response) {
                if (!response.success || !response.data) {
                    renderScanEmpty('Failed to load scan results.');
                    return;
                }
                renderScanSummary(response.data.scan);
                renderScanItems(response.data.items || []);
                renderScanPagination(response.data.total_items || 0);
            }).fail(function() {
                renderScanEmpty('Request failed. Please try again.');
            });
        }

        function renderScanSummary(scan) {
            if (!scan) {
                $('#scan-total-files, #scan-ok-files, #scan-modified-files, #scan-missing-files, #scan-unknown-files').text('0');
                return;
            }
            $('#scan-total-files').text(scan.total_files || 0);
            $('#scan-ok-files').text(scan.ok_files || 0);
            $('#scan-modified-files').text(scan.modified_files || 0);
            $('#scan-missing-files').text(scan.missing_files || 0);
            $('#scan-unknown-files').text(scan.unknown_files || 0);
        }

        function renderScanItems(items) {
            var $tbody = $('#scan-results-table tbody');
            $tbody.empty();

            if (!items.length) {
                $tbody.html('<tr class="empty-row"><td colspan="6">No issues found for this filter.</td></tr>');
                return;
            }

            items.forEach(function(item) {
                var statusClass = 'scan-status-' + escapeHtml(item.status || 'unknown');
                var sizeText = item.file_size ? formatBytes(item.file_size) : '-';
                var mtimeText = item.file_mtime ? escapeHtml(item.file_mtime) : '-';

                var row = '<tr>' +
                    '<td><span class="scan-status ' + statusClass + '">' + escapeHtml(item.status || '') + '</span></td>' +
                    '<td><code>' + escapeHtml(item.file_path || '') + '</code></td>' +
                    '<td class="hash-col">' + (item.expected_hash ? '<code>' + escapeHtml(item.expected_hash) + '</code>' : '-') + '</td>' +
                    '<td class="hash-col">' + (item.actual_hash ? '<code>' + escapeHtml(item.actual_hash) + '</code>' : '-') + '</td>' +
                    '<td>' + sizeText + '</td>' +
                    '<td>' + mtimeText + '</td>' +
                    '</tr>';
                $tbody.append(row);
            });
        }

        function renderScanPagination(totalItems) {
            var $pagination = $('#scan-pagination');
            $pagination.empty();

            if (totalItems <= scanState.perPage) {
                return;
            }

            var totalPages = Math.ceil(totalItems / scanState.perPage);
            var prevDisabled = scanState.page <= 1 ? 'disabled' : '';
            var nextDisabled = scanState.page >= totalPages ? 'disabled' : '';

            var html = '<button class="button scan-page-prev" ' + prevDisabled + '>Previous</button>' +
                '<span class="scan-page-info">Page ' + scanState.page + ' of ' + totalPages + '</span>' +
                '<button class="button scan-page-next" ' + nextDisabled + '>Next</button>';
            $pagination.html(html);
        }

        function renderScanEmpty(message) {
            var $tbody = $('#scan-results-table tbody');
            $tbody.html('<tr class="empty-row"><td colspan="6">' + escapeHtml(message) + '</td></tr>');
        }

        $('#vietshield-run-scan').on('click', function(e) {
            e.preventDefault();
            var $btn = $(this);
            $btn.prop('disabled', true).text('Scanning...');

            $.post(vietshieldAdmin.ajaxUrl, {
                action: 'vietshield_start_file_scan',
                nonce: vietshieldAdmin.nonce
            }, function(response) {
                if (response.success && response.data) {
                    scanState.scanId = response.data.scan_id || null;
                    scanState.page = 1;
                    loadScanResults();
                    showNotice('success', 'File scan completed successfully.');
                } else {
                    showNotice('error', response.data || 'Failed to run scan.');
                }
                $btn.prop('disabled', false).html('<span class="dashicons dashicons-update"></span> Run Scan');
            }).fail(function() {
                showNotice('error', 'Request failed. Please try again.');
                $btn.prop('disabled', false).html('<span class="dashicons dashicons-update"></span> Run Scan');
            });
        });

        $('#scan-status-filter').on('change', function() {
            scanState.status = $(this).val();
            scanState.page = 1;
            loadScanResults();
        });

        $(document).on('click', '.scan-page-prev', function() {
            if (scanState.page > 1) {
                scanState.page--;
                loadScanResults();
            }
        });

        $(document).on('click', '.scan-page-next', function() {
            scanState.page++;
            loadScanResults();
        });

        // Clear file scan history
        $('#vietshield-clear-file-history').on('click', function(e) {
            e.preventDefault();
            
            if (!confirm('Are you sure you want to clear all file scan history? This action cannot be undone.')) {
                return;
            }
            
            var $btn = $(this);
            var originalHtml = $btn.html();
            $btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> Clearing...');
            
            $.post(vietshieldAdmin.ajaxUrl, {
                action: 'vietshield_clear_file_history',
                nonce: vietshieldAdmin.nonce
            }, function(response) {
                $btn.prop('disabled', false).html(originalHtml);
                
                if (response.success) {
                    showNotice('success', 'File scan history cleared successfully.');
                    scanState.scanId = null;
                    scanState.page = 1;
                    loadScanResults();
                } else {
                    showNotice('error', response.data || 'Failed to clear history.');
                }
            }).fail(function() {
                $btn.prop('disabled', false).html(originalHtml);
                showNotice('error', 'Request failed. Please try again.');
            });
        });

        // Initial load
        loadScanResults();
    }

    // Malware Scanner
    if ($('#vietshield-malware-scanner').length) {
        var malwareState = {
            scanId: null,
            page: 1,
            perPage: 50,
            severity: ''
        };

        function loadMalwareResults() {
            var requestData = {
                action: 'vietshield_get_malware_scan',
                nonce: vietshieldAdmin.nonce,
                page: malwareState.page,
                per_page: malwareState.perPage,
                severity: malwareState.severity
            };
            if (malwareState.scanId) {
                requestData.scan_id = malwareState.scanId;
            }

            $.post(vietshieldAdmin.ajaxUrl, requestData, function(response) {
                if (!response.success || !response.data) {
                    renderMalwareEmpty('Failed to load scan results.');
                    return;
                }
                renderMalwareSummary(response.data.scan);
                renderMalwareItems(response.data.items || []);
                renderMalwarePagination(response.data.total_items || 0);
            }).fail(function() {
                renderMalwareEmpty('Request failed. Please try again.');
            });
        }

        function renderMalwareSummary(scan) {
            if (!scan) {
                $('#malware-total-files, #malware-clean-files, #malware-infected-files, #malware-suspicious-files').text('0');
                return;
            }
            $('#malware-total-files').text(scan.total_files || 0);
            $('#malware-clean-files').text(scan.clean_files || 0);
            $('#malware-infected-files').text(scan.infected_files || 0);
            $('#malware-suspicious-files').text(scan.suspicious_files || 0);
        }

        function renderMalwareItems(items) {
            var $tbody = $('#malware-results-table tbody');
            $tbody.empty();

            if (!items.length) {
                $tbody.html('<tr class="empty-row"><td colspan="6">No issues found. Your site appears clean!</td></tr>');
                return;
            }

            items.forEach(function(item) {
                var severityClass = 'severity-' + escapeHtml(item.severity || 'low');
                var sizeText = item.file_size ? formatBytes(item.file_size) : '-';
                var mtimeText = item.file_mtime ? escapeHtml(item.file_mtime) : '-';
                var findingsCount = item.findings ? item.findings.length : 0;

                var row = '<tr data-item-id="' + item.id + '">' +
                    '<td><span class="severity ' + severityClass + '">' + escapeHtml((item.severity || 'low').toUpperCase()) + '</span></td>' +
                    '<td><code class="file-path-code">' + escapeHtml(item.file_path || '') + '</code></td>' +
                    '<td>' + escapeHtml(item.file_type || 'unknown') + '</td>' +
                    '<td><button class="button button-small view-malware-findings" data-findings=\'' + escapeAttr(JSON.stringify(item.findings || [])) + '\' data-filepath="' + escapeAttr(item.file_path) + '">' + findingsCount + ' finding(s)</button></td>' +
                    '<td>' + sizeText + '</td>' +
                    '<td>' + mtimeText + '</td>' +
                    '</tr>';
                $tbody.append(row);
            });
        }

        function renderMalwarePagination(totalItems) {
            var $pagination = $('#malware-pagination');
            $pagination.empty();

            if (totalItems <= malwareState.perPage) {
                return;
            }

            var totalPages = Math.ceil(totalItems / malwareState.perPage);
            var prevDisabled = malwareState.page <= 1 ? 'disabled' : '';
            var nextDisabled = malwareState.page >= totalPages ? 'disabled' : '';

            var html = '<button class="button malware-page-prev" ' + prevDisabled + '>Previous</button>' +
                '<span class="malware-page-info">Page ' + malwareState.page + ' of ' + totalPages + '</span>' +
                '<button class="button malware-page-next" ' + nextDisabled + '>Next</button>';
            $pagination.html(html);
        }

        function renderMalwareEmpty(message) {
            var $tbody = $('#malware-results-table tbody');
            $tbody.html('<tr class="empty-row"><td colspan="6">' + escapeHtml(message) + '</td></tr>');
        }

        function escapeAttr(str) {
            if (!str) return '';
            return str.replace(/'/g, '&#39;').replace(/"/g, '&quot;');
        }

        $('#vietshield-run-malware-scan').on('click', function(e) {
            e.preventDefault();
            var $btn = $(this);
            var scope = $('#malware-scan-scope').val() || 'all';
            
            // Show scanning state with animation
            $btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> Scanning...');
            $('#malware-results-table tbody').html('<tr class="scanning-row"><td colspan="6"><span class="spinner is-active"></span> Scanning ' + scope + ' files for malware... This may take a moment.</td></tr>');
            
            // Reset stats to show scanning
            $('#malware-total-files, #malware-clean-files, #malware-infected-files, #malware-suspicious-files').text('...');

            $.post(vietshieldAdmin.ajaxUrl, {
                action: 'vietshield_start_malware_scan',
                nonce: vietshieldAdmin.nonce,
                scope: scope
            }, function(response) {
                if (response.success && response.data) {
                    malwareState.scanId = response.data.scan_id || null;
                    malwareState.page = 1;
                    loadMalwareResults();
                    
                    // Update last scan time
                    var now = new Date();
                    var timeStr = now.getFullYear() + '-' + String(now.getMonth()+1).padStart(2,'0') + '-' + String(now.getDate()).padStart(2,'0') + ' ' + String(now.getHours()).padStart(2,'0') + ':' + String(now.getMinutes()).padStart(2,'0') + ':' + String(now.getSeconds()).padStart(2,'0');
                    $('.scan-meta').find('div:contains("Last Scan")').html('<strong>Last Scan:</strong> ' + timeStr + ' (Scan #' + response.data.scan_id + ')');
                    
                    var msg = 'Malware scan #' + response.data.scan_id + ' completed (' + response.data.total_files + ' files scanned). ';
                    if (response.data.infected_files > 0) {
                        msg += response.data.infected_files + ' infected file(s) found!';
                        showNotice('error', msg);
                    } else if (response.data.suspicious_files > 0) {
                        msg += response.data.suspicious_files + ' suspicious file(s) found.';
                        showNotice('warning', msg);
                    } else {
                        msg += 'No threats detected.';
                        showNotice('success', msg);
                    }
                } else {
                    showNotice('error', response.data || 'Failed to run scan.');
                    loadMalwareResults(); // Reload previous results
                }
                $btn.prop('disabled', false).html('<span class="dashicons dashicons-search"></span> Run Scan');
            }).fail(function() {
                showNotice('error', 'Request failed. Please try again.');
                $btn.prop('disabled', false).html('<span class="dashicons dashicons-search"></span> Run Scan');
                loadMalwareResults(); // Reload previous results
            });
        });

        $('#malware-severity-filter').on('change', function() {
            malwareState.severity = $(this).val();
            malwareState.page = 1;
            loadMalwareResults();
        });

        $(document).on('click', '.malware-page-prev', function() {
            if (malwareState.page > 1) {
                malwareState.page--;
                loadMalwareResults();
            }
        });

        $(document).on('click', '.malware-page-next', function() {
            malwareState.page++;
            loadMalwareResults();
        });

        // View findings modal
        $(document).on('click', '.view-malware-findings', function(e) {
            e.preventDefault();
            var findingsRaw = $(this).attr('data-findings') || '[]';
            var filepath = $(this).attr('data-filepath') || '';
            var $modal = $('#malware-finding-modal');
            var $details = $('#malware-finding-details');

            // Parse findings JSON
            var findings = [];
            try {
                findings = JSON.parse(findingsRaw.replace(/&#39;/g, "'").replace(/&quot;/g, '"'));
            } catch(err) {
                console.error('Failed to parse findings:', err);
            }

            var html = '<div class="finding-filepath">';
            html += '<strong>File Path</strong>';
            html += '<code>' + escapeHtml(filepath) + '</code>';
            html += '</div>';
            
            if (!findings || !findings.length) {
                html += '<p style="text-align:center;color:#666;padding:20px;">No detailed findings available.</p>';
            } else {
                html += '<div class="findings-list">';
                findings.forEach(function(f) {
                    var severityClass = 'severity-' + (f.severity || 'low');
                    html += '<div class="finding-item">';
                    html += '<div class="finding-header">';
                    html += '<span class="severity ' + severityClass + '">' + escapeHtml((f.severity || 'low').toUpperCase()) + '</span>';
                    html += '<strong>' + escapeHtml(f.name || 'Unknown') + '</strong>';
                    html += '<span class="rule-id">' + escapeHtml(f.rule_id || '') + '</span>';
                    html += '</div>';
                    html += '<p class="finding-desc">' + escapeHtml(f.description || '') + '</p>';
                    if (f.matched || f.code_snippet) {
                        html += '<div class="finding-matched">';
                        html += '<strong>Matched Pattern</strong>';
                        
                        // Prefer code_snippet if available
                        var contentToShow = f.code_snippet || f.matched || '';
                        
                        if (!contentToShow) {
                            html += '<p style="color:#666;font-style:italic;">No pattern details available.</p>';
                        } else if (contentToShow.indexOf('\n') !== -1) {
                            // Multiline content - check if it's code snippet with line numbers
                            if (contentToShow.match(/^\s*\d+\s*\|/m)) {
                                // Code snippet with line numbers
                                var lines = contentToShow.split('\n');
                                html += '<pre class="matched-list"><code>';
                                lines.forEach(function(line) {
                                    if (!line.trim()) {
                                        html += '<div class="matched-list-line"></div>';
                                        return;
                                    }
                                    // Check if line starts with function name (format: "function() - desc")
                                    if (line.match(/^[a-zA-Z_][a-zA-Z0-9_]*\s*\(\)\s*-\s*/)) {
                                        // Function header line
                                        html += '<div class="matched-list-line" style="color:#60a5fa;font-weight:600;margin-top:8px;">' + escapeHtml(line) + '</div>';
                                    } else if (line.trim().startsWith('>>>')) {
                                        // Highlighted line (contains the match)
                                        html += '<div class="matched-list-line highlight">' + escapeHtml(line) + '</div>';
                                    } else if (line.match(/^\s*\d+\s*\|/)) {
                                        // Code line with line number
                                        html += '<div class="matched-list-line">' + escapeHtml(line) + '</div>';
                                    } else {
                                        // Regular line
                                        html += '<div class="matched-list-line">' + escapeHtml(line) + '</div>';
                                    }
                                });
                                html += '</code></pre>';
                            } else {
                                // Simple multiline text
                                html += '<pre class="matched-list"><code>' + escapeHtml(contentToShow) + '</code></pre>';
                            }
                        } else {
                            // Single line
                            html += '<code>' + escapeHtml(contentToShow) + '</code>';
                        }
                        html += '</div>';
                    }
                    html += '</div>';
                });
                html += '</div>';
            }

            $details.html(html);
            $modal.show();
        });

        // Close modal
        $(document).on('click', '#malware-finding-modal .modal-close, #malware-finding-modal .modal-close-btn, #malware-finding-modal .modal-overlay', function() {
            $('#malware-finding-modal').hide();
        });

        // Clear malware scan history
        $('#vietshield-clear-malware-history').on('click', function(e) {
            e.preventDefault();
            
            if (!confirm('Are you sure you want to clear all malware scan history? This action cannot be undone.')) {
                return;
            }
            
            var $btn = $(this);
            var originalHtml = $btn.html();
            $btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> Clearing...');
            
            $.post(vietshieldAdmin.ajaxUrl, {
                action: 'vietshield_clear_malware_history',
                nonce: vietshieldAdmin.nonce
            }, function(response) {
                $btn.prop('disabled', false).html(originalHtml);
                
                if (response.success) {
                    showNotice('success', 'Malware scan history cleared successfully.');
                    malwareState.scanId = null;
                    malwareState.page = 1;
                    loadMalwareResults();
                } else {
                    showNotice('error', response.data || 'Failed to clear history.');
                }
            }).fail(function() {
                $btn.prop('disabled', false).html(originalHtml);
                showNotice('error', 'Request failed. Please try again.');
            });
        });

        // Initial load
        loadMalwareResults();
    }

    // Threat Intelligence
    if ($('#threat-intel-category').length) {
        var threatIntelSyncing = false;

        // Auto-sync when category changes
        $('#threat-intel-category').on('change', function() {
            var category = $(this).val();
            if (!category) {
                return;
            }

            if (!confirm('Changing the category will clear existing data and sync the new feed. This may take a few minutes. Continue?')) {
                $(this).val($(this).data('old-value') || '');
                return;
            }

            $(this).data('old-value', category);
            syncThreatIntel(category);
        });

        // Manual sync
        $('#threat-intel-sync-btn').on('click', function(e) {
            e.preventDefault();
            var category = $('#threat-intel-category').val();
            if (!category) {
                alert('Please select a category first.');
                return;
            }
            syncThreatIntel(category);
        });

        // Clear data
        $('#threat-intel-clear-btn').on('click', function(e) {
            e.preventDefault();
            
            if (!confirm('Are you sure you want to clear all threat intelligence data? This action cannot be undone.')) {
                return;
            }

            var $btn = $(this);
            var originalHtml = $btn.html();
            $btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> Clearing...');

            $.post(vietshieldAdmin.ajaxUrl, {
                action: 'vietshield_clear_threat_intel',
                nonce: vietshieldAdmin.nonce
            }, function(response) {
                $btn.prop('disabled', false).html(originalHtml);
                
                if (response.success) {
                    showNotice('success', response.data.message || 'Threat intelligence data cleared successfully.');
                    updateThreatIntelStatus();
                } else {
                    showNotice('error', response.data || 'Failed to clear data.');
                }
            }).fail(function() {
                $btn.prop('disabled', false).html(originalHtml);
                showNotice('error', 'Request failed. Please try again.');
            });
        });

        function syncThreatIntel(category) {
            if (threatIntelSyncing) {
                return;
            }

            threatIntelSyncing = true;
            var $category = $('#threat-intel-category');
            var $syncBtn = $('#threat-intel-sync-btn');
            var $clearBtn = $('#threat-intel-clear-btn');
            
            $category.prop('disabled', true);
            $syncBtn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> Syncing...');
            $clearBtn.prop('disabled', true);

            // Show syncing message
            $('#threat-intel-status').html('<p class="description" style="color: #f59e0b;"><span class="dashicons dashicons-update spin"></span> Syncing feed... This may take a few minutes.</p>');

            $.post(vietshieldAdmin.ajaxUrl, {
                action: 'vietshield_sync_threat_intel',
                nonce: vietshieldAdmin.nonce,
                category: category
            }, function(response) {
                threatIntelSyncing = false;
                $category.prop('disabled', false);
                $syncBtn.prop('disabled', false).html('<span class="dashicons dashicons-update"></span> Sync Now');
                $clearBtn.prop('disabled', false);

                if (response.success) {
                    showNotice('success', response.data.message || 'Threat intelligence feed synced successfully.');
                    updateThreatIntelStatus();
                } else {
                    var errorMsg = response.data && response.data.message ? response.data.message : (response.data || 'Failed to sync feed.');
                    console.error('Threat Intel Sync Error:', response);
                    showNotice('error', errorMsg);
                    updateThreatIntelStatus();
                }
            }).fail(function(xhr, status, error) {
                threatIntelSyncing = false;
                $category.prop('disabled', false);
                $syncBtn.prop('disabled', false).html('<span class="dashicons dashicons-update"></span> Sync Now');
                $clearBtn.prop('disabled', false);
                console.error('Threat Intel Sync Request Failed:', status, error);
                showNotice('error', 'Request failed: ' + error + '. Please check console for details.');
                updateThreatIntelStatus();
            });
        }

        function updateThreatIntelStatus() {
            $.post(vietshieldAdmin.ajaxUrl, {
                action: 'vietshield_get_threat_intel_status',
                nonce: vietshieldAdmin.nonce
            }, function(response) {
                if (response.success) {
                    var status = response.data;
                    var html = '';
                    
                    if (status.count > 0) {
                        html += '<p><strong>IPs in Database:</strong> ' + number_format(status.count) + '</p>';
                        if (status.last_sync) {
                            html += '<p><strong>Last Sync:</strong> ' + escapeHtml(status.last_sync) + '</p>';
                        }
                        if (status.category) {
                            html += '<p><strong>Category:</strong> ' + escapeHtml(status.category.toUpperCase()) + '</p>';
                        }
                        if (status.next_sync) {
                            html += '<p><strong>Next Auto-Sync:</strong> ' + escapeHtml(status.next_sync) + '</p>';
                        }
                    } else {
                        html = '<p class="description">No threat intelligence data synced yet.</p>';
                    }
                    
                    $('#threat-intel-status').html(html);
                    
                    // Show/hide Clear button based on data
                    if (status.count > 0) {
                        $('#threat-intel-clear-btn').show();
                    } else {
                        $('#threat-intel-clear-btn').hide();
                    }
                } else {
                    console.error('Failed to get threat intel status:', response);
                }
            }).fail(function(xhr, status, error) {
                console.error('Threat Intel Status Request Failed:', status, error);
            });
        }

        // Initial status update
        updateThreatIntelStatus();
    }

    // Update early blocking toggle based on firewall mode
    function updateEarlyBlockingToggle() {
        var firewallMode = $('#firewall-mode-select').val();
        var wafEnabled = $('#waf-enabled-toggle').is(':checked');
        
        if (firewallMode === 'protecting' && wafEnabled) {
            $('#early-blocking-toggle').prop('disabled', false);
        } else {
            $('#early-blocking-toggle').prop('disabled', true);
        }
    }
    
    // Auto-enable Whitelist Admins when WAF is enabled
    function updateWhitelistAdminsToggle() {
        var wafEnabled = $('#waf-enabled-toggle').is(':checked');
        var $whitelistToggle = $('#whitelist-admins-toggle');
        
        if (wafEnabled) {
            // Enable the toggle and automatically check it
            $whitelistToggle.prop('disabled', false);
            if (!$whitelistToggle.is(':checked')) {
                $whitelistToggle.prop('checked', true);
            }
        } else {
            // Disable the toggle when WAF is off
            $whitelistToggle.prop('disabled', true);
        }
    }
    
    // Initialize on page load - only update early blocking toggle
    // Container visibility is controlled by PHP based on saved value
    $(document).ready(function() {
        updateEarlyBlockingToggle();
        updateWhitelistAdminsToggle();
        
        // Update early blocking toggle when firewall mode changes
        $('#firewall-mode-select').on('change', function() {
            updateEarlyBlockingToggle();
        });
        
        // Update whitelist admins toggle when WAF enabled changes
        $('#waf-enabled-toggle').on('change', function() {
            updateWhitelistAdminsToggle();
        });
    });
    
    // Firewall Mode change handler
    if ($('#firewall-mode-select').length) {
        $('#firewall-mode-select').on('change', function() {
            updateEarlyBlockingToggle();
        });
        
        // Initial update
        updateEarlyBlockingToggle();
    }

    // Early Blocking
    if ($('#early-blocking-sync-btn').length) {
        $('#early-blocking-sync-btn').on('click', function(e) {
            e.preventDefault();
            
            var $btn = $(this);
            var originalHtml = $btn.html();
            $btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> Syncing...');

            $.post(vietshieldAdmin.ajaxUrl, {
                action: 'vietshield_sync_early_blocker',
                nonce: vietshieldAdmin.nonce
            }, function(response) {
                $btn.prop('disabled', false).html(originalHtml);
                
                if (response.success) {
                    showNotice('success', response.data.message || 'Early blocker synced successfully.');
                    // Reload page to update stats
                    setTimeout(function() {
                        location.reload();
                    }, 1000);
                } else {
                    showNotice('error', response.data || 'Failed to sync early blocker.');
                }
            }).fail(function() {
                $btn.prop('disabled', false).html(originalHtml);
                showNotice('error', 'Request failed. Please try again.');
            });
        });
    }
    
})(jQuery);
