jQuery(document).ready(function ($) {
    /**
     * Firewall View Scripts
     */
    if ($('.vietshield-wrap .tab-btn').length) {
        // Tab switching
        $('.tab-btn').on('click', function () {
            var tab = $(this).data('tab');

            $('.tab-btn').removeClass('active');
            $(this).addClass('active');

            $('.tab-content').removeClass('active');
            $('#tab-' + tab).addClass('active');
        });

        // Show/hide duration field
        $('#list-type').on('change', function () {
            if ($(this).val() === 'temporary') {
                $('.duration-group').show();
            } else {
                $('.duration-group').hide();
            }
        });
    }

    /**
     * Settings View Scripts
     */
    if ($('#ip-whitelist-sync-btn').length) {
        // IP Whitelist Sync Button
        $('#ip-whitelist-sync-btn').on('click', function () {
            var $btn = $(this);
            var $status = $('#ip-whitelist-status');
            var originalText = $btn.html();

            $btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> Syncing...');

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'vietshield_sync_ip_whitelist',
                    nonce: vietshieldAdmin.nonce
                },
                success: function (response) {
                    if (response.success) {
                        var status = response.data.status;
                        var html = '<p><strong>' + (vietshieldAdmin.strings.lastSync || 'Last Sync:') + '</strong> ' + status.last_sync + '</p>';
                        if (status.googlebot_count > 0) {
                            html += '<p>Googlebot: ' + status.googlebot_count + ' IP ranges</p>';
                        }
                        if (status.cloudflare_count > 0) {
                            html += '<p>Cloudflare: ' + status.cloudflare_count + ' IP ranges</p>';
                        }
                        $status.html(html);
                        alert('IP whitelist synced successfully!');
                    } else {
                        alert('Sync failed: ' + response.data);
                    }
                },
                error: function () {
                    alert('An error occurred during sync.');
                },
                complete: function () {
                    $btn.prop('disabled', false).html(originalText);
                }
            });
        });
    }

    /**
     * Wizard View Scripts
     */
    if ($('.vietshield-wizard-wrap').length && typeof vswafWizardData !== 'undefined') {
        // Wizard logic

        // Save step data
        function saveStep(step, data) {
            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'vietshield_wizard_save',
                    nonce: vietshieldAdmin.nonce, // Assuming nonce is available globally or we need to pass it
                    step: step,
                    data: data
                }
            });
        }

        // Next button
        $('.wizard-next').on('click', function () {
            var step = parseInt($(this).data('step'));
            var data = {};

            if (step === 1) {
                // Step 1: Web server
                saveStep(1, vswafWizardData);
                var url = new URL(window.location.href);
                url.searchParams.set('step', '2');
                window.location.href = url.toString();
            } else if (step === 2) {
                // Step 2: Firewall mode
                var firewallMode = $('input[name="firewall_mode"]:checked').val();
                if (firewallMode === 'extended') {
                    firewallMode = 'protecting';
                }
                data.firewall_mode = firewallMode;
                saveStep(2, data);
                var url = new URL(window.location.href);
                url.searchParams.set('step', '3');
                window.location.href = url.toString();
            }
        });

        // Previous button
        $('.wizard-prev').on('click', function () {
            var step = parseInt($(this).data('step'));
            var url = new URL(window.location.href);
            if (step === 2) {
                url.searchParams.set('step', '1');
            } else if (step === 3) {
                url.searchParams.set('step', '2');
            }
            window.location.href = url.toString();
        });

        // Complete wizard
        $('.wizard-complete').on('click', function () {
            var firewallMode = $('input[name="firewall_mode"]:checked').val() || 'protecting';
            if (firewallMode === 'extended') {
                firewallMode = 'protecting';
            }
            var data = {
                firewall_mode: firewallMode,
                auto_optimize: $('input[name="auto_optimize"]:checked').length > 0 ? 1 : 0,
                webserver: vswafWizardData.webserver
            };

            $(this).prop('disabled', true).text('Setting up...');

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'vietshield_wizard_complete',
                    nonce: vietshieldAdmin.nonce,
                    data: data
                },
                success: function (response) {
                    if (response.success) {
                        window.location.href = response.data.redirect;
                    } else {
                        alert(response.data.message || 'An error occurred');
                        $('.wizard-complete').prop('disabled', false);
                    }
                },
                error: function () {
                    alert('An error occurred');
                    $('.wizard-complete').prop('disabled', false);
                }
            });
        });

        // Option card selection
        $('.option-card').on('click', function () {
            $('.option-card').removeClass('selected');
            $(this).addClass('selected');
            $(this).find('input[type="radio"]').prop('checked', true);
        });

        // Auto-optimize checkbox
        $('input[name="auto_optimize"]').on('change', function () {
            if ($(this).is(':checked')) {
                $('#optimize-features').slideDown();
            } else {
                $('#optimize-features').slideUp();
            }
        });
    }

    /**
     * Live Traffic View Scripts
     */
    if ($('#traffic-table').length) {
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

            $.post(vietshieldAdmin.ajaxUrl, filters, function (response) {
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

            data.logs.forEach(function (log) {
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
                    actionButtons += '<button class="button button-small unblock-ip-btn button-link-delete" data-ip="' + safeIp + '" title="Unblock IP">Unblock</button>';
                } else if (log.ip_status === 'temporary') {
                    actionButtons += '<button class="button button-small unblock-ip-btn button-link-delete" data-ip="' + safeIp + '" title="Unblock IP">Unblock</button> ';
                    actionButtons += '<button class="button button-small block-ip-btn" data-ip="' + safeIp + '" title="Permanently Blacklist">Blacklist</button>';
                } else if (log.ip_status === 'whitelisted') {
                    actionButtons += '<span class="dashicons dashicons-yes" title="IP is Whitelisted" style="color: #46b450; font-size: 20px; vertical-align: middle;"></span>';
                } else {
                    actionButtons += '<button class="button button-small block-ip-btn" data-ip="' + safeIp + '" title="Block IP">Block</button>';
                }

                var displayType = safeAttackType.toUpperCase();
                var row = '<tr class="action-' + safeAction + '">' +
                    '<td class="col-time">' + formatTime(log.timestamp) + '</td>' +
                    '<td class="col-ip"><code>' + safeIp + '</code></td>' +
                    '<td class="col-country">' + (countryCode ? '<span class="country-flag" title="' + countryCode + '">' + countryCode + '</span>' : '-') + '</td>' +
                    '<td class="col-asn-number">' + (asNumber ? '<code>' + asNumber + '</code>' : '-') + '</td>' +
                    '<td class="col-asn-name">' + (asName ? truncate(asName, 30) : '-') + '</td>' +
                    '<td class="col-method"><span class="method-' + safeMethod.toLowerCase() + '">' + safeMethod + '</span></td>' +
                    '<td class="col-uri" title="' + escapeHtml(log.request_uri || '') + '">' + truncate(log.request_uri, 50) + '</td>' +
                    '<td class="col-action"><span class="action-badge ' + safeAction + '">' + safeAction + '</span></td>' +
                    '<td class="col-type">' + (safeAttackType ? '<span class="attack-type type-' + safeAttackType + '">' + displayType + '</span>' : '-') + '</td>' +
                    '<td class="col-block-id">' + (safeBlockId ? '<code>' + safeBlockId + '</code>' : '-') + '</td>' +
                    '<td class="col-actions">' + actionButtons + '</td>' +
                    '</tr>';
                tbody.append(row);
            });

            var pageText = vietshieldAdmin.strings.page + ' ' + data.page + ' ' + vietshieldAdmin.strings.of + ' ' + data.pages;
            $('#page-info').text(pageText);
            $('#prev-page').prop('disabled', data.page <= 1);
            $('#next-page').prop('disabled', data.page >= data.pages);
        }

        function formatTime(timestamp) {
            return timestamp;
        }

        function escapeHtml(text) {
            if (!text) return '';
            return $('<div>').text(text).html();
        }

        function truncate(str, len) {
            if (!str) return '';
            var escaped = escapeHtml(str);
            return escaped.length > len ? escaped.substring(0, len) + '...' : escaped;
        }

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

        $('#toggle-live').on('click', function () {
            if (isLive) {
                stopLive();
            } else {
                startLive();
            }
        });

        $('#prev-page').on('click', function () {
            if (currentPage > 1) {
                currentPage--;
                loadTraffic();
            }
        });

        $('#next-page').on('click', function () {
            currentPage++;
            loadTraffic();
        });

        $('#apply-filters').on('click', function () {
            currentPage = 1;
            loadTraffic();
        });

        $(document).on('click', '.modal-close, .modal-close-btn, .modal-overlay', function (e) {
            if ($(e.target).closest('.modal-content').length &&
                !$(e.target).hasClass('modal-close') &&
                !$(e.target).hasClass('modal-close-btn') &&
                !$(e.target).closest('.modal-close').length &&
                !$(e.target).closest('.modal-close-btn').length) {
                return;
            }
            $('#request-modal').hide();
        });

        loadTraffic();
        startLive();
    }
});
