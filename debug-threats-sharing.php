<?php
/**
 * Debug script for Threats Sharing
 * Access via: /wp-content/plugins/vietshield-waf/debug-threats-sharing.php
 */

// Load WordPress
$wp_load = __DIR__ . '/../../../wp-load.php';
if (!file_exists($wp_load)) {
    $wp_load = __DIR__ . '/../../../../wp-load.php';
}
require_once($wp_load);

if (!defined('ABSPATH') || !current_user_can('manage_options')) {
    die('Access denied');
}

require_once(__DIR__ . '/includes/firewall/class-threats-sharing.php');

use VietShield\Firewall\ThreatsSharing;

header('Content-Type: text/plain; charset=utf-8');

echo "=== VietShield Threats Sharing Debug ===\n\n";

// 1. Check queue table
global $wpdb;
$table = $wpdb->prefix . 'vietshield_threats_queue';
$table_exists = $wpdb->get_var("SHOW TABLES LIKE '$table'") === $table;

echo "1. Queue Table Status:\n";
echo "   Table exists: " . ($table_exists ? "YES" : "NO") . "\n";

if ($table_exists) {
    $pending = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table WHERE submitted = 0");
    $submitted = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table WHERE submitted = 1");
    $failed = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table WHERE submitted = 0 AND retries >= 3");
    
    echo "   Pending IPs: $pending\n";
    echo "   Submitted IPs: $submitted\n";
    echo "   Failed IPs (max retries): $failed\n\n";
    
    // Show recent pending IPs with details
    if ($pending > 0) {
        echo "   Recent Pending IPs (last 10):\n";
        $recent = $wpdb->get_results("SELECT * FROM $table WHERE submitted = 0 ORDER BY created_at DESC LIMIT 10", ARRAY_A);
        foreach ($recent as $item) {
            echo "   - IP: {$item['ip']}\n";
            echo "     Attack Type: {$item['attack_type']}\n";
            echo "     Reason: {$item['reason']}\n";
            echo "     Severity: {$item['severity']}\n";
            echo "     Country: {$item['country_code']}\n";
            echo "     ASN: {$item['as_number']}\n";
            echo "     Retries: {$item['retries']}\n";
            echo "     Created: {$item['created_at']}\n";
            echo "     Updated: {$item['updated_at']}\n\n";
        }
    }
    
    // Show recent submitted IPs
    if ($submitted > 0) {
        echo "   Recent Submitted IPs (last 5):\n";
        $recent_submitted = $wpdb->get_results("SELECT * FROM $table WHERE submitted = 1 ORDER BY submitted_at DESC LIMIT 5", ARRAY_A);
        foreach ($recent_submitted as $item) {
            echo "   - IP: {$item['ip']} - Submitted: {$item['submitted_at']}\n";
        }
        echo "\n";
    }
} else {
    echo "   ERROR: Queue table does not exist!\n\n";
}

// 2. Check cron job
echo "2. Cron Job Status:\n";
$next_run = wp_next_scheduled('vietshield_submit_threats');
if ($next_run) {
    $next_run_time = date('Y-m-d H:i:s', $next_run);
    $time_until = $next_run - time();
    echo "   Next scheduled run: $next_run_time (in $time_until seconds)\n";
    
    // Check if cron is actually running
    $cron_array = _get_cron_array();
    $found = false;
    foreach ($cron_array as $timestamp => $cron) {
        if (isset($cron['vietshield_submit_threats'])) {
            $found = true;
            echo "   Cron found in cron array: YES\n";
            break;
        }
    }
    if (!$found) {
        echo "   WARNING: Cron not found in cron array!\n";
    }
} else {
    echo "   ERROR: Cron job not scheduled!\n";
    echo "   Attempting to schedule...\n";
    if (!wp_next_scheduled('vietshield_submit_threats')) {
        wp_schedule_event(time(), 'vietshield_5minutes', 'vietshield_submit_threats');
        echo "   Cron job scheduled!\n";
    }
}
echo "\n";

// 3. Get stats
echo "3. Queue Statistics:\n";
$stats = ThreatsSharing::get_stats();
echo "   Pending: {$stats['pending']}\n";
echo "   Submitted: {$stats['submitted']}\n";
echo "   Failed: {$stats['failed']}\n";
echo "   Last submission: " . ($stats['last_submission'] ?? 'Never') . "\n\n";

// 4. Test submit queue manually
if (isset($_GET['test_submit']) && $_GET['test_submit'] === '1') {
    echo "4. Manual Submit Test:\n";
    echo "   Submitting queue...\n";
    $submit_result = ThreatsSharing::submit_queue(10); // Submit max 10 for test
    echo "   Result: " . ($submit_result['success'] ? "SUCCESS" : "FAILED") . "\n";
    echo "   Message: " . ($submit_result['message'] ?? 'N/A') . "\n";
    echo "   Submitted: {$submit_result['submitted']}\n";
    echo "   Failed: {$submit_result['failed']}\n";
    echo "   Total: {$submit_result['total']}\n\n";
} else {
    echo "4. Manual Submit Test:\n";
    echo "   Add ?test_submit=1 to URL to test submission\n\n";
}

// 5. Check recent blocked IPs from logs
echo "5. Recent Blocked IPs from Logs (last 10):\n";
$log_table = $wpdb->prefix . 'vietshield_logs';
$recent_blocks = $wpdb->get_results(
    "SELECT ip, attack_type, rule_id, timestamp 
     FROM $log_table 
     WHERE action = 'blocked' 
     ORDER BY timestamp DESC 
     LIMIT 10",
    ARRAY_A
);

if (!empty($recent_blocks)) {
    foreach ($recent_blocks as $block) {
        // Check if IP is in queue
        $in_queue = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $table WHERE ip = %s",
            $block['ip']
        ));
        $queue_status = $in_queue > 0 ? "IN QUEUE" : "NOT IN QUEUE";
        echo "   - IP: {$block['ip']} | Type: {$block['attack_type']} | Rule: {$block['rule_id']} | Time: {$block['timestamp']} | $queue_status\n";
    }
} else {
    echo "   No recent blocked IPs found\n";
}
echo "\n";

// 6. Check API endpoint
echo "6. API Endpoint Test:\n";
$api_url = 'https://intelligence.vietshield.org/api/submit.php';
$test_response = wp_remote_get($api_url, [
    'method' => 'POST',
    'timeout' => 10,
    'sslverify' => true
]);

if (is_wp_error($test_response)) {
    echo "   ERROR: " . $test_response->get_error_message() . "\n";
} else {
    $code = wp_remote_retrieve_response_code($test_response);
    $body = wp_remote_retrieve_body($test_response);
    echo "   HTTP Status: $code\n";
    echo "   Response: " . substr($body, 0, 200) . "\n";
}
echo "\n";

echo "=== Debug Complete ===\n";
echo "\nTo manually trigger submission, visit: " . admin_url('admin.php?page=vietshield-settings') . "\n";
