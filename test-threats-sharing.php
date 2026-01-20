<?php
/**
 * Test script for Threats Sharing functionality
 * Run this from command line: php test-threats-sharing.php
 */

// Load WordPress
$wp_load = __DIR__ . '/../../../wp-load.php';
if (!file_exists($wp_load)) {
    $wp_load = __DIR__ . '/../../../../wp-load.php';
}
require_once($wp_load);

if (!defined('ABSPATH')) {
    die('WordPress not loaded');
}

require_once(__DIR__ . '/includes/firewall/class-threats-sharing.php');

use VietShield\Firewall\ThreatsSharing;

echo "=== VietShield Threats Sharing Test ===\n\n";

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
    
    // Show recent pending IPs
    if ($pending > 0) {
        echo "   Recent Pending IPs:\n";
        $recent = $wpdb->get_results("SELECT ip, reason, attack_type, created_at, retries FROM $table WHERE submitted = 0 ORDER BY created_at DESC LIMIT 5", ARRAY_A);
        foreach ($recent as $item) {
            echo "   - {$item['ip']} ({$item['attack_type']}) - {$item['reason']} - Retries: {$item['retries']} - Created: {$item['created_at']}\n";
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
} else {
    echo "   ERROR: Cron job not scheduled!\n";
}
echo "\n";

// 3. Test queue IP
echo "3. Test Queue IP:\n";
$test_ip = '192.0.2.1'; // Test IP (RFC 5737)
$result = ThreatsSharing::queue_ip($test_ip, 'Test reason', 'sqli', 'high', [
    'country_code' => 'US',
    'as_number' => 'AS12345',
    'organization' => 'Test Org'
]);
echo "   Queue test IP result: " . ($result ? "SUCCESS" : "FAILED") . "\n\n";

// 4. Get stats
echo "4. Queue Statistics:\n";
$stats = ThreatsSharing::get_stats();
echo "   Pending: {$stats['pending']}\n";
echo "   Submitted: {$stats['submitted']}\n";
echo "   Failed: {$stats['failed']}\n";
echo "   Last submission: " . ($stats['last_submission'] ?? 'Never') . "\n\n";

// 5. Test submit queue
if ($pending > 0 || $result) {
    echo "5. Test Submit Queue:\n";
    echo "   Submitting queue...\n";
    $submit_result = ThreatsSharing::submit_queue(5); // Submit max 5 for test
    echo "   Result: " . ($submit_result['success'] ? "SUCCESS" : "FAILED") . "\n";
    echo "   Message: " . ($submit_result['message'] ?? 'N/A') . "\n";
    echo "   Submitted: {$submit_result['submitted']}\n";
    echo "   Failed: {$submit_result['failed']}\n";
    echo "   Total: {$submit_result['total']}\n\n";
}

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

echo "=== Test Complete ===\n";
