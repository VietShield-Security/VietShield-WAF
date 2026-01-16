<?php
/**
 * Database Index Upgrade Script
 * 
 * This script checks and adds missing indexes to existing database tables.
 * Run this once to upgrade indexes for existing installations.
 * 
 * Usage: php upgrade-indexes.php
 * Or access via: /wp-content/plugins/vietshield-waf/upgrade-indexes.php?run=1
 */

// Load WordPress
$wp_load_path = dirname(dirname(dirname(dirname(__FILE__)))) . '/wp-load.php';
if (file_exists($wp_load_path)) {
    require_once $wp_load_path;
} else {
    die("Error: Cannot find wp-load.php. Please run this script from WordPress root or via web.\n");
}

// Security check for web access
if (php_sapi_name() !== 'cli') {
    if (!isset($_GET['run']) || $_GET['run'] !== '1') {
        die("Add ?run=1 to URL to execute. Or run via CLI: php upgrade-indexes.php\n");
    }
    // Check if user is admin
    if (!current_user_can('manage_options')) {
        die("Error: You must be an administrator to run this script.\n");
    }
}

// Load plugin activator
require_once __DIR__ . '/includes/class-vietshield-activator.php';

echo "=== VietShield WAF - Database Index Upgrade ===\n\n";

global $wpdb;

// List of tables to check
$tables = [
    'logs' => $wpdb->prefix . 'vietshield_logs',
    'ip_lists' => $wpdb->prefix . 'vietshield_ip_lists',
    'login_attempts' => $wpdb->prefix . 'vietshield_login_attempts',
    'file_scan_items' => $wpdb->prefix . 'vietshield_file_scan_items',
    'malware_scan_items' => $wpdb->prefix . 'vietshield_malware_scan_items',
];

$total_added = 0;
$total_checked = 0;

foreach ($tables as $table_key => $table_name) {
    echo "Checking table: {$table_name}...\n";
    
    // Check if table exists
    $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$table_name'") === $table_name;
    
    if (!$table_exists) {
        echo "  ⚠️  Table does not exist. Skipping.\n\n";
        continue;
    }
    
    $total_checked++;
    
    // Get existing indexes
    $existing_indexes_result = $wpdb->get_results("SHOW INDEXES FROM `$table_name`", ARRAY_A);
    $existing_indexes = [];
    foreach ($existing_indexes_result as $row) {
        $existing_indexes[] = $row['Key_name'];
    }
    $existing_indexes = array_unique($existing_indexes);
    
    echo "  Existing indexes: " . implode(', ', $existing_indexes) . "\n";
    
    // Define indexes to add
    $indexes_to_add = [];
    
    switch ($table_key) {
        case 'logs':
            $indexes_to_add = [
                'idx_user_id' => 'ADD INDEX idx_user_id (user_id)',
                'idx_country' => 'ADD INDEX idx_country (country)',
                'idx_ip_timestamp' => 'ADD INDEX idx_ip_timestamp (ip, timestamp)',
                'idx_action_timestamp' => 'ADD INDEX idx_action_timestamp (action, timestamp)',
                'idx_attack_type_timestamp' => 'ADD INDEX idx_attack_type_timestamp (attack_type, timestamp)',
                'idx_severity_timestamp' => 'ADD INDEX idx_severity_timestamp (severity, timestamp)',
            ];
            break;
            
        case 'ip_lists':
            $indexes_to_add = [
                'idx_list_type_created' => 'ADD INDEX idx_list_type_created (list_type, created_at)',
                'idx_list_type_expires' => 'ADD INDEX idx_list_type_expires (list_type, expires_at)',
            ];
            break;
            
        case 'login_attempts':
            $indexes_to_add = [
                'idx_username' => 'ADD INDEX idx_username (username)',
                'idx_ip_success_timestamp' => 'ADD INDEX idx_ip_success_timestamp (ip, success, timestamp)',
                'idx_success_timestamp' => 'ADD INDEX idx_success_timestamp (success, timestamp)',
            ];
            break;
            
        case 'file_scan_items':
            $indexes_to_add = [
                'idx_scan_status' => 'ADD INDEX idx_scan_status (scan_id, status)',
            ];
            break;
            
        case 'malware_scan_items':
            $indexes_to_add = [
                'idx_scan_severity' => 'ADD INDEX idx_scan_severity (scan_id, severity)',
                'idx_scan_quarantined' => 'ADD INDEX idx_scan_quarantined (scan_id, quarantined)',
            ];
            break;
    }
    
    // Add missing indexes
    $added_count = 0;
    foreach ($indexes_to_add as $index_name => $index_sql) {
        if (!in_array($index_name, $existing_indexes)) {
            echo "  ➕ Adding index: {$index_name}... ";
            
            $result = $wpdb->query("ALTER TABLE `$table_name` $index_sql");
            
            if ($result !== false) {
                echo "✅ Success\n";
                $added_count++;
                $total_added++;
            } else {
                echo "❌ Failed: " . $wpdb->last_error . "\n";
            }
        } else {
            echo "  ✓ Index {$index_name} already exists\n";
        }
    }
    
    if ($added_count > 0) {
        echo "  ✅ Added {$added_count} new index(es)\n";
    } else {
        echo "  ✓ All indexes are up to date\n";
    }
    
    echo "\n";
}

echo "=== Summary ===\n";
echo "Tables checked: {$total_checked}\n";
echo "Indexes added: {$total_added}\n";

if ($total_added > 0) {
    echo "\n✅ Database indexes have been successfully upgraded!\n";
    echo "Performance improvements should be noticeable immediately.\n";
} else {
    echo "\n✓ All database indexes are already up to date!\n";
}

echo "\nDone!\n";
