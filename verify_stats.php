<?php
require_once '/www/wwwroot/anonychat.top/wp-load.php';
require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-scheduled-tasks.php';

echo "Checking cron schedule...\n";
$crons = _get_cron_array();
$found = false;
foreach ($crons as $ts => $hooks) {
    if (isset($hooks['vietshield_aggregate_stats'])) {
        $found = true;
        break;
    }
}
echo "Cron 'vietshield_aggregate_stats' found: " . ($found ? 'YES' : 'NO') . "\n";

echo "Running aggregation...\n";
VietShield_Scheduled_Tasks::aggregate_stats();

global $wpdb;
$table_stats = $wpdb->prefix . 'vietshield_stats';
$count = $wpdb->get_var("SELECT COUNT(*) FROM $table_stats");
echo "Stats table count: $count\n";

if ($count > 0) {
    $rows = $wpdb->get_results("SELECT * FROM $table_stats ORDER BY date DESC, hour DESC LIMIT 5");
    foreach ($rows as $row) {
        echo "Date: {$row->date}, Hour: {$row->hour}, Requests: {$row->total_requests}, Blocked: {$row->blocked}\n";
    }
} else {
    echo "Stats table is still empty.\n";
}
