<?php
/**
 * File Scanner (Core Integrity)
 *
 * @package VietShield_WAF
 */

namespace VietShield\Scanner;

if (!defined('ABSPATH')) {
    exit;
}

class FileScanner {
    const STATUS_RUNNING = 'running';
    const STATUS_COMPLETED = 'completed';
    const STATUS_FAILED = 'failed';

    /**
     * Run a core file scan and store results.
     */
    public function run_scan() {
        global $wpdb;

        $table_scans = $wpdb->prefix . 'vietshield_file_scans';
        $table_items = $wpdb->prefix . 'vietshield_file_scan_items';

        $started_at = current_time('mysql', true);
        $core_version = get_bloginfo('version');

        $wpdb->insert($table_scans, [
            'started_at' => $started_at,
            'status' => self::STATUS_RUNNING,
            'core_version' => $core_version,
        ]);

        $scan_id = (int) $wpdb->insert_id;

        $summary = [
            'scan_id' => $scan_id,
            'status' => self::STATUS_RUNNING,
            'total_files' => 0,
            'ok_files' => 0,
            'modified_files' => 0,
            'missing_files' => 0,
            'unknown_files' => 0,
            'core_version' => $core_version,
            'started_at' => $started_at,
            'finished_at' => null,
        ];

        require_once ABSPATH . 'wp-admin/includes/update.php';
        $locale = get_locale();
        $checksums = \get_core_checksums($core_version, $locale);
        if (!is_array($checksums)) {
            $checksums = \get_core_checksums($core_version, 'en_US');
        }

        if (!is_array($checksums)) {
            $wpdb->update($table_scans, [
                'status' => self::STATUS_FAILED,
                'finished_at' => current_time('mysql', true),
                'notes' => 'Failed to fetch core checksums.',
            ], ['id' => $scan_id]);

            $summary['status'] = self::STATUS_FAILED;
            $summary['finished_at'] = current_time('mysql', true);
            return $summary;
        }

        $summary['total_files'] = count($checksums);
        $known_files = array_fill_keys(array_keys($checksums), true);

        foreach ($checksums as $relative => $expected_hash) {
            // Skip wp-content (themes, plugins, languages, uploads)
            if (strpos($relative, 'wp-content/') === 0) {
                continue;
            }
            
            // Skip files that are commonly modified legitimately
            if ($this->is_whitelisted_modified($relative)) {
                $summary['ok_files']++;
                continue;
            }
            
            $absolute = ABSPATH . $relative;
            
            // Skip missing files - only detect modified (per user request)
            if (!file_exists($absolute)) {
                // Don't log missing, just count for stats
                $summary['missing_files']++;
                continue;
            }

            $actual_hash = md5_file($absolute);
            if ($actual_hash !== $expected_hash) {
                $summary['modified_files']++;
                $this->insert_item($table_items, $scan_id, [
                    'file_path' => $relative,
                    'status' => 'modified',
                    'expected_hash' => $expected_hash,
                    'actual_hash' => $actual_hash,
                    'file_size' => filesize($absolute),
                    'file_mtime' => gmdate('Y-m-d H:i:s', filemtime($absolute)),
                    'file_type' => 'core',
                ]);
            } else {
                $summary['ok_files']++;
            }
        }

        // Detect unknown files in core directories
        $this->scan_unknown_core_files($scan_id, $table_items, $known_files, $summary);

        $finished_at = current_time('mysql', true);
        $wpdb->update($table_scans, [
            'finished_at' => $finished_at,
            'status' => self::STATUS_COMPLETED,
            'total_files' => $summary['total_files'],
            'ok_files' => $summary['ok_files'],
            'modified_files' => $summary['modified_files'],
            'missing_files' => $summary['missing_files'],
            'unknown_files' => $summary['unknown_files'],
        ], ['id' => $scan_id]);

        $summary['status'] = self::STATUS_COMPLETED;
        $summary['finished_at'] = $finished_at;

        return $summary;
    }

    /**
     * Get latest scan summary.
     */
    public function get_latest_scan() {
        global $wpdb;
        $table_scans = $wpdb->prefix . 'vietshield_file_scans';
        if (!$this->table_exists($table_scans)) {
            return null;
        }
        return $wpdb->get_row("SELECT * FROM {$table_scans} ORDER BY id DESC LIMIT 1", ARRAY_A);
    }

    /**
     * Get scan summary and items.
     */
    public function get_scan($scan_id, $args = []) {
        global $wpdb;

        $table_scans = $wpdb->prefix . 'vietshield_file_scans';
        $table_items = $wpdb->prefix . 'vietshield_file_scan_items';
        if (!$this->table_exists($table_scans) || !$this->table_exists($table_items)) {
            return null;
        }

        $scan = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table_scans} WHERE id = %d", $scan_id), ARRAY_A);
        if (!$scan) {
            return null;
        }

        $page = max(1, absint($args['page'] ?? 1));
        $per_page = max(1, min(200, absint($args['per_page'] ?? 50)));
        $offset = ($page - 1) * $per_page;
        $status = sanitize_text_field($args['status'] ?? '');

        $where = "WHERE scan_id = %d";
        $params = [$scan_id];
        if (!empty($status)) {
            $where .= " AND status = %s";
            $params[] = $status;
        }

        $total_items = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table_items} {$where}",
            $params
        ));

        $params[] = $per_page;
        $params[] = $offset;

        $items = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table_items} {$where} ORDER BY id DESC LIMIT %d OFFSET %d",
            $params
        ), ARRAY_A);

        return [
            'scan' => $scan,
            'items' => $items,
            'total_items' => (int) $total_items,
            'page' => $page,
            'per_page' => $per_page,
        ];
    }

    /**
     * Reschedule file scan cron based on options.
     */
    public static function reschedule($options) {
        $hook = 'vietshield_file_scan_event';
        wp_clear_scheduled_hook($hook);

        $enabled = !empty($options['file_scanner_enabled']);
        $schedule = $options['file_scan_schedule'] ?? 'manual';

        if (!$enabled || $schedule === 'manual') {
            return;
        }

        $recurrence = $schedule === 'weekly' ? 'weekly' : 'daily';
        wp_schedule_event(time(), $recurrence, $hook);
    }

    /**
     * Insert a scan item.
     */
    private function insert_item($table, $scan_id, $data) {
        global $wpdb;

        $wpdb->insert($table, [
            'scan_id' => $scan_id,
            'file_path' => $data['file_path'],
            'status' => $data['status'],
            'expected_hash' => $data['expected_hash'],
            'actual_hash' => $data['actual_hash'],
            'file_size' => $data['file_size'],
            'file_mtime' => $data['file_mtime'],
            'file_type' => $data['file_type'],
        ]);
    }

    /**
     * Scan for unknown files in core directories.
     */
    private function scan_unknown_core_files($scan_id, $table_items, $known_files, &$summary) {
        $core_dirs = ['wp-admin', 'wp-includes'];

        foreach ($core_dirs as $dir) {
            $base = ABSPATH . $dir;
            if (!is_dir($base)) {
                continue;
            }
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($base, \FilesystemIterator::SKIP_DOTS)
            );
            foreach ($iterator as $file) {
                if (!$file->isFile()) {
                    continue;
                }
                $relative = ltrim(str_replace(ABSPATH, '', $file->getPathname()), '/');
                if (isset($known_files[$relative])) {
                    continue;
                }
                if ($this->should_ignore_unknown($relative)) {
                    continue;
                }
                $summary['unknown_files']++;
                $this->insert_item($table_items, $scan_id, [
                    'file_path' => $relative,
                    'status' => 'unknown',
                    'expected_hash' => '',
                    'actual_hash' => md5_file($file->getPathname()),
                    'file_size' => $file->getSize(),
                    'file_mtime' => gmdate('Y-m-d H:i:s', $file->getMTime()),
                    'file_type' => 'core',
                ]);
            }
        }

        // Root files only
        $root = ABSPATH;
        $root_iterator = new \DirectoryIterator($root);
        foreach ($root_iterator as $file) {
            if ($file->isDot() || !$file->isFile()) {
                continue;
            }
            $relative = ltrim(str_replace(ABSPATH, '', $file->getPathname()), '/');
            if (isset($known_files[$relative])) {
                continue;
            }
            if ($this->should_ignore_unknown($relative)) {
                continue;
            }
            $summary['unknown_files']++;
            $this->insert_item($table_items, $scan_id, [
                'file_path' => $relative,
                'status' => 'unknown',
                'expected_hash' => '',
                'actual_hash' => md5_file($file->getPathname()),
                'file_size' => $file->getSize(),
                'file_mtime' => gmdate('Y-m-d H:i:s', $file->getMTime()),
                'file_type' => 'core',
            ]);
        }
    }

    /**
     * Check if file is whitelisted for modification (commonly modified by hosts/plugins).
     */
    private function is_whitelisted_modified($relative_path) {
        // Files that are commonly modified legitimately
        $whitelist = [
            // Often patched by security plugins or hosts
            'wp-includes/version.php',
            'wp-config-sample.php',
            
            // XML-RPC (often disabled/modified for security)
            'xmlrpc.php',
            
            // Cron (sometimes modified by managed hosts)
            'wp-cron.php',
            
            // Robots (sometimes customized)
            'robots.txt',
            
            // License/readme (sometimes removed for security)
            'license.txt',
            'readme.html',
            'wp-admin/install.php',
            'wp-admin/upgrade.php',
        ];
        
        return in_array($relative_path, $whitelist, true);
    }

    /**
     * Ignore files that are expected to be custom in WordPress root.
     */
    private function should_ignore_unknown($relative_path) {
        // Specific files to ignore
        $ignore_files = [
            'wp-config.php',
            '.htaccess',
            'web.config',
            'php.ini',
            'error_log',
            '.user.ini',
            'wp-cli.yml',
            'wp-cli.local.yml',
            '.maintenance',
            'sitemap.xml',
            'sitemap_index.xml',
            'robots.txt',
            'ads.txt',
            'app-ads.txt',
            'security.txt',
            '.well-known',
        ];

        if (in_array($relative_path, $ignore_files, true)) {
            return true;
        }

        // Ignore wp-content entirely
        if (strpos($relative_path, 'wp-content/') === 0) {
            return true;
        }

        // Ignore .well-known directory
        if (strpos($relative_path, '.well-known/') === 0) {
            return true;
        }

        // File extension patterns to ignore
        $ignore_extensions = [
            '.log',
            '.tmp',
            '.bak',
            '.backup',
            '.cache',
            '.swp',
            '.swo',
            '.DS_Store',
        ];
        
        foreach ($ignore_extensions as $ext) {
            if (substr($relative_path, -strlen($ext)) === $ext) {
                return true;
            }
        }
        
        // Ignore common cache/temp patterns
        $ignore_patterns = [
            '/cache/',
            '/tmp/',
            '/temp/',
            'object-cache.php',
            'advanced-cache.php',
            'db.php',
            'sunrise.php',
            'blog-deleted.php',
            'blog-inactive.php',
            'blog-suspended.php',
        ];
        
        foreach ($ignore_patterns as $pattern) {
            if (strpos($relative_path, $pattern) !== false) {
                return true;
            }
        }
        
        // Ignore hidden files (starting with .)
        $filename = basename($relative_path);
        if (strpos($filename, '.') === 0 && $filename !== '.htaccess') {
            return true;
        }

        return false;
    }

    /**
     * Check if a table exists.
     */
    private function table_exists($table_name) {
        global $wpdb;
        $like = $wpdb->esc_like($table_name);
        $result = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $like));
        return !empty($result);
    }
}
