<?php
/**
 * VietShield WAF - GitHub Plugin Updater
 * 
 * Enables automatic updates from GitHub Releases
 *
 * @package VietShield
 * @since 1.0.5
 */

namespace VietShield;

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Plugin Updater Class
 * 
 * Hooks into WordPress update system to check for updates from GitHub Releases
 */
class PluginUpdater {
    
    /**
     * Plugin slug
     * @var string
     */
    private $plugin_slug = 'vietshield-waf';
    
    /**
     * Plugin basename (folder/file.php)
     * @var string
     */
    private $plugin_basename;
    
    /**
     * Current installed version
     * @var string
     */
    private $current_version;
    
    /**
     * GitHub username/organization
     * @var string
     */
    private $github_username = 'VietShield-Security';
    
    /**
     * GitHub repository name
     * @var string
     */
    private $github_repo = 'vietshield-waf';
    
    /**
     * Cache key for storing release data
     * @var string
     */
    private $cache_key = 'vietshield_github_release';
    
    /**
     * Cache TTL in seconds (12 hours)
     * @var int
     */
    private $cache_ttl = 43200;
    
    /**
     * Singleton instance
     * @var PluginUpdater|null
     */
    private static $instance = null;
    
    /**
     * Get singleton instance
     * 
     * @return PluginUpdater
     */
    public static function get_instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Constructor
     */
    private function __construct() {
        $this->plugin_basename = defined('VIETSHIELD_PLUGIN_BASENAME') 
            ? VIETSHIELD_PLUGIN_BASENAME 
            : 'vietshield-waf/vietshield-waf.php';
            
        $this->current_version = defined('VIETSHIELD_VERSION') 
            ? VIETSHIELD_VERSION 
            : '1.0.0';
    }
    
    /**
     * Initialize updater hooks
     */
    public function init() {
        // Hook into WordPress update check
        add_filter('pre_set_site_transient_update_plugins', [$this, 'check_for_update']);
        
        // Hook into plugin info dialog (View Details)
        add_filter('plugins_api', [$this, 'plugin_info'], 20, 3);
        
        // Clear cache after update
        add_action('upgrader_process_complete', [$this, 'after_update'], 10, 2);
        
        // Add custom update message
        add_action('in_plugin_update_message-' . $this->plugin_basename, [$this, 'update_message'], 10, 2);
    }
    
    /**
     * Check for plugin updates
     * 
     * @param object $transient Update transient data
     * @return object Modified transient
     */
    public function check_for_update($transient) {
        if (empty($transient->checked)) {
            return $transient;
        }
        
        // Get latest release from GitHub
        $release = $this->get_latest_release();
        
        if (!$release || !isset($release['version'])) {
            return $transient;
        }
        
        // Compare versions
        if ($this->is_newer_version($release['version'], $this->current_version)) {
            $transient->response[$this->plugin_basename] = (object) [
                'slug'        => $this->plugin_slug,
                'plugin'      => $this->plugin_basename,
                'new_version' => $release['version'],
                'url'         => $release['url'] ?? "https://github.com/{$this->github_username}/{$this->github_repo}",
                'package'     => $release['download_url'],
                'icons'       => [
                    '1x' => VIETSHIELD_PLUGIN_URL . 'assets/images/icon-128x128.png',
                    '2x' => VIETSHIELD_PLUGIN_URL . 'assets/images/icon-256x256.png',
                ],
                'banners'     => [
                    'low'  => VIETSHIELD_PLUGIN_URL . 'assets/images/banner-772x250.png',
                    'high' => VIETSHIELD_PLUGIN_URL . 'assets/images/banner-1544x500.png',
                ],
                'tested'      => $release['tested'] ?? '',
                'requires_php' => $release['requires_php'] ?? '7.4',
                'requires'    => $release['requires'] ?? '5.0',
            ];
        } else {
            // No update available - ensure it's in no_update list
            $transient->no_update[$this->plugin_basename] = (object) [
                'slug'        => $this->plugin_slug,
                'plugin'      => $this->plugin_basename,
                'new_version' => $this->current_version,
                'url'         => "https://github.com/{$this->github_username}/{$this->github_repo}",
            ];
        }
        
        return $transient;
    }
    
    /**
     * Plugin info for "View Details" popup
     * 
     * @param false|object|array $result The result object/array
     * @param string $action API action
     * @param object $args API arguments
     * @return false|object Plugin info or false
     */
    public function plugin_info($result, $action, $args) {
        // Only handle our plugin
        if ($action !== 'plugin_information') {
            return $result;
        }
        
        if (!isset($args->slug) || $args->slug !== $this->plugin_slug) {
            return $result;
        }
        
        // Get latest release
        $release = $this->get_latest_release();
        
        if (!$release) {
            return $result;
        }
        
        // Build plugin info object
        $plugin_info = (object) [
            'name'              => 'VietShield WAF',
            'slug'              => $this->plugin_slug,
            'version'           => $release['version'],
            'author'            => '<a href="https://github.com/VietShield-Security">VietShield Security</a>',
            'author_profile'    => 'https://github.com/VietShield-Security',
            'homepage'          => 'https://vietshield.org',
            'short_description' => 'High-performance Web Application Firewall (WAF) for WordPress.',
            'sections'          => [
                'description'  => $this->get_description_section(),
                'changelog'    => $this->format_changelog($release['changelog'] ?? ''),
                'installation' => $this->get_installation_section(),
            ],
            'download_link'     => $release['download_url'],
            'requires'          => $release['requires'] ?? '5.0',
            'tested'            => $release['tested'] ?? '',
            'requires_php'      => $release['requires_php'] ?? '7.4',
            'last_updated'      => $release['published_at'] ?? '',
            'icons'             => [
                '1x' => VIETSHIELD_PLUGIN_URL . 'assets/images/icon-128x128.png',
                '2x' => VIETSHIELD_PLUGIN_URL . 'assets/images/icon-256x256.png',
            ],
            'banners'           => [
                'low'  => VIETSHIELD_PLUGIN_URL . 'assets/images/banner-772x250.png',
                'high' => VIETSHIELD_PLUGIN_URL . 'assets/images/banner-1544x500.png',
            ],
        ];
        
        return $plugin_info;
    }
    
    /**
     * Clear cache after plugin update
     * 
     * @param \WP_Upgrader $upgrader Upgrader instance
     * @param array $options Update options
     */
    public function after_update($upgrader, $options) {
        if ($options['action'] !== 'update' || $options['type'] !== 'plugin') {
            return;
        }
        
        // Check if our plugin was updated
        if (isset($options['plugins']) && is_array($options['plugins'])) {
            if (in_array($this->plugin_basename, $options['plugins'], true)) {
                $this->clear_cache();
            }
        }
        
        // Single plugin update
        if (isset($options['plugin']) && $options['plugin'] === $this->plugin_basename) {
            $this->clear_cache();
        }
    }
    
    /**
     * Display custom update message
     * 
     * @param array $plugin_data Plugin data
     * @param object $response Update response
     */
    public function update_message($plugin_data, $response) {
        $release = $this->get_latest_release();
        
        if (!$release || empty($release['changelog'])) {
            return;
        }
        
        // Show brief changelog in update row
        $changelog_url = "https://github.com/{$this->github_username}/{$this->github_repo}/releases/tag/v{$release['version']}";
        
        echo '<br><span class="vietshield-update-message">';
        echo '<strong>' . esc_html__('What\'s new:', 'vietshield-waf') . '</strong> ';
        echo '<a href="' . esc_url($changelog_url) . '" target="_blank">';
        echo esc_html__('View changelog', 'vietshield-waf');
        echo '</a>';
        echo '</span>';
    }
    
    /**
     * Get latest release from GitHub API
     * 
     * @return array|null Release data or null
     */
    private function get_latest_release() {
        // Try to get from cache first
        $cached = $this->get_cached_release();
        if ($cached !== false) {
            return $cached;
        }
        
        // Fetch from GitHub API
        $api_url = "https://api.github.com/repos/{$this->github_username}/{$this->github_repo}/releases/latest";
        
        $response = wp_remote_get($api_url, [
            'timeout' => 15,
            'headers' => [
                'Accept'     => 'application/vnd.github.v3+json',
                'User-Agent' => 'VietShield-WAF/' . $this->current_version,
            ],
        ]);
        
        if (is_wp_error($response)) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log('VietShield Updater: GitHub API error - ' . $response->get_error_message());
            return null;
        }
        
        $response_code = wp_remote_retrieve_response_code($response);
        
        if ($response_code !== 200) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log("VietShield Updater: GitHub API returned {$response_code}");
            return null;
        }
        
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        
        if (json_last_error() !== JSON_ERROR_NONE || !is_array($data)) {
            return null;
        }
        
        // Parse and cache the release data
        $release = $this->parse_github_release($data);
        
        if ($release) {
            $this->set_cached_release($release);
        }
        
        return $release;
    }
    
    /**
     * Parse GitHub release response
     * 
     * @param array $data GitHub API response
     * @return array|null Parsed release data
     */
    private function parse_github_release($data) {
        if (empty($data['tag_name'])) {
            return null;
        }
        
        // Extract version from tag (remove 'v' prefix if present)
        $version = ltrim($data['tag_name'], 'vV');
        
        // Find the ZIP asset
        $download_url = null;
        if (!empty($data['assets']) && is_array($data['assets'])) {
            foreach ($data['assets'] as $asset) {
                if (isset($asset['name']) && $asset['name'] === 'vietshield-waf.zip') {
                    $download_url = $asset['browser_download_url'];
                    break;
                }
            }
        }
        
        // Fallback to zipball_url if no asset found
        if (!$download_url && !empty($data['zipball_url'])) {
            $download_url = $data['zipball_url'];
        }
        
        if (!$download_url) {
            return null;
        }
        
        // Parse release body for metadata
        $body = $data['body'] ?? '';
        $requires = '5.0';
        $tested = '';
        $requires_php = '7.4';
        
        // Try to extract metadata from release body
        // Format: Tested: 6.4, Requires: 5.0, Requires PHP: 7.4
        if (preg_match('/Tested:\s*([\d.]+)/i', $body, $match)) {
            $tested = $match[1];
        }
        if (preg_match('/Requires:\s*([\d.]+)/i', $body, $match)) {
            $requires = $match[1];
        }
        if (preg_match('/Requires PHP:\s*([\d.]+)/i', $body, $match)) {
            $requires_php = $match[1];
        }
        
        return [
            'version'       => $version,
            'download_url'  => $download_url,
            'changelog'     => $body,
            'published_at'  => $data['published_at'] ?? '',
            'url'           => $data['html_url'] ?? '',
            'requires'      => $requires,
            'tested'        => $tested,
            'requires_php'  => $requires_php,
        ];
    }
    
    /**
     * Get cached release data
     * 
     * @return array|false Cached data or false
     */
    private function get_cached_release() {
        return get_transient($this->cache_key);
    }
    
    /**
     * Set cached release data
     * 
     * @param array $data Release data
     */
    private function set_cached_release($data) {
        set_transient($this->cache_key, $data, $this->cache_ttl);
    }
    
    /**
     * Clear release cache
     */
    public function clear_cache() {
        delete_transient($this->cache_key);
    }
    
    /**
     * Compare versions
     * 
     * @param string $remote Remote version
     * @param string $local Local version
     * @return bool True if remote is newer
     */
    private function is_newer_version($remote, $local) {
        return version_compare($remote, $local, '>');
    }
    
    /**
     * Get description section HTML
     * 
     * @return string HTML content
     */
    private function get_description_section() {
        return '<p>VietShield WAF is a high-performance Web Application Firewall (WAF) for WordPress.</p>
        <h4>Features</h4>
        <ul>
            <li>Real-time protection against SQL Injection, XSS, RCE, and LFI attacks</li>
            <li>Threat Intelligence integration with automatic IP blocking</li>
            <li>Country-based blocking with allow/block modes</li>
            <li>Rate limiting to prevent brute force attacks</li>
            <li>CAPTCHA challenge for suspicious requests</li>
            <li>Login security with failed attempt tracking</li>
            <li>File integrity monitoring and malware scanning</li>
            <li>Detailed traffic logs and analytics</li>
        </ul>';
    }
    
    /**
     * Get installation section HTML
     * 
     * @return string HTML content
     */
    private function get_installation_section() {
        return '<ol>
            <li>Upload the plugin files to <code>/wp-content/plugins/vietshield-waf/</code></li>
            <li>Activate the plugin through the "Plugins" menu in WordPress</li>
            <li>Go to VietShield WAF menu to configure the firewall</li>
            <li>Complete the setup wizard for optimal protection</li>
        </ol>';
    }
    
    /**
     * Format changelog for display
     * 
     * @param string $changelog Raw changelog from GitHub
     * @return string Formatted HTML
     */
    private function format_changelog($changelog) {
        if (empty($changelog)) {
            return '<p>No changelog available.</p>';
        }
        
        // Convert markdown to HTML (basic conversion)
        $html = $changelog;
        
        // Convert headers
        $html = preg_replace('/^### (.+)$/m', '<h4>$1</h4>', $html);
        $html = preg_replace('/^## (.+)$/m', '<h3>$1</h3>', $html);
        $html = preg_replace('/^# (.+)$/m', '<h2>$1</h2>', $html);
        
        // Convert bold
        $html = preg_replace('/\*\*(.+?)\*\*/', '<strong>$1</strong>', $html);
        
        // Convert lists
        $html = preg_replace('/^- (.+)$/m', '<li>$1</li>', $html);
        $html = preg_replace('/(<li>.+<\/li>\n?)+/', '<ul>$0</ul>', $html);
        
        // Convert line breaks
        $html = nl2br($html);
        
        // Clean up
        $html = str_replace('<br /><ul>', '<ul>', $html);
        $html = str_replace('</ul><br />', '</ul>', $html);
        $html = str_replace('<br /><h', '<h', $html);
        $html = str_replace('</h2><br />', '</h2>', $html);
        $html = str_replace('</h3><br />', '</h3>', $html);
        $html = str_replace('</h4><br />', '</h4>', $html);
        
        return $html;
    }
    
    /**
     * Force check for updates (admin action)
     */
    public function force_check() {
        $this->clear_cache();
        delete_site_transient('update_plugins');
        wp_update_plugins();
    }
}
