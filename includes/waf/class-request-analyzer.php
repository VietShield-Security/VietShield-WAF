<?php
/**
 * Request Analyzer - Parse and normalize incoming requests
 * 
 * @package VietShield_WAF
 */

namespace VietShield\WAF;

if (!defined('ABSPATH')) {
    exit;
}

class RequestAnalyzer {
    
    /**
     * Analyze the current request
     * 
     * @return array Normalized request data
     */
    public function analyze() {
        return [
            'method' => $this->get_method(),
            'uri' => $this->get_uri(),
            'query_string' => $this->get_query_string(),
            'get' => $this->get_get_params(),
            'post' => $this->get_post_params(),
            'cookies' => $this->get_cookies(),
            'headers' => $this->get_headers(),
            'user_agent' => $this->get_user_agent(),
            'referer' => $this->get_referer(),
            'content_type' => $this->get_content_type(),
            'raw_body' => $this->get_raw_body(),
            'is_ajax' => $this->is_ajax(),
            'is_rest' => $this->is_rest_request(),
            'is_xmlrpc' => $this->is_xmlrpc(),
            'is_login' => $this->is_login_page(),
            'timestamp' => time(),
        ];
    }
    
    /**
     * Get request method
     */
    private function get_method() {
        return strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'] ?? 'GET')));
    }
    
    /**
     * Get request URI
     */
    private function get_uri() {
        // Do NOT use esc_url_raw() here - it strips non-http protocols and
        // modifies the URI before WAF inspection, which could allow bypasses.
        // We only sanitize with wp_unslash() to undo WordPress magic quotes.
        $uri = isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : '/';
        // Strip null bytes for safety
        $uri = str_replace(chr(0), '', $uri);
        // Decode URL to catch encoded attacks
        $uri = urldecode($uri);
        return $uri;
    }
    
    /**
     * Get query string
     */
    private function get_query_string() {
        return isset($_SERVER['QUERY_STRING']) ? sanitize_text_field(wp_unslash($_SERVER['QUERY_STRING'])) : '';
    }
    
    /**
     * WordPress parameter keys that should be excluded from WAF scanning
     * These contain legitimate content (HTML editors, code, encoded data) that
     * would cause false positives if scanned.
     */
    private static $wp_excluded_params = [
        // WordPress core editor fields
        'content',           // Post content (TinyMCE/Gutenberg editor)
        'post_content',      // Post content field
        'post_title',        // Post title (can contain special characters)
        'comment',           // Comment text
        'comment_content',   // Comment content field
        'description',       // Term/user description
        'excerpt',           // Post excerpt
        'post_excerpt',      // Post excerpt field
        'editor',            // Generic editor field
        'widget-text',       // Text widget
        'customized',        // Customizer data (JSON encoded)
        'wp_autosave',       // Autosave data
        // WordPress internal fields
        '_wp_http_referer',  // WordPress nonce referer
        '_wpnonce',          // WordPress nonce value
        's',                 // WordPress search query
        'tax_query',         // Taxonomy query (complex array)
        'meta_query',        // Meta query (complex array)
        // Page builder / plugin fields
        'acf',               // Advanced Custom Fields data
        'meta',              // Meta fields
        'data',              // Elementor/page builder data
        'css',               // Customizer CSS / inline styles
        'code',              // Code block content (Gutenberg)
        // WooCommerce fields
        'order_comments',    // WooCommerce order notes
        'billing_address_1', // WooCommerce billing address
        'shipping_address_1',// WooCommerce shipping address
        // Form plugin fields
        'form_fields',       // Generic form fields
        'wpforms',           // WPForms data
        'gform_fields',      // Gravity Forms data
        'gform_field_values',// Gravity Forms field values
        'input_values',      // Gravity Forms input values
        '_wpcf7',            // Contact Form 7 form ID
        'your-message',      // Contact Form 7 message field
        'your-name',         // Contact Form 7 name field
        'your-subject',      // Contact Form 7 subject field
        // Elementor / Page Builders
        'actions',           // Elementor form actions
        'editor_post_id',    // Elementor editor
        'initial_document_id',// Elementor initial document
        'elements',          // Elementor elements data
        'settings',          // Elementor/page builder settings
        // WPBakery / Visual Composer
        'vc_grid_data',      // Visual Composer grid
        'shortcode',         // Shortcode content
        'shortcodes',        // Multiple shortcodes
        // Divi Builder
        'et_pb_contact_message', // Divi contact form
        'modules',           // Divi modules data
        'et_builder_version',// Divi builder
        // Yoast SEO
        'yoast_wpseo_metadesc',  // Yoast meta description
        'yoast_wpseo_title',     // Yoast title
        'wpseo_title',           // Yoast title alt
        'wpseo_metadesc',        // Yoast meta desc alt
        // WooCommerce extended
        'product_description',   // WooCommerce product description
        'product_short_description', // WooCommerce short description
        'variation_description', // WooCommerce variation
        // ACF extended
        'acf_fields',       // Advanced Custom Fields
        'fields',            // ACF fields data
        // bbPress / BuddyPress
        'bbp_reply_content', // bbPress reply content
        'bbp_topic_content', // bbPress topic content
        'whats-new',         // BuddyPress activity
    ];

    /**
     * Get and sanitize GET parameters
     */
    private function get_get_params() {
        $params = [];

        foreach ($_GET as $key => $value) {
            // Skip WordPress excluded parameters to avoid false positives
            if (in_array($key, self::$wp_excluded_params, true)) {
                continue;
            }
            $params[$key] = $this->normalize_value($value);
        }

        return $params;
    }

    /**
     * Get and sanitize POST parameters
     */
    private function get_post_params() {
        $params = [];

        // Handle JSON body (REST API / Gutenberg)
        $content_type = $this->get_content_type();
        if (strpos($content_type, 'application/json') !== false) {
            $body = $this->get_raw_body();
            $json = json_decode($body, true);
            if (is_array($json)) {
                // Filter out excluded params from JSON body too
                // (Gutenberg sends content/title etc. as JSON fields)
                $filtered = array_diff_key($json, array_flip(self::$wp_excluded_params));
                return $this->normalize_array($filtered);
            }
        }

        // Handle regular POST
        foreach ($_POST as $key => $value) {
            // Skip WordPress excluded parameters to avoid false positives
            // on editor content, customizer data, etc.
            if (in_array($key, self::$wp_excluded_params, true)) {
                continue;
            }
            $params[$key] = $this->normalize_value($value);
        }

        return $params;
    }
    
    /**
     * Get cookies
     */
    private function get_cookies() {
        $cookies = [];
        
        // Skip sensitive WordPress cookies
        $skip_cookies = ['wordpress_logged_in_', 'wordpress_sec_', 'wp-settings-'];
        
        foreach ($_COOKIE as $key => $value) {
            // Skip sensitive cookies
            $skip = false;
            foreach ($skip_cookies as $prefix) {
                if (strpos($key, $prefix) === 0) {
                    $skip = true;
                    break;
                }
            }
            
            if (!$skip) {
                $cookies[$key] = $this->normalize_value($value);
            }
        }
        
        return $cookies;
    }
    
    /**
     * Get request headers
     */
    private function get_headers() {
        $headers = [];
        
        // Important headers to check
        $check_headers = [
            'HTTP_HOST',
            'HTTP_USER_AGENT',
            'HTTP_ACCEPT',
            'HTTP_ACCEPT_LANGUAGE',
            'HTTP_ACCEPT_ENCODING',
            'HTTP_REFERER',
            'HTTP_ORIGIN',
            'HTTP_X_REQUESTED_WITH',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED_HOST',
            'HTTP_X_FORWARDED_PROTO',
            'CONTENT_TYPE',
            'CONTENT_LENGTH',
        ];
        
        foreach ($check_headers as $header) {
            if (isset($_SERVER[$header])) {
                $name = str_replace(['HTTP_', '_'], ['', '-'], $header);
                $headers[$name] = sanitize_text_field(wp_unslash($_SERVER[$header]));
            }
        }
        
        return $headers;
    }
    
    /**
     * Get user agent
     */
    private function get_user_agent() {
        return isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
    }
    
    /**
     * Get referer
     */
    private function get_referer() {
        return sanitize_text_field($_SERVER['HTTP_REFERER'] ?? '');
    }
    
    /**
     * Get content type
     */
    private function get_content_type() {
        return isset($_SERVER['CONTENT_TYPE']) ? sanitize_text_field(wp_unslash($_SERVER['CONTENT_TYPE'])) : '';
    }
    
    /**
     * Get raw request body
     */
    private function get_raw_body() {
        static $body = null;
        
        if ($body === null) {
            $body = file_get_contents('php://input');
        }
        
        return $body;
    }
    
    /**
     * Check if AJAX request
     */
    private function is_ajax() {
        if (defined('DOING_AJAX') && DOING_AJAX) {
            return true;
        }
        
        if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && 
            strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if REST API request
     */
    private function is_rest_request() {
        $uri = $this->get_uri();
        
        // Check for /wp-json/ path
        if (strpos($uri, '/wp-json/') !== false) {
            return true;
        }
        
        // Check REST_REQUEST constant
        if (defined('REST_REQUEST') && REST_REQUEST) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if XML-RPC request
     */
    private function is_xmlrpc() {
        $uri = $this->get_uri();
        return strpos($uri, 'xmlrpc.php') !== false;
    }
    
    /**
     * Check if login page
     */
    private function is_login_page() {
        $uri = $this->get_uri();
        
        $login_paths = ['wp-login.php', 'wp-admin'];
        
        foreach ($login_paths as $path) {
            if (strpos($uri, $path) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Normalize a value (recursive for arrays)
     *
     * Note: PHP already URL-decodes $_GET/$_POST values automatically.
     * We only decode once more to catch double-encoded attacks, but we do NOT
     * apply html_entity_decode aggressively as it can transform legitimate
     * content (e.g., "&lt;script&gt;" in a blog comment) into attack patterns.
     */
    private function normalize_value($value) {
        if (is_array($value)) {
            return $this->normalize_array($value);
        }

        // Single URL decode pass to catch double-encoded attacks
        // (PHP already decoded once; this catches %2527 -> %27 -> ' type attacks)
        $decoded = urldecode($value);
        // Only use the decoded version if it actually changed (indicates double encoding)
        if ($decoded !== $value) {
            $value = $decoded;
        }

        // Decode numeric HTML entities to their actual characters for attack detection
        // e.g., &#60; -> '<', &#x3C; -> '<'
        // Do NOT decode named entities like &lt; &gt; - those are safe escaped content
        $value = preg_replace_callback('/&#x([0-9a-fA-F]+);/', function($m) {
            $char = chr(hexdec($m[1]));
            return ($char !== false) ? $char : $m[0];
        }, $value);
        $value = preg_replace_callback('/&#(\d+);/', function($m) {
            $code = (int) $m[1];
            return ($code > 0 && $code < 127) ? chr($code) : $m[0];
        }, $value);

        // Remove null bytes
        $value = str_replace(chr(0), '', $value);

        // Normalize whitespace
        $value = preg_replace('/\s+/', ' ', $value);

        return $value;
    }
    
    /**
     * Normalize array recursively
     */
    private function normalize_array($array) {
        $result = [];
        
        foreach ($array as $key => $value) {
            $result[$key] = $this->normalize_value($value);
        }
        
        return $result;
    }
    
    /**
     * Get all parameters combined (for scanning)
     */
    public function get_all_params() {
        $data = $this->analyze();
        
        $all_params = [];
        
        // Combine all scannable data
        $all_params['uri'] = $data['uri'];
        $all_params['query'] = $data['query_string'];
        $all_params = array_merge($all_params, $data['get']);
        $all_params = array_merge($all_params, $data['post']);
        $all_params = array_merge($all_params, $data['cookies']);
        $all_params['user_agent'] = $data['user_agent'];
        $all_params['referer'] = $data['referer'];
        
        return $all_params;
    }
}
