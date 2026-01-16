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
        return strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
    }
    
    /**
     * Get request URI
     */
    private function get_uri() {
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        // Decode URL to catch encoded attacks
        $uri = urldecode($uri);
        return $uri;
    }
    
    /**
     * Get query string
     */
    private function get_query_string() {
        return $_SERVER['QUERY_STRING'] ?? '';
    }
    
    /**
     * Get and sanitize GET parameters
     */
    private function get_get_params() {
        $params = [];
        
        foreach ($_GET as $key => $value) {
            $params[$key] = $this->normalize_value($value);
        }
        
        return $params;
    }
    
    /**
     * Get and sanitize POST parameters
     */
    private function get_post_params() {
        $params = [];
        
        // Handle JSON body
        $content_type = $this->get_content_type();
        if (strpos($content_type, 'application/json') !== false) {
            $body = $this->get_raw_body();
            $json = json_decode($body, true);
            if (is_array($json)) {
                return $this->normalize_array($json);
            }
        }
        
        // Handle regular POST
        foreach ($_POST as $key => $value) {
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
                $headers[$name] = $_SERVER[$header];
            }
        }
        
        return $headers;
    }
    
    /**
     * Get user agent
     */
    private function get_user_agent() {
        return $_SERVER['HTTP_USER_AGENT'] ?? '';
    }
    
    /**
     * Get referer
     */
    private function get_referer() {
        return $_SERVER['HTTP_REFERER'] ?? '';
    }
    
    /**
     * Get content type
     */
    private function get_content_type() {
        return $_SERVER['CONTENT_TYPE'] ?? '';
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
     */
    private function normalize_value($value) {
        if (is_array($value)) {
            return $this->normalize_array($value);
        }
        
        // Decode URL encoded values
        $value = urldecode($value);
        
        // Decode HTML entities
        $value = html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        
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
