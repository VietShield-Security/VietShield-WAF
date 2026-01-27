<?php
/**
 * Threat Detector - Detect various attack types
 * 
 * @package VietShield_WAF
 */

namespace VietShield\WAF;

if (!defined('ABSPATH')) {
    exit;
}

class ThreatDetector {
    
    /**
     * Rule matcher instance
     */
    private $rule_matcher;
    
    /**
     * Plugin options
     */
    private $options;
    
    /**
     * Constructor
     */
    public function __construct(RuleMatcher $rule_matcher) {
        $this->rule_matcher = $rule_matcher;
        $this->options = get_option('vietshield_options', []);
    }
    
    /**
     * Detect threats in request data
     * 
     * @param array $request_data Analyzed request data
     * @return array List of detected threats
     */
    public function detect($request_data) {
        $threats = [];
        
        // Check Empty/Unknown User-Agent (new)
        if ($this->get_option('block_empty_useragent', true)) {
            $empty_ua_threats = $this->detect_empty_useragent($request_data);
            $threats = array_merge($threats, $empty_ua_threats);
        }
        
        // Check Bad User-Agents (enhanced)
        if ($this->get_option('block_bad_useragents', true)) {
            $bot_threats = $this->detect_bad_bots($request_data);
            $threats = array_merge($threats, $bot_threats);
        }
        
        // Check SQL Injection
        if ($this->get_option('block_sqli', true)) {
            $sqli_threats = $this->detect_sqli($request_data);
            $threats = array_merge($threats, $sqli_threats);
        }
        
        // Check XSS
        if ($this->get_option('block_xss', true)) {
            $xss_threats = $this->detect_xss($request_data);
            $threats = array_merge($threats, $xss_threats);
        }
        
        // Check RCE (Remote Code Execution)
        if ($this->get_option('block_rce', true)) {
            $rce_threats = $this->detect_rce($request_data);
            $threats = array_merge($threats, $rce_threats);
        }
        
        // Check LFI (Local File Inclusion)
        if ($this->get_option('block_lfi', true)) {
            // Skip LFI check for WordPress login redirects
            if (!$this->is_wordpress_login_redirect($request_data)) {
                $lfi_threats = $this->detect_lfi($request_data);
                $threats = array_merge($threats, $lfi_threats);
            }
        }
        
        // Check Advanced Injection (POST, Cookie, Args - new Lua rules)
        if ($this->get_option('advanced_injection_detection', true)) {
            // Skip advanced injection check for WordPress login requests
            if (!$this->is_wordpress_login_redirect($request_data)) {
                $injection_threats = $this->detect_advanced_injection($request_data);
                $threats = array_merge($threats, $injection_threats);
            }
        }
        
        // Check Author Scan
        if ($this->get_option('block_author_scan', true)) {
            $author_threats = $this->detect_author_scan($request_data);
            $threats = array_merge($threats, $author_threats);
        }
        
        // Check XML-RPC abuse
        if ($this->get_option('block_xmlrpc', false) && $request_data['is_xmlrpc']) {
            $threats[] = [
                'rule_id' => 'xmlrpc_blocked',
                'type' => 'xmlrpc',
                'name' => 'XML-RPC Blocked',
                'severity' => 'medium',
                'matched' => 'xmlrpc.php access',
                'description' => 'XML-RPC endpoint is disabled',
            ];
        }
        
        // Sort by severity
        usort($threats, function($a, $b) {
            $severity_order = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3];
            return ($severity_order[$a['severity']] ?? 3) - ($severity_order[$b['severity']] ?? 3);
        });
        
        return $threats;
    }
    
    /**
     * Detect SQL Injection
     */
    private function detect_sqli($request_data) {
        $threats = [];
        
        // Check all input sources
        $sources = [
            'uri' => [$request_data['uri']],
            'get' => $request_data['get'] ?? [],
            'post' => $request_data['post'] ?? [],
            'cookies' => $request_data['cookies'] ?? [],
        ];
        
        foreach ($sources as $context => $values) {
            $values_to_check = is_array($values) ? $this->flatten_values($values) : [$values];
            
            foreach ($values_to_check as $value) {
                // Use rule matcher
                $match = $this->rule_matcher->match($value, 'sqli', $context);
                if ($match) {
                    $threats[] = $match;
                }
                
                // Built-in patterns as fallback
                if (empty($match) && $this->detect_sqli_builtin($value)) {
                    $threats[] = [
                        'rule_id' => 'sqli_builtin',
                        'type' => 'sqli',
                        'name' => 'SQL Injection Detected',
                        'severity' => 'critical',
                        'matched' => substr($value, 0, 100),
                        'description' => 'Potential SQL injection attack detected',
                    ];
                }
            }
        }
        
        return $threats;
    }
    
    /**
     * Built-in SQLi detection patterns
     */
    private function detect_sqli_builtin($value) {
        $patterns = [
            // Union based
            '/\bunion\b.*\bselect\b/is',
            '/\bunion\b.*\ball\b.*\bselect\b/is',
            
            // Error based
            '/\bor\b.*[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+/is',
            '/\band\b.*[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+/is',
            '/[\'"]\s*or\s*[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+/is',
            
            // Stacked queries
            '/;\s*(drop|truncate|delete|insert|update|create|alter)\b/is',
            
            // Comment injection
            '/(\/\*|\*\/|--\s|#.*$)/m',
            
            // Common payloads
            '/\bsleep\s*\(\s*\d+\s*\)/is',
            '/\bbenchmark\s*\(/is',
            '/\bwaitfor\s+delay\b/is',
            '/\bload_file\s*\(/is',
            '/\binto\s+(out|dump)file\b/is',
            
            // Information schema
            '/information_schema\./is',
            '/\bsys\.(databases|tables|columns)\b/is',
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $value)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Detect XSS
     */
    private function detect_xss($request_data) {
        $threats = [];
        
        $sources = [
            'uri' => [$request_data['uri']],
            'get' => $request_data['get'] ?? [],
            'post' => $request_data['post'] ?? [],
            'cookies' => $request_data['cookies'] ?? [],
            'referer' => [$request_data['referer'] ?? ''],
        ];
        
        foreach ($sources as $context => $values) {
            $values_to_check = is_array($values) ? $this->flatten_values($values) : [$values];
            
            foreach ($values_to_check as $value) {
                $match = $this->rule_matcher->match($value, 'xss', $context);
                if ($match) {
                    $threats[] = $match;
                }
                
                // Built-in XSS patterns
                if (empty($match) && $this->detect_xss_builtin($value)) {
                    $threats[] = [
                        'rule_id' => 'xss_builtin',
                        'type' => 'xss',
                        'name' => 'XSS Attack Detected',
                        'severity' => 'high',
                        'matched' => substr($value, 0, 100),
                        'description' => 'Potential XSS attack detected',
                    ];
                }
            }
        }
        
        return $threats;
    }
    
    /**
     * Built-in XSS detection patterns
     */
    private function detect_xss_builtin($value) {
        $patterns = [
            // Script tags
            '/<script[^>]*>.*?<\/script>/is',
            '/<script[^>]*>/is',
            
            // Event handlers
            '/\bon\w+\s*=\s*["\']?[^"\']+["\']?/is',
            '/\bon(load|error|click|mouse|focus|blur|key|submit|change|input)\s*=/is',
            
            // JavaScript protocol
            '/javascript\s*:/is',
            '/vbscript\s*:/is',
            '/data\s*:.*base64/is',
            
            // SVG/XML attacks
            '/<svg[^>]*onload/is',
            '/<img[^>]*onerror/is',
            '/<iframe[^>]*>/is',
            '/<object[^>]*>/is',
            '/<embed[^>]*>/is',
            
            // Expression/eval
            '/expression\s*\(/is',
            '/eval\s*\(/is',
            
            // HTML injection
            '/<(script|img|svg|body|iframe|object|embed|link|style|meta|base|form|input|button)[^>]*>/is',
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $value)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Detect Remote Code Execution
     */
    private function detect_rce($request_data) {
        $threats = [];
        
        // Get RCE whitelist patterns
        $whitelist_patterns = $this->get_option('rce_whitelist_patterns', []);
        
        $sources = [
            'get' => $request_data['get'] ?? [],
            'post' => $request_data['post'] ?? [],
            'cookies' => $request_data['cookies'] ?? [],
        ];
        
        // Also check URI and referer for whitelist patterns
        $uri = $request_data['uri'] ?? '';
        $referer = $request_data['referer'] ?? '';
        $query_string = $request_data['query_string'] ?? '';
        
        // Combine all request data for whitelist checking
        $all_request_data = $uri . ' ' . $referer . ' ' . $query_string;
        
        // Check if request matches whitelist patterns
        $is_whitelisted = false;
        if (!empty($whitelist_patterns) && is_array($whitelist_patterns)) {
            foreach ($whitelist_patterns as $pattern) {
                if (empty($pattern)) {
                    continue;
                }
                // Check in URI, referer, query string, and all parameter values
                if (preg_match($pattern, $all_request_data)) {
                    $is_whitelisted = true;
                    break;
                }
            }
        }
        
        // If whitelisted, skip RCE detection
        if ($is_whitelisted) {
            return $threats;
        }
        
        foreach ($sources as $context => $values) {
            $values_to_check = is_array($values) ? $this->flatten_values($values) : [$values];
            
            foreach ($values_to_check as $value) {
                // Check whitelist for individual parameter values
                $value_whitelisted = false;
                if (!empty($whitelist_patterns) && is_array($whitelist_patterns)) {
                    foreach ($whitelist_patterns as $pattern) {
                        if (empty($pattern)) {
                            continue;
                        }
                        if (preg_match($pattern, $value)) {
                            $value_whitelisted = true;
                            break;
                        }
                    }
                }
                
                if ($value_whitelisted) {
                    continue; // Skip this value if whitelisted
                }
                
                $match = $this->rule_matcher->match($value, 'rce', $context);
                if ($match) {
                    $threats[] = $match;
                }
                
                // Built-in RCE patterns
                if (empty($match) && $this->detect_rce_builtin($value)) {
                    $threats[] = [
                        'rule_id' => 'rce_builtin',
                        'type' => 'rce',
                        'name' => 'Remote Code Execution Attempt',
                        'severity' => 'critical',
                        'matched' => substr($value, 0, 100),
                        'description' => 'Potential remote code execution attack',
                    ];
                }
            }
        }
        
        return $threats;
    }
    
    /**
     * Built-in RCE detection patterns
     */
    private function detect_rce_builtin($value) {
        $patterns = [
            // PHP functions
            '/\b(eval|assert|preg_replace|create_function|call_user_func|call_user_func_array)\s*\(/is',
            '/\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(/is',
            '/\b(include|include_once|require|require_once)\s*\(/is',
            '/`[^`]+`/',
            
            // Shell commands
            '/;\s*(ls|cat|wget|curl|nc|netcat|bash|sh|python|perl|ruby|php)\b/is',
            '/\|\s*(ls|cat|wget|curl|nc|netcat|bash|sh)\b/is',
            '/\$\([^)]+\)/',
            '/\$\{[^}]+\}/',
            
            // Reverse shells
            '/bash\s+-i\s+>&\s+\/dev\/tcp/is',
            '/nc\s+-e\s+\/bin\/(ba)?sh/is',
            '/python\s+-c\s+[\'"]import\s+socket/is',
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $value)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Detect Local File Inclusion
     */
    private function detect_lfi($request_data) {
        $threats = [];
        
        // Early return for WordPress login requests to prevent false positives
        if ($this->is_wordpress_login_redirect($request_data)) {
            return $threats;
        }
        
        // Check GET parameters first, excluding redirect parameters
        $get_params = $request_data['get'] ?? [];
        $redirect_params = ['redirect_to', 'redirect', 'return_to', 'return', 'redirect_uri'];
        
        foreach ($get_params as $key => $value) {
            // Skip legitimate WordPress redirect URLs
            if (in_array(strtolower($key), $redirect_params) && $this->is_legitimate_redirect_url($value)) {
                continue;
            }
            
            $values_to_check = is_array($value) ? $this->flatten_values($value) : [$value];
            
            foreach ($values_to_check as $val) {
                $match = $this->rule_matcher->match($val, 'lfi', 'get');
                if ($match) {
                    $threats[] = $match;
                }
                
                // Built-in LFI patterns
                if (empty($match) && $this->detect_lfi_builtin($val)) {
                    $threats[] = [
                        'rule_id' => 'lfi_builtin',
                        'type' => 'lfi',
                        'name' => 'Local File Inclusion Attempt',
                        'severity' => 'high',
                        'matched' => substr($val, 0, 100),
                        'description' => 'Potential local file inclusion attack',
                    ];
                }
            }
        }
        
        // Check POST parameters
        $post_params = $request_data['post'] ?? [];
        foreach ($post_params as $key => $value) {
            // Skip legitimate WordPress redirect URLs
            if (in_array(strtolower($key), $redirect_params) && $this->is_legitimate_redirect_url($value)) {
                continue;
            }
            
            $values_to_check = is_array($value) ? $this->flatten_values($value) : [$value];
            
            foreach ($values_to_check as $val) {
                $match = $this->rule_matcher->match($val, 'lfi', 'post');
                if ($match) {
                    $threats[] = $match;
                }
                
                // Built-in LFI patterns
                if (empty($match) && $this->detect_lfi_builtin($val)) {
                    $threats[] = [
                        'rule_id' => 'lfi_builtin',
                        'type' => 'lfi',
                        'name' => 'Local File Inclusion Attempt',
                        'severity' => 'high',
                        'matched' => substr($val, 0, 100),
                        'description' => 'Potential local file inclusion attack',
                    ];
                }
            }
        }
        
        // Check URI (but exclude from lfi_003 rule which is now only for get/post)
        // Skip URI check for WordPress login pages with redirect parameters
        $uri = $request_data['uri'] ?? '';
        if (!empty($uri) && !$this->is_wordpress_login_redirect($request_data)) {
            // Extract path only (without query string) for URI checking
            // Query string parameters are already checked separately above
            $uri_path = wp_parse_url($uri, PHP_URL_PATH);
            if ($uri_path === null) {
                $uri_path = $uri;
            }
            
            // Only check the path part, not the full URI with query string
            $match = $this->rule_matcher->match($uri_path, 'lfi', 'uri');
            if ($match) {
                $threats[] = $match;
            }
            
            // Built-in LFI patterns
            if (empty($match) && $this->detect_lfi_builtin($uri_path)) {
                $threats[] = [
                    'rule_id' => 'lfi_builtin',
                    'type' => 'lfi',
                    'name' => 'Local File Inclusion Attempt',
                    'severity' => 'high',
                    'matched' => substr($uri_path, 0, 100),
                    'description' => 'Potential local file inclusion attack',
                ];
            }
        }
        
        return $threats;
    }
    
    /**
     * Check if this is a WordPress login request (GET or POST)
     * WordPress uses wp-login.php for login page and form submission
     * We allow all requests to wp-login.php to prevent false positives
     */
    private function is_wordpress_login_redirect($request_data) {
        $uri = $request_data['uri'] ?? '';
        
        // Check if this is a wp-login.php request
        // Allow all requests to wp-login.php to prevent false positives with redirect URLs
        if (strpos($uri, 'wp-login.php') !== false) {
            return true;
        }
        
        // Also check for wp-admin redirects (when accessing /wp-admin without auth)
        // WordPress redirects to wp-login.php with redirect_to parameter
        $redirect_params = ['redirect_to', 'redirect', 'return_to', 'return', 'redirect_uri'];
        $get_params = $request_data['get'] ?? [];
        $post_params = $request_data['post'] ?? [];
        
        // Check GET parameters for legitimate redirect URLs
        foreach ($redirect_params as $param) {
            if (isset($get_params[$param])) {
                $value = $get_params[$param];
                if ($this->is_legitimate_redirect_url($value)) {
                    return true;
                }
            }
        }
        
        // Check POST parameters for legitimate redirect URLs
        foreach ($redirect_params as $param) {
            if (isset($post_params[$param])) {
                $value = $post_params[$param];
                if ($this->is_legitimate_redirect_url($value)) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Check if value is a legitimate WordPress redirect URL
     * WordPress redirect_to parameters contain full URLs like https://domain.com/path
     */
    private function is_legitimate_redirect_url($value) {
        if (empty($value) || !is_string($value)) {
            return false;
        }
        
        // Check if value is a valid URL (http:// or https://)
        // This indicates it's a legitimate redirect URL, not a path traversal attempt
        if (preg_match('/^https?:\/\//i', $value)) {
            return true;
        }
        
        // Also check URL-encoded versions (before normalization)
        if (preg_match('/^https?%3A%2F%2F/i', $value)) {
            return true;
        }
        
        // Check for double-encoded or mixed case
        if (preg_match('/^https?%3[aA]%2[fF]%2[fF]/i', $value)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Built-in LFI detection patterns
     */
    private function detect_lfi_builtin($value) {
        $patterns = [
            // Path traversal
            '/\.\.[\/\\\\]/is',
            '/\.\.%2f/is',
            '/\.\.%5c/is',
            '/%2e%2e[\/\\\\%]/is',
            
            // Common targets
            '/\/etc\/(passwd|shadow|hosts|group)/is',
            '/\/proc\/self\/(environ|fd)/is',
            '/\/var\/log\//is',
            '/wp-config\.php/is',
            
            // PHP wrappers
            '/php:\/\/filter/is',
            '/php:\/\/input/is',
            '/expect:\/\//is',
            '/zip:\/\//is',
            '/phar:\/\//is',
            
            // Windows paths
            '/[a-z]:[\/\\\\]windows/is',
            '/[a-z]:[\/\\\\]boot\.ini/is',
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $value)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Detect empty or unknown User-Agent
     */
    private function detect_empty_useragent($request_data) {
        $threats = [];
        $user_agent = $request_data['user_agent'] ?? '';
        
        // Block empty User-Agent
        if (empty(trim($user_agent))) {
            $threats[] = [
                'rule_id' => 'empty_useragent',
                'type' => 'bad_bot',
                'name' => 'Empty User-Agent',
                'severity' => 'medium',
                'matched' => 'Empty User-Agent',
                'description' => 'Request blocked: Empty or missing User-Agent',
            ];
        }
        
        return $threats;
    }
    
    /**
     * Detect bad bots/scanners - Enhanced with Lua WAF patterns
     */
    private function detect_bad_bots($request_data) {
        $threats = [];
        $user_agent = $request_data['user_agent'] ?? '';
        
        if (empty($user_agent)) {
            return $threats;
        }
        
        // Check with rule matcher first
        $match = $this->rule_matcher->match($user_agent, 'bad_bots', 'user_agent');
        if ($match) {
            $threats[] = $match;
            return $threats;
        }
        
        // Regex patterns for security scanners and bots (from Lua WAF)
        $regex_patterns = [
            // Security scanners
            '/(?i)(BabyKrokodil|netsparker|httperf|bench)/',
            '/(?i)(Parser|libwww|BBBike|fimap|havij)/',
            '/(?i)(burp|zap|acunetix|netsparker|appscan)/',
            '/(?i)(censys|shodan|zoomeye|binaryedge|onyphe|fofa)/',
            '/(?i)(harvest|audit|dirbuster|pangolin|hydra)/',
            '/(?i)(masscan|nessus|openvas|qualys)/',
            '/(?i)(masscan|nmap|zmap)/',
            '/(?i)(scanner|scan|spider|crawler)/',
            '/(?i)(sqlmap|nikto|nuclei|wpscan|w3af|owasp)/',
            '/(HTTrack|harvest|audit|dirbuster|pangolin|nmap|sqln|-scan|hydra|Parser|libwww|BBBike|sqlmap|w3af|owasp|Nikto|fimap|havij|PycURL|zmeu|BabyKrokodil|netsparker|httperf|bench)/',
        ];
        
        foreach ($regex_patterns as $pattern) {
            if (preg_match($pattern, $user_agent)) {
                $threats[] = [
                    'rule_id' => 'bad_ua_regex',
                    'type' => 'bad_bot',
                    'name' => 'Malicious User-Agent Detected',
                    'severity' => 'high',
                    'matched' => substr($user_agent, 0, 100),
                    'description' => 'Known malicious scanner/bot User-Agent pattern matched',
                ];
                return $threats;
            }
        }
        
        // Literal string matches (from Lua WAF)
        $literal_patterns = [
            'Apache-HttpClient/',
            'Go-http-client/',
            'HTTrack/',
            'Java/',
            'PostmanRuntime/',
            'PycURL/',
            'Wget/',
            'ZmEu',
            'curl/',
            'libwww-perl/',
            'okhttp/',
            'python-requests/',
            'HeadlessChrome/',
            // Additional common bad bots
            'masscan',
            'zgrab',
            'gobuster',
            'skipfish',
        ];
        
        foreach ($literal_patterns as $pattern) {
            if (stripos($user_agent, $pattern) !== false) {
                $threats[] = [
                    'rule_id' => 'bad_ua_' . preg_replace('/[^a-z0-9]/', '_', strtolower($pattern)),
                    'type' => 'bad_bot',
                    'name' => 'Bad Bot Detected: ' . $pattern,
                    'severity' => 'medium',
                    'matched' => substr($user_agent, 0, 100),
                    'description' => 'Known malicious bot/scanner detected',
                ];
                return $threats;
            }
        }
        
        return $threats;
    }
    
    /**
     * Detect advanced injection patterns (POST, Cookie, Args) - Lua WAF rules
     */
    private function detect_advanced_injection($request_data) {
        $threats = [];
        
        // Get RCE whitelist patterns (shared with RCE detection)
        $rce_whitelist_patterns = $this->get_option('rce_whitelist_patterns', []);
        
        // Combine request data for whitelist checking
        $uri = $request_data['uri'] ?? '';
        $referer = $request_data['referer'] ?? '';
        $query_string = $request_data['query_string'] ?? '';
        $all_request_data = $uri . ' ' . $referer . ' ' . $query_string;
        
        // Check if request matches whitelist patterns
        $is_whitelisted = false;
        if (!empty($rce_whitelist_patterns) && is_array($rce_whitelist_patterns)) {
            foreach ($rce_whitelist_patterns as $pattern) {
                if (empty($pattern)) {
                    continue;
                }
                if (preg_match($pattern, $all_request_data)) {
                    $is_whitelisted = true;
                    break;
                }
            }
        }
        
        // Advanced injection patterns from Lua WAF
        $patterns = [
            // Path traversal (URL encoded)
            ['pattern' => '/(?i)%2e%2e%2f/', 'name' => 'URL Encoded Path Traversal', 'type' => 'lfi'],
            ['pattern' => '/(?i)%2e%2e%5c/', 'name' => 'URL Encoded Path Traversal (Backslash)', 'type' => 'lfi'],
            
            // Command injection
            ['pattern' => '/(?i);\s*(rm|cat|ls|pwd|whoami|id|uname|ps|kill)\b/', 'name' => 'Command Injection (semicolon)', 'type' => 'rce'],
            ['pattern' => '/(?i)\|\s*(rm|cat|ls|pwd|whoami|id|uname|ps|kill)\b/', 'name' => 'Command Injection (pipe)', 'type' => 'rce'],
            ['pattern' => '/(?i)\|\|\s*(rm|cat|ls|pwd|whoami|id|uname|ps|kill)\b/', 'name' => 'Command Injection (double pipe)', 'type' => 'rce'],
            ['pattern' => '/(?i)&&\s*(rm|cat|ls|pwd|whoami|id|uname|ps|kill)\b/', 'name' => 'Command Injection (double ampersand)', 'type' => 'rce'],
            ['pattern' => '/(?i)\$\([^)]*\)/', 'name' => 'Command Substitution', 'type' => 'rce'],
            ['pattern' => '/`[^`]+`/', 'name' => 'Backtick Command Execution', 'type' => 'rce'],
            
            // SQL injection (additional from Lua)
            ['pattern' => '/(?i)\binto\s+(outfile|dumpfile)\b/', 'name' => 'SQL File Write', 'type' => 'sqli'],
            ['pattern' => '/(?i)\bpg_sleep\s*\(/', 'name' => 'PostgreSQL Sleep Injection', 'type' => 'sqli'],
            ['pattern' => '/(?i)\bupdatexml\s*\(/', 'name' => 'MySQL UpdateXML Injection', 'type' => 'sqli'],
            ['pattern' => '/(?i)\bextractvalue\s*\(/', 'name' => 'MySQL ExtractValue Injection', 'type' => 'sqli'],
            
            // LFI targets
            ['pattern' => '/(?i)etc\/\W*passwd/', 'name' => 'etc/passwd Access', 'type' => 'lfi'],
            ['pattern' => '/(?i)proc\/\W*self\/\W*environ/', 'name' => 'proc/self/environ Access', 'type' => 'lfi'],
            ['pattern' => '/(?i)(boot|win|system)\.ini/', 'name' => 'Windows INI File Access', 'type' => 'lfi'],
            
            // Protocol smuggling
            ['pattern' => '/(?i)\b(gopher|phar|file|ftp|ldap|dict|data):\/\//', 'name' => 'Protocol Smuggling', 'type' => 'ssrf'],
            
            // OGNL/Java injection
            ['pattern' => '/(?i)\bxwork\.MethodAccessor\b/', 'name' => 'OGNL Injection (Struts)', 'type' => 'rce'],
            ['pattern' => '/(?i)\bjava\.lang\b/', 'name' => 'Java Class Injection', 'type' => 'rce'],
        ];
        
        // Check POST, GET (args), and Cookies
        $sources = [
            'post' => $request_data['post'] ?? [],
            'get' => $request_data['get'] ?? [],
            'cookies' => $request_data['cookies'] ?? [],
        ];
        
        $redirect_params = ['redirect_to', 'redirect', 'return_to', 'return', 'redirect_uri'];
        
        foreach ($sources as $source_name => $source_data) {
            if (empty($source_data)) continue;
            
            // For GET and POST, check redirect parameters separately
            if (in_array($source_name, ['get', 'post']) && is_array($source_data)) {
                foreach ($source_data as $key => $value) {
                    // Skip legitimate WordPress redirect URLs
                    if (in_array(strtolower($key), $redirect_params) && $this->is_legitimate_redirect_url($value)) {
                        continue;
                    }
                    
                    $values = is_array($value) ? $this->flatten_values($value) : [$value];
                    
                    foreach ($values as $val) {
                        if (empty($val) || !is_string($val)) continue;
                        
                        // Check whitelist for RCE patterns
                        $value_whitelisted = false;
                        if ($is_whitelisted || (!empty($rce_whitelist_patterns) && is_array($rce_whitelist_patterns))) {
                            foreach ($rce_whitelist_patterns as $pattern) {
                                if (empty($pattern)) {
                                    continue;
                                }
                                if (preg_match($pattern, $val) || preg_match($pattern, $all_request_data)) {
                                    $value_whitelisted = true;
                                    break;
                                }
                            }
                        }
                        
                        foreach ($patterns as $rule) {
                            // Skip RCE patterns if whitelisted
                            if ($rule['type'] === 'rce' && ($is_whitelisted || $value_whitelisted)) {
                                continue;
                            }
                            
                            if (preg_match($rule['pattern'], $val)) {
                                $threats[] = [
                                    'rule_id' => 'adv_injection_' . $rule['type'],
                                    'type' => $rule['type'],
                                    'name' => $rule['name'],
                                    'severity' => 'high',
                                    'matched' => substr($val, 0, 100),
                                    'description' => 'Advanced injection pattern detected in ' . $source_name,
                                ];
                                return $threats; // Return on first match
                            }
                        }
                    }
                }
            } else {
                // For cookies, check normally
                $values = $this->flatten_values($source_data);
                
                foreach ($values as $value) {
                    if (empty($value) || !is_string($value)) continue;
                    
                    foreach ($patterns as $rule) {
                        if (preg_match($rule['pattern'], $value)) {
                            $threats[] = [
                                'rule_id' => 'adv_injection_' . $rule['type'],
                                'type' => $rule['type'],
                                'name' => $rule['name'],
                                'severity' => 'high',
                                'matched' => substr($value, 0, 100),
                                'description' => 'Advanced injection pattern detected in ' . $source_name,
                            ];
                            return $threats; // Return on first match
                        }
                    }
                }
            }
        }
        
        return $threats;
    }
    
    /**
     * Detect WordPress author enumeration
     */
    private function detect_author_scan($request_data) {
        $threats = [];
        
        $uri = $request_data['uri'] ?? '';
        $get = $request_data['get'] ?? [];
        
        // Check for ?author=N enumeration
        if (isset($get['author']) && is_numeric($get['author'])) {
            $threats[] = [
                'rule_id' => 'author_scan',
                'type' => 'enumeration',
                'name' => 'Author Enumeration Attempt',
                'severity' => 'low',
                'matched' => 'author=' . $get['author'],
                'description' => 'WordPress user enumeration attempt blocked',
            ];
        }
        
        // Check for /author/1/ pattern with numbers
        if (preg_match('/\/author\/\d+\/?$/i', $uri)) {
            $threats[] = [
                'rule_id' => 'author_scan_path',
                'type' => 'enumeration',
                'name' => 'Author Enumeration via Path',
                'severity' => 'low',
                'matched' => $uri,
                'description' => 'WordPress user enumeration attempt blocked',
            ];
        }
        
        // Check REST API user endpoint
        if (preg_match('/\/wp-json\/wp\/v2\/users/i', $uri)) {
            // Only block if not authenticated admin
            if (!is_user_logged_in() || !current_user_can('list_users')) {
                $threats[] = [
                    'rule_id' => 'rest_user_enum',
                    'type' => 'enumeration',
                    'name' => 'REST API User Enumeration',
                    'severity' => 'low',
                    'matched' => $uri,
                    'description' => 'WordPress REST API user enumeration blocked',
                ];
            }
        }
        
        return $threats;
    }
    
    /**
     * Flatten nested array values
     */
    private function flatten_values($array, &$result = []) {
        foreach ($array as $value) {
            if (is_array($value)) {
                $this->flatten_values($value, $result);
            } else {
                $result[] = $value;
            }
        }
        return $result;
    }
    
    /**
     * Get option with default
     */
    private function get_option($key, $default = null) {
        return $this->options[$key] ?? $default;
    }
}
