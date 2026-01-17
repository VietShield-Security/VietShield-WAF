<?php
/**
 * Rule Matcher - Pattern matching engine
 * 
 * @package VietShield_WAF
 */

namespace VietShield\WAF;

if (!defined('ABSPATH')) {
    exit;
}

class RuleMatcher {
    
    /**
     * Loaded rules
     */
    private $rules = [];
    
    /**
     * Rules cache
     */
    private static $rules_cache = null;
    
    /**
     * Constructor
     */
    public function __construct() {
        $this->load_rules();
    }
    
    /**
     * Load all rules from JSON files
     */
    private function load_rules() {
        // Use cache if available
        if (self::$rules_cache !== null) {
            $this->rules = self::$rules_cache;
            return;
        }
        
        $rules_dir = VIETSHIELD_PLUGIN_DIR . 'rules/';
        
        $rule_files = [
            'sqli' => 'sqli-rules.json',
            'xss' => 'xss-rules.json',
            'rce' => 'rce-rules.json',
            'lfi' => 'lfi-rules.json',
            'bad_bots' => 'bad-bots.json',
            'custom' => 'custom-rules.json',
        ];
        
        foreach ($rule_files as $type => $file) {
            $filepath = $rules_dir . $file;
            
            if (file_exists($filepath)) {
                $content = file_get_contents($filepath);
                $data = json_decode($content, true);
                
                if (isset($data['rules']) && is_array($data['rules'])) {
                    foreach ($data['rules'] as $rule) {
                        $rule['type'] = $type;
                        $this->rules[] = $rule;
                    }
                }
            }
        }
        
        // Sort by severity (critical first)
        usort($this->rules, function($a, $b) {
            $severity_order = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3];
            $a_order = $severity_order[$a['severity'] ?? 'low'] ?? 3;
            $b_order = $severity_order[$b['severity'] ?? 'low'] ?? 3;
            return $a_order - $b_order;
        });
        
        // Cache rules
        self::$rules_cache = $this->rules;
    }
    
    /**
     * Match value against all rules of a type
     * 
     * @param string $value Value to check
     * @param string $type Rule type (sqli, xss, rce, lfi, bad_bots)
     * @param string $context Where the value came from (get, post, cookie, header, uri)
     * @return array|false Matched rule or false
     */
    public function match($value, $type = null, $context = 'any') {
        if (empty($value)) {
            return false;
        }
        
        // Convert to string if array
        if (is_array($value)) {
            $value = $this->flatten_array($value);
        }
        
        foreach ($this->rules as $rule) {
            // Filter by type if specified
            if ($type !== null && $rule['type'] !== $type) {
                continue;
            }
            
            // Check if rule is enabled
            if (isset($rule['enabled']) && !$rule['enabled']) {
                continue;
            }
            
            // Check context restrictions
            if (isset($rule['contexts']) && !in_array($context, $rule['contexts']) && !in_array('any', $rule['contexts'])) {
                continue;
            }
            
            // Match pattern
            if ($this->match_pattern($value, $rule)) {
                return [
                    'rule_id' => $rule['id'] ?? 'unknown',
                    'type' => $rule['type'],
                    'name' => $rule['name'] ?? '',
                    'severity' => $rule['severity'] ?? 'medium',
                    'matched' => $this->get_matched_string($value, $rule['pattern']),
                    'description' => $rule['description'] ?? '',
                ];
            }
        }
        
        return false;
    }
    
    /**
     * Match all rules against a value (returns all matches)
     */
    public function match_all($value, $type = null, $context = 'any') {
        $matches = [];
        
        if (empty($value)) {
            return $matches;
        }
        
        if (is_array($value)) {
            $value = $this->flatten_array($value);
        }
        
        foreach ($this->rules as $rule) {
            if ($type !== null && $rule['type'] !== $type) {
                continue;
            }
            
            if (isset($rule['enabled']) && !$rule['enabled']) {
                continue;
            }
            
            if (isset($rule['contexts']) && !in_array($context, $rule['contexts']) && !in_array('any', $rule['contexts'])) {
                continue;
            }
            
            if ($this->match_pattern($value, $rule)) {
                $matches[] = [
                    'rule_id' => $rule['id'] ?? 'unknown',
                    'type' => $rule['type'],
                    'name' => $rule['name'] ?? '',
                    'severity' => $rule['severity'] ?? 'medium',
                    'matched' => $this->get_matched_string($value, $rule['pattern']),
                    'description' => $rule['description'] ?? '',
                ];
            }
        }
        
        return $matches;
    }
    
    /**
     * Match a single pattern against value
     */
    private function match_pattern($value, $rule) {
        $pattern = $rule['pattern'] ?? '';
        
        if (empty($pattern)) {
            return false;
        }
        
        // Case insensitive by default
        $flags = isset($rule['case_sensitive']) && $rule['case_sensitive'] ? '' : 'i';
        
        // Build regex pattern - escape delimiter if it appears in pattern
        // Use a delimiter that's less likely to appear in patterns
        $delimiter = '#';
        // If delimiter appears in pattern, use different one
        if (strpos($pattern, $delimiter) !== false) {
            $delimiter = '~';
        }
        if (strpos($pattern, $delimiter) !== false) {
            $delimiter = '/';
            // Escape forward slashes in pattern
            $pattern = str_replace('/', '\/', $pattern);
        }
        
        $regex = $delimiter . $pattern . $delimiter . $flags . 's';
        
        // Suppress warnings and use error handling
        $prev_error = error_get_last();
        $result = @preg_match($regex, $value);
        
        // Check for regex errors
        $error = error_get_last();
        if ($error !== $prev_error && $error !== null && strpos($error['message'], 'preg_match') !== false) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log('VietShield WAF: Invalid regex pattern in rule ' . ($rule['id'] ?? 'unknown') . ': ' . $error['message'] . ' Pattern: ' . $pattern);
            return false;
        }
        
        return $result === 1;
    }
    
    /**
     * Get the matched substring
     */
    private function get_matched_string($value, $pattern) {
        // Use delimiter that's less likely to appear in pattern
        $delimiter = '#';
        if (strpos($pattern, $delimiter) !== false) {
            $delimiter = '~';
        }
        if (strpos($pattern, $delimiter) !== false) {
            $delimiter = '/';
            // Escape forward slashes in pattern
            $pattern = str_replace('/', '\/', $pattern);
        }
        
        $regex = $delimiter . $pattern . $delimiter . 'is';
        
        // Suppress warnings and use error handling
        $prev_error = error_get_last();
        $result = @preg_match($regex, $value, $matches);
        
        // Check for regex errors
        $error = error_get_last();
        if ($error !== $prev_error && $error !== null && strpos($error['message'], 'preg_match') !== false) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log('VietShield WAF: Invalid regex pattern in get_matched_string: ' . $error['message'] . ' Pattern: ' . $pattern);
            return '';
        }
        
        if ($result > 0 && isset($matches[0])) {
            $matched = $matches[0];
            // Truncate if too long
            if (strlen($matched) > 200) {
                $matched = substr($matched, 0, 200) . '...';
            }
            return $matched;
        }
        
        return '';
    }
    
    /**
     * Flatten array to string for matching
     */
    private function flatten_array($array, $prefix = '') {
        $result = '';
        
        foreach ($array as $key => $value) {
            $full_key = $prefix ? "{$prefix}[{$key}]" : $key;
            
            if (is_array($value)) {
                $result .= $this->flatten_array($value, $full_key);
            } else {
                $result .= "{$full_key}={$value} ";
            }
        }
        
        return $result;
    }
    
    /**
     * Get all loaded rules
     */
    public function get_rules($type = null) {
        if ($type === null) {
            return $this->rules;
        }
        
        return array_filter($this->rules, function($rule) use ($type) {
            return $rule['type'] === $type;
        });
    }
    
    /**
     * Add custom rule at runtime
     */
    public function add_rule($rule) {
        $this->rules[] = $rule;
    }
    
    /**
     * Clear rules cache
     */
    public static function clear_cache() {
        self::$rules_cache = null;
    }
    
    /**
     * Test a pattern against a value (for admin testing)
     */
    public function test_pattern($pattern, $value) {
        $rule = [
            'pattern' => $pattern,
            'case_sensitive' => false,
        ];
        
        return $this->match_pattern($value, $rule);
    }
}
