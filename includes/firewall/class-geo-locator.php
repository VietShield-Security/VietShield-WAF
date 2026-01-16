<?php
/**
 * GeoIP Locator - Get country from IP address
 * 
 * @package VietShield_WAF
 */

namespace VietShield\Firewall;

if (!defined('ABSPATH')) {
    exit;
}

class GeoLocator {
    
    /**
     * Cache for IP lookups
     */
    private static $cache = [];
    
    /**
     * MaxMind GeoIP2 database path (optional)
     */
    private $geoip_db_path = null;
    
    /**
     * Constructor
     */
    public function __construct() {
        // Check for MaxMind GeoIP2 database
        $db_path = VIETSHIELD_PLUGIN_DIR . 'data/GeoLite2-Country.mmdb';
        if (file_exists($db_path)) {
            $this->geoip_db_path = $db_path;
        }
    }
    
    /**
     * Get country code from IP address
     * 
     * @param string $ip IP address
     * @return string|false Country code (e.g., 'VN', 'US') or false on failure
     */
    public function get_country($ip) {
        // Validate IP
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        
        // Check cache first
        if (isset(self::$cache[$ip])) {
            return self::$cache[$ip];
        }
        
        $country = false;
        
        // Try MaxMind GeoIP2 first (most accurate)
        if ($this->geoip_db_path && class_exists('MaxMind\Db\Reader')) {
            $country = $this->get_country_maxmind($ip);
        }
        
        // Fallback to free API services
        if (!$country) {
            $country = $this->get_country_api($ip);
        }
        
        // Cache result
        self::$cache[$ip] = $country;
        
        return $country;
    }
    
    /**
     * Get country using MaxMind GeoIP2 database
     * 
     * @param string $ip
     * @return string|false
     */
    private function get_country_maxmind($ip) {
        try {
            $reader = new \MaxMind\Db\Reader($this->geoip_db_path);
            $record = $reader->get($ip);
            $reader->close();
            
            if (isset($record['country']['iso_code'])) {
                return strtoupper($record['country']['iso_code']);
            }
        } catch (\Exception $e) {
            // MaxMind not available or error
            error_log('VietShield GeoIP MaxMind error: ' . $e->getMessage());
        }
        
        return false;
    }
    
    /**
     * Get country using free API services
     * 
     * @param string $ip
     * @return string|false
     */
    private function get_country_api($ip) {
        // Skip private/local IPs
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return false;
        }
        
        // Try ip-api.com (free, no API key needed)
        $country = $this->get_country_ipapi($ip);
        if ($country) {
            return $country;
        }
        
        // Try ipapi.co (backup)
        $country = $this->get_country_ipapico($ip);
        if ($country) {
            return $country;
        }
        
        return false;
    }
    
    /**
     * Get country from ip-api.com
     * 
     * @param string $ip
     * @return string|false
     */
    private function get_country_ipapi($ip) {
        $url = 'http://ip-api.com/json/' . urlencode($ip) . '?fields=status,countryCode';
        
        $response = wp_remote_get($url, [
            'timeout' => 3,
            'sslverify' => false,
        ]);
        
        if (is_wp_error($response)) {
            return false;
        }
        
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        
        if (isset($data['status']) && $data['status'] === 'success' && !empty($data['countryCode'])) {
            return strtoupper($data['countryCode']);
        }
        
        return false;
    }
    
    /**
     * Get country from ipapi.co
     * 
     * @param string $ip
     * @return string|false
     */
    private function get_country_ipapico($ip) {
        $url = 'https://ipapi.co/' . urlencode($ip) . '/country_code/';
        
        $response = wp_remote_get($url, [
            'timeout' => 3,
            'sslverify' => true,
        ]);
        
        if (is_wp_error($response)) {
            return false;
        }
        
        $body = trim(wp_remote_retrieve_body($response));
        
        if (!empty($body) && strlen($body) === 2) {
            return strtoupper($body);
        }
        
        return false;
    }
    
    /**
     * Get country name from code
     * 
     * @param string $code Country code
     * @return string Country name
     */
    public function get_country_name($code) {
        $countries = $this->get_countries_list();
        return $countries[$code] ?? $code;
    }
    
    /**
     * Get list of all countries
     * 
     * @return array Country code => Country name
     */
    public function get_countries_list() {
        return [
            'AD' => 'Andorra',
            'AE' => 'United Arab Emirates',
            'AF' => 'Afghanistan',
            'AG' => 'Antigua and Barbuda',
            'AI' => 'Anguilla',
            'AL' => 'Albania',
            'AM' => 'Armenia',
            'AO' => 'Angola',
            'AQ' => 'Antarctica',
            'AR' => 'Argentina',
            'AS' => 'American Samoa',
            'AT' => 'Austria',
            'AU' => 'Australia',
            'AW' => 'Aruba',
            'AX' => 'Åland Islands',
            'AZ' => 'Azerbaijan',
            'BA' => 'Bosnia and Herzegovina',
            'BB' => 'Barbados',
            'BD' => 'Bangladesh',
            'BE' => 'Belgium',
            'BF' => 'Burkina Faso',
            'BG' => 'Bulgaria',
            'BH' => 'Bahrain',
            'BI' => 'Burundi',
            'BJ' => 'Benin',
            'BL' => 'Saint Barthélemy',
            'BM' => 'Bermuda',
            'BN' => 'Brunei',
            'BO' => 'Bolivia',
            'BQ' => 'Caribbean Netherlands',
            'BR' => 'Brazil',
            'BS' => 'Bahamas',
            'BT' => 'Bhutan',
            'BV' => 'Bouvet Island',
            'BW' => 'Botswana',
            'BY' => 'Belarus',
            'BZ' => 'Belize',
            'CA' => 'Canada',
            'CC' => 'Cocos Islands',
            'CD' => 'Congo (DRC)',
            'CF' => 'Central African Republic',
            'CG' => 'Congo',
            'CH' => 'Switzerland',
            'CI' => 'Côte d\'Ivoire',
            'CK' => 'Cook Islands',
            'CL' => 'Chile',
            'CM' => 'Cameroon',
            'CN' => 'China',
            'CO' => 'Colombia',
            'CR' => 'Costa Rica',
            'CU' => 'Cuba',
            'CV' => 'Cape Verde',
            'CW' => 'Curaçao',
            'CX' => 'Christmas Island',
            'CY' => 'Cyprus',
            'CZ' => 'Czech Republic',
            'DE' => 'Germany',
            'DJ' => 'Djibouti',
            'DK' => 'Denmark',
            'DM' => 'Dominica',
            'DO' => 'Dominican Republic',
            'DZ' => 'Algeria',
            'EC' => 'Ecuador',
            'EE' => 'Estonia',
            'EG' => 'Egypt',
            'EH' => 'Western Sahara',
            'ER' => 'Eritrea',
            'ES' => 'Spain',
            'ET' => 'Ethiopia',
            'FI' => 'Finland',
            'FJ' => 'Fiji',
            'FK' => 'Falkland Islands',
            'FM' => 'Micronesia',
            'FO' => 'Faroe Islands',
            'FR' => 'France',
            'GA' => 'Gabon',
            'GB' => 'United Kingdom',
            'GD' => 'Grenada',
            'GE' => 'Georgia',
            'GF' => 'French Guiana',
            'GG' => 'Guernsey',
            'GH' => 'Ghana',
            'GI' => 'Gibraltar',
            'GL' => 'Greenland',
            'GM' => 'Gambia',
            'GN' => 'Guinea',
            'GP' => 'Guadeloupe',
            'GQ' => 'Equatorial Guinea',
            'GR' => 'Greece',
            'GS' => 'South Georgia',
            'GT' => 'Guatemala',
            'GU' => 'Guam',
            'GW' => 'Guinea-Bissau',
            'GY' => 'Guyana',
            'HK' => 'Hong Kong',
            'HM' => 'Heard Island',
            'HN' => 'Honduras',
            'HR' => 'Croatia',
            'HT' => 'Haiti',
            'HU' => 'Hungary',
            'ID' => 'Indonesia',
            'IE' => 'Ireland',
            'IL' => 'Israel',
            'IM' => 'Isle of Man',
            'IN' => 'India',
            'IO' => 'British Indian Ocean Territory',
            'IQ' => 'Iraq',
            'IR' => 'Iran',
            'IS' => 'Iceland',
            'IT' => 'Italy',
            'JE' => 'Jersey',
            'JM' => 'Jamaica',
            'JO' => 'Jordan',
            'JP' => 'Japan',
            'KE' => 'Kenya',
            'KG' => 'Kyrgyzstan',
            'KH' => 'Cambodia',
            'KI' => 'Kiribati',
            'KM' => 'Comoros',
            'KN' => 'Saint Kitts and Nevis',
            'KP' => 'North Korea',
            'KR' => 'South Korea',
            'KW' => 'Kuwait',
            'KY' => 'Cayman Islands',
            'KZ' => 'Kazakhstan',
            'LA' => 'Laos',
            'LB' => 'Lebanon',
            'LC' => 'Saint Lucia',
            'LI' => 'Liechtenstein',
            'LK' => 'Sri Lanka',
            'LR' => 'Liberia',
            'LS' => 'Lesotho',
            'LT' => 'Lithuania',
            'LU' => 'Luxembourg',
            'LV' => 'Latvia',
            'LY' => 'Libya',
            'MA' => 'Morocco',
            'MC' => 'Monaco',
            'MD' => 'Moldova',
            'ME' => 'Montenegro',
            'MF' => 'Saint Martin',
            'MG' => 'Madagascar',
            'MH' => 'Marshall Islands',
            'MK' => 'North Macedonia',
            'ML' => 'Mali',
            'MM' => 'Myanmar',
            'MN' => 'Mongolia',
            'MO' => 'Macao',
            'MP' => 'Northern Mariana Islands',
            'MQ' => 'Martinique',
            'MR' => 'Mauritania',
            'MS' => 'Montserrat',
            'MT' => 'Malta',
            'MU' => 'Mauritius',
            'MV' => 'Maldives',
            'MW' => 'Malawi',
            'MX' => 'Mexico',
            'MY' => 'Malaysia',
            'MZ' => 'Mozambique',
            'NA' => 'Namibia',
            'NC' => 'New Caledonia',
            'NE' => 'Niger',
            'NF' => 'Norfolk Island',
            'NG' => 'Nigeria',
            'NI' => 'Nicaragua',
            'NL' => 'Netherlands',
            'NO' => 'Norway',
            'NP' => 'Nepal',
            'NR' => 'Nauru',
            'NU' => 'Niue',
            'NZ' => 'New Zealand',
            'OM' => 'Oman',
            'PA' => 'Panama',
            'PE' => 'Peru',
            'PF' => 'French Polynesia',
            'PG' => 'Papua New Guinea',
            'PH' => 'Philippines',
            'PK' => 'Pakistan',
            'PL' => 'Poland',
            'PM' => 'Saint Pierre and Miquelon',
            'PN' => 'Pitcairn',
            'PR' => 'Puerto Rico',
            'PS' => 'Palestine',
            'PT' => 'Portugal',
            'PW' => 'Palau',
            'PY' => 'Paraguay',
            'QA' => 'Qatar',
            'RE' => 'Réunion',
            'RO' => 'Romania',
            'RS' => 'Serbia',
            'RU' => 'Russia',
            'RW' => 'Rwanda',
            'SA' => 'Saudi Arabia',
            'SB' => 'Solomon Islands',
            'SC' => 'Seychelles',
            'SD' => 'Sudan',
            'SE' => 'Sweden',
            'SG' => 'Singapore',
            'SH' => 'Saint Helena',
            'SI' => 'Slovenia',
            'SJ' => 'Svalbard and Jan Mayen',
            'SK' => 'Slovakia',
            'SL' => 'Sierra Leone',
            'SM' => 'San Marino',
            'SN' => 'Senegal',
            'SO' => 'Somalia',
            'SR' => 'Suriname',
            'SS' => 'South Sudan',
            'ST' => 'São Tomé and Príncipe',
            'SV' => 'El Salvador',
            'SX' => 'Sint Maarten',
            'SY' => 'Syria',
            'SZ' => 'Eswatini',
            'TC' => 'Turks and Caicos Islands',
            'TD' => 'Chad',
            'TF' => 'French Southern Territories',
            'TG' => 'Togo',
            'TH' => 'Thailand',
            'TJ' => 'Tajikistan',
            'TK' => 'Tokelau',
            'TL' => 'Timor-Leste',
            'TM' => 'Turkmenistan',
            'TN' => 'Tunisia',
            'TO' => 'Tonga',
            'TR' => 'Turkey',
            'TT' => 'Trinidad and Tobago',
            'TV' => 'Tuvalu',
            'TW' => 'Taiwan',
            'TZ' => 'Tanzania',
            'UA' => 'Ukraine',
            'UG' => 'Uganda',
            'UM' => 'U.S. Outlying Islands',
            'US' => 'United States',
            'UY' => 'Uruguay',
            'UZ' => 'Uzbekistan',
            'VA' => 'Vatican City',
            'VC' => 'Saint Vincent and the Grenadines',
            'VE' => 'Venezuela',
            'VG' => 'British Virgin Islands',
            'VI' => 'U.S. Virgin Islands',
            'VN' => 'Vietnam',
            'VU' => 'Vanuatu',
            'WF' => 'Wallis and Futuna',
            'WS' => 'Samoa',
            'YE' => 'Yemen',
            'YT' => 'Mayotte',
            'ZA' => 'South Africa',
            'ZM' => 'Zambia',
            'ZW' => 'Zimbabwe',
        ];
    }
    
    /**
     * Clear cache
     */
    public static function clear_cache() {
        self::$cache = [];
    }
    
    /**
     * Batch lookup countries for multiple IPs
     * 
     * @param array $ips Array of IP addresses
     * @return array IP => Country code
     */
    public function batch_lookup($ips) {
        $results = [];
        
        foreach ($ips as $ip) {
            $results[$ip] = $this->get_country($ip);
        }
        
        return $results;
    }
}
