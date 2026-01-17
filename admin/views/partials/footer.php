<?php
/**
 * Footer partial for admin pages
 * 
 * @package VietShield_WAF
 */

if (!defined('ABSPATH')) {
    exit;
}
?>
<div class="vietshield-footer">
    <p class="vietshield-copyright">
        <?php
        $vswaf_current_year = wp_date('Y');
        printf(
            /* translators: %1$s: Current year, %2$s: Link to VietShield website */
            esc_html__('Copyright © %1$s %2$s', 'vietshield-waf'),
            esc_html($vswaf_current_year),
            '<a href="' . esc_url('https://vietshield.org') . '" target="_blank" rel="noopener noreferrer">VietShield WAF</a>'
        );
        ?>
    </p>
    <p class="vietshield-version">
        Version: <?php echo esc_html(VIETSHIELD_VERSION); ?>
    </p>
</div>
