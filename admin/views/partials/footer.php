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
        $current_year = date('Y');
        printf(
            /* translators: %1$s: Current year, %2$s: Link to VietShield website */
            __('Copyright © %1$s <a href="%2$s" target="_blank" rel="noopener noreferrer">VietShield WAF</a>', 'vietshield-waf'),
            esc_html($current_year),
            esc_url('https://vietshield.org')
        );
        ?>
    </p>
    <p class="vietshield-version">
        Version: <?php echo VIETSHIELD_VERSION; ?>
    </p>
</div>
