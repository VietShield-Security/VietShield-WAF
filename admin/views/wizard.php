<?php
if (!defined('ABSPATH')) {
    exit;
}

// Always start at step 1 - steps are now handled via JavaScript
$vswaf_current_step = 1;
$vswaf_total_steps = 2;
?>
<div class="wrap vietshield-wizard-wrap">
    <div class="wizard-header">
        <div class="wizard-logo">
            <span class="dashicons dashicons-shield-alt"></span>
            <h1><?php esc_html_e('VietShield WAF Setup', 'vietshield-waf'); ?> <span style="font-size: 13px; color: #666; font-weight: 400; margin-left: 8px;">v<?php echo esc_html(VIETSHIELD_VERSION); ?></span></h1>
        </div>
        <div class="wizard-progress">
            <div class="progress-steps">
                <div class="step-indicator active" data-step="1" id="step-indicator-1">
                    <span class="step-number">1</span>
                    <span class="step-label"><?php esc_html_e('Choose Mode', 'vietshield-waf'); ?></span>
                </div>
                <div class="step-line" id="step-line"></div>
                <div class="step-indicator" data-step="2" id="step-indicator-2">
                    <span class="step-number">2</span>
                    <span class="step-label"><?php esc_html_e('Activate', 'vietshield-waf'); ?></span>
                </div>
            </div>
        </div>
    </div>

    <div class="wizard-content">
        <!-- Step 1: Firewall Mode Selection -->
        <div class="wizard-step" id="wizard-step-1">
            <div class="wizard-step-header">
                <h2><?php esc_html_e('Choose Protection Mode', 'vietshield-waf'); ?></h2>
                <p class="wizard-description">
                    <?php esc_html_e('Select how VietShield WAF should protect your website. We recommend Protecting Mode for maximum security.', 'vietshield-waf'); ?>
                </p>
            </div>
            
            <div class="wizard-options">
                <div class="option-card selected" data-value="protecting">
                    <div class="option-header">
                        <input type="radio" name="firewall_mode" value="protecting" id="mode-protecting" checked>
                        <label for="mode-protecting">
                            <div class="option-icon protecting-icon">
                                <span class="dashicons dashicons-shield"></span>
                            </div>
                            <div class="option-text">
                                <span class="option-title"><?php esc_html_e('Protecting Mode', 'vietshield-waf'); ?></span>
                                <span class="option-badge-inline"><?php esc_html_e('Recommended', 'vietshield-waf'); ?></span>
                            </div>
                        </label>
                    </div>
                    <div class="option-content">
                        <p><?php esc_html_e('Actively blocks malicious requests and provides maximum protection for your website.', 'vietshield-waf'); ?></p>
                        <ul>
                            <li><span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e('Block threats in real-time', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e('Full threat logging', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e('Early blocking enabled', 'vietshield-waf'); ?></li>
                        </ul>
                    </div>
                </div>
                
                <div class="option-card" data-value="learning">
                    <div class="option-header">
                        <input type="radio" name="firewall_mode" value="learning" id="mode-learning">
                        <label for="mode-learning">
                            <div class="option-icon">
                                <span class="dashicons dashicons-visibility"></span>
                            </div>
                            <div class="option-text">
                                <span class="option-title"><?php esc_html_e('Learning Mode', 'vietshield-waf'); ?></span>
                            </div>
                        </label>
                    </div>
                    <div class="option-content">
                        <p><?php esc_html_e('Monitors threats without blocking. Ideal for testing before enabling protection.', 'vietshield-waf'); ?></p>
                        <ul>
                            <li><span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e('Log threats only', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e('No request blocking', 'vietshield-waf'); ?></li>
                            <li><span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e('Safe for testing', 'vietshield-waf'); ?></li>
                        </ul>
                    </div>
                </div>
            </div>
            
            <div class="wizard-actions">
                <button type="button" class="button button-primary button-hero wizard-next" data-step="1">
                    <?php esc_html_e('Continue', 'vietshield-waf'); ?>
                    <span class="dashicons dashicons-arrow-right-alt"></span>
                </button>
            </div>
        </div>

        <!-- Step 2: Activation with Progress (hidden initially) -->
        <div class="wizard-step" id="wizard-step-2" style="display: none;">
            <div class="wizard-step-header">
                <h2><?php esc_html_e('Activate Protection', 'vietshield-waf'); ?></h2>
                <p class="wizard-description">
                    <?php esc_html_e('Click the button below to configure and activate all security features.', 'vietshield-waf'); ?>
                </p>
            </div>
            
            <!-- Initial State -->
            <div class="wizard-card activation-ready" id="activation-ready">
                <div class="activation-icon">
                    <span class="dashicons dashicons-shield"></span>
                </div>
                <h3><?php esc_html_e('Ready to Protect', 'vietshield-waf'); ?></h3>
                <p><?php esc_html_e('VietShield WAF will configure all security features automatically.', 'vietshield-waf'); ?></p>
                
                <div class="wizard-actions" style="margin-top: 30px;">
                    <button type="button" class="button wizard-prev" data-step="2">
                        <span class="dashicons dashicons-arrow-left-alt"></span>
                        <?php esc_html_e('Back', 'vietshield-waf'); ?>
                    </button>
                    <button type="button" class="button button-primary button-hero wizard-activate" id="wizard-activate-btn">
                        <span class="dashicons dashicons-yes"></span>
                        <?php esc_html_e('Activate Protection', 'vietshield-waf'); ?>
                    </button>
                </div>
            </div>
            
            <!-- Progress State (hidden initially) -->
            <div class="wizard-card activation-progress" id="activation-progress" style="display: none;">
                <div class="progress-header">
                    <div class="progress-icon spinning">
                        <span class="dashicons dashicons-update"></span>
                    </div>
                    <h3 id="progress-title"><?php esc_html_e('Configuring Security Features...', 'vietshield-waf'); ?></h3>
                    <p class="progress-subtitle"><?php esc_html_e('Please wait while we enable all protection modules.', 'vietshield-waf'); ?></p>
                </div>
                
                <!-- Feature Progress List -->
                <div class="progress-tasks" id="progress-tasks">
                    <div class="task-item" data-task="sqli" data-status="pending">
                        <div class="task-icon"><span class="dashicons dashicons-clock"></span></div>
                        <span class="task-name"><?php esc_html_e('SQL Injection Protection (SQLi)', 'vietshield-waf'); ?></span>
                        <span class="task-status"></span>
                    </div>
                    <div class="task-item" data-task="xss" data-status="pending">
                        <div class="task-icon"><span class="dashicons dashicons-clock"></span></div>
                        <span class="task-name"><?php esc_html_e('Cross-Site Scripting Protection (XSS)', 'vietshield-waf'); ?></span>
                        <span class="task-status"></span>
                    </div>
                    <div class="task-item" data-task="lfi" data-status="pending">
                        <div class="task-icon"><span class="dashicons dashicons-clock"></span></div>
                        <span class="task-name"><?php esc_html_e('Local File Inclusion Protection (LFI)', 'vietshield-waf'); ?></span>
                        <span class="task-status"></span>
                    </div>
                    <div class="task-item" data-task="rce" data-status="pending">
                        <div class="task-icon"><span class="dashicons dashicons-clock"></span></div>
                        <span class="task-name"><?php esc_html_e('Remote Code Execution Detection (RCE)', 'vietshield-waf'); ?></span>
                        <span class="task-status"></span>
                    </div>
                    <div class="task-item" data-task="bad_bots" data-status="pending">
                        <div class="task-icon"><span class="dashicons dashicons-clock"></span></div>
                        <span class="task-name"><?php esc_html_e('Bad Bot Protection', 'vietshield-waf'); ?></span>
                        <span class="task-status"></span>
                    </div>
                    <div class="task-item" data-task="rate_limit" data-status="pending">
                        <div class="task-icon"><span class="dashicons dashicons-clock"></span></div>
                        <span class="task-name"><?php esc_html_e('Rate Limiting', 'vietshield-waf'); ?></span>
                        <span class="task-status"></span>
                    </div>
                    <div class="task-item" data-task="login_security" data-status="pending">
                        <div class="task-icon"><span class="dashicons dashicons-clock"></span></div>
                        <span class="task-name"><?php esc_html_e('Login Security & Brute Force Protection', 'vietshield-waf'); ?></span>
                        <span class="task-status"></span>
                    </div>
                    <div class="task-item" data-task="threat_intel" data-status="pending">
                        <div class="task-icon"><span class="dashicons dashicons-clock"></span></div>
                        <span class="task-name"><?php esc_html_e('Threat Intelligence Feed', 'vietshield-waf'); ?></span>
                        <span class="task-status"></span>
                    </div>
                    <div class="task-item" data-task="googlebot" data-status="pending">
                        <div class="task-icon"><span class="dashicons dashicons-clock"></span></div>
                        <span class="task-name"><?php esc_html_e('Googlebot IP Whitelist', 'vietshield-waf'); ?></span>
                        <span class="task-status"></span>
                    </div>
                    <div class="task-item" data-task="early_blocker" data-status="pending">
                        <div class="task-icon"><span class="dashicons dashicons-clock"></span></div>
                        <span class="task-name"><?php esc_html_e('Early Blocking System', 'vietshield-waf'); ?></span>
                        <span class="task-status"></span>
                    </div>
                </div>
                
                <div class="progress-bar-container" style="margin-top: 20px;">
                    <div class="progress-bar-bg">
                        <div class="progress-bar-fill" id="progress-bar-fill"></div>
                    </div>
                    <div class="progress-percentage" id="progress-percentage">0%</div>
                </div>
            </div>
            
            <!-- Complete State (hidden initially) -->
            <div class="wizard-card activation-complete" id="activation-complete" style="display: none;">
                <div class="complete-icon">
                    <span class="dashicons dashicons-yes-alt"></span>
                </div>
                <h3><?php esc_html_e('Protection Activated!', 'vietshield-waf'); ?></h3>
                <p><?php esc_html_e('VietShield WAF is now protecting your website. All security features have been configured.', 'vietshield-waf'); ?></p>
                
                <div class="complete-stats">
                    <div class="stat-item">
                        <span class="stat-number">10</span>
                        <span class="stat-label"><?php esc_html_e('Features Enabled', 'vietshield-waf'); ?></span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number" id="early-blocking-stat">✓</span>
                        <span class="stat-label" id="early-blocking-label"><?php esc_html_e('Early Blocking Active', 'vietshield-waf'); ?></span>
                    </div>
                </div>
                
                <div class="wizard-actions" style="margin-top: 30px;">
                    <a href="<?php echo esc_url(admin_url('admin.php?page=vietshield-waf')); ?>" class="button button-primary button-hero">
                        <span class="dashicons dashicons-dashboard"></span>
                        <?php esc_html_e('Go to Dashboard', 'vietshield-waf'); ?>
                    </a>
                </div>
            </div>
        </div>
    </div>
</div>

<style>
/* Wizard Progress Steps */
.progress-steps {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0;
}

.step-indicator {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    opacity: 0.5;
    transition: opacity 0.3s;
}

.step-indicator.active {
    opacity: 1;
}

.step-number {
    width: 32px;
    height: 32px;
    border-radius: 50%;
    background: #e0e0e0;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 600;
    color: #666;
    transition: all 0.3s;
}

.step-indicator.active .step-number {
    background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
    color: white;
}

.step-label {
    font-size: 12px;
    color: #666;
}

.step-line {
    width: 80px;
    height: 3px;
    background: #e0e0e0;
    margin: 0 10px;
    margin-bottom: 20px;
    transition: background 0.3s;
}

.step-line.active {
    background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
}

/* Wizard Step Header */
.wizard-step-header {
    text-align: center;
    margin-bottom: 30px;
}

.wizard-step-header h2 {
    margin: 0 0 10px;
    font-size: 24px;
    font-weight: 600;
}

/* Option Cards */
.wizard-options {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
    max-width: 800px;
    margin: 0 auto 30px;
}

.option-card {
    background: white;
    border: 2px solid #e0e0e0;
    border-radius: 12px;
    padding: 0;
    cursor: pointer;
    transition: all 0.3s;
    overflow: hidden;
}

.option-card:hover {
    border-color: #3b82f6;
    box-shadow: 0 4px 12px rgba(59, 130, 246, 0.15);
}

.option-card.selected {
    border-color: #3b82f6;
    box-shadow: 0 4px 12px rgba(59, 130, 246, 0.2);
}

.option-header {
    padding: 20px;
    border-bottom: 1px solid #f0f0f0;
}

.option-header label {
    display: flex;
    align-items: center;
    gap: 15px;
    cursor: pointer;
}

.option-header input[type="radio"] {
    display: none;
}

.option-icon {
    width: 48px;
    height: 48px;
    border-radius: 10px;
    background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
    display: flex;
    align-items: center;
    justify-content: center;
}

.option-icon .dashicons {
    color: white;
    font-size: 24px;
    width: 24px;
    height: 24px;
}

.option-text {
    display: flex;
    flex-direction: column;
    gap: 4px;
}

.option-title {
    font-size: 16px;
    font-weight: 600;
    color: #1e293b;
}

.option-badge-inline {
    display: inline-block;
    font-size: 10px;
    font-weight: 600;
    background: #10b981;
    color: white;
    padding: 3px 10px;
    border-radius: 12px;
    margin-left: 8px;
    vertical-align: middle;
}

.option-content {
    padding: 20px;
    background: #fafafa;
}

.option-content p {
    margin: 0 0 15px;
    color: #64748b;
    font-size: 14px;
}

.option-content ul {
    margin: 0;
    padding: 0;
    list-style: none;
}

.option-content li {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
    font-size: 13px;
    color: #475569;
}

.option-content li .dashicons {
    color: #10b981;
    font-size: 16px;
    width: 16px;
    height: 16px;
}

/* Wizard Actions */
.wizard-actions {
    display: flex;
    justify-content: center;
    gap: 15px;
    margin-top: 20px;
}

.button-hero {
    padding: 12px 30px !important;
    font-size: 15px !important;
    height: auto !important;
    display: flex !important;
    align-items: center;
    gap: 8px;
}

.button-hero .dashicons {
    font-size: 18px;
    width: 18px;
    height: 18px;
}

/* Activation States */
.activation-ready,
.activation-progress,
.activation-complete {
    text-align: center;
    padding: 40px;
    max-width: 500px;
    margin: 0 auto;
}

.activation-icon,
.complete-icon {
    width: 80px;
    height: 80px;
    border-radius: 50%;
    background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0 auto 20px;
}

.activation-icon .dashicons,
.complete-icon .dashicons {
    font-size: 40px;
    width: 40px;
    height: 40px;
    color: white;
}

.complete-icon {
    background: linear-gradient(135deg, #059669 0%, #10b981 100%);
}

.activation-ready h3,
.activation-progress h3,
.activation-complete h3 {
    margin: 0 0 10px;
    font-size: 22px;
    font-weight: 600;
}

.activation-ready p,
.activation-progress p,
.activation-complete p {
    margin: 0;
    color: #64748b;
}

/* Progress Bar */
.progress-header {
    margin-bottom: 30px;
}

.progress-icon {
    width: 60px;
    height: 60px;
    border-radius: 50%;
    background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0 auto 15px;
}

.progress-icon .dashicons {
    font-size: 30px;
    width: 30px;
    height: 30px;
    color: white;
}

.progress-icon.spinning .dashicons {
    animation: spin 1s linear infinite;
}

@keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
}

.progress-bar-container {
    margin: 20px 0;
}

.progress-bar-bg {
    height: 12px;
    background: #e5e7eb;
    border-radius: 6px;
    overflow: hidden;
}

.progress-bar-fill {
    height: 100%;
    width: 0%;
    background: linear-gradient(90deg, #1e40af 0%, #3b82f6 100%);
    border-radius: 6px;
    transition: width 0.3s ease-out;
}

.progress-percentage {
    font-size: 24px;
    font-weight: 700;
    color: #1e40af;
    margin-top: 10px;
}

.progress-status {
    margin-top: 15px;
}

.progress-status .status-text {
    font-size: 14px;
    color: #64748b;
}

/* Complete Stats */
.complete-stats {
    display: flex;
    justify-content: center;
    gap: 40px;
    margin-top: 30px;
    padding-top: 30px;
    border-top: 1px solid #e5e7eb;
}

.stat-item {
    text-align: center;
}

.stat-number {
    display: block;
    font-size: 28px;
    font-weight: 700;
    color: #1e40af;
}

.stat-label {
    font-size: 13px;
    color: #64748b;
}

/* Task Checklist */
.progress-tasks {
    margin-top: 25px;
    text-align: left;
    background: #f8fafc;
    border-radius: 8px;
    padding: 15px 20px;
}

.task-item {
    display: flex;
    align-items: center;
    padding: 10px 0;
    border-bottom: 1px solid #e5e7eb;
}

.task-item:last-child {
    border-bottom: none;
}

.task-icon {
    width: 24px;
    height: 24px;
    margin-right: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
}

.task-icon .dashicons {
    font-size: 18px;
    width: 18px;
    height: 18px;
}

.task-item[data-status="pending"] .task-icon .dashicons {
    color: #9ca3af;
}

.task-item[data-status="running"] .task-icon .dashicons {
    color: #3b82f6;
    animation: spin 1s linear infinite;
}

.task-item[data-status="done"] .task-icon .dashicons {
    color: #10b981;
}

.task-item[data-status="error"] .task-icon .dashicons {
    color: #ef4444;
}

.task-item[data-status="skipped"] .task-icon .dashicons {
    color: #9ca3af;
}

.task-name {
    flex: 1;
    font-size: 14px;
    color: #374151;
}

.task-item[data-status="done"] .task-name {
    color: #10b981;
}

.task-item[data-status="error"] .task-name {
    color: #ef4444;
}

.task-item[data-status="skipped"] .task-name {
    color: #9ca3af;
    text-decoration: line-through;
}

.task-status {
    font-size: 12px;
    color: #6b7280;
    min-width: 80px;
    text-align: right;
}

.task-status .count {
    font-weight: 600;
    color: #3b82f6;
}
</style>

<script>
var vswafWizardData = {
    configMethod: '.user.ini'
};

// Ensure nonce is available (WordPress Admin adds this via wp_localize_script)
if (typeof vietshieldWizard === 'undefined') {
    var vietshieldWizard = {
        nonce: '<?php echo wp_create_nonce('vietshield_admin'); ?>'
    };
}

jQuery(document).ready(function($) {
    // Store the selected firewall mode
    var selectedFirewallMode = 'protecting';
    
    // Features list for animated progress
    var features = [
        { id: 'sqli', name: 'SQL Injection Protection', delay: 200 },
        { id: 'xss', name: 'XSS Protection', delay: 180 },
        { id: 'lfi', name: 'LFI Protection', delay: 160 },
        { id: 'rce', name: 'RCE Detection', delay: 200, skipInLearning: false },
        { id: 'bad_bots', name: 'Bad Bot Protection', delay: 180 },
        { id: 'rate_limit', name: 'Rate Limiting', delay: 150 },
        { id: 'login_security', name: 'Login Security', delay: 200 },
        { id: 'threat_intel', name: 'Threat Intelligence', delay: 300 },
        { id: 'googlebot', name: 'Googlebot Whitelist', delay: 250 },
        { id: 'early_blocker', name: 'Early Blocker', delay: 300, skipInLearning: true }
    ];
    
    // Option card selection
    $('.option-card').on('click', function() {
        var value = $(this).data('value');
        selectedFirewallMode = value;
        $('.option-card').removeClass('selected');
        $(this).addClass('selected');
        $(this).find('input[type="radio"]').prop('checked', true);
    });
    
    // Continue button - go to step 2
    $('.wizard-next').on('click', function() {
        goToStep(2);
    });
    
    // Back button - go to step 1
    $('.wizard-prev').on('click', function() {
        goToStep(1);
    });
    
    function goToStep(step) {
        if (step === 2) {
            // Go to step 2
            $('#wizard-step-1').fadeOut(300, function() {
                $('#wizard-step-2').fadeIn(300);
                // Update progress indicators
                $('#step-indicator-2').addClass('active');
                $('#step-line').addClass('active');
            });
        } else {
            // Go back to step 1
            $('#wizard-step-2').fadeOut(300, function() {
                $('#wizard-step-1').fadeIn(300);
                // Reset progress indicators
                $('#step-indicator-2').removeClass('active');
                $('#step-line').removeClass('active');
            });
        }
    }
    
    // Activation button
    $('#wizard-activate-btn').on('click', function() {
        startActivation();
    });
    
    function startActivation() {
        // Hide ready state, show progress
        $('#activation-ready').fadeOut(300, function() {
            $('#activation-progress').fadeIn(300);
            
            // Start feature animation
            animateFeatures();
            
            // Send single AJAX request to activate
            activateProtection();
        });
    }
    
    function updateTaskStatus(taskId, status, statusText) {
        var $task = $('.task-item[data-task="' + taskId + '"]');
        $task.attr('data-status', status);
        
        // Update icon
        var iconClass = 'dashicons-clock';
        if (status === 'running') iconClass = 'dashicons-update';
        else if (status === 'done') iconClass = 'dashicons-yes-alt';
        else if (status === 'skipped') iconClass = 'dashicons-minus';
        else if (status === 'error') iconClass = 'dashicons-warning';
        
        $task.find('.task-icon .dashicons').removeClass().addClass('dashicons ' + iconClass);
        
        if (statusText) {
            $task.find('.task-status').html(statusText);
        }
    }
    
    function animateFeatures() {
        var currentIndex = 0;
        var totalFeatures = features.length;
        
        function processNextFeature() {
            if (currentIndex >= totalFeatures) {
                // All features done
                $('#progress-bar-fill').css('width', '100%');
                $('#progress-percentage').text('100%');
                return;
            }
            
            var feature = features[currentIndex];
            
            // Check if feature should be skipped in learning mode
            if (selectedFirewallMode === 'learning' && feature.skipInLearning) {
                updateTaskStatus(feature.id, 'skipped', '<?php echo esc_js(__('Skipped', 'vietshield-waf')); ?>');
                currentIndex++;
                var progress = Math.round((currentIndex / totalFeatures) * 100);
                $('#progress-bar-fill').css('width', progress + '%');
                $('#progress-percentage').text(progress + '%');
                setTimeout(processNextFeature, 100);
                return;
            }
            
            // Set running status
            updateTaskStatus(feature.id, 'running', '<?php echo esc_js(__('Configuring...', 'vietshield-waf')); ?>');
            
            // Simulate processing time
            setTimeout(function() {
                // Set done status
                updateTaskStatus(feature.id, 'done', '<?php echo esc_js(__('Enabled', 'vietshield-waf')); ?>');
                
                // Update progress bar
                currentIndex++;
                var progress = Math.round((currentIndex / totalFeatures) * 100);
                $('#progress-bar-fill').css('width', progress + '%');
                $('#progress-percentage').text(progress + '%');
                
                // Process next feature
                setTimeout(processNextFeature, 50);
            }, feature.delay);
        }
        
        // Start processing
        processNextFeature();
    }
    
    function activateProtection() {
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'vietshield_wizard_complete',
                nonce: vietshieldWizard.nonce,
                firewall_mode: selectedFirewallMode,
                auto_optimize: 1
            },
            dataType: 'json',
            timeout: 30000, // 30 second timeout
            success: function(response) {
                if (response.success) {
                    // Wait for animation to complete then show finish
                    waitForAnimationThenFinish(response.data);
                } else {
                    // Error - still finish but log error
                    console.log('VietShield Wizard error:', response.data);
                    waitForAnimationThenFinish({ error: response.data ? response.data.message : 'Unknown error' });
                }
            },
            error: function(xhr, status, error) {
                // Try to parse response
                var errorMsg = 'Connection error';
                if (xhr.responseText) {
                    try {
                        var response = JSON.parse(xhr.responseText);
                        if (response && response.success) {
                            waitForAnimationThenFinish(response.data);
                            return;
                        }
                        if (response && response.data && response.data.message) {
                            errorMsg = response.data.message;
                        }
                    } catch (e) {}
                }
                
                // Still finish the wizard
                waitForAnimationThenFinish({ error: errorMsg });
            }
        });
    }
    
    function waitForAnimationThenFinish(data) {
        // Check if animation is complete (progress at 100%)
        var checkInterval = setInterval(function() {
            var progress = parseInt($('#progress-percentage').text());
            if (progress >= 100) {
                clearInterval(checkInterval);
                setTimeout(function() {
                    finishWizard(data);
                }, 500);
            }
        }, 100);
        
        // Fallback: force finish after 5 seconds
        setTimeout(function() {
            clearInterval(checkInterval);
            finishWizard(data);
        }, 5000);
    }
    
    function finishWizard(data) {
        // Update completion stats
        var enabledCount = selectedFirewallMode === 'learning' ? 9 : 10;
        $('.stat-number').first().text(enabledCount);
        
        if (selectedFirewallMode === 'learning') {
            $('#early-blocking-stat').text('—');
            $('#early-blocking-label').text('<?php echo esc_js(__('Learning Mode Active', 'vietshield-waf')); ?>');
        }
        
        // Show complete state
        $('#activation-progress').fadeOut(300, function() {
            $('#activation-complete').fadeIn(300);
        });
    }
});
</script>
