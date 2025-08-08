/**
 * Encryption utilities and UI enhancements for SecureChat
 */

// Global app state
const SecureChat = {
    isOnline: navigator.onLine,
    notifications: [],
    settings: {
        autoRefresh: true,
        refreshInterval: 30000, // 30 seconds
        showNotifications: true
    }
};

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
    checkBrowserCompatibility();
});

/**
 * Initialize the application
 */
function initializeApp() {
    console.log('SecureChat initialized');
    
    // Setup connection monitoring
    setupConnectionMonitoring();
    
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Setup auto-refresh for messages page
    if (window.location.pathname.includes('/messages')) {
        setupMessageRefresh();
    }
    
    // Setup form validations
    setupFormValidations();
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
    // Online/offline status
    window.addEventListener('online', function() {
        SecureChat.isOnline = true;
        showConnectionStatus('Connected', 'success');
    });
    
    window.addEventListener('offline', function() {
        SecureChat.isOnline = false;
        showConnectionStatus('Offline', 'danger');
    });
    
    // Form submissions
    document.addEventListener('submit', function(e) {
        const form = e.target;
        if (form.tagName === 'FORM') {
            handleFormSubmission(form, e);
        }
    });
    
    // Security indicator animations
    animateSecurityIndicators();
}

/**
 * Check browser compatibility for encryption features
 */
function checkBrowserCompatibility() {
    const requiredFeatures = [
        'crypto',
        'TextEncoder',
        'Promise',
        'fetch'
    ];
    
    const missingFeatures = requiredFeatures.filter(feature => {
        switch (feature) {
            case 'crypto':
                return !window.crypto || !window.crypto.subtle;
            case 'TextEncoder':
                return !window.TextEncoder;
            case 'Promise':
                return !window.Promise;
            case 'fetch':
                return !window.fetch;
            default:
                return false;
        }
    });
    
    if (missingFeatures.length > 0) {
        showNotification(
            'Browser Compatibility Warning',
            `Your browser may not support all security features. Missing: ${missingFeatures.join(', ')}`,
            'warning'
        );
    }
}

/**
 * Setup connection monitoring
 */
function setupConnectionMonitoring() {
    // Check connection status periodically
    setInterval(function() {
        if (!SecureChat.isOnline) {
            // Attempt to check connectivity
            fetch('/api/ping', { method: 'HEAD', cache: 'no-cache' })
                .then(() => {
                    if (!SecureChat.isOnline) {
                        SecureChat.isOnline = true;
                        showConnectionStatus('Reconnected', 'success');
                    }
                })
                .catch(() => {
                    // Still offline
                });
        }
    }, 10000); // Check every 10 seconds
}

/**
 * Show connection status notification
 */
function showConnectionStatus(message, type) {
    const existingStatus = document.querySelector('.connection-status');
    if (existingStatus) {
        existingStatus.remove();
    }
    
    const statusDiv = document.createElement('div');
    statusDiv.className = `alert alert-${type} connection-status position-fixed start-50 translate-middle-x`;
    statusDiv.style.cssText = 'top: 20px; z-index: 9999; min-width: 200px; text-align: center;';
    statusDiv.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-triangle'} me-2"></i>
        ${message}
    `;
    
    document.body.appendChild(statusDiv);
    
    // Auto-remove after 3 seconds
    setTimeout(() => {
        statusDiv.remove();
    }, 3000);
}

/**
 * Setup automatic message refresh
 */
function setupMessageRefresh() {
    if (!SecureChat.settings.autoRefresh) return;
    
    setInterval(function() {
        if (SecureChat.isOnline && document.visibilityState === 'visible') {
            checkForNewMessages();
        }
    }, SecureChat.settings.refreshInterval);
}

/**
 * Check for new messages
 */
function checkForNewMessages() {
    fetch('/api/messages/check-new', {
        headers: {
            'Cache-Control': 'no-cache'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.new_messages > 0) {
            showNewMessageNotification(data.new_messages);
            
            // Update unread count in UI
            const unreadBadges = document.querySelectorAll('.unread-count');
            unreadBadges.forEach(badge => {
                badge.textContent = data.total_unread;
                badge.classList.add('pulse');
            });
        }
    })
    .catch(error => {
        console.error('Error checking for new messages:', error);
    });
}

/**
 * Show new message notification
 */
function showNewMessageNotification(count) {
    if (!SecureChat.settings.showNotifications) return;
    
    const message = count === 1 ? '1 new message' : `${count} new messages`;
    showNotification('New Message', message, 'info');
    
    // Browser notification if permitted
    if (Notification.permission === 'granted') {
        new Notification('SecureChat', {
            body: message,
            icon: '/favicon.ico',
            badge: '/favicon.ico'
        });
    }
}

/**
 * Generic notification system
 */
function showNotification(title, message, type = 'info', duration = 5000) {
    const notificationId = 'notification-' + Date.now();
    
    const notificationHtml = `
        <div id="${notificationId}" class="alert alert-${type} alert-dismissible fade show position-fixed" 
             style="top: 80px; right: 20px; z-index: 9999; min-width: 300px;">
            <strong>${title}</strong><br>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', notificationHtml);
    
    // Auto-remove after duration
    setTimeout(() => {
        const notification = document.getElementById(notificationId);
        if (notification) {
            notification.remove();
        }
    }, duration);
}

/**
 * Handle form submissions with loading states
 */
function handleFormSubmission(form, event) {
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) {
        // Show loading state
        const originalText = submitBtn.innerHTML;
        submitBtn.disabled = true;
        submitBtn.innerHTML = `
            <span class="spinner-border spinner-border-sm me-2" role="status"></span>
            Processing...
        `;
        
        // Restore button after 5 seconds (fallback)
        setTimeout(() => {
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalText;
        }, 5000);
    }
}

/**
 * Setup form validations
 */
function setupFormValidations() {
    // Real-time password confirmation
    const passwordFields = document.querySelectorAll('input[type="password"]');
    passwordFields.forEach(field => {
        if (field.name === 'confirm_password') {
            field.addEventListener('input', function() {
                const password = document.querySelector('input[name="password"]');
                if (password && password.value !== this.value) {
                    this.setCustomValidity('Passwords do not match');
                    this.classList.add('is-invalid');
                } else {
                    this.setCustomValidity('');
                    this.classList.remove('is-invalid');
                    this.classList.add('is-valid');
                }
            });
        }
    });
    
    // Email validation enhancement
    const emailFields = document.querySelectorAll('input[type="email"]');
    emailFields.forEach(field => {
        field.addEventListener('blur', function() {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (this.value && !emailRegex.test(this.value)) {
                this.setCustomValidity('Please enter a valid email address');
                this.classList.add('is-invalid');
            } else {
                this.setCustomValidity('');
                this.classList.remove('is-invalid');
                if (this.value) {
                    this.classList.add('is-valid');
                }
            }
        });
    });
}

/**
 * Animate security indicators
 */
function animateSecurityIndicators() {
    const indicators = document.querySelectorAll('.security-indicator.secure');
    indicators.forEach((indicator, index) => {
        setTimeout(() => {
            indicator.style.animation = 'pulse 2s ease-in-out infinite';
        }, index * 200);
    });
}

/**
 * Copy text to clipboard with feedback
 */
function copyToClipboard(text, element) {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
            showCopyFeedback(element, true);
        }).catch(() => {
            showCopyFeedback(element, false);
        });
    } else {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        try {
            document.execCommand('copy');
            showCopyFeedback(element, true);
        } catch (err) {
            showCopyFeedback(element, false);
        }
        document.body.removeChild(textArea);
    }
}

/**
 * Show copy feedback
 */
function showCopyFeedback(element, success) {
    const originalText = element.innerHTML;
    const icon = success ? 'check' : 'times';
    const message = success ? 'Copied!' : 'Failed';
    
    element.innerHTML = `<i class="fas fa-${icon} me-1"></i>${message}`;
    element.classList.add(success ? 'btn-success' : 'btn-danger');
    
    setTimeout(() => {
        element.innerHTML = originalText;
        element.classList.remove('btn-success', 'btn-danger');
    }, 2000);
}

/**
 * Security utilities
 */
const SecurityUtils = {
    /**
     * Generate a secure random string
     */
    generateSecureRandom: function(length = 32) {
        const array = new Uint8Array(length);
        window.crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    },
    
    /**
     * Check password strength
     */
    checkPasswordStrength: function(password) {
        const checks = {
            length: password.length >= 8,
            lowercase: /[a-z]/.test(password),
            uppercase: /[A-Z]/.test(password),
            numbers: /\d/.test(password),
            special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
        };
        
        const score = Object.values(checks).filter(Boolean).length;
        const strength = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'][score] || 'Very Weak';
        
        return { score, strength, checks };
    },
    
    /**
     * Validate secure context
     */
    validateSecureContext: function() {
        return window.isSecureContext || location.protocol === 'https:' || location.hostname === 'localhost';
    }
};

// Export for global use
window.SecureChat = SecureChat;
window.SecurityUtils = SecurityUtils;
