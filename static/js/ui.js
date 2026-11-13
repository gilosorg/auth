(function (window) {
    'use strict';

    var toastContainer = null;

    function escapeHtml(value) {
        if (value === null || value === undefined) return '';
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function ensureToastContainer() {
        if (toastContainer && document.body.contains(toastContainer)) {
            return toastContainer;
        }
        toastContainer = document.createElement('div');
        toastContainer.className = 'gilos-toast-region';
        toastContainer.setAttribute('aria-live', 'polite');
        toastContainer.setAttribute('aria-atomic', 'false');
        document.body.appendChild(toastContainer);
        return toastContainer;
    }

    function getToastIcon(type) {
        switch (type) {
            case 'success':
                return '<svg class="gilos-toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>';
            case 'error':
                return '<svg class="gilos-toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
            case 'warning':
                return '<svg class="gilos-toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
            default:
                return '<svg class="gilos-toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>';
        }
    }

    function toast(message, type, durationMs) {
        if (!message) return;
        var kind = type || 'info';
        var duration = typeof durationMs === 'number' ? durationMs : (kind === 'error' ? 4500 : 3200);
        var container = ensureToastContainer();

        var el = document.createElement('div');
        el.className = 'gilos-toast gilos-toast--' + kind;
        el.setAttribute('role', kind === 'error' ? 'alert' : 'status');
        el.innerHTML =
            getToastIcon(kind) +
            '<div class="gilos-toast-body">' + escapeHtml(message) + '</div>' +
            '<button type="button" class="gilos-toast-close" aria-label="Dismiss">' +
                '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>' +
            '</button>';

        var dismiss = function () {
            if (!el.parentNode || el.classList.contains('is-leaving')) return;
            el.classList.add('is-leaving');
            window.setTimeout(function () {
                if (el.parentNode) el.parentNode.removeChild(el);
            }, 170);
        };

        el.querySelector('.gilos-toast-close').addEventListener('click', dismiss);
        container.appendChild(el);

        while (container.children.length > 4) {
            container.removeChild(container.firstChild);
        }

        if (duration > 0) {
            window.setTimeout(dismiss, duration);
        }
    }

    function copyText(text, options) {
        var opts = options || {};
        var successMsg = opts.successMsg || 'Copied to clipboard';
        var errorMsg = opts.errorMsg || 'Failed to copy';

        function onCopied() {
            if (opts.triggerEl) {
                var btn = opts.triggerEl;
                if (!btn.dataset.origHtml) {
                    btn.dataset.origHtml = btn.innerHTML;
                }
                btn.classList.add('is-copied');
                if (opts.copiedHtml) {
                    btn.innerHTML = opts.copiedHtml;
                }
                window.setTimeout(function () {
                    btn.classList.remove('is-copied');
                    if (opts.copiedHtml && btn.dataset.origHtml) {
                        btn.innerHTML = btn.dataset.origHtml;
                    }
                }, 1600);
            }
            if (!opts.silent) {
                toast(successMsg, 'success', 2200);
            }
            return true;
        }

        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(String(text)).then(onCopied).catch(function () {
                return fallbackCopy(String(text)) ? onCopied() : (toast(errorMsg, 'error'), false);
            });
        }
        return Promise.resolve(fallbackCopy(String(text)) ? onCopied() : (toast(errorMsg, 'error'), false));
    }

    function fallbackCopy(text) {
        try {
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.left = '-9999px';
            ta.style.top = '-9999px';
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            var ok = document.execCommand('copy');
            document.body.removeChild(ta);
            return ok;
        } catch (e) {
            return false;
        }
    }

    function setButtonLoading(btn, isLoading, loadingText) {
        if (!btn) return;
        if (isLoading) {
            if (!btn.dataset.origContent) {
                btn.dataset.origContent = btn.innerHTML;
            }
            btn.disabled = true;
            btn.setAttribute('aria-busy', 'true');
            var label = loadingText || btn.textContent.trim();
            btn.innerHTML = '<span class="btn-spinner" aria-hidden="true"></span><span>' + escapeHtml(label) + '</span>';
        } else {
            btn.disabled = false;
            btn.removeAttribute('aria-busy');
            if (btn.dataset.origContent) {
                btn.innerHTML = btn.dataset.origContent;
                delete btn.dataset.origContent;
            }
        }
    }

    function parseUserAgent(ua) {
        if (!ua || typeof ua !== 'string') {
            return { browser: '', os: '', deviceType: 'desktop', shortLabel: '', raw: '' };
        }
        var lower = ua.toLowerCase();

        var isBot = /curl|wget|postman|insomnia|httpie|python-requests|go-http-client|okhttp|axios|bot|crawler|spider/.test(lower);
        var deviceType = 'desktop';
        if (isBot) {
            deviceType = 'api';
        } else if (/ipad|tablet|playbook|silk|(android(?!.*mobile))/.test(lower)) {
            deviceType = 'tablet';
        } else if (/mobile|iphone|ipod|android|blackberry|iemobile|opera mini/.test(lower)) {
            deviceType = 'mobile';
        }

        var browser = '';
        if (/edg\/|edge\/|edgios|edga/.test(lower)) browser = 'Microsoft Edge';
        else if (/opr\/|opera/.test(lower)) browser = 'Opera';
        else if (/samsungbrowser/.test(lower)) browser = 'Samsung Internet';
        else if (/yabrowser/.test(lower)) browser = 'Yandex Browser';
        else if (/vivaldi/.test(lower)) browser = 'Vivaldi';
        else if (/firefox|fxios/.test(lower)) browser = 'Firefox';
        else if (/crios|chrome/.test(lower) && !/chromium/.test(lower)) browser = 'Chrome';
        else if (/safari/.test(lower) && !/chrome|crios|chromium/.test(lower)) browser = 'Safari';
        else if (/go-http-client/.test(lower)) browser = 'Go HTTP Client';
        else if (/curl/.test(lower)) browser = 'cURL';
        else if (/postman/.test(lower)) browser = 'Postman';
        else if (/okhttp/.test(lower)) browser = 'Android Client';

        var os = '';
        if (/iphone/.test(lower)) os = 'iPhone';
        else if (/ipad/.test(lower)) os = 'iPad';
        else if (/android/.test(lower)) os = 'Android';
        else if (/mac os x|macintosh/.test(lower)) os = 'macOS';
        else if (/windows nt/.test(lower)) os = 'Windows';
        else if (/cros/.test(lower)) os = 'ChromeOS';
        else if (/linux/.test(lower)) os = 'Linux';

        var parts = [];
        if (browser) parts.push(browser);
        if (os) parts.push(os);
        var shortLabel = parts.length ? parts.join(' on ') : ua.slice(0, 48);

        return {
            browser: browser,
            os: os,
            deviceType: deviceType,
            shortLabel: shortLabel,
            raw: ua
        };
    }

    function getDeviceIconSvg(deviceType, size) {
        var s = size || 18;
        switch (deviceType) {
            case 'mobile':
                return '<svg width="' + s + '" height="' + s + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="7" y="2" width="10" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>';
            case 'tablet':
                return '<svg width="' + s + '" height="' + s + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="2" width="16" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>';
            case 'api':
                return '<svg width="' + s + '" height="' + s + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>';
            default:
                return '<svg width="' + s + '" height="' + s + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>';
        }
    }

    function formatRelativeTime(dateString, T) {
        var labels = T || {};
        if (!dateString) return labels.na || 'N/A';
        var date = new Date(dateString);
        if (isNaN(date.getTime())) return labels.na || 'N/A';

        var diffSec = Math.floor((Date.now() - date.getTime()) / 1000);
        if (diffSec < 60) return labels.just_now || 'just now';
        var diffMin = Math.floor(diffSec / 60);
        if (diffMin < 60) {
            return diffMin === 1 ? (labels.minute_ago || '1m ago') : diffMin + ' ' + (labels.minutes_ago || 'minutes ago');
        }
        var diffHr = Math.floor(diffMin / 60);
        if (diffHr < 24) {
            return diffHr === 1 ? (labels.hour_ago || '1h ago') : diffHr + ' ' + (labels.hours_ago || 'hours ago');
        }
        var diffDay = Math.floor(diffHr / 24);
        if (diffDay < 30) {
            return diffDay === 1 ? (labels.day_ago || '1d ago') : diffDay + ' ' + (labels.days_ago || 'days ago');
        }
        var diffMonth = Math.floor(diffDay / 30);
        if (diffMonth < 12) {
            return diffMonth === 1 ? (labels.month_ago || '1 month ago') : diffMonth + ' ' + (labels.months_ago || 'months ago');
        }
        return date.toLocaleDateString(document.documentElement.lang || 'en', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    }

    function formatExactTime(dateString) {
        if (!dateString) return '';
        var date = new Date(dateString);
        if (isNaN(date.getTime())) return '';
        return date.toLocaleString(document.documentElement.lang || 'en', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    function evaluatePassword(pw) {
        var val = typeof pw === 'string' ? pw : '';
        var rules = {
            length: val.length >= 8 && val.length <= 72,
            upperLower: /[a-z]/.test(val) && /[A-Z]/.test(val),
            number: /[0-9]/.test(val),
            special: /[^A-Za-z0-9]/.test(val)
        };

        if (!val.length) {
            return { score: 0, rules: rules };
        }

        var score = 1;
        if (rules.length) {
            var checks = (rules.upperLower ? 1 : 0) + (rules.number ? 1 : 0) + (rules.special ? 1 : 0);
            if (val.length >= 12 && checks >= 2) {
                score = 4;
            } else if (checks >= 2) {
                score = 3;
            } else if (checks >= 1 || val.length >= 10) {
                score = 2;
            } else {
                score = 1;
            }
        }
        return { score: score, rules: rules };
    }

    function attachPasswordStrength(inputEl, containerEl, T) {
        if (!inputEl || !containerEl) return function () {};
        var t = T || {};

        var checkIcon = '<svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';

        containerEl.innerHTML =
            '<div class="pw-strength">' +
                '<div class="pw-strength-header">' +
                    '<span>' + escapeHtml(t.password_strength || 'Password strength') + '</span>' +
                    '<span class="pw-strength-label" data-level="0"></span>' +
                '</div>' +
                '<div class="pw-strength-bars" data-level="0">' +
                    '<span class="pw-strength-segment"></span>' +
                    '<span class="pw-strength-segment"></span>' +
                    '<span class="pw-strength-segment"></span>' +
                    '<span class="pw-strength-segment"></span>' +
                '</div>' +
                '<div class="pw-rules">' +
                    '<span class="pw-rule" data-rule="length"><span class="pw-rule-dot">' + checkIcon + '</span>' + escapeHtml(t.password_min_8 || '8-72 characters') + '</span>' +
                    '<span class="pw-rule" data-rule="upperLower"><span class="pw-rule-dot">' + checkIcon + '</span>' + escapeHtml(t.pw_rule_case || 'Upper & lowercase') + '</span>' +
                    '<span class="pw-rule" data-rule="number"><span class="pw-rule-dot">' + checkIcon + '</span>' + escapeHtml(t.pw_rule_number || 'Number (0-9)') + '</span>' +
                    '<span class="pw-rule" data-rule="special"><span class="pw-rule-dot">' + checkIcon + '</span>' + escapeHtml(t.pw_rule_symbol || 'Special character') + '</span>' +
                '</div>' +
            '</div>';

        var labelEl = containerEl.querySelector('.pw-strength-label');
        var barsEl = containerEl.querySelector('.pw-strength-bars');
        var ruleEls = {
            length: containerEl.querySelector('[data-rule="length"]'),
            upperLower: containerEl.querySelector('[data-rule="upperLower"]'),
            number: containerEl.querySelector('[data-rule="number"]'),
            special: containerEl.querySelector('[data-rule="special"]')
        };

        var levelNames = {
            0: '',
            1: t.pw_strength_weak || 'Weak',
            2: t.pw_strength_fair || 'Fair',
            3: t.pw_strength_good || 'Good',
            4: t.pw_strength_strong || 'Strong'
        };

        function update() {
            var res = evaluatePassword(inputEl.value);
            barsEl.setAttribute('data-level', String(res.score));
            labelEl.setAttribute('data-level', String(res.score));
            labelEl.textContent = levelNames[res.score] || '';

            Object.keys(ruleEls).forEach(function (key) {
                if (ruleEls[key]) {
                    ruleEls[key].classList.toggle('is-met', Boolean(res.rules[key]));
                }
            });
        }

        inputEl.addEventListener('input', update);
        update();
        return update;
    }

    function getFocusableElements(container) {
        if (!container || typeof container.querySelectorAll !== 'function') return [];
        var candidates = container.querySelectorAll(
            'button:not([disabled]), [href], input:not([type="hidden"]):not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
        );
        return Array.prototype.filter.call(candidates, function (el) {
            if (!el) return false;
            if (el.hidden) return false;
            if (typeof window.getComputedStyle === 'function' && el.style) {
                if (el.style.display === 'none' || el.style.visibility === 'hidden') return false;
            }
            return el.offsetParent === undefined || el.offsetParent !== null || el === document.activeElement;
        });
    }

    function bindModalA11y(modalEl, closeFn, options) {
        if (!modalEl || typeof closeFn !== 'function') return;
        if (modalEl.dataset && modalEl.dataset.a11yBound === '1') return;
        if (modalEl.dataset) modalEl.dataset.a11yBound = '1';
        var opts = options || {};
        if (opts.closeOnBackdrop !== false) {
            modalEl.addEventListener('click', function (e) {
                if (e.target === modalEl) {
                    closeFn();
                }
            });
        }
        document.addEventListener('keydown', function (e) {
            if (!modalEl.classList.contains('is-open')) return;
            if (document.querySelector('.swal2-container')) return;
            var openModals = document.querySelectorAll('.modal.is-open');
            if (openModals.length && openModals[openModals.length - 1] !== modalEl) return;

            if (e.key === 'Escape' && opts.closeOnEscape !== false) {
                e.preventDefault();
                closeFn();
                return;
            }

            if (e.key === 'Tab') {
                var focusables = getFocusableElements(modalEl);
                if (!focusables.length) return;
                var first = focusables[0];
                var last = focusables[focusables.length - 1];
                var active = document.activeElement;
                if (e.shiftKey) {
                    if (!modalEl.contains || !modalEl.contains(active) || active === first) {
                        e.preventDefault();
                        if (typeof last.focus === 'function') last.focus();
                    }
                } else {
                    if (!modalEl.contains || !modalEl.contains(active) || active === last) {
                        e.preventDefault();
                        if (typeof first.focus === 'function') first.focus();
                    }
                }
            }
        });
    }

    function attachCapsLockWarning(inputEl, badgeEl, labelText) {
        if (!inputEl || !badgeEl) return;
        if (labelText && !badgeEl.firstElementChild && !badgeEl.textContent.trim()) {
            badgeEl.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg><span>' + escapeHtml(labelText) + '</span>';
        }
        badgeEl.hidden = true;
        function update(e) {
            if (!e || typeof e.getModifierState !== 'function') return;
            var active = !!e.getModifierState('CapsLock');
            badgeEl.hidden = !active;
            badgeEl.classList.toggle('is-visible', active);
        }
        inputEl.addEventListener('keydown', update);
        inputEl.addEventListener('keyup', update);
        inputEl.addEventListener('blur', function () {
            badgeEl.hidden = true;
            badgeEl.classList.remove('is-visible');
        });
    }

    window.GilosUI = {
        escapeHtml: escapeHtml,
        toast: toast,
        copyText: copyText,
        setButtonLoading: setButtonLoading,
        parseUserAgent: parseUserAgent,
        getDeviceIconSvg: getDeviceIconSvg,
        formatRelativeTime: formatRelativeTime,
        formatExactTime: formatExactTime,
        evaluatePassword: evaluatePassword,
        attachPasswordStrength: attachPasswordStrength,
        attachCapsLockWarning: attachCapsLockWarning,
        bindModalA11y: bindModalA11y
    };
})(window);

