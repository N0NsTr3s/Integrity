class IntegrityMonitor {
    constructor() {
        this.originalTags = new Set();
        this.observer = null;
        this.config = this.getConfig();
        this.manifestEndpoint = this.config.manifestEndpoint;
        this.reportEndpoint = this.config.reportEndpoint;

        const script = document.currentScript || document.querySelector('script[data-tenant]');
        // explicit base path set on script tag (preferred)
        this.basePath = (script && script.dataset && script.dataset.basePath) || null;

        // autodetect site repo base if not provided: e.g. /Integrity from page path
        if (!this.basePath) {
            const parts = window.location.pathname.split('/').filter(Boolean);
            this.basePath = parts.length > 0 ? '/' + parts[0] : '';
        }

        this.origin = window.location.origin;

        // --- auth/token state ---
        this.authToken = null;
        this.tokenExpires = 0;
    }

    getConfig() {
        const script = document.currentScript || document.querySelector('script[data-tenant]');
        return {
            tenant: script?.dataset.tenant || 'default',
            manifestEndpoint: script?.dataset.manifestEndpoint || `/tenant/${script?.dataset.tenant || 'default'}/manifest`,
            reportEndpoint: script?.dataset.reportEndpoint || `/tenant/${script?.dataset.tenant || 'default'}/report`
        };
    }

    // === CLIENT ENVIRONMENT DETECTION ===
    
    getBrowserInfo() {
        const ua = navigator.userAgent;
        const result = {
            browser: 'Unknown',
            version: 'unknown',
            platform: navigator.platform || 'unknown',
            language: navigator.language || 'unknown',
            cookieEnabled: navigator.cookieEnabled,
            onLine: navigator.onLine,
            screenResolution: `${screen.width}x${screen.height}`,
            colorDepth: screen.colorDepth,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            userAgent: ua
        };

        // Browser detection
        if (ua.includes('Chrome/') && !ua.includes('Edg/')) {
            result.browser = 'Chrome';
            const match = ua.match(/Chrome\/([0-9.]+)/);
            result.version = match ? match[1] : 'unknown';
        } else if (ua.includes('Edg/')) {
            result.browser = 'Edge';
            const match = ua.match(/Edg\/([0-9.]+)/);
            result.version = match ? match[1] : 'unknown';
        } else if (ua.includes('Firefox/')) {
            result.browser = 'Firefox';
            const match = ua.match(/Firefox\/([0-9.]+)/);
            result.version = match ? match[1] : 'unknown';
        } else if (ua.includes('Safari/') && !ua.includes('Chrome')) {
            result.browser = 'Safari';
            const match = ua.match(/Version\/([0-9.]+)/);
            result.version = match ? match[1] : 'unknown';
        } else if (ua.includes('Trident/') || ua.includes('MSIE')) {
            result.browser = 'Internet Explorer';
            const match = ua.match(/(?:MSIE |rv:)([0-9.]+)/);
            result.version = match ? match[1] : 'unknown';
        }

        // Enhanced platform detection
        if (ua.includes('Windows NT 10.0')) {
            result.platform = 'Windows 10';
        } else if (ua.includes('Windows NT 6.3')) {
            result.platform = 'Windows 8.1';
        } else if (ua.includes('Windows NT 6.1')) {
            result.platform = 'Windows 7';
        } else if (ua.includes('Mac OS X')) {
            const match = ua.match(/Mac OS X ([0-9_]+)/);
            result.platform = match ? `macOS ${match[1].replace(/_/g, '.')}` : 'macOS';
        } else if (ua.includes('Android')) {
            const match = ua.match(/Android ([0-9.]+)/);
            result.platform = match ? `Android ${match[1]}` : 'Android';
        } else if (ua.includes('iPhone') || ua.includes('iPad')) {
            const match = ua.match(/OS ([0-9_]+)/);
            result.platform = match ? `iOS ${match[1].replace(/_/g, '.')}` : 'iOS';
        }

        return result;
    }

    getSecurityContext() {
        return {
            isSecureContext: window.isSecureContext || false,
            protocol: window.location.protocol,
            port: window.location.port || (window.location.protocol === 'https:' ? '443' : '80'),
            origin: window.location.origin,
            documentDomain: document.domain,
            cookieEnabled: navigator.cookieEnabled,
            doNotTrack: navigator.doNotTrack,
            webdriver: navigator.webdriver || false,
            deviceMemory: navigator.deviceMemory || 'unknown',
            hardwareConcurrency: navigator.hardwareConcurrency || 'unknown'
        };
    }

    // === ORIGINAL FILE INTEGRITY MONITORING ===
    
    async sha256Base64(data) {
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashString = hashArray.map(b => String.fromCharCode(b)).join('');
        return btoa(hashString);
    }

    // Resolve original URL into candidate absolute URLs (tries basePath variants)
    resolveCandidates(url) {
        // if already absolute, return as-is
        try {
            const u = new URL(url, this.origin);
            if (u.origin !== this.origin || url.startsWith('http')) {
                return [u.href];
            }
        } catch (e) {
            /* ignore */
        }

        const normalized = url.startsWith('/') ? url : '/' + url;
        const candidates = [
            this.origin + normalized,                        // root-based
        ];

        if (this.basePath && !normalized.startsWith(this.basePath)) {
            candidates.unshift(this.origin + this.basePath + normalized); // repo-prefixed first
        } else if (this.basePath && normalized.startsWith(this.basePath)) {
            candidates.unshift(this.origin + normalized); // already includes basePath
        }

        // also try relative to current document
        candidates.push(new URL(url, window.location.href).href);

        // unique
        return [...new Set(candidates)];
    }

    // replace fetchArrayBuffer usages with this helper
    async fetchArrayBufferWithFallback(url) {
        const candidates = this.resolveCandidates(url);
        let lastErr = null;
        for (const u of candidates) {
            try {
                const res = await fetch(u, { mode: 'cors' });
                if (res.ok) return await res.arrayBuffer();
                lastErr = new Error(`HTTP ${res.status} for ${u}`);
            } catch (err) {
                lastErr = err;
            }
        }
        throw lastErr;
    }

    // Example: update verifyResources/performFileIntegrityCheck to call fetchArrayBufferWithFallback
    async fetchArrayBuffer(url) {
        // replace existing implementation with fallback wrapper
        return await this.fetchArrayBufferWithFallback(url);
    }

    async verifyResources(manifest) {
        const findings = [];
        const files = manifest.files || {};

        for (const [path, meta] of Object.entries(files)) {
            const expectedSha = meta.sha256;
            if (!expectedSha) continue;

            try {
                // If manifest entry is already an absolute URL, fetch that exact URL.
                // Otherwise use the fallback fetch which will try repo basePath (/Integrity) and other candidates.
                let arrayBuffer;
                if (/^https?:\/\//i.test(path)) {
                    arrayBuffer = await this.fetchArrayBuffer(path);
                } else {
                    arrayBuffer = await this.fetchArrayBufferWithFallback(path);
                }

                if (!arrayBuffer) {
                    findings.push({
                        url: path,
                        path: path,
                        issue: 'unable_to_fetch',
                        expected: expectedSha,
                        actual: null
                    });
                    continue;
                }

                const actualSha = await this.sha256Base64(new Uint8Array(arrayBuffer));
                if (actualSha !== expectedSha) {
                    findings.push({
                        url: path,
                        path: path,
                        issue: 'hash_mismatch',
                        expected: expectedSha,
                        actual: actualSha
                    });
                }
            } catch (error) {
                findings.push({
                    url: path,
                    path: path,
                    issue: 'verification_error',
                    expected: expectedSha,
                    actual: null,
                    error: error.message
                });
            }
        }

        return findings;
    }

    // --- TOKEN ACQUISITION FOR PROTECTED ENDPOINTS ---
    // derive token endpoint from reportEndpoint: /tenant/:t/report -> /tenant/:t/token
    getTokenUrl() {
        try {
            return this.reportEndpoint.replace(/\/report\/?$/i, '/token');
        } catch (e) {
            return null;
        }
    }

    // fetch a short-lived token from backend, cache until near expiry
    async fetchAuthToken() {
        // reuse token while valid (refresh 10s before expiry)
        if (this.authToken && Date.now() < (this.tokenExpires - 10000)) return this.authToken;

        const tokenUrl = this.getTokenUrl();
        if (!tokenUrl) return null;

        try {
            const resp = await fetch(tokenUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ tenant: this.config.tenant }),
                cache: 'no-cache'
            });
            if (!resp.ok) {
                console.warn(`[Integrity] token fetch failed ${resp.status} ${tokenUrl}`);
                return null;
            }
            const j = await resp.json();
            if (!j || !j.token) return null;
            this.authToken = j.token;
            if (j.expires_in) {
                this.tokenExpires = Date.now() + (j.expires_in * 1000);
            } else {
                // try to parse JWT exp
                try {
                    const payload = JSON.parse(atob(this.authToken.split('.')[1]));
                    this.tokenExpires = (payload.exp || 0) * 1000;
                } catch (e) {
                    // default short window
                    this.tokenExpires = Date.now() + 120000;
                }
            }
            return this.authToken;
        } catch (err) {
            console.warn('[Integrity] fetchAuthToken failed', err);
            return null;
        }
    }

    async performFileIntegrityCheck() {
        try {
            // attempt to attach token when fetching manifest
            const headers = {};
            const token = await this.fetchAuthToken();
            if (token) headers['Authorization'] = `Bearer ${token}`;

            const resp = await fetch(this.manifestEndpoint, { method: 'GET', headers, cache: 'no-cache' });
            if (!resp.ok) {
                console.warn(`[Integrity] Could not fetch manifest ${this.manifestEndpoint}: HTTP ${resp.status}`);
                return;
            }
            const manifest = await resp.json();

            // continue with verification using manifest (existing code)
            const findings = await this.verifyResources(manifest);
            if (findings && findings.length) {
                await this.sendReport({ type: 'file_integrity', findings });
            }
        } catch (error) {
            console.error('[Integrity] performFileIntegrityCheck error', error);
        }
    }

    // === ENHANCED DOM INJECTION MONITORING ===

    async captureInitialState() {
        const scripts = [];
        const allScripts = document.querySelectorAll('script');
        
        for (const script of allScripts) {
            if (script.src) {
                scripts.push({
                    type: 'external',
                    src: script.src,
                    integrity: script.integrity || null,
                    crossorigin: script.crossorigin || null
                });
            } else {
                const text = script.textContent || '';
                const hash = await this.sha256Base64(new TextEncoder().encode(text));
                scripts.push({
                    type: 'inline',
                    hash: hash,
                    content: text.substring(0, 200)
                });
            }
        }

        const pageHtml = document.documentElement.outerHTML;
        const pageHtmlHash = await this.sha256Base64(new TextEncoder().encode(pageHtml));

        return {
            scripts: scripts,
            pageHtmlHash: pageHtmlHash,
            capturedAt: new Date().toISOString()
        };
    }

    captureOriginalTags() {
        // Only capture security-relevant elements
        const relevantSelectors = [
            'script',
            'iframe',
            'object',
            'embed',
            'form',
            'input[type="hidden"]',
            'link[rel="stylesheet"]',
            'style',
            'img[src^="javascript:"]',
            '[onclick]',
            '[onload]',
            '[onerror]',
            '[onmouseover]',
            'body',
            'html'
        ];

        for (const selector of relevantSelectors) {
            let elements = null;
            try {
                elements = document.querySelectorAll(selector);
            } catch (err) {
                // Fallback: if selector isn't valid, try selecting by tag name
                const m = selector.match(/^([a-zA-Z]+)/);
                if (m) {
                    elements = document.getElementsByTagName(m[1].toLowerCase());
                } else {
                    continue;
                }
            }

            Array.from(elements || []).forEach(el => {
                try {
                    const signature = this.getElementSignature(el);
                    this.originalTags.add(signature);
                } catch (e) {
                    // ignore any element-level errors
                }
            });
        }
        
        console.log(`[Integrity] Captured ${this.originalTags.size} security-relevant DOM elements`);
    }

    getElementSignature(element) {
        const tag = element.tagName.toLowerCase();
        const id = element.id ? `#${element.id}` : '';
        const classes = element.className ? `.${element.className.replace(/\s+/g, '.')}` : '';
        const src = element.src || element.href || '';
        const type = element.type || '';
        
        if (tag === 'script') {
            // For scripts, include src and a hash of inline content
            if (src) {
                return `${tag}${id}${classes}[src="${src}"][type="${type}"]`;
            } else {
                const content = element.textContent || '';
                const contentHash = this.simpleHash(content);
                return `${tag}${id}${classes}[inline="${contentHash}"][type="${type}"]`;
            }
        } else if (tag === 'link') {
            const rel = element.rel || '';
            return `${tag}${id}${classes}[href="${src}"][rel="${rel}"]`;
        } else if (tag === 'iframe' || tag === 'object' || tag === 'embed') {
            return `${tag}${id}${classes}[src="${src}"]`;
        } else if (tag === 'form') {
            const action = element.action || '';
            const method = element.method || '';
            return `${tag}${id}${classes}[action="${action}"][method="${method}"]`;
        } else if (tag === 'input') {
            const name = element.name || '';
            const value = element.value || '';
            return `${tag}${id}${classes}[type="${type}"][name="${name}"][value="${value.substring(0, 50)}"]`;
        } else {
            // For elements with event handlers
            const events = this.getEventHandlers(element);
            return `${tag}${id}${classes}[events="${events}"]`;
        }
    }

    simpleHash(text) {
        // Simple hash function for content comparison
        let hash = 0;
        for (let i = 0; i < text.length; i++) {
            const char = text.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit integer
        }
        return hash.toString(36);
    }

    getEventHandlers(element) {
        const events = [];
        const eventAttributes = ['onclick', 'onload', 'onerror', 'onmouseover', 'onsubmit', 'onchange', 'onfocus', 'onblur'];
        
        eventAttributes.forEach(attr => {
            if (element.hasAttribute(attr)) {
                events.push(attr);
            }
        });
        
        return events.join(',');
    }

    isSecurityRelevant(element) {
        const tag = element.tagName.toLowerCase();
        
        // High-priority security elements
        if (['script', 'iframe', 'object', 'embed', 'form', 'img', 'src', 'style'].includes(tag)) {
            return true;
        }
        
        // Elements with dangerous attributes
        const dangerousAttrs = ['onclick', 'onload', 'onerror', 'onmouseover', 'onsubmit', 'onfocus', 'onblur'];
        if (dangerousAttrs.some(attr => element.hasAttribute(attr))) {
            return true;
        }
        
        // External resource links
        if (tag === 'link' && element.rel === 'stylesheet') {
            return true;
        }
        
        // Hidden inputs (often used for CSRF attacks)
        if (tag === 'input' && element.type === 'hidden') {
            return true;
        }
        
        // Images with javascript: src
        if (tag === 'img' && element.src && element.src.startsWith('javascript:')) {
            return true;
        }
        
        return false;
    }

    isNewInjection(element) {
        const signature = this.getElementSignature(element);
        return !this.originalTags.has(signature);
    }

    analyzeAddedNodes(addedNodes) {
        const injections = [];
        
        addedNodes.forEach(node => {
            if (node.nodeType === Node.ELEMENT_NODE) {
                // Check the element itself
                if (this.isSecurityRelevant(node) && this.isNewInjection(node)) {
                    injections.push(this.createInjectionReport(node));
                }
                
                // Check descendants, but only security-relevant ones
                const relevantDescendants = node.querySelectorAll(
                    'script, iframe, object, embed, form, input[type="hidden"], link[rel="stylesheet"], style, [onclick], [onload], [onerror], [onmouseover]'
                );
                
                relevantDescendants.forEach(descendant => {
                    if (this.isNewInjection(descendant)) {
                        injections.push(this.createInjectionReport(descendant));
                    }
                });
            }
        });
        
        return injections;
    }

    createInjectionReport(element) {
        const report = {
            tag: element.tagName.toLowerCase(),
            signature: this.getElementSignature(element),
            outerHTML: element.outerHTML.substring(0, 500),
            attributes: {},
            timestamp: new Date().toISOString(),
            risk_level: this.assessRiskLevel(element)
        };

        ['id', 'class', 'src', 'href', 'type', 'rel', 'onclick', 'onload', 'style'].forEach(attr => {
            if (element.hasAttribute(attr)) {
                report.attributes[attr] = element.getAttribute(attr);
            }
        });

        Array.from(element.attributes).forEach(attr => {
            if (attr.name.startsWith('on')) {
                report.attributes[attr.name] = attr.value;
                report.risk_level = 'critical';
            }
        });

        return report;
    }

    assessRiskLevel(element) {
        const tag = element.tagName.toLowerCase();
        
        if (['script', 'iframe', 'object', 'embed'].includes(tag)) {
            return 'high';
        }
        
        if (['link', 'img', 'video', 'audio'].includes(tag)) {
            return 'medium';
        }
        
        const dangerousAttrs = ['onclick', 'onload', 'onerror', 'onmouseover', 'style'];
        if (dangerousAttrs.some(attr => element.hasAttribute(attr))) {
            return 'high';
        }
        
        return 'low';
    }

    startDOMMonitoring() {
        this.observer = new MutationObserver(mutations => {
            const allInjections = [];
            
            mutations.forEach(mutation => {
                if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                    const injections = this.analyzeAddedNodes(mutation.addedNodes);
                    allInjections.push(...injections);
                }
            });
            
            if (allInjections.length > 0) {
                this.reportDOMInjections(allInjections);
            }
        });

        this.observer.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: false
        });
        
        console.log('[Integrity] DOM injection monitoring started');
    }

    async reportDOMInjections(injections) {
        const report = {
            tenant: this.config.tenant,
            page: window.location.href,
            time: new Date().toISOString(),
            type: 'dom_injection',
            injections: injections,
            total_injections: injections.length,
            high_risk_count: injections.filter(i => i.risk_level === 'high').length,
            critical_count: injections.filter(i => i.risk_level === 'critical').length
        };

        console.warn(`[Integrity] DOM INJECTION DETECTED! Count: ${injections.length}`, injections);
        await this.sendReport(report);
    }

    async sendReport(report) {
        // Add client environment information
        report.browser_info = this.getBrowserInfo();
        report.security_context = this.getSecurityContext();
        report.page_info = {
            url: window.location.href,
            title: document.title,
            referrer: document.referrer || null,
            loadTime: performance.now(),
            domReady: document.readyState,
            visibilityState: document.visibilityState
        };

        const headers = {
            'Content-Type': 'application/json'
        };

        // try to get token and attach Authorization header
        const token = await this.fetchAuthToken();
        if (token) headers['Authorization'] = `Bearer ${token}`;

        try {
            await fetch(this.reportEndpoint, {
                method: 'POST',
                headers,
                body: JSON.stringify(report),
                keepalive: true
            });
        } catch (error) {
            console.error('[Integrity] sendReport failed', error);
        }
    }

    // === INITIALIZATION ===

    init() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                this.startMonitoring();
            });
        } else {
            this.startMonitoring();
        }
    }

    async startMonitoring() {
        this.captureOriginalTags();
        this.startDOMMonitoring();
        await this.performFileIntegrityCheck();
        console.log('[Integrity] All monitoring systems active');
    }
}

// Auto-initialize
const integrityMonitor = new IntegrityMonitor();
integrityMonitor.init();

// Export for testing
window.IntegrityMonitor = integrityMonitor;
