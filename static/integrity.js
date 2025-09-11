class IntegrityMonitor {
    constructor() {
        this.originalTags = new Set();
        this.observer = null;
        this.config = this.getConfig();
        this.manifestEndpoint = this.config.manifestEndpoint;
        this.reportEndpoint = this.config.reportEndpoint;
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

    async fetchArrayBuffer(url) {
        try {
            const response = await fetch(url, { 
                method: 'GET',
                mode: 'cors',
                credentials: 'same-origin'
            });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.arrayBuffer();
        } catch (error) {
            console.warn(`[Integrity] Could not fetch ${url}:`, error.message);
            return null;
        }
    }

    async verifyResources(manifest) {
        const findings = [];
        const files = manifest.files || {};

        for (const [path, meta] of Object.entries(files)) {
            const expectedSha = meta.sha256;
            if (!expectedSha) continue;

            let resourceUrl;
            if (path.startsWith('/')) {
                resourceUrl = window.location.origin + path;
            } else {
                resourceUrl = new URL(path, window.location.href).href;
            }

            try {
                const data = await this.fetchArrayBuffer(resourceUrl);
                if (data === null) {
                    findings.push({
                        url: resourceUrl,
                        path: path,
                        issue: 'unable_to_fetch',
                        expected: expectedSha,
                        actual: null
                    });
                    continue;
                }

                const actualSha = await this.sha256Base64(new Uint8Array(data));
                if (actualSha !== expectedSha) {
                    findings.push({
                        url: resourceUrl,
                        path: path,
                        issue: 'hash_mismatch',
                        expected: expectedSha,
                        actual: actualSha
                    });
                }
            } catch (error) {
                findings.push({
                    url: resourceUrl,
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

    async performFileIntegrityCheck() {
        try {
            const response = await fetch(this.manifestEndpoint);
            if (!response.ok) {
                console.warn('[Integrity] Could not fetch manifest:', response.status);
                return;
            }

            const manifest = await response.json();
            const findings = await this.verifyResources(manifest);
            const initialState = await this.captureInitialState();

            if (findings.length > 0) {
                console.warn('[Integrity] File integrity issues found:', findings);
                
                const report = {
                    tenant: this.config.tenant,
                    page: window.location.href,
                    time: new Date().toISOString(),
                    type: 'file_integrity',
                    findings: findings,
                    injected: [],
                    initialState: initialState
                };

                await this.sendReport(report);
            } else {
                console.log('[Integrity] All files verified successfully');
            }
        } catch (error) {
            console.error('[Integrity] File integrity check failed:', error);
        }
    }

    // === DOM INJECTION MONITORING ===

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
        const allElements = document.querySelectorAll('*');
        allElements.forEach(el => {
            const tagInfo = this.getElementSignature(el);
            this.originalTags.add(tagInfo);
        });
        
        console.log(`[Integrity] Captured ${this.originalTags.size} original DOM elements`);
    }

    getElementSignature(element) {
        const tag = element.tagName.toLowerCase();
        const id = element.id ? `#${element.id}` : '';
        const classes = element.className ? `.${element.className.replace(/\s+/g, '.')}` : '';
        const src = element.src || element.href || '';
        const type = element.type || '';
        
        if (tag === 'script') {
            return `${tag}${id}${classes}[src="${src}"][type="${type}"]`;
        } else if (tag === 'link') {
            const rel = element.rel || '';
            return `${tag}${id}${classes}[href="${src}"][rel="${rel}"]`;
        } else if (tag === 'iframe') {
            return `${tag}${id}${classes}[src="${src}"]`;
        } else {
            return `${tag}${id}${classes}`;
        }
    }

    isNewInjection(element) {
        const signature = this.getElementSignature(element);
        return !this.originalTags.has(signature);
    }

    analyzeAddedNodes(addedNodes) {
        const injections = [];
        
        addedNodes.forEach(node => {
            if (node.nodeType === Node.ELEMENT_NODE) {
                if (this.isNewInjection(node)) {
                    injections.push(this.createInjectionReport(node));
                }
                
                const descendants = node.querySelectorAll('*');
                descendants.forEach(descendant => {
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

        try {
            const response = await fetch(this.reportEndpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(report)
            });
            
            if (response.ok) {
                const result = await response.json();
                console.log(`[Integrity] Report sent successfully (${report.type}):`, result);
            } else {
                console.error(`[Integrity] Failed to send report (${report.type}):`, response.status);
            }
        } catch (error) {
            console.error(`[Integrity] Error sending report (${report.type}):`, error);
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
