package evasion

import (
	"net/http"
	"regexp"
	"strings"
)

type BotGuard struct {
	detectionPatterns []*regexp.Regexp
	evasionHeaders    map[string]string
}

func NewBotGuard() *BotGuard {
	return &BotGuard{
		detectionPatterns: []*regexp.Regexp{
			// Cloudflare Turnstile
			regexp.MustCompile(`challenges\.cloudflare\.com`),
			regexp.MustCompile(`turnstile`),
			regexp.MustCompile(`cf-turnstile`),
			
			// reCAPTCHA
			regexp.MustCompile(`google\.com/recaptcha`),
			regexp.MustCompile(`grecaptcha`),
			regexp.MustCompile(`recaptcha`),
			
			// hCaptcha
			regexp.MustCompile(`hcaptcha\.com`),
			regexp.MustCompile(`hcaptcha`),
			
			// Phishing detection
			regexp.MustCompile(`safebrowsing`),
			regexp.MustCompile(`phishing`),
			regexp.MustCompile(`malware`),
			regexp.MustCompile(`deceptive`),
			
			// Chrome Enhanced Protection
			regexp.MustCompile(`chrome://settings/security`),
			regexp.MustCompile(`enhancedProtection`),
			regexp.MustCompile(`EnhancedProtection`),
			
			// Browser warnings
			regexp.MustCompile(`Your connection is not private`),
			regexp.MustCompile(`ERR_CERT`),
			regexp.MustCompile(`NET::ERR`),
		},
		evasionHeaders: map[string]string{
			"User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
			"Accept-Language":           "en-US,en;q=0.9",
			"Accept-Encoding":           "gzip, deflate, br",
			"Connection":                "keep-alive",
			"Upgrade-Insecure-Requests": "1",
			"Sec-Ch-Ua":                 `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
			"Sec-Ch-Ua-Mobile":          "?0",
			"Sec-Ch-Ua-Platform":        `"Windows"`,
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-User":            "?1",
			"Cache-Control":             "max-age=0",
		},
	}
}

func (b *BotGuard) Detect(content string) []string {
	var detections []string
	for _, pattern := range b.detectionPatterns {
		if pattern.MatchString(content) {
			detections = append(detections, pattern.String())
		}
	}
	return detections
}

func (b *BotGuard) ApplyEvasionHeaders(req *http.Request) {
	for key, value := range b.evasionHeaders {
		req.Header.Set(key, value)
	}
}

func (b *BotGuard) RemoveTrackingHeaders(req *http.Request) {
	trackingHeaders := []string{
		"X-Forwarded-For",
		"X-Real-IP",
		"CF-Connecting-IP",
		"CF-Ray",
		"True-Client-IP",
		"X-Forwarded-Proto",
		"Forwarded",
	}
	
	for _, header := range trackingHeaders {
		req.Header.Del(header)
	}
}

func (b *BotGuard) ObfuscateRequest(req *http.Request) {
	b.ApplyEvasionHeaders(req)
	b.RemoveTrackingHeaders(req)
	
	if referer := req.Header.Get("Referer"); referer != "" {
		req.Header.Del("Referer")
	}
}

type AdvancedEvasion struct {
	domainFronting    *DomainFronting
	trafficObfuscation *TrafficObfuscation
	fingerprintEvasion *FingerprintEvasion
}

type DomainFronting struct {
	frontDomain string
	realDomain  string
}

type TrafficObfuscation struct {
	jitter   int
	padding  int
	encoding string
}

type FingerprintEvasion struct {
	OverrideWebdriver    bool
	OverrideLanguages    bool
	OverridePlugins      bool
	OverrideScreen       bool
	OverrideTimezone     bool
	OverridePlatform     bool
}

func NewAdvancedEvasion() *AdvancedEvasion {
	return &AdvancedEvasion{
		domainFronting: &DomainFronting{},
		trafficObfuscation: &TrafficObfuscation{
			jitter:   100,
			padding:  512,
			encoding: "gzip",
		},
		fingerprintEvasion: &FingerprintEvasion{
			OverrideWebdriver: true,
			OverrideLanguages: true,
			OverridePlugins:   true,
			OverrideScreen:    true,
			OverrideTimezone:  true,
			OverridePlatform:  true,
		},
	}
}

func (a *AdvancedEvasion) ApplyDomainFronting(req *http.Request, frontDomain string) {
	req.Host = frontDomain
	req.Header.Set("Host", frontDomain)
}

func (a *AdvancedEvasion) GetFingerprintJS() string {
	var js []string
	
	if a.fingerprintEvasion.OverrideWebdriver {
		js = append(js, `Object.defineProperty(navigator, 'webdriver', {get: () => false});`)
	}
	
	if a.fingerprintEvasion.OverrideLanguages {
		js = append(js, `Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});`)
	}
	
	if a.fingerprintEvasion.OverridePlugins {
		js = append(js, `Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});`)
	}
	
	if a.fingerprintEvasion.OverrideScreen {
		js = append(js, `
			Object.defineProperty(screen, 'width', {get: () => 1920});
			Object.defineProperty(screen, 'height', {get: () => 1080});
			Object.defineProperty(screen, 'availWidth', {get: () => 1920});
			Object.defineProperty(screen, 'availHeight', {get: () => 1040});
			Object.defineProperty(screen, 'colorDepth', {get: () => 24});
			Object.defineProperty(screen, 'pixelDepth', {get: () => 24});
		`)
	}
	
	if a.fingerprintEvasion.OverrideTimezone {
		js = append(js, `
			Intl.DateTimeFormat = class extends Intl.DateTimeFormat {
				constructor() {
					super('en-US', {timeZone: 'America/New_York'});
				}
			};
		`)
	}
	
	if a.fingerprintEvasion.OverridePlatform {
		js = append(js, `Object.defineProperty(navigator, 'platform', {get: () => 'Win32'});`)
	}
	
	return strings.Join(js, "\n")
}
