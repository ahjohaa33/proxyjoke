// 📁 /middlewares/superSmartProxy.js

const { Resolver } = require('dns').promises;
const profiles = require('../data/browserProfiles.json');
const http = require('http');
const https = require('https');
const { JSDOM } = require('jsdom'); // Add this package to your dependencies

// Custom DNS Resolver options
const dnsResolvers = [
  '8.8.8.8',           // Google
  '1.1.1.1',           // Cloudflare
  '9.9.9.9',           // Quad9
  '208.67.222.222'     // OpenDNS
];

// Rotating TLS fingerprints (JA3 signatures)
const tlsFingerprints = [
  // Chrome 113 on Windows 10
  {
    ciphers: ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384'],
    curves: ['x25519', 'secp256r1', 'secp384r1'],
    versions: ['TLSv1.2', 'TLSv1.3'],
    sigAlgs: ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256', 'rsa_pkcs1_sha256']
  },
  // Firefox 112 on Ubuntu
  {
    ciphers: ['TLS_AES_128_GCM_SHA256', 'TLS_CHACHA20_POLY1305_SHA256'],
    curves: ['x25519', 'secp256r1'],
    versions: ['TLSv1.2', 'TLSv1.3'],
    sigAlgs: ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256']
  },
  // Safari 16 on macOS
  {
    ciphers: ['TLS_AES_256_GCM_SHA384', 'TLS_AES_128_GCM_SHA256'],
    curves: ['x25519', 'secp256r1'],
    versions: ['TLSv1.2', 'TLSv1.3'],
    sigAlgs: ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256']
  }
];

function getRandomResolver() {
  const resolver = new Resolver();
  resolver.setServers([dnsResolvers[Math.floor(Math.random() * dnsResolvers.length)]]);
  return resolver;
}

function getRandomProfile() {
  return profiles[Math.floor(Math.random() * profiles.length)];
}

function getRandomTLSFingerprint() {
  return tlsFingerprints[Math.floor(Math.random() * tlsFingerprints.length)];
}

function sanitizeUrl(url) {
  if (!/^https?:\/\//i.test(url)) {
    return 'https://' + url;
  }
  return url;
}

// Time randomization to prevent timing attacks
function randomizeRequestTiming() {
  const delay = Math.floor(Math.random() * 500) + 100; // Random delay between 100-600ms
  return new Promise(resolve => setTimeout(resolve, delay));
}

// Custom fetch implementation with timing randomization and TLS fingerprinting
async function customFetch(url, options = {}) {
  await randomizeRequestTiming();
  
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const isHttps = urlObj.protocol === 'https:';
    
    const requestOptions = {
      method: options.method || 'GET',
      headers: options.headers || {},
      host: urlObj.hostname,
      port: urlObj.port || (isHttps ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      timeout: 10000,
      // Randomize rejectUnauthorized to make TLS handshakes less predictable
      rejectUnauthorized: Math.random() > 0.05, // 5% chance of accepting invalid certs
    };
    
    // Apply TLS fingerprinting for HTTPS requests
    if (isHttps) {
      const tlsProfile = getRandomTLSFingerprint();
      requestOptions.ALPNProtocols = ['h2', 'http/1.1'];
      requestOptions.ciphers = tlsProfile.ciphers.join(':');
      requestOptions.minVersion = tlsProfile.versions[0];
      requestOptions.maxVersion = tlsProfile.versions[tlsProfile.versions.length - 1];
      
      // Note: Node.js http module doesn't support all TLS fingerprinting options
      // For complete TLS fingerprinting, consider using a specialized library
    }

    let rawData = '';
    const clientRequest = (isHttps ? https : http).request(requestOptions, (response) => {
      const { statusCode } = response;
      
      response.on('data', (chunk) => {
        rawData += chunk.toString();
      });
      
      response.on('end', () => {
        resolve({
          status: statusCode,
          headers: response.headers,
          rawBody: rawData,
          text: async () => rawData
        });
      });
    });

    clientRequest.on('error', (err) => {
      reject(err);
    });

    clientRequest.on('timeout', () => {
      clientRequest.abort();
      reject(new Error('Request timeout'));
    });

    if (options.body) {
      clientRequest.write(options.body);
    }

    clientRequest.end();
  });
}

// Generate randomized browser canvas fingerprint noise
function generateRandomCanvasFingerprint() {
  return `
    // Canvas fingerprinting protection
    HTMLCanvasElement.prototype.toDataURL = new Proxy(HTMLCanvasElement.prototype.toDataURL, {
      apply(target, thisArg, args) {
        let result = Reflect.apply(target, thisArg, args);
        // Add slight noise to canvas data
        if (result.length > 100) {
          const noiseFactor = ${Math.random() * 0.01};
          const canvas = document.createElement('canvas');
          const ctx = canvas.getContext('2d');
          const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const pixels = imageData.data;
          
          for (let i = 0; i < pixels.length; i += 4) {
            // Add subtle noise to RGB channels
            pixels[i] = Math.max(0, Math.min(255, pixels[i] + Math.floor(Math.random() * ${Math.floor(Math.random() * 3) + 1} - ${Math.floor(Math.random() * 2)})));
            pixels[i+1] = Math.max(0, Math.min(255, pixels[i+1] + Math.floor(Math.random() * ${Math.floor(Math.random() * 3) + 1} - ${Math.floor(Math.random() * 2)})));
            pixels[i+2] = Math.max(0, Math.min(255, pixels[i+2] + Math.floor(Math.random() * ${Math.floor(Math.random() * 3) + 1} - ${Math.floor(Math.random() * 2)})));
          }
          
          ctx.putImageData(imageData, 0, 0);
          result = canvas.toDataURL.apply(canvas, args);
        }
        return result;
      }
    });
  `;
}

// Generate audio fingerprinting protection
function generateAudioFingerprintProtection() {
  return `
    // Audio fingerprinting protection
    if (window.AudioContext || window.webkitAudioContext) {
      const originalGetFloatFrequencyData = (window.AudioContext || window.webkitAudioContext).prototype.getFloatFrequencyData;
      (window.AudioContext || window.webkitAudioContext).prototype.getFloatFrequencyData = function(array) {
        originalGetFloatFrequencyData.call(this, array);
        // Add very slight noise to audio data
        for (let i = 0; i < array.length; i++) {
          array[i] += (Math.random() * ${Math.random() * 0.01} - ${Math.random() * 0.005});
        }
      };
    }
  `;
}

// WebRTC protection
function generateWebRTCProtection() {
  return `
    // WebRTC IP leakage protection
    if (window.RTCPeerConnection) {
      const originalRTCPeerConnection = window.RTCPeerConnection;
      window.RTCPeerConnection = function(...args) {
        if (args[0]?.iceServers) {
          args[0].iceServers = [];
        }
        const pc = new originalRTCPeerConnection(...args);
        
        // Block getStats to prevent fingerprinting
        const originalGetStats = pc.getStats.bind(pc);
        pc.getStats = function(...args) {
          // Return empty stats
          return Promise.resolve(new Map());
        };
        
        return pc;
      };
    }
  `;
}

// Font enumeration protection
function generateFontProtection() {
  return `
    // Font enumeration protection
    if (document.fonts && document.fonts.check) {
      const originalCheck = document.fonts.check;
      document.fonts.check = function(fontface) {
        // Only allow basic fonts to be detected
        const basicFonts = ["Arial", "Times New Roman", "Courier New", "Georgia", "Verdana"];
        for (let font of basicFonts) {
          if (fontface.includes(font)) {
            return originalCheck.apply(this, arguments);
          }
        }
        // Give somewhat random results for other fonts
        return Math.random() > 0.5;
      };
    }
  `;
}

// Generate script to inject for fingerprinting protection
function generateAntiFingerprinting() {
  return `
    <script>
    (function() {
      // Override properties used for fingerprinting
      Object.defineProperty(navigator, 'hardwareConcurrency', { value: ${Math.floor(Math.random() * 8) + 2} });
      Object.defineProperty(navigator, 'deviceMemory', { value: ${[2, 4, 8][Math.floor(Math.random() * 3)]} });
      Object.defineProperty(navigator, 'platform', { value: "${['Win32', 'MacIntel', 'Linux x86_64'][Math.floor(Math.random() * 3)]}" });
      
      // Battery API
      if (navigator.getBattery) {
        navigator.getBattery = function() {
          return Promise.resolve({
            charging: Math.random() > 0.5,
            chargingTime: Math.floor(Math.random() * 1000),
            dischargingTime: Math.floor(Math.random() * 10000),
            level: Math.random()
          });
        };
      }
      
      // Screen and window properties
      const originalScreen = window.screen;
      Object.defineProperty(window, 'screen', {
        get: function() {
          return {
            availHeight: originalScreen.availHeight,
            availWidth: originalScreen.availWidth,
            colorDepth: ${[24, 30, 48][Math.floor(Math.random() * 3)]},
            height: originalScreen.height,
            width: originalScreen.width,
            pixelDepth: ${[24, 30, 48][Math.floor(Math.random() * 3)]}
          };
        }
      });
      
      ${generateCanvasFingerprint()}
      ${generateAudioFingerprintProtection()}
      ${generateWebRTCProtection()}
      ${generateFontProtection()}
      
      // Timezone protection
      Object.defineProperty(Intl, 'DateTimeFormat', {
        get: function() {
          const original = Intl.DateTimeFormat;
          const timezones = ['America/New_York', 'Europe/London', 'Asia/Tokyo', 'Europe/Berlin'];
          const selectedTimezone = "${timezones[Math.floor(Math.random() * timezones.length)]}";
          
          return function(...args) {
            if (args.length > 0 && args[1] && args[1].timeZone === undefined) {
              if (!args[1]) args[1] = {};
              args[1].timeZone = selectedTimezone;
            }
            return new original(...args);
          };
        }
      });
      
      // Add random timing to functions to prevent timing attacks
      ['setTimeout', 'setInterval'].forEach(function(method) {
        const original = window[method];
        window[method] = function(fn, delay, ...args) {
          const randomizedDelay = delay + (Math.random() * ${Math.floor(Math.random() * 10) + 5} - ${Math.floor(Math.random() * 5)});
          return original.call(this, fn, randomizedDelay, ...args);
        };
      });
    })();
    </script>
  `;
}

async function fetchWithAdvancedSpoofing(url) {
  const profile = getRandomProfile();
  const resolver = getRandomResolver();

  // Enhanced headers to better hide identity
  const headers = {
    'User-Agent': profile.userAgent,
    'Referer': profile.referer || 'https://www.google.com/',
    'Accept-Language': profile.acceptLanguage || 'en-US,en;q=0.9',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': Math.random() > 0.5 ? 'keep-alive' : 'close', // Randomize
    'Cache-Control': 'max-age=0',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'DNT': Math.random() > 0.5 ? '1' : '0', // Randomize Do Not Track
    'Upgrade-Insecure-Requests': '1'
  };

  // Add some randomized headers to make fingerprinting harder
  if (Math.random() > 0.5) {
    headers['Sec-Ch-Ua'] = '"Google Chrome";v="113", "Chromium";v="113", "Not-A.Brand";v="24"';
    headers['Sec-Ch-Ua-Mobile'] = '?0';
    headers['Sec-Ch-Ua-Platform'] = profile.platform || '"Windows"';
  }

  // Randomize header order (important for TLS fingerprinting)
  const reorderedHeaders = {};
  const headerKeys = Object.keys(headers).sort(() => Math.random() - 0.5);
  headerKeys.forEach(key => {
    reorderedHeaders[key] = headers[key];
  });

  const urlObj = new URL(url);

  // DNS resolution for non-HTTPS
  if (!urlObj.protocol.startsWith('https')) {
    try {
      const [resolvedIP] = await resolver.resolve4(urlObj.hostname);
      urlObj.hostname = resolvedIP;
      reorderedHeaders['Host'] = url.replace(/^https?:\/\//, '').split('/')[0];
    } catch (err) {
      console.warn('DNS Resolution Failed, falling back to default DNS');
    }
  }

  try {
    return await customFetch(urlObj.toString(), { headers: reorderedHeaders });
  } catch (err) {
    if (url.startsWith('http://')) {
      const fallbackUrl = url.replace(/^http:\/\//, 'https://');
      return customFetch(fallbackUrl, { headers: reorderedHeaders });
    }
    throw err;
  }
}

// Process HTML content to remove/modify fingerprinting scripts
async function processContent(contentType, body) {
  // Only process HTML content
  if (!contentType || !contentType.includes('text/html')) {
    return body;
  }

  try {
    const dom = new JSDOM(body);
    const document = dom.window.document;
    
    // Remove known fingerprinting scripts
    const fingerprintingServices = [
      'fingerprintjs', 
      'analytics', 
      'tracking', 
      'fpcdn.io',
      'scorecardresearch',
      'clarity.ms',
      'hotjar',
      'mouseflow',
      'google-analytics',
      'gtm.js',
      'facebook.net',
      'doubleclick.net'
    ];
    
    // Remove scripts that might be used for fingerprinting
    const scripts = document.querySelectorAll('script');
    scripts.forEach(script => {
      const src = script.getAttribute('src') || '';
      const content = script.textContent || '';
      
      // Remove scripts from known fingerprinting services
      if (fingerprintingServices.some(service => src.includes(service))) {
        script.parentNode.removeChild(script);
        return;
      }
      
      // Remove inline scripts that look like they might be fingerprinting
      const fingerprintPatterns = [
        'canvas', 'fingerprint', 'webgl', 'font', 'AudioContext', 
        'getBattery', 'navigator.userAgent', 'navigator.platform',
        'hardwareConcurrency', 'deviceMemory', 'screenX', 'pixelDepth'
      ];
      
      if (fingerprintPatterns.some(pattern => content.includes(pattern))) {
        script.parentNode.removeChild(script);
      }
    });
    
    // Inject our anti-fingerprinting script at the top of the head
    const head = document.querySelector('head');
    if (head) {
      const antiFingerprint = document.createElement('script');
      antiFingerprint.textContent = generateAntiFingerprinting();
      head.insertBefore(antiFingerprint, head.firstChild);
    }
    
    return dom.serialize();
  } catch (err) {
    // If processing fails, inject the script directly as a string at the top
    const injectionPoint = '<head>';
    if (body.includes(injectionPoint)) {
      return body.replace(injectionPoint, `<head>${generateAntiFingerprinting()}`);
    }
    return body;
  }
}

module.exports = async function superSmartProxy(req, res) {
  const rawUrl = req.query.targetUrl;
  if (!rawUrl) return res.status(400).send('Missing URL');

  const targetUrl = sanitizeUrl(rawUrl);

  try {
    // Add variable delay to requests to prevent timing-based fingerprinting
    await randomizeRequestTiming();
    
    const response = await fetchWithAdvancedSpoofing(targetUrl);
    const contentType = response.headers['content-type'] || 'text/plain';
    const rawBody = await response.text();
    
    // Process HTML to remove fingerprinting scripts and inject protections
    const processedBody = await processContent(contentType, rawBody);

    // Set response headers that don't leak information
    res.removeHeader('X-Powered-By'); // Remove Express fingerprint
    res.removeHeader('Server');
    
    // Block any headers that might reveal the proxy
    const blockedHeaders = [
      'x-forwarded-for',
      'x-real-ip',
      'cf-connecting-ip',
      'true-client-ip',
      'x-client-ip',
      'forwarded',
      'via',
      'x-served-by',
      'x-cache',
      'x-timer',
      'x-request-id',
      'x-correlation-id'
    ];
    
    blockedHeaders.forEach(header => {
      res.removeHeader(header);
    });
    
    // Set fake server headers to blend in
    const servers = ['Apache/2.4.41', 'nginx/1.18.0', 'Microsoft-IIS/10.0', 'cloudflare'];
    res.set('Server', servers[Math.floor(Math.random() * servers.length)]);
    res.set('Content-Type', contentType);
    
    // Add some security headers
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('X-Frame-Options', 'DENY');
    res.set('Referrer-Policy', 'no-referrer');
    
    // Randomize date slightly to prevent timing analysis
    const date = new Date();
    date.setSeconds(date.getSeconds() + Math.floor(Math.random() * 10));
    res.set('Date', date.toUTCString());
    
    res.status(response.status).send(processedBody);
  } catch (err) {
    // Generic error message to avoid leaking information
    res.status(500).send(`Proxy error occurred`);
  }
};