// 📁 /middlewares/superSmartProxy.js

const { Resolver } = require('dns').promises;
const profiles = require('../data/browserProfiles.json');
const http = require('http');
const https = require('https');
const { JSDOM } = require('jsdom');

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

// Initialize resolver with rotating DNS servers
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
  const delay = Math.floor(Math.random() * 500) + 100;
  return new Promise(resolve => setTimeout(resolve, delay));
}

// Custom fetch implementation with all fixes
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
      timeout: 30000,  // Increased timeout to 30 seconds
      rejectUnauthorized: Math.random() > 0.05,
      servername: options.originalHostname || urlObj.hostname // SNI fix
    };
    
    // Apply TLS fingerprinting for HTTPS requests
    if (isHttps) {
      const tlsProfile = getRandomTLSFingerprint();
      requestOptions.ALPNProtocols = ['h2', 'http/1.1'];
      requestOptions.ciphers = tlsProfile.ciphers.join(':');
      requestOptions.minVersion = tlsProfile.versions[0];
      requestOptions.maxVersion = tlsProfile.versions[tlsProfile.versions.length - 1];
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
      console.error('Request Error:', {
        url: url,
        message: err.message,
        stack: err.stack
      });
      reject(err);
    });

    clientRequest.on('timeout', () => {
      clientRequest.abort();
      reject(new Error(`Request timeout after ${requestOptions.timeout}ms`));
    });

    if (options.body) {
      clientRequest.write(options.body);
    }

    clientRequest.end();
  });
}

// ... [Keep all the fingerprint protection functions the same] ...

async function fetchWithAdvancedSpoofing(url) {
  const profile = getRandomProfile();
  const resolver = getRandomResolver();
  const urlObj = new URL(url);
  const originalHostname = urlObj.hostname;

  // Enhanced headers
  const headers = {
    'User-Agent': profile.userAgent,
    'Referer': profile.referer || 'https://www.google.com/',
    'Accept-Language': profile.acceptLanguage || 'en-US,en;q=0.9',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': Math.random() > 0.5 ? 'keep-alive' : 'close',
    'Cache-Control': 'max-age=0',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'DNT': Math.random() > 0.5 ? '1' : '0',
    'Upgrade-Insecure-Requests': '1'
  };

  // Randomize headers
  const reorderedHeaders = {};
  Object.keys(headers)
    .sort(() => Math.random() - 0.5)
    .forEach(key => reorderedHeaders[key] = headers[key]);

  // DNS resolution with error handling
  if (!urlObj.protocol.startsWith('https')) {
    try {
      const [resolvedIP] = await resolver.resolve4(urlObj.hostname);
      urlObj.hostname = resolvedIP;
      reorderedHeaders['Host'] = originalHostname;
    } catch (err) {
      console.warn('DNS resolution failed:', err.message);
    }
  }

  try {
    return await customFetch(urlObj.toString(), {
      headers: reorderedHeaders,
      originalHostname: originalHostname // Pass original hostname for SNI
    });
  } catch (err) {
    console.error('Fetch error:', {
      url: url,
      message: err.message,
      stack: err.stack
    });
    
    if (url.startsWith('http://')) {
      const fallbackUrl = url.replace(/^http:\/\//, 'https://');
      return customFetch(fallbackUrl, { headers: reorderedHeaders });
    }
    throw err;
  }
}

async function processContent(contentType, body) {
  if (!contentType || !contentType.includes('text/html')) {
    return body;
  }

  try {
    const dom = new JSDOM(body, {
      runScripts: 'dangerously',
      resources: 'usable',
      pretendToBeVisual: true
    });
    
    // ... [Keep existing content processing logic] ...
    
    return dom.serialize();
  } catch (err) {
    console.error('Content processing error:', {
      message: err.message,
      stack: err.stack
    });
    
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
    await randomizeRequestTiming();
    
    const response = await fetchWithAdvancedSpoofing(targetUrl);
    const contentType = response.headers['content-type'] || 'text/plain';
    const rawBody = await response.text();
    
    const processedBody = await processContent(contentType, rawBody);

    // Clean response headers
    res.removeHeader('X-Powered-By');
    res.removeHeader('Server');
    
    // Set randomized security headers
    const servers = ['Apache/2.4.41', 'nginx/1.18.0', 'Microsoft-IIS/10.0', 'cloudflare'];
    res.set({
      'Server': servers[Math.floor(Math.random() * servers.length)],
      'Content-Type': contentType,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Date': new Date(Date.now() + Math.floor(Math.random() * 10000)).toUTCString()
    });
    
    res.status(response.status).send(processedBody);
  } catch (err) {
    console.error('Proxy Error:', {
      url: targetUrl,
      message: err.message,
      stack: err.stack,
      timestamp: new Date().toISOString()
    });
    
    res.status(500).send('Proxy error occurred');
  }
};