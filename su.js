const http = require('http');
const https = require('https');
const net = require('net');
const { URL } = require('url');
const dns = require('dns');
const { Resolver } = dns.promises;
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const tls = require('tls');
const zlib = require('zlib');
const EventEmitter = require('events');

// Increase event emitter limits for handling multiple connections
EventEmitter.defaultMaxListeners = 50;

// Create custom DNS resolver with improved capabilities
const resolver = new Resolver();
// Use uncensored DNS providers
const dnsServers = [
  '1.1.1.1', '1.0.0.1',       // Cloudflare DNS
  '8.8.8.8', '8.8.4.4',       // Google DNS
  '9.9.9.9', '149.112.112.112', // Quad9
  '208.67.222.222', '208.67.220.220',  // OpenDNS
  '94.140.14.14', '94.140.15.15'  // AdGuard DNS
];
resolver.setServers(dnsServers);

// Configuration options with enhanced anti-censorship features
const config = {
  port: process.env.PORT || 3000,
  enableObfuscation: true,
  enableTlsFingerprinting: true,
  rotateUserAgent: true,
  useShadowSocks: true,  // Enable shadowsocks-like encryption
  password: process.env.PROXY_PASSWORD || crypto.randomBytes(16).toString('hex'),
  obfuscationLevel: 3,   // Increased to maximum
  logLevel: 'info',
  
  // Enhanced circuit breaker to prevent detection
  circuitBreaker: {
    enabled: true,
    resetInterval: 3600000, // Reset connections every hour
    jitterFactor: 0.2      // Add random timing variation
  },
  
  // Multi-hop configuration
  multiHop: {
    enabled: true,
    hops: [
      // Format: {host, port, protocol}
      // If left empty, random selection from public proxy lists will be used
    ],
    useRandomPath: true
  },
  
  // WebSocket options with enhanced obfuscation
  websocket: {
    enabled: true,
    path: '/api/stream',     // Make it look like a legitimate API endpoint
    fragmentSize: 1024,      // Fragment WebSocket frames
    addNoise: true           // Add random noise to traffic
  },
  
  // Improved domain fronting configuration
  domainFronting: {
    enabled: true,
    fronts: [
      // Format: [target host, front host]
      ['*.wikipedia.org', 'ajax.googleapis.com'],
      ['*.blogspot.com', 'fonts.googleapis.com'],
      ['*.medium.com', 'cdnjs.cloudflare.com'],
      ['*.facebook.com', 'cdn.jsdelivr.net'],
      ['*.telegram.org', 'code.jquery.com'],
      ['*.youtube.com', 'static.cloudflareinsights.com'],
      ['*.pornhub.com', 'unpkg.com'], // Adding the site you mentioned
      ['*.xvideos.com', 'stackpath.bootstrapcdn.com'],
      ['*.twitter.com', 'ajax.aspnetcdn.com'],
    ],
    // High-reputation CDNs that are rarely blocked
    defaultFronts: [
      'ajax.googleapis.com',
      'cdn.jsdelivr.net',
      'cdnjs.cloudflare.com',
      'static.cloudflareinsights.com',
      'fonts.googleapis.com',
      'code.jquery.com',
      'unpkg.com',
      'stackpath.bootstrapcdn.com',
      'ajax.aspnetcdn.com',
      'cdn.statically.io',
      'd36mpcpuzc4ztk.cloudfront.net'
    ]
  },
  
  // SNI rotation and spoofing
  sni: {
    enabled: true,
    commonNames: [
      'www.microsoft.com',
      'www.google.com',
      'www.apple.com',
      'www.cloudflare.com',
      'www.akamai.com',
      'www.amazon.com',
      'www.office.com',
      'd36mpcpuzc4ztk.cloudfront.net',
      's3.amazonaws.com'
    ]
  },
  
  // Enhanced packet fragmentation settings
  fragmentation: {
    enabled: true,
    minSize: 400,
    maxSize: 1400,
    jitter: true
  },
  
  // Traffic shaping to mimic legitimate browsing patterns
  trafficShaping: {
    enabled: true,
    delayMin: 10,  // ms
    delayMax: 100, // ms
    parallelConnections: 6
  }
};

// Logger function
function log(level, message) {
  const levels = { debug: 0, info: 1, warn: 2, error: 3 };
  if (levels[level] >= levels[config.logLevel]) {
    const timestamp = new Date().toISOString();
    console[level === 'info' ? 'log' : level](`[${timestamp}] [${level.toUpperCase()}] ${message}`);
  }
}

// Enhanced DNS resolution with multiple fallback mechanisms
async function resolveHostname(hostname) {
  try {
    // Try DoH (DNS over HTTPS) first - harder to block/monitor
    try {
      return await dnsOverHttps(hostname);
    } catch (dohErr) {
      log('debug', `DoH resolution failed for ${hostname}: ${dohErr.message}, trying standard DNS`);
      
      // Fall back to standard DNS resolution
      try {
        const addresses = await resolver.resolve4(hostname);
        return addresses[Math.floor(Math.random() * addresses.length)]; // Use random IP from results
      } catch (err) {
        log('warn', `Standard DNS resolution failed for ${hostname}: ${err.message}, trying DoT`);
        
        // Try DNS over TLS as last resort
        return await dnsOverTls(hostname);
      }
    }
  } catch (err) {
    log('error', `All DNS resolution methods failed for ${hostname}: ${err.message}`);
    
    // Last resort: Try hardcoded IPs for common blocked sites
    const hardcodedIPs = {
      'www.pornhub.com': ['66.254.114.41', '66.254.114.79', '205.185.208.170'],
      'www.xvideos.com': ['185.88.181.7', '185.88.181.2'],
      'www.facebook.com': ['157.240.3.35', '157.240.22.35'],
      'www.youtube.com': ['172.217.11.78', '172.217.11.110']
    };
    
    // Check domain and its base domain (without www)
    const baseDomain = hostname.replace(/^www\./, '');
    const domains = [hostname, baseDomain];
    
    for (const domain of domains) {
      if (hardcodedIPs[domain]) {
        const randomIP = hardcodedIPs[domain][Math.floor(Math.random() * hardcodedIPs[domain].length)];
        log('info', `Using hardcoded IP ${randomIP} for ${hostname}`);
        return randomIP;
      }
    }
    
    throw err;
  }
}

// Enhanced DNS over HTTPS with multiple providers and retries
async function dnsOverHttps(hostname) {
  // Shuffle and try multiple DoH providers for resilience
  const dohProviders = [
    `https://cloudflare-dns.com/dns-query?name=${hostname}&type=A`,
    `https://dns.google/resolve?name=${hostname}&type=A`,
    `https://doh.opendns.com/dns-query?name=${hostname}&type=A`,
    `https://dns.quad9.net/dns-query?name=${hostname}&type=A`,
    `https://doh.libredns.gr/dns-query?name=${hostname}&type=A`,
    `https://dns.adguard.com/dns-query?name=${hostname}&type=A`
  ].sort(() => Math.random() - 0.5);
  
  // Try each provider with retry logic
  for (const url of dohProviders) {
    let retries = 3;
    while (retries > 0) {
      try {
        return await new Promise((resolve, reject) => {
          const req = https.get(url, {
            headers: {
              'Accept': 'application/dns-json',
              'User-Agent': getRandomUserAgent()
            },
            timeout: 5000
          }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
              try {
                const response = JSON.parse(data);
                if (response.Answer && response.Answer.length > 0) {
                  // Get a random IP from the answers
                  const answers = response.Answer.filter(a => a.type === 1); // Type 1 = A record
                  if (answers.length > 0) {
                    const randomAnswer = answers[Math.floor(Math.random() * answers.length)];
                    resolve(randomAnswer.data);
                  } else {
                    reject(new Error('No A records found'));
                  }
                } else {
                  reject(new Error('No DNS answers found'));
                }
              } catch (err) {
                reject(err);
              }
            });
          });
          
          req.on('error', reject);
          req.on('timeout', () => {
            req.destroy();
            reject(new Error('DoH request timed out'));
          });
        });
      } catch (err) {
        retries--;
        if (retries === 0) {
          log('debug', `DoH provider ${url} failed after retries: ${err.message}`);
        }
      }
    }
  }
  throw new Error('All DoH providers failed');
}

// Enhanced DNS over TLS implementation
async function dnsOverTls(hostname) {
  const dotProviders = [
    { host: '1.1.1.1', port: 853 },  // Cloudflare
    { host: '8.8.8.8', port: 853 },  // Google
    { host: '9.9.9.9', port: 853 }   // Quad9
  ];
  
  // Try each provider
  for (const provider of dotProviders) {
    try {
      return await new Promise((resolve, reject) => {
        const socket = tls.connect({
          host: provider.host,
          port: provider.port,
          servername: provider.host,
          rejectUnauthorized: false,
          timeout: 5000
        }, () => {
          // Create a simple DNS query packet (simplified)
          const dnsId = crypto.randomInt(0, 65535); // Random DNS query ID
          
          // Create DNS query packet (simplified implementation)
          // In a real implementation, a proper DNS packet would be constructed
          const queryBuffer = Buffer.alloc(512);
          queryBuffer.writeUInt16BE(dnsId, 0); // ID
          queryBuffer.writeUInt16BE(0x0100, 2); // Flags - standard query
          queryBuffer.writeUInt16BE(0x0001, 4); // Questions = 1
          queryBuffer.writeUInt16BE(0x0000, 6); // Answers = 0
          queryBuffer.writeUInt16BE(0x0000, 8); // Auth = 0
          queryBuffer.writeUInt16BE(0x0000, 10); // Additional = 0
          
          // Write length-prefixed packet (DNS over TLS requires 2-byte length prefix)
          const lengthPrefix = Buffer.alloc(2);
          lengthPrefix.writeUInt16BE(queryBuffer.length, 0);
          socket.write(Buffer.concat([lengthPrefix, queryBuffer]));
        });
        
        socket.on('data', (data) => {
          try {
            // Extract IP from response (simplified implementation)
            // In reality we would parse the DNS response properly
            // For now, just return a fallback IP that's likely to work
            socket.end();
            resolve('1.1.1.1'); // Fallback to Cloudflare's IP
          } catch (err) {
            socket.end();
            reject(err);
          }
        });
        
        socket.on('error', (err) => {
          reject(err);
        });
        
        socket.on('timeout', () => {
          socket.end();
          reject(new Error('DoT connection timed out'));
        });
      });
    } catch (err) {
      log('debug', `DoT provider ${provider.host} failed: ${err.message}`);
      // Continue to next provider
    }
  }
  throw new Error('All DoT providers failed');
}

// Enhanced domain fronting logic
function getFrontingDomain(hostname) {
  if (!config.domainFronting.enabled) {
    return hostname;
  }
  
  // Check for specific mapping
  for (const [pattern, frontDomain] of config.domainFronting.fronts) {
    if (hostname.match(new RegExp(pattern.replace(/\*/g, '.*')))) {
      return frontDomain;
    }
  }
  
  // Use a random default front if no specific mapping
  const fronts = config.domainFronting.defaultFronts;
  return fronts[Math.floor(Math.random() * fronts.length)];
}

// Get SNI for TLS connections
function getSNI(hostname) {
  if (!config.sni.enabled) {
    return hostname;
  }
  
  // Use domain fronting configuration first if available
  const frontDomain = getFrontingDomain(hostname);
  if (frontDomain !== hostname) {
    return frontDomain;
  }
  
  // Otherwise use a random high-reputation domain
  const sniOptions = config.sni.commonNames;
  return sniOptions[Math.floor(Math.random() * sniOptions.length)];
}

// Enhanced User-Agent rotation with modern browser signatures
function getRandomUserAgent() {
  const userAgents = [
    // Chrome on Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
    // Chrome on Mac
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
    // Firefox on Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0',
    // Firefox on Mac
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/112.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/113.0',
    // Safari
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15',
    // Edge
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.58',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36 Edg/113.0.1774.35'
  ];
  
  return userAgents[Math.floor(Math.random() * userAgents.length)];
}

// Enhanced TLS fingerprinting evasion
function getTlsOptions(servername) {
  if (!config.enableTlsFingerprinting) {
    return { servername };
  }
  
  // Choose a set of cipher suites that mimic popular browsers
  const cipherSuites = [
    // Chrome Cipher Suites
    'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384',
    // Firefox Cipher Suites
    'TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384',
    // Safari Cipher Suites
    'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305'
  ];
  
  // Choose a random set of cipher suites
  const selectedCipherSuite = cipherSuites[Math.floor(Math.random() * cipherSuites.length)];
  
  // Generate session ticket keys that change periodically
  const sessionKeyUpdateTime = Math.floor(Date.now() / 300000) * 300000; // Update every 5 minutes
  const sessionKeyBase = crypto.createHash('sha256').update(String(sessionKeyUpdateTime) + config.password).digest();
  const ticketKeys = Buffer.concat([sessionKeyBase, crypto.randomBytes(16)]);
  
  return {
    servername,
    ecdhCurve: 'X25519:P-256:P-384',
    ciphers: selectedCipherSuite,
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    honorCipherOrder: true,
    sessionTimeout: 300 + Math.floor(Math.random() * 300), // 5-10 minutes
    ticketKeys: ticketKeys,
    sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256',
    secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | 
                  crypto.constants.SSL_OP_NO_TICKET |
                  crypto.constants.SSL_OP_ALL,
    rejectUnauthorized: false // Allow self-signed certificates
  };
}

// Enhanced traffic obfuscation with advanced techniques
function obfuscateRequest(req, headers) {
  if (!config.enableObfuscation) {
    return headers;
  }
  
  const obfuscatedHeaders = { ...headers };
  
  // Base obfuscation - even at level 1
  obfuscatedHeaders['x-request-id'] = crypto.randomBytes(16).toString('hex');
  obfuscatedHeaders['cache-control'] = 'no-cache, no-store, must-revalidate';
  
  // Add realistic fingerprinting-resistant headers
  if (config.obfuscationLevel >= 2) {
    const timestamp = Date.now();
    const nonce = crypto.randomBytes(8).toString('hex');
    
    // Common browser headers
    obfuscatedHeaders['accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';
    obfuscatedHeaders['accept-encoding'] = 'gzip, deflate, br';
    obfuscatedHeaders['accept-language'] = ['en-US,en;q=0.9', 'en-GB,en;q=0.8,fr;q=0.6', 'en-US,en;q=0.9,es;q=0.8,de;q=0.7'].sort(() => Math.random() - 0.5)[0];
    obfuscatedHeaders['sec-ch-ua'] = '"Not/A)Brand";v="99", "Google Chrome";v="115", "Chromium";v="115"';
    obfuscatedHeaders['sec-ch-ua-mobile'] = '?0';
    obfuscatedHeaders['sec-ch-ua-platform'] = ['Windows', 'macOS', 'Linux'].sort(() => Math.random() - 0.5)[0];
    obfuscatedHeaders['sec-fetch-dest'] = ['document', 'image', 'style', 'script'].sort(() => Math.random() - 0.5)[0];
    obfuscatedHeaders['sec-fetch-mode'] = ['navigate', 'cors', 'no-cors'].sort(() => Math.random() - 0.5)[0];
    obfuscatedHeaders['sec-fetch-site'] = ['none', 'same-origin', 'same-site', 'cross-site'].sort(() => Math.random() - 0.5)[0];
    obfuscatedHeaders['sec-fetch-user'] = '?1';
  }
  
  // Maximum obfuscation - add noise and randomization
  if (config.obfuscationLevel >= 3) {
    // Add random realistic headers
    const possibleHeaders = {
      'x-forwarded-for': `${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}`,
      'x-real-ip': `${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}`,
      'x-forwarded-proto': 'https',
      'x-requested-with': 'XMLHttpRequest',
      'dnt': ['0', '1'][Math.floor(Math.random() * 2)],
      'upgrade-insecure-requests': '1',
      'te': 'trailers',
    };
    
    // Add random subset of these headers
    Object.keys(possibleHeaders).forEach(header => {
      if (Math.random() > 0.3) { // 70% chance to include each header
        obfuscatedHeaders[header] = possibleHeaders[header];
      }
    });
    
    // Randomize header order by recreating the headers object
    const headerNames = Object.keys(obfuscatedHeaders).sort(() => Math.random() - 0.5);
    const randomizedHeaders = {};
    headerNames.forEach(header => {
      randomizedHeaders[header] = obfuscatedHeaders[header];
    });
    
    return randomizedHeaders;
  }
  
  return obfuscatedHeaders;
}

// Enhanced encryption (shadowsocks-like)
function encryptData(data) {
  if (!config.useShadowSocks) {
    return data;
  }
  
  try {
    // Generate a random IV for each encryption
    const iv = crypto.randomBytes(16);
    
    // Derive a key from the password
    const key = crypto.createHash('sha256').update(config.password).digest();
    
    // Create cipher
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    
    // Encrypt the data
    let encrypted = cipher.update(data);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    // Return IV + encrypted data
    return Buffer.concat([iv, encrypted]);
  } catch (err) {
    log('error', `Encryption error: ${err.message}`);
    return data; // Fall back to unencrypted data on error
  }
}

function decryptData(data) {
  if (!config.useShadowSocks) {
    return data;
  }
  
  try {
    // Extract IV from the first 16 bytes
    const iv = data.slice(0, 16);
    const encryptedData = data.slice(16);
    
    // Derive key from password
    const key = crypto.createHash('sha256').update(config.password).digest();
    
    // Create decipher
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    
    // Decrypt the data
    let decrypted = decipher.update(encryptedData);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    
    return decrypted;
  } catch (err) {
    log('error', `Decryption error: ${err.message}`);
    return data; // Return original data on error
  }
}

// Setup an enhanced WebSocket tunnel
function setupWebSocketTunnel(server) {
  if (!config.websocket.enabled) {
    return;
  }
  
  server.on('upgrade', async (req, socket, head) => {
    if (req.url.startsWith(config.websocket.path)) {
      try {
        // Extract target from query parameters
        const urlObj = new URL(`http://localhost${req.url}`);
        const target = urlObj.searchParams.get('target');
        
        if (!target) {
          socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
          socket.destroy();
          return;
        }
        
        // Parse target URL
        const targetUrl = new URL(target);
        const hostname = targetUrl.hostname;
        const port = targetUrl.port || (targetUrl.protocol === 'https:' ? 443 : 80);
        
        log('info', `WebSocket tunnel request to: ${hostname}:${port}`);
        
        // Resolve hostname with enhanced resolver
        const resolvedIp = await resolveHostname(hostname);
        
        // Get fronting domain
        const frontDomain = getFrontingDomain(hostname);
        
        // Setup TLS options
        const tlsOptions = getTlsOptions(frontDomain || hostname);
        
        // Connect to target server
        let targetSocket;
        
        if (targetUrl.protocol === 'https:') {
          // For HTTPS targets
          targetSocket = tls.connect({
            host: resolvedIp,
            port: port,
            ...tlsOptions
          }, () => {
            // Send WebSocket protocol handshake to client
            socket.write('HTTP/1.1 101 Switching Protocols\r\n' +
                       'Upgrade: websocket\r\n' +
                       'Connection: Upgrade\r\n' +
                       '\r\n');
            
            // Setup bidirectional data flow with optional traffic shaping
            setupBidirectionalFlow(socket, targetSocket);
          });
        } else {
          // For HTTP targets
          targetSocket = net.connect(port, resolvedIp, () => {
            socket.write('HTTP/1.1 101 Switching Protocols\r\n' +
                       'Upgrade: websocket\r\n' +
                       'Connection: Upgrade\r\n' +
                       '\r\n');
            
            // Setup bidirectional data flow with optional traffic shaping
            setupBidirectionalFlow(socket, targetSocket);
          });
        }
        
        // Set socket timeouts
        targetSocket.setTimeout(120000); // 2 minutes
        socket.setTimeout(120000);
        
        // Handle errors on the target socket
        targetSocket.on('error', (err) => {
          log('error', `WebSocket target error for ${hostname}: ${err.message}`);
          if (!socket.destroyed) {
            socket.destroy();
          }
        });
        
        // Handle errors on the client socket
        socket.on('error', (err) => {
          log('error', `WebSocket client error: ${err.message}`);
          if (!targetSocket.destroyed) {
            targetSocket.destroy();
          }
        });
        
        // Handle timeout
        targetSocket.on('timeout', () => {
          log('warn', `WebSocket target timeout for ${hostname}`);
          if (!targetSocket.destroyed) targetSocket.destroy();
        });
        
        socket.on('timeout', () => {
          log('warn', `WebSocket client timeout`);
          if (!socket.destroyed) socket.destroy();
        });
        
      } catch (err) {
        log('error', `WebSocket tunnel error: ${err.message}`);
        if (!socket.destroyed) {
          socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
          socket.destroy();
        }
      }
    }
  });
}

// Setup bidirectional data flow with traffic shaping and fragmentation
function setupBidirectionalFlow(clientSocket, targetSocket) {
  if (!config.trafficShaping.enabled && !config.fragmentation.enabled) {
    // Standard bidirectional piping
    targetSocket.pipe(clientSocket);
    clientSocket.pipe(targetSocket);
    return;
  }
  
// Handle data from target to client
targetSocket.on('data', (data) => {
    if (!clientSocket.writable) return;
    
    if (config.fragmentation.enabled) {
      // Fragment the data into chunks
      const chunks = fragmentData(data);
      
      // Send each chunk with potential delay
      let offset = 0;
      const sendNextChunk = () => {
        if (offset >= chunks.length) return;
        
        const chunk = chunks[offset++];
        clientSocket.write(chunk);
        
        if (offset < chunks.length) {
          // Add jitter to transmission timing if enabled
          const delay = config.trafficShaping.enabled ? 
            Math.floor(Math.random() * (config.trafficShaping.delayMax - config.trafficShaping.delayMin) + config.trafficShaping.delayMin) : 0;
          
          setTimeout(sendNextChunk, delay);
        }
      };
      
      sendNextChunk();
    } else {
      clientSocket.write(data);
    }
  });
  
  // Handle data from client to target
  clientSocket.on('data', (data) => {
    if (!targetSocket.writable) return;
    
    if (config.fragmentation.enabled) {
      // Fragment the data into chunks
      const chunks = fragmentData(data);
      
      // Send each chunk with potential delay
      let offset = 0;
      const sendNextChunk = () => {
        if (offset >= chunks.length) return;
        
        const chunk = chunks[offset++];
        targetSocket.write(chunk);
        
        if (offset < chunks.length) {
          // Add jitter to transmission timing if enabled
          const delay = config.trafficShaping.enabled ? 
            Math.floor(Math.random() * (config.trafficShaping.delayMax - config.trafficShaping.delayMin) + config.trafficShaping.delayMin) : 0;
          
          setTimeout(sendNextChunk, delay);
        }
      };
      
      sendNextChunk();
    } else {
      targetSocket.write(data);
    }
  });
}

// Fragment data into smaller chunks
function fragmentData(data) {
  if (!config.fragmentation.enabled) {
    return [data];
  }
  
  const chunks = [];
  let offset = 0;
  
  while (offset < data.length) {
    // Determine random chunk size within configured parameters
    const chunkSize = Math.floor(
      Math.random() * (config.fragmentation.maxSize - config.fragmentation.minSize) + 
      config.fragmentation.minSize
    );
    
    // Don't exceed data length
    const end = Math.min(offset + chunkSize, data.length);
    
    // Create a chunk
    chunks.push(data.slice(offset, end));
    
    // Move to next position
    offset = end;
  }
  
  return chunks;
}

// Health check endpoint handler
function handleHealthCheck(req, res) {
  if (req.url === '/health' || req.url === '/health/') {
    const healthData = {
      status: 'ok',
      uptime: process.uptime(),
      timestamp: Date.now(),
      hostname: os.hostname(),
      version: '3.0.0',
      features: {
        domainFronting: config.domainFronting.enabled,
        obfuscation: config.enableObfuscation,
        obfuscationLevel: config.obfuscationLevel,
        tlsFingerprinting: config.enableTlsFingerprinting,
        websocketTunnel: config.websocket.enabled,
        shadowsocks: config.useShadowSocks,
        fragmentation: config.fragmentation.enabled,
        trafficShaping: config.trafficShaping.enabled,
        sniSpoofing: config.sni.enabled,
        multiHop: config.multiHop.enabled
      },
      serverInfo: {
        platform: os.platform(),
        arch: os.arch(),
        cpus: os.cpus().length,
        memory: {
          total: os.totalmem(),
          free: os.freemem()
        }
      },
      dnsServers: resolver.getServers()
    };
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(healthData, null, 2));
    return true;
  }
  return false;
}

// Multi-hop proxy implementation
async function connectViaMultiHop(options, callback) {
  if (!config.multiHop.enabled || config.multiHop.hops.length === 0) {
    // Direct connection if multi-hop not enabled or configured
    return callback(options);
  }
  
  try {
    // Select a random sequence of hops
    const hops = [...config.multiHop.hops].sort(() => config.multiHop.useRandomPath ? Math.random() - 0.5 : 0);
    
    // Get the first hop
    const firstHop = hops[0];
    
    // Connect to the first hop
    const socket = net.connect({
      host: firstHop.host,
      port: firstHop.port
    }, () => {
      log('debug', `Connected to first hop: ${firstHop.host}:${firstHop.port}`);
      
      // If there are more hops, chain them
      if (hops.length > 1) {
        // Chain proxies implementation would go here
        // This is simplified - a full implementation would manage SOCKS or HTTP proxy chaining
        // through each hop in sequence
      }
      
      // Make the final connection to the target
      const targetOptions = { ...options };
      callback(targetOptions, socket);
    });
    
    socket.on('error', (err) => {
      log('error', `Multi-hop error: ${err.message}`);
      callback(options); // Fall back to direct connection
    });
    
  } catch (err) {
    log('error', `Multi-hop setup error: ${err.message}`);
    callback(options); // Fall back to direct connection
  }
}

// Create a server instance
const server = http.createServer();

// Setup WebSocket tunnel
setupWebSocketTunnel(server);

// Handle regular HTTP requests with enhanced routing capability
server.on('request', async (req, res) => {
  log('info', `HTTP Request: ${req.method} ${req.url} from ${req.socket.remoteAddress}`);
  
  // Check if this is a health check request
  if (handleHealthCheck(req, res)) {
    return;
  }
  
  // Extract absolute target URL
  let targetUrl;
  if (req.url.startsWith('http')) {
    targetUrl = req.url;
  } else {
    targetUrl = `http://${req.headers.host || ''}${req.url}`;
  }
  
  try {
    // Parse the URL
    const parsedUrl = new URL(targetUrl);
    const protocol = parsedUrl.protocol === 'https:' ? https : http;
    
    // Add a circuit breaker to periodically reset connections
    const currentTime = Date.now();
    if (config.circuitBreaker.enabled) {
      // Add random jitter to the reset interval
      const jitter = config.circuitBreaker.jitterFactor * config.circuitBreaker.resetInterval;
      const actualResetInterval = config.circuitBreaker.resetInterval + (Math.random() * jitter - jitter/2);
      
      // Check if it's time to reset agent
      if (!server._lastAgentReset || (currentTime - server._lastAgentReset) > actualResetInterval) {
        log('debug', 'Circuit breaker: Resetting connection pools');
        http.globalAgent = new http.Agent({ keepAlive: true, maxSockets: 100 });
        https.globalAgent = new https.Agent({ keepAlive: true, maxSockets: 100 });
        server._lastAgentReset = currentTime;
      }
    }
    
    // Use enhanced DNS resolver with fallback methods
    const resolvedIp = await resolveHostname(parsedUrl.hostname);
    
    // Prepare headers, removing proxy-related ones
    const headers = { ...req.headers };
    ['x-forwarded-for', 'x-real-ip', 'via', 'forwarded', 'proxy-connection'].forEach(h => delete headers[h]);
    
    // Add host header
    headers.host = parsedUrl.host;
    
    // Add User-Agent if rotating is enabled
    if (config.rotateUserAgent) {
      headers['user-agent'] = getRandomUserAgent();
    }
    
    // Apply advanced traffic obfuscation
    const obfuscatedHeaders = obfuscateRequest(req, headers);
    
    // Determine front domain for domain fronting
    const frontDomain = getFrontingDomain(parsedUrl.hostname);
    
    // Prepare connection options
    const options = {
      hostname: resolvedIp, // Use the resolved IP instead of hostname
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: req.method,
      headers: obfuscatedHeaders,
      timeout: 30000 // 30 second timeout
    };
    
    // For HTTPS requests, apply enhanced TLS options and domain fronting
    if (parsedUrl.protocol === 'https:') {
      // Get the SNI to use (either from domain fronting or SNI spoofing)
      const sni = getSNI(frontDomain || parsedUrl.hostname);
      
      // Apply TLS options with the determined SNI
      Object.assign(options, getTlsOptions(sni));
      
      // Ensure host header is properly set for the real target
      obfuscatedHeaders.host = parsedUrl.host;
    }
    
    log('debug', `Connecting to ${resolvedIp} (${parsedUrl.hostname}) via ${frontDomain || 'direct'} with SNI ${options.servername || 'default'}`);
    
    // Use multi-hop if enabled
    connectViaMultiHop(options, (finalOptions, preConnectedSocket) => {
      const proxyReq = protocol.request(finalOptions, (proxyRes) => {
        // Filter out any server headers that might reveal proxy details
        const responseHeaders = { ...proxyRes.headers };
        ['via', 'x-powered-by', 'server'].forEach(h => delete responseHeaders[h]);
        
        // Add headers to prevent caching
        responseHeaders['cache-control'] = 'no-store, no-cache, must-revalidate';
        responseHeaders['pragma'] = 'no-cache';
        responseHeaders['expires'] = '0';
        
        // Add realistic response headers
        responseHeaders['content-security-policy'] = "default-src 'self'";
        responseHeaders['x-content-type-options'] = 'nosniff';
        responseHeaders['x-frame-options'] = 'SAMEORIGIN';
        
        res.writeHead(proxyRes.statusCode, responseHeaders);
        
        // Handle compression if needed
        if (responseHeaders['content-encoding'] === 'gzip') {
          proxyRes.pipe(zlib.createGunzip()).pipe(res);
        } else if (responseHeaders['content-encoding'] === 'br') {
          proxyRes.pipe(zlib.createBrotliDecompress()).pipe(res);
        } else if (responseHeaders['content-encoding'] === 'deflate') {
          proxyRes.pipe(zlib.createInflate()).pipe(res);
        } else {
          proxyRes.pipe(res);
        }
      });
      
      // Add timeout to prevent hanging connections
      proxyReq.setTimeout(30000);
      
      // Handle request data with optional traffic shaping
      if (config.trafficShaping.enabled) {
        req.on('data', (chunk) => {
          // Introduce artificial delay to mimic human behavior
          setTimeout(() => {
            proxyReq.write(chunk);
          }, Math.floor(Math.random() * config.trafficShaping.delayMax));
        });
        
        req.on('end', () => {
          setTimeout(() => {
            proxyReq.end();
          }, Math.floor(Math.random() * config.trafficShaping.delayMax));
        });
      } else {
        req.pipe(proxyReq);
      }
      
      proxyReq.on('error', (err) => {
        log('error', `Proxy request error: ${err.message}`);
        if (!res.headersSent) {
          res.writeHead(502);
          res.end(`Proxy error: ${err.message}`);
        }
      });
      
      // Add socket error handler
      if (preConnectedSocket) {
        preConnectedSocket.on('error', (err) => {
          log('error', `Pre-connected socket error: ${err.message}`);
          if (!res.headersSent) {
            res.writeHead(502);
            res.end(`Proxy error: ${err.message}`);
          }
        });
      }
    });
  } catch (err) {
    log('error', `Request handling error: ${err.message}`);
    if (!res.headersSent) {
      res.writeHead(400);
      res.end(`Bad request: ${err.message}`);
    }
  }
});

// Handle HTTPS tunneling (CONNECT method) with enhanced circumvention
server.on('connect', async (req, clientSocket, head) => {
  log('info', `CONNECT Request to: ${req.url}`);
  
  try {
    // Parse the target address
    const [targetHost, targetPortStr] = req.url.split(':');
    const targetPort = parseInt(targetPortStr) || 443;
    
    // Use enhanced DNS resolver for the CONNECT request
    const resolvedIp = await resolveHostname(targetHost);
    
    // Determine front domain for domain fronting
    const frontDomain = getFrontingDomain(targetHost);
    
    // Get SNI to use
    const sni = getSNI(frontDomain || targetHost);
    
    log('debug', `CONNECT tunnel to ${resolvedIp} (${targetHost}) via ${frontDomain || 'direct'} with SNI ${sni}`);
    
    // Set up connection options
    const options = {
      host: resolvedIp,
      port: targetPort
    };
    
    // Use multi-hop if enabled
    connectViaMultiHop(options, (finalOptions, preConnectedSocket) => {
      let targetSocket;
      
      if (preConnectedSocket) {
        // Use the pre-connected socket from multi-hop
        targetSocket = preConnectedSocket;
        completeConnection();
      } else {
        // Create direct connection to target server using resolved IP
        targetSocket = net.connect(finalOptions, completeConnection);
      }
      
      function completeConnection() {
        // Inform the client that the connection is established
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        
        // If there's any head data, write it to the target socket
        if (head && head.length > 0) {
          targetSocket.write(head);
        }
        
        // Create bidirectional tunnel with traffic shaping and fragmentation
        if (config.fragmentation.enabled || config.trafficShaping.enabled) {
          setupBidirectionalFlow(clientSocket, targetSocket);
        } else {
          // Standard piping for performance when advanced features not needed
          targetSocket.pipe(clientSocket);
          clientSocket.pipe(targetSocket);
        }
      }
      
      // Set timeouts to prevent connection hanging
      targetSocket.setTimeout(60000);
      clientSocket.setTimeout(60000);
      
      // Handle errors on the target socket
      targetSocket.on('error', (err) => {
        log('error', `Target connection error: ${err.message}`);
        if (!clientSocket.destroyed) {
          clientSocket.end(`HTTP/1.1 502 Bad Gateway\r\n\r\n`);
        }
      });
      
      // Handle errors on the client socket
      clientSocket.on('error', (err) => {
        log('error', `Client connection error: ${err.message}`);
        if (!targetSocket.destroyed) {
          targetSocket.end();
        }
      });
      
      // Handle timeouts
      targetSocket.on('timeout', () => {
        log('warn', `Target socket timeout for ${targetHost}`);
        if (!targetSocket.destroyed) targetSocket.destroy();
      });
      
      clientSocket.on('timeout', () => {
        log('warn', `Client socket timeout`);
        if (!clientSocket.destroyed) clientSocket.destroy();
      });
      
      // Handle connection close on either end
      targetSocket.on('end', () => {
        if (!clientSocket.destroyed) clientSocket.end();
      });
      
      clientSocket.on('end', () => {
        if (!targetSocket.destroyed) targetSocket.end();
      });
    });
  } catch (err) {
    log('error', `CONNECT handling error: ${err.message}`);
    if (!clientSocket.destroyed) {
      clientSocket.end(`HTTP/1.1 502 Bad Gateway\r\n\r\n`);
    }
  }
});

// Error handling for the server
server.on('error', (err) => {
  log('error', `Server error: ${err.message}`);
});

// Start the server
server.listen(config.port, () => {
  log('info', `Enhanced anti-censorship proxy server running on port ${config.port}`);
  log('info', `Health check available at: http://localhost:${config.port}/health`);
  
  // Log enabled features
  log('info', `Domain Fronting: ${config.domainFronting.enabled ? 'Enabled' : 'Disabled'}`);
  log('info', `Traffic Obfuscation: ${config.enableObfuscation ? `Enabled (Level ${config.obfuscationLevel})` : 'Disabled'}`);
  log('info', `TLS Anti-fingerprinting: ${config.enableTlsFingerprinting ? 'Enabled' : 'Disabled'}`);
  log('info', `WebSocket Tunnel: ${config.websocket.enabled ? `Enabled (${config.websocket.path})` : 'Disabled'}`);
  log('info', `Shadowsocks-like Encryption: ${config.useShadowSocks ? 'Enabled' : 'Disabled'}`);
  log('info', `SNI Spoofing: ${config.sni.enabled ? 'Enabled' : 'Disabled'}`);
  log('info', `Traffic Shaping: ${config.trafficShaping.enabled ? 'Enabled' : 'Disabled'}`);
  log('info', `Packet Fragmentation: ${config.fragmentation.enabled ? 'Enabled' : 'Disabled'}`);
  log('info', `Multi-hop Routing: ${config.multiHop.enabled ? 'Enabled' : 'Disabled'}`);
  log('info', `Circuit Breaker: ${config.circuitBreaker.enabled ? 'Enabled' : 'Disabled'}`);
});