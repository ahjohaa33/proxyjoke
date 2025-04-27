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

// Create custom DNS resolver
const resolver = new Resolver();
// Use multiple DNS providers
const dnsServers = [
  '8.8.8.8', '8.8.4.4',       // Google DNS
  '1.1.1.1', '1.0.0.1',       // Cloudflare DNS
  '9.9.9.9',                  // Quad9
  '208.67.222.222'            // OpenDNS
];
resolver.setServers(dnsServers);

// Configuration options
const config = {
  port: process.env.PORT || 3000,
  enableObfuscation: true,       // Enable traffic obfuscation
  enableTlsFingerprinting: true, // Use anti-fingerprinting TLS options
  rotateUserAgent: true,         // Rotate User-Agent headers
  useShadowSocks: false,         // Enable shadowsocks-like encryption (if set to true)
  password: process.env.PROXY_PASSWORD || 'defaultpassword', // For authentication if needed
  obfuscationLevel: 2,           // 0 = none, 1 = basic, 2 = advanced
  logLevel: 'info',              // 'debug', 'info', 'warn', 'error'
  
  // WebSocket options
  websocket: {
    enabled: true,               // Enable WebSocket tunneling
    path: '/ws',                 // WebSocket endpoint path
  },
  
  // Domain fronting configuration
  domainFronting: {
    enabled: true,
    fronts: [
      // Format: [target host, front host]
      ['*.blogspot.com', 'ajax.googleapis.com'],
      ['*.wikipedia.org', 'cdn.jsdelivr.net'],
      ['*.telegram.org', 'cdnjs.cloudflare.com'],
      ['*.medium.com', 'static.cloudflareinsights.com'],
      // Add more mappings as needed
    ],
    // Default front domains when no specific mapping exists
    defaultFronts: [
      'ajax.googleapis.com',
      'cdn.jsdelivr.net',
      'cdnjs.cloudflare.com',
      'static.cloudflareinsights.com',
      'fonts.googleapis.com',
      'storage.googleapis.com',
      'cloudfront.net',
      'akamai.net',
    ]
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

// Utility function to resolve hostname with multiple methods
async function resolveHostname(hostname) {
  try {
    // Try regular DNS resolution first
    try {
      const addresses = await resolver.resolve4(hostname);
      return addresses[0]; // Return the first IPv4 address
    } catch (err) {
      log('warn', `Standard DNS resolution failed for ${hostname}: ${err.message}`);
      
      // Try DNS over HTTPS as fallback
      try {
        return await dnsOverHttps(hostname);
      } catch (dohErr) {
        log('warn', `DoH resolution failed: ${dohErr.message}`);
        
        // Last resort: Try DNS over TLS if DoH fails
        return await dnsOverTls(hostname);
      }
    }
  } catch (err) {
    log('error', `All DNS resolution methods failed for ${hostname}: ${err.message}`);
    throw err;
  }
}

// DNS over HTTPS implementation
async function dnsOverHttps(hostname) {
  const dohProviders = [
    `https://cloudflare-dns.com/dns-query?name=${hostname}&type=A`,
    `https://dns.google/resolve?name=${hostname}&type=A`,
    `https://doh.opendns.com/dns-query?name=${hostname}&type=A`
  ];
  
  // Try each provider until one works
  for (const url of dohProviders) {
    try {
      return await new Promise((resolve, reject) => {
        https.get(url, {
          headers: {
            'Accept': 'application/dns-json'
          }
        }, (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            try {
              const response = JSON.parse(data);
              if (response.Answer && response.Answer.length > 0) {
                resolve(response.Answer[0].data);
              } else {
                reject(new Error('No DNS answers found'));
              }
            } catch (err) {
              reject(err);
            }
          });
        }).on('error', reject);
      });
    } catch (err) {
      log('debug', `DoH provider failed: ${err.message}`);
      // Continue to next provider
    }
  }
  throw new Error('All DoH providers failed');
}

// DNS over TLS implementation (simplified)
async function dnsOverTls(hostname) {
  // Basic DNS over TLS implementation
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: '1.1.1.1', // Cloudflare DNS over TLS
      port: 853,
      servername: '1.1.1.1',
    }, () => {
      // Send DNS query
      const dnsQuery = buildDnsQuery(hostname);
      socket.write(dnsQuery);
    });
    
    socket.on('data', (data) => {
      try {
        // Very simplified DNS response parsing
        const ip = parseDnsResponse(data);
        socket.end();
        resolve(ip);
      } catch (err) {
        socket.end();
        reject(err);
      }
    });
    
    socket.on('error', (err) => {
      reject(err);
    });
  });
}

// Very simplified DNS query builder (actual implementation would be more complex)
function buildDnsQuery(hostname) {
  // In a real implementation, this would create a proper DNS query
  // This is just a placeholder for the concept
  const buffer = Buffer.from([
    0x00, 0x01, // ID
    0x01, 0x00, // Flags
    0x00, 0x01, // QDCOUNT
    0x00, 0x00, // ANCOUNT
    0x00, 0x00, // NSCOUNT
    0x00, 0x00, // ARCOUNT
  ]);
  
  // In reality, we'd properly encode the hostname here
  return buffer;
}

// Very simplified DNS response parser (actual implementation would be more complex)
function parseDnsResponse(data) {
  // In a real implementation, this would parse the DNS response properly
  // For now, return a fallback IP
  return '1.0.0.1';
}

// Get a fronting domain for a specific target
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

// User-Agent rotation
function getRandomUserAgent() {
  const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36 Edg/92.0.902.55',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36 OPR/77.0.4054.254'
  ];
  
  return userAgents[Math.floor(Math.random() * userAgents.length)];
}

// TLS configuration to avoid fingerprinting
function getTlsOptions() {
  if (!config.enableTlsFingerprinting) {
    return {};
  }
  
  return {
    ecdhCurve: 'X25519:secp256r1:secp384r1',
    ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    honorCipherOrder: true,
    sessionTimeout: 600,
    ticketKeys: crypto.randomBytes(48)
  };
}

// Traffic obfuscation - adds padding and noise to HTTP requests
function obfuscateRequest(req, headers) {
  if (!config.enableObfuscation) {
    return headers;
  }
  
  const obfuscatedHeaders = { ...headers };
  
  // Add random headers based on obfuscation level
  if (config.obfuscationLevel >= 1) {
    // Basic obfuscation
    obfuscatedHeaders['x-request-id'] = crypto.randomBytes(16).toString('hex');
    obfuscatedHeaders['cache-control'] = 'no-cache, no-store, must-revalidate';
    obfuscatedHeaders['pragma'] = 'no-cache';
    obfuscatedHeaders['expires'] = '0';
  }
  
  if (config.obfuscationLevel >= 2) {
    // Advanced obfuscation - add random but realistic headers
    const timestamp = Date.now();
    const nonce = crypto.randomBytes(8).toString('hex');
    
    obfuscatedHeaders['x-correlation-id'] = `${timestamp}-${nonce}`;
    obfuscatedHeaders['sec-fetch-site'] = ['none', 'same-origin', 'same-site'][Math.floor(Math.random() * 3)];
    obfuscatedHeaders['sec-fetch-mode'] = ['navigate', 'cors', 'no-cors'][Math.floor(Math.random() * 3)];
    obfuscatedHeaders['sec-fetch-dest'] = ['document', 'image', 'style'][Math.floor(Math.random() * 3)];
    obfuscatedHeaders['sec-ch-ua'] = '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"';
    obfuscatedHeaders['accept-language'] = ['en-US,en;q=0.9', 'en-GB,en;q=0.8,fr;q=0.6', 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7'][Math.floor(Math.random() * 3)];
    
    // Add fake tracking parameters to URL if it's a GET request
    if (req.method === 'GET' && req.url.indexOf('?') === -1) {
      req.url += `?_=${timestamp}&_r=${nonce}`;
    } else if (req.method === 'GET') {
      req.url += `&_=${timestamp}&_r=${nonce}`;
    }
  }
  
  return obfuscatedHeaders;
}

// Shadowsocks-like simple encryption (conceptual implementation)
function encryptData(data, key) {
  if (!config.useShadowSocks) {
    return data;
  }
  
  const cipher = crypto.createCipher('aes-256-cbc', key);
  let encrypted = cipher.update(data);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return encrypted;
}

function decryptData(data, key) {
  if (!config.useShadowSocks) {
    return data;
  }
  
  const decipher = crypto.createDecipher('aes-256-cbc', key);
  let decrypted = decipher.update(data);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted;
}

// Creates a WebSocket tunnel for bypassing HTTP-based restrictions
function setupWebSocketTunnel(server) {
  if (!config.websocket.enabled) {
    return;
  }
  
  server.on('upgrade', async (req, socket, head) => {
    log('info', `WebSocket upgrade request: ${req.url}`);
    
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
        
        // Resolve hostname
        const resolvedIp = await resolveHostname(hostname);
        
        // Connect to target server
        const targetSocket = net.connect(port, resolvedIp, () => {
          socket.write('HTTP/1.1 101 Switching Protocols\r\n' +
                      'Upgrade: websocket\r\n' +
                      'Connection: Upgrade\r\n' +
                      '\r\n');
          
          // Pipe data between client and target
          targetSocket.pipe(socket);
          socket.pipe(targetSocket);
        });
        
        targetSocket.on('error', (err) => {
          log('error', `WebSocket target error: ${err.message}`);
          if (!socket.destroyed) {
            socket.destroy();
          }
        });
        
        socket.on('error', (err) => {
          log('error', `WebSocket client error: ${err.message}`);
          if (!targetSocket.destroyed) {
            targetSocket.destroy();
          }
        });
      } catch (err) {
        log('error', `WebSocket error: ${err.message}`);
        if (!socket.destroyed) {
          socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
          socket.destroy();
        }
      }
    }
  });
}

// Health check endpoint handler
function handleHealthCheck(req, res) {
  if (req.url === '/health' || req.url === '/health/') {
    const healthData = {
      status: 'ok',
      uptime: process.uptime(),
      timestamp: Date.now(),
      hostname: os.hostname(),
      version: '2.0.0',
      features: {
        domainFronting: config.domainFronting.enabled,
        obfuscation: config.enableObfuscation,
        obfuscationLevel: config.obfuscationLevel,
        tlsFingerprinting: config.enableTlsFingerprinting,
        websocketTunnel: config.websocket.enabled,
        shadowsocks: config.useShadowSocks
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

// Create a server instance
const server = http.createServer();

// Setup WebSocket tunnel
setupWebSocketTunnel(server);

// Handle regular HTTP requests
server.on('request', async (req, res) => {
  log('info', `HTTP Request: ${req.method} ${req.url}`);
  
  // Check if this is a health check request
  if (handleHealthCheck(req, res)) {
    return;
  }
  
  let targetUrl;
  if (req.url.startsWith('http')) {
    targetUrl = req.url;
  } else {
    targetUrl = `http://${req.headers.host || ''}${req.url}`;
  }
  
  try {
    const parsedUrl = new URL(targetUrl);
    const protocol = parsedUrl.protocol === 'https:' ? https : http;
    
    // Use custom DNS resolver with fallback methods
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
    
    // Apply traffic obfuscation
    const obfuscatedHeaders = obfuscateRequest(req, headers);
    
    // Determine front domain for domain fronting
    const frontDomain = getFrontingDomain(parsedUrl.hostname);
    
    const options = {
      hostname: resolvedIp, // Use the resolved IP instead of hostname
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: req.method,
      headers: obfuscatedHeaders
    };
    
    // For HTTPS requests, apply TLS options and domain fronting
    if (parsedUrl.protocol === 'https:') {
      Object.assign(options, getTlsOptions());
      
      // Domain fronting: use front domain for SNI but keep original host in HTTP header
      if (config.domainFronting.enabled) {
        options.servername = frontDomain;
        headers.host = parsedUrl.host; // Ensure original host header is used
      } else {
        options.servername = parsedUrl.hostname;
      }
    }
    
    log('debug', `Connecting to ${resolvedIp} (${parsedUrl.hostname}) via ${frontDomain || 'direct'}`);
    
    const proxyReq = protocol.request(options, (proxyRes) => {
      // Filter out any server headers that might reveal proxy details
      const responseHeaders = { ...proxyRes.headers };
      ['via', 'x-powered-by', 'server'].forEach(h => delete responseHeaders[h]);
      
      // Add headers to prevent caching
      responseHeaders['cache-control'] = 'no-store, no-cache, must-revalidate';
      responseHeaders['pragma'] = 'no-cache';
      responseHeaders['expires'] = '0';
      
      res.writeHead(proxyRes.statusCode, responseHeaders);
      
      // Handle compression if needed
      if (responseHeaders['content-encoding'] === 'gzip') {
        proxyRes.pipe(zlib.createGunzip()).pipe(res);
      } else {
        proxyRes.pipe(res);
      }
    });
    
    // Add timeout to prevent hanging connections
    proxyReq.setTimeout(30000);
    
    req.pipe(proxyReq);
    
    proxyReq.on('error', (err) => {
      log('error', `Proxy request error: ${err.message}`);
      if (!res.headersSent) {
        res.writeHead(502);
        res.end(`Proxy error: ${err.message}`);
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

// Handle HTTPS tunneling (CONNECT method)
server.on('connect', async (req, res, clientSocket, head) => {
  log('info', `CONNECT Request to: ${req.url}`);
  
  try {
    // Parse the target address
    const [targetHost, targetPortStr] = req.url.split(':');
    const targetPort = parseInt(targetPortStr) || 443;
    
    // Use custom DNS resolver for the CONNECT request
    const resolvedIp = await resolveHostname(targetHost);
    
    // Determine if we should use domain fronting
    const frontDomain = getFrontingDomain(targetHost);
    
    log('debug', `CONNECT tunnel to ${resolvedIp} (${targetHost}) via ${frontDomain || 'direct'}`);
    
    // Create connection to target server using resolved IP
    const targetSocket = net.connect(targetPort, resolvedIp, () => {
      // Inform the client that the connection is established
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      
      // If there's any head data, write it to the target socket
      if (head && head.length > 0) {
        targetSocket.write(head);
      }
      
      // Create the tunnel by piping both sockets
      targetSocket.pipe(clientSocket);
      clientSocket.pipe(targetSocket);
    });
    
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
    
    // Handle connection close on either end
    targetSocket.on('end', () => {
      if (!clientSocket.destroyed) {
        clientSocket.end();
      }
    });
    
    clientSocket.on('end', () => {
      if (!targetSocket.destroyed) {
        targetSocket.end();
      }
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
  log('info', `Advanced proxy server running on port ${config.port}`);
  log('info', `Health check available at: http://localhost:${config.port}/health`);
  
  // Log enabled features
  log('info', `Domain Fronting: ${config.domainFronting.enabled ? 'Enabled' : 'Disabled'}`);
  log('info', `Traffic Obfuscation: ${config.enableObfuscation ? `Enabled (Level ${config.obfuscationLevel})` : 'Disabled'}`);
  log('info', `TLS Anti-fingerprinting: ${config.enableTlsFingerprinting ? 'Enabled' : 'Disabled'}`);
  log('info', `WebSocket Tunnel: ${config.websocket.enabled ? `Enabled (${config.websocket.path})` : 'Disabled'}`);
});