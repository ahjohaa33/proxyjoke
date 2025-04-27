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

// Configuration
const config = {
  port: process.env.PORT || 3000,
  // List of high-value front domains that are rarely blocked
  frontDomains: [
    'ajax.googleapis.com',
    'cdnjs.cloudflare.com',
    'cdn.jsdelivr.net',
    'fonts.googleapis.com',
    'use.fontawesome.com',
    'static.cloudflareinsights.com'
  ],
  // These domains will always use domain fronting
  alwaysFront: [
    '.blogspot.com',
    '.wikipedia.org',
    '.telegram.org',
    '.facebook.com',
    '.twitter.com',
    '.instagram.com',
    '.youtube.com'
  ],
  // User agent rotation
  userAgents: [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
  ],
  // Enable debug logging
  debug: process.env.DEBUG === 'true'
};

// Logger function
function log(message, isError = false) {
  const timestamp = new Date().toISOString();
  if (isError) {
    console.error(`[${timestamp}] ERROR: ${message}`);
  } else if (config.debug) {
    console.log(`[${timestamp}] DEBUG: ${message}`);
  }
}

// Fast utility function to resolve hostname using DNS-over-HTTPS
async function resolveHostname(hostname) {
  try {
    // Try standard DNS first
    try {
      const addresses = await resolver.resolve4(hostname);
      log(`Resolved ${hostname} to ${addresses[0]} using standard DNS`);
      return addresses[0];
    } catch (err) {
      log(`Standard DNS failed for ${hostname}, trying DoH`, true);
      
      // Use DNS over HTTPS as fallback
      const dohUrl = `https://cloudflare-dns.com/dns-query?name=${hostname}&type=A`;
      return new Promise((resolve, reject) => {
        https.get(dohUrl, {
          headers: { 'Accept': 'application/dns-json' }
        }, (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            try {
              const response = JSON.parse(data);
              if (response.Answer && response.Answer.length > 0) {
                log(`Resolved ${hostname} to ${response.Answer[0].data} using DoH`);
                resolve(response.Answer[0].data);
              } else {
                reject(new Error('No DNS answers found'));
              }
            } catch (err) {
              reject(err);
            }
          });
        }).on('error', reject).end();
      });
    }
  } catch (err) {
    log(`All DNS methods failed for ${hostname}: ${err.message}`, true);
    
    // Fall back to sending the request directly to the hostname
    // This is needed when all else fails
    log(`Falling back to direct hostname resolution for ${hostname}`);
    return hostname;
  }
}

// Check if we should use domain fronting for this hostname
function shouldUseFronting(hostname) {
  return config.alwaysFront.some(domain => hostname.endsWith(domain));
}

// Get a front domain for domain fronting
function getFrontDomain(hostname) {
  // Get a consistent front domain based on hostname
  const index = hostname.length % config.frontDomains.length;
  return config.frontDomains[index];
}

// Get a random user agent
function getRandomUserAgent() {
  return config.userAgents[Math.floor(Math.random() * config.userAgents.length)];
}

// Create HTTP server
const server = http.createServer();

// Health check endpoint handler
function handleHealthCheck(req, res) {
  if (req.url === '/health' || req.url === '/health/') {
    const healthData = {
      status: 'ok',
      uptime: process.uptime(),
      timestamp: Date.now(),
      hostname: os.hostname(),
      dnsServers: resolver.getServers(),
      serverInfo: {
        platform: os.platform(),
        memory: {
          total: Math.round(os.totalmem() / 1024 / 1024) + 'MB',
          free: Math.round(os.freemem() / 1024 / 1024) + 'MB'
        }
      }
    };
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(healthData, null, 2));
    return true;
  }
  
  // Add a plain text ping endpoint
  if (req.url === '/ping') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('pong');
    return true;
  }
  
  return false;
}

// Handle regular HTTP requests
server.on('request', async (req, res) => {
  const requestId = crypto.randomBytes(4).toString('hex');
  log(`[${requestId}] ${req.method} ${req.url}`);
  
  // Check if this is a health check request
  if (handleHealthCheck(req, res)) {
    return;
  }
  
  let targetUrl;
  try {
    if (req.url.startsWith('http')) {
      targetUrl = req.url;
    } else {
      targetUrl = `http://${req.headers.host || ''}${req.url}`;
    }
    
    const parsedUrl = new URL(targetUrl);
    const protocol = parsedUrl.protocol === 'https:' ? https : http;
    
    // Resolve hostname to IP
    const resolvedIp = await resolveHostname(parsedUrl.hostname);
    
    // Prepare headers, removing proxy-related ones
    const headers = { ...req.headers };
    ['x-forwarded-for', 'x-real-ip', 'via', 'forwarded', 'proxy-connection'].forEach(h => delete headers[h]);
    
    // Set host header explicitly
    headers.host = parsedUrl.host;
    
    // Rotate user agent
    headers['user-agent'] = getRandomUserAgent();
    
    // Add privacy headers to avoid tracking
    headers['dnt'] = '1';
    headers['sec-fetch-site'] = 'cross-site';
    headers['sec-fetch-mode'] = 'navigate';
    headers['sec-fetch-user'] = '?1';
    headers['sec-fetch-dest'] = 'document';
    headers['sec-ch-ua'] = '"Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"';
    headers['accept-language'] = 'en-US,en;q=0.9';
    
    // Add a unique request ID
    headers['x-request-id'] = requestId;
    
    // Check if we should use domain fronting
    const useFronting = shouldUseFronting(parsedUrl.hostname);
    const frontDomain = useFronting ? getFrontDomain(parsedUrl.hostname) : null;
    
    if (useFronting) {
      log(`[${requestId}] Using domain fronting for ${parsedUrl.hostname} via ${frontDomain}`);
    }
    
    const options = {
      hostname: resolvedIp,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: req.method,
      headers: headers
    };
    
    // For HTTPS requests, set TLS options and handle domain fronting
    if (parsedUrl.protocol === 'https:') {
      // Set TLS options to avoid fingerprinting
      options.rejectUnauthorized = false; // Important for some sites
      options.minVersion = 'TLSv1.2';
      options.maxVersion = 'TLSv1.3';
      
      // Use domain fronting if needed
      if (useFronting && frontDomain) {
        options.servername = frontDomain;
      } else {
        options.servername = parsedUrl.hostname;
      }
    }
    
    log(`[${requestId}] Forwarding to ${resolvedIp}:${options.port} (${parsedUrl.hostname})`);
    
    const proxyReq = protocol.request(options, (proxyRes) => {
      // Copy response headers
      const responseHeaders = { ...proxyRes.headers };
      ['via', 'x-powered-by', 'server'].forEach(h => delete responseHeaders[h]);
      
      // Anti-caching headers
      responseHeaders['cache-control'] = 'no-store, no-cache, must-revalidate';
      responseHeaders['pragma'] = 'no-cache';
      responseHeaders['expires'] = '0';
      
      res.writeHead(proxyRes.statusCode, responseHeaders);
      
      // Pipe the response data
      proxyRes.pipe(res);
      
      // Log completion
      proxyRes.on('end', () => {
        log(`[${requestId}] Response completed with status ${proxyRes.statusCode}`);
      });
    });
    
    // Set timeout for request
    proxyReq.setTimeout(30000);
    
    // Handle errors
    proxyReq.on('error', (err) => {
      log(`[${requestId}] Error: ${err.message}`, true);
      if (!res.headersSent) {
        res.writeHead(502);
        res.end(`Proxy Error: ${err.message}`);
      }
    });
    
    // Pipe the client request to the proxy request
    req.pipe(proxyReq);
    
    // Handle client disconnection
    req.on('close', () => {
      if (!proxyReq.destroyed) {
        proxyReq.destroy();
      }
    });
    
  } catch (err) {
    log(`[${requestId}] Request failed: ${err.message}`, true);
    if (!res.headersSent) {
      res.writeHead(400);
      res.end(`Bad Request: ${err.message}`);
    }
  }
});

// Handle HTTPS CONNECT method (tunneling)
server.on('connect', async (req, clientSocket, head) => {
  const requestId = crypto.randomBytes(4).toString('hex');
  log(`[${requestId}] CONNECT ${req.url}`);
  
  try {
    // Parse the target
    const [targetHost, targetPortStr] = req.url.split(':');
    const targetPort = parseInt(targetPortStr) || 443;
    
    // Resolve the hostname to IP
    const resolvedIp = await resolveHostname(targetHost);
    
    log(`[${requestId}] CONNECT tunnel to ${resolvedIp}:${targetPort} (${targetHost})`);
    
    // Create a connection to the target server
    const targetSocket = net.connect({
      host: resolvedIp,
      port: targetPort
    }, () => {
      // Tell the client the connection is established
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      
      // If there's any head data, write it to the target socket
      if (head && head.length > 0) {
        targetSocket.write(head);
      }
      
      // Pipe data between the sockets
      targetSocket.pipe(clientSocket);
      clientSocket.pipe(targetSocket);
      
      log(`[${requestId}] CONNECT tunnel established`);
    });
    
    // Set timeout to avoid hanging connections
    targetSocket.setTimeout(60000);
    clientSocket.setTimeout(60000);
    
    // Handle errors
    targetSocket.on('error', (err) => {
      log(`[${requestId}] Target connection error: ${err.message}`, true);
      if (!clientSocket.destroyed) {
        clientSocket.end();
      }
    });
    
    clientSocket.on('error', (err) => {
      log(`[${requestId}] Client connection error: ${err.message}`, true);
      if (!targetSocket.destroyed) {
        targetSocket.end();
      }
    });
    
    // Handle connection close
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
    log(`[${requestId}] CONNECT error: ${err.message}`, true);
    if (!clientSocket.destroyed) {
      clientSocket.end(`HTTP/1.1 502 Bad Gateway\r\n\r\n`);
    }
  }
});

// Handle server errors
server.on('error', (err) => {
  log(`Server error: ${err.message}`, true);
});

// Start the server
server.listen(config.port, () => {
  console.log(`Proxy server running on port ${config.port}`);
  console.log(`Health check available at: http://localhost:${config.port}/health`);
  console.log(`Using DNS servers: ${resolver.getServers().join(', ')}`);
});