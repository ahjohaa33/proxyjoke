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

// Create custom DNS resolver with multiple fallback options
const resolver = new Resolver();
// Use multiple DNS providers for redundancy and to help bypass DNS-based blocking
const dnsServers = [
  '8.8.8.8', '8.8.4.4',       // Google DNS
  '1.1.1.1', '1.0.0.1',       // Cloudflare DNS
  '9.9.9.9',                  // Quad9
  '208.67.222.222'            // OpenDNS
];
resolver.setServers(dnsServers);

// Create a simple DoH (DNS over HTTPS) client for additional DNS resolution options
async function dnsOverHttps(hostname) {
  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${hostname}&type=A`;
    return new Promise((resolve, reject) => {
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
    console.error(`DoH resolution error: ${err.message}`);
    throw err;
  }
}

// Create a server instance
const server = http.createServer();

// Utility function to resolve hostname with multiple methods
async function resolveHostname(hostname) {
  try {
    // Try regular DNS resolution first
    try {
      const addresses = await resolver.resolve4(hostname);
      return addresses[0]; // Return the first IPv4 address
    } catch (err) {
      console.log(`Standard DNS resolution failed, trying DoH: ${err.message}`);
      // If standard DNS fails, try DNS over HTTPS
      return await dnsOverHttps(hostname);
    }
  } catch (err) {
    console.error(`All DNS resolution methods failed for ${hostname}: ${err.message}`);
    throw err;
  }
}

// Domain fronting helper - replaces the SNI hostname with a front domain
// This helps bypass SNI-based filtering
function getFrontingOptions(hostname) {
  // List of potential fronting domains (major CDNs often used for this purpose)
  const frontDomains = [
    'ajax.googleapis.com',
    'cdn.jsdelivr.net',
    'cdnjs.cloudflare.com',
    'akamai.net'
  ];
  
  // Choose a random front domain
  const frontDomain = frontDomains[Math.floor(Math.random() * frontDomains.length)];
  
  return {
    originalHost: hostname,
    frontHost: frontDomain
  };
}

// Simple rotation of User-Agent headers to avoid fingerprinting
function getRandomUserAgent() {
  const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
  ];
  
  return userAgents[Math.floor(Math.random() * userAgents.length)];
}

// Health check endpoint and route handler
function handleHealthCheck(req, res) {
  if (req.url === '/health' || req.url === '/health/') {
    const healthData = {
      status: 'ok',
      uptime: process.uptime(),
      timestamp: Date.now(),
      hostname: os.hostname(),
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

// Handle regular HTTP requests
server.on('request', async (req, res) => {
  console.log(`HTTP Request: ${req.method} ${req.url}`);
  
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
    
    // Prepare headers, removing proxy-related ones and adding privacy-enhancing ones
    const headers = { ...req.headers };
    ['x-forwarded-for', 'x-real-ip', 'via', 'forwarded', 'proxy-connection'].forEach(h => delete headers[h]);
    
    // Add obfuscation headers - this helps bypass some header-based filtering
    headers.host = parsedUrl.host;
    headers['user-agent'] = getRandomUserAgent();
    headers['accept-language'] = 'en-US,en;q=0.9';
    headers['cache-control'] = 'no-cache';
    
    // Add a random request ID to help avoid caching/tracking
    headers['x-request-id'] = crypto.randomBytes(16).toString('hex');
    
    const options = {
      hostname: resolvedIp, // Use the resolved IP instead of hostname
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: req.method,
      headers: headers
    };
    
    // For HTTPS requests, we need to include servername for SNI
    // Use domain fronting technique for certain restricted sites
    if (parsedUrl.protocol === 'https:') {
      const fronting = getFrontingOptions(parsedUrl.hostname);
      options.servername = fronting.frontHost; // Use front domain for SNI
      headers.host = fronting.originalHost; // Keep original host in HTTP header
    }
    
    const proxyReq = protocol.request(options, (proxyRes) => {
      // Filter out any server headers that might reveal proxy details
      const responseHeaders = { ...proxyRes.headers };
      ['via', 'x-powered-by', 'server'].forEach(h => delete responseHeaders[h]);
      
      // Add headers to prevent caching which can help bypass some restrictions
      responseHeaders['cache-control'] = 'no-store, no-cache, must-revalidate';
      responseHeaders['pragma'] = 'no-cache';
      responseHeaders['expires'] = '0';
      
      res.writeHead(proxyRes.statusCode, responseHeaders);
      proxyRes.pipe(res);
    });
    
    // Add timeout to prevent hanging connections
    proxyReq.setTimeout(30000);
    
    req.pipe(proxyReq);
    
    proxyReq.on('error', (err) => {
      console.error(`Proxy request error: ${err.message}`);
      if (!res.headersSent) {
        res.writeHead(502);
        res.end(`Proxy error: ${err.message}`);
      }
    });
  } catch (err) {
    console.error(`Request handling error: ${err.message}`);
    if (!res.headersSent) {
      res.writeHead(400);
      res.end(`Bad request: ${err.message}`);
    }
  }
});

// Handle HTTPS tunneling (CONNECT method)
server.on('connect', async (req, res, clientSocket, head) => {
  // Log the CONNECT request
  console.log(`CONNECT Request to: ${req.url}`);
  
  try {
    // Parse the target address
    const [targetHost, targetPortStr] = req.url.split(':');
    const targetPort = parseInt(targetPortStr) || 443;
    
    // Use custom DNS resolver for the CONNECT request
    const resolvedIp = await resolveHostname(targetHost);
    
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
      console.error(`Target connection error: ${err.message}`);
      if (!clientSocket.destroyed) {
        clientSocket.end(`HTTP/1.1 502 Bad Gateway\r\n\r\n`);
      }
    });
    
    // Handle errors on the client socket
    clientSocket.on('error', (err) => {
      console.error(`Client connection error: ${err.message}`);
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
    console.error(`CONNECT handling error: ${err.message}`);
    if (!clientSocket.destroyed) {
      clientSocket.end(`HTTP/1.1 502 Bad Gateway\r\n\r\n`);
    }
  }
});

// Error handling for the server
server.on('error', (err) => {
  console.error(`Server error: ${err.message}`);
});

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Proxy server running on port ${PORT}`);
  console.log(`Using custom DNS servers: ${resolver.getServers().join(', ')}`);
  console.log(`Health check available at: http://localhost:${PORT}/health`);
});