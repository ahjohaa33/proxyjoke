const http = require('http');
const https = require('https');
const net = require('net');
const { URL } = require('url');
const dns = require('dns');
const { Resolver } = dns.promises;

// Create custom DNS resolver
const resolver = new Resolver();
// Example: Use Google's DNS instead of system DNS
resolver.setServers(['8.8.8.8', '8.8.4.4']);

// Create a server instance
const server = http.createServer();

// Utility function to resolve hostname with custom DNS
async function resolveHostname(hostname) {
  try {
    const addresses = await resolver.resolve4(hostname);
    return addresses[0]; // Return the first IPv4 address
  } catch (err) {
    console.error(`DNS resolution error for ${hostname}: ${err.message}`);
    throw err;
  }
}

// Handle regular HTTP requests
server.on('request', async (req, res) => {
  console.log(`HTTP Request: ${req.method} ${req.url}`);
  
  let targetUrl;
  if (req.url.startsWith('http')) {
    targetUrl = req.url;
  } else {
    targetUrl = `http://${req.headers.host || ''}${req.url}`;
  }
  
  try {
    const parsedUrl = new URL(targetUrl);
    const protocol = parsedUrl.protocol === 'https:' ? https : http;
    
    // Use custom DNS resolver
    const resolvedIp = await resolveHostname(parsedUrl.hostname);
    
    // Prepare headers, removing proxy-related ones and adding privacy-enhancing ones
    const headers = { ...req.headers };
    ['x-forwarded-for', 'x-real-ip', 'via', 'forwarded', 'proxy-connection'].forEach(h => delete headers[h]);
    headers.host = parsedUrl.host;
    
    const options = {
      hostname: resolvedIp, // Use the resolved IP instead of hostname
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: req.method,
      headers: headers
    };
    
    // For HTTPS requests, we need to include servername for SNI
    if (parsedUrl.protocol === 'https:') {
      options.servername = parsedUrl.hostname;
    }
    
    const proxyReq = protocol.request(options, (proxyRes) => {
      // Filter out any server headers that might reveal proxy details
      const responseHeaders = { ...proxyRes.headers };
      ['via', 'x-powered-by', 'server'].forEach(h => delete responseHeaders[h]);
      
      res.writeHead(proxyRes.statusCode, responseHeaders);
      proxyRes.pipe(res);
    });
    
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
});