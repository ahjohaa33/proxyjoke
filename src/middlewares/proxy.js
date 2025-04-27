const http = require('http');
const https = require('https');
const net = require('net');
const { URL } = require('url');

// Create a server instance
const server = http.createServer();

// Handle regular HTTP requests
server.on('request', (req, res) => {
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
    
    // Prepare headers, removing proxy-related ones
    const headers = { ...req.headers };
    ['x-forwarded-for', 'x-real-ip', 'via', 'forwarded', 'proxy-connection'].forEach(h => delete headers[h]);
    headers.host = parsedUrl.host;
    
    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: req.method,
      headers: headers
    };
    
    const proxyReq = protocol.request(options, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
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
    console.error(`URL parsing error: ${err.message}`);
    res.writeHead(400);
    res.end(`Bad request: ${err.message}`);
  }
});

// Handle HTTPS tunneling (CONNECT method)
server.on('connect', (req, res, clientSocket, head) => {
  // Log the CONNECT request
  console.log(`CONNECT Request to: ${req.url}`);
  
  // Parse the target address
  const [targetHost, targetPort] = req.url.split(':');
  const port = parseInt(targetPort) || 443;
  
  // Create connection to target server
  const targetSocket = net.connect(port, targetHost, () => {
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
    clientSocket.end(`HTTP/1.1 502 Bad Gateway\r\n\r\n`);
  });
  
  // Handle errors on the client socket
  clientSocket.on('error', (err) => {
    console.error(`Client connection error: ${err.message}`);
    targetSocket.end();
  });
  
  // Handle connection close on either end
  targetSocket.on('end', () => {
    clientSocket.end();
  });
  
  clientSocket.on('end', () => {
    targetSocket.end();
  });
});

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Proxy server running on port ${PORT}`);
});

module.exports = server; // Export for use in other files if needed