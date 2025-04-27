const http = require('http');
const https = require('https');
const net = require('net');
const { URL } = require('url');

function proxyjoke(req, res) {
  const stripHeaders = [
    'x-forwarded-for',
    'x-real-ip',
    'via',
    'forwarded',
    'proxy-connection',
  ];

  const defaultUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.78 Safari/537.36';

  if (req.method === 'CONNECT') {
    // Handle HTTPS tunneling
    const [host, port] = req.url.split(':');
    const targetPort = parseInt(port) || 443;

    console.log(`CONNECT tunnel to ${host}:${targetPort}`);

    const clientSocket = req.socket;
    const serverSocket = net.connect(targetPort, host, () => {
      // Connection established
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      
      // Pipe data between client and target server
      clientSocket.pipe(serverSocket);
      serverSocket.pipe(clientSocket);
    });

    serverSocket.on('error', (err) => {
      console.error('Tunnel Error:', err.message);
      clientSocket.end(`HTTP/1.1 500 Tunnel Error\r\n\r\n${err.message}`);
    });

    clientSocket.on('error', (err) => {
      console.error('Client Socket Error:', err.message);
      serverSocket.end();
    });

    // Handle connection close from either end
    clientSocket.on('end', () => {
      serverSocket.end();
    });
    
    serverSocket.on('end', () => {
      clientSocket.end();
    });
    
    return; // Important to return here to avoid trying to handle as HTTP request
  }

  // For HTTP/HTTPS requests
  try {
    // Make sure we have a valid URL to proxy
    let targetUrl;
    if (req.url.startsWith('http')) {
      targetUrl = req.url;
    } else if (req.headers.host) {
      targetUrl = `http://${req.headers.host}${req.url}`;
    } else {
      res.writeHead(400);
      res.end('Bad Request: Missing host header');
      return;
    }

    const parsedUrl = new URL(targetUrl);
    
    // Clone and clean up headers
    const headers = { ...req.headers };
    
    // Strip sensitive headers
    stripHeaders.forEach(header => {
      delete headers[header];
    });
    
    // Set proper host header
    headers['host'] = parsedUrl.host;
    
    // Set default user agent if not present
    if (!headers['user-agent']) {
      headers['user-agent'] = defaultUserAgent;
    }

    const protocol = parsedUrl.protocol === 'https:' ? https : http;
    const targetPort = parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80);
    
    console.log(`Proxying ${req.method} request to ${parsedUrl.protocol}//${parsedUrl.hostname}:${targetPort}${parsedUrl.pathname}${parsedUrl.search}`);
    
    const options = {
      hostname: parsedUrl.hostname,
      port: targetPort,
      path: parsedUrl.pathname + parsedUrl.search,
      method: req.method,
      headers: headers
    };

    const proxyReq = protocol.request(options, (proxyRes) => {
      // Copy status code and headers from the target response
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      
      // Stream the response body
      proxyRes.pipe(res);
    });

    // Handle request errors
    proxyReq.on('error', (err) => {
      console.error('Proxy Request Error:', err.message);
      if (!res.headersSent) {
        res.writeHead(502);
        res.end(`Proxy Error: ${err.message}`);
      } else {
        res.end();
      }
    });

    // If there is a request body, forward it to the target
    req.pipe(proxyReq);
    
    // Handle client abort
    req.on('aborted', () => {
      proxyReq.abort();
    });

  } catch (err) {
    console.error('Proxy Error:', err.message);
    res.writeHead(500);
    res.end(`Proxy Error: ${err.message}`);
  }
}

// Create a server to handle proxy requests
const server = http.createServer((req, res) => {
  proxyjoke(req, res);
});

// Handle CONNECT method for HTTPS tunneling
server.on('connect', (req, res, socket, head) => {
  proxyjoke(req, res);
});

// For use as middleware or standalone server
module.exports = proxyjoke;

// If this file is run directly (not imported), start the server
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  server.listen(PORT, () => {
    console.log(`Proxy server running on port ${PORT}`);
  });
}