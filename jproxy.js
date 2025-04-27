const http = require('http');
const https = require('https');
const url = require('url');

// Create a proxy server
const server = http.createServer((clientReq, clientRes) => {
  // Parse the requested URL
  const targetUrl = url.parse(clientReq.url.substring(1));
  
  // Ensure we have a valid URL
  if (!targetUrl.hostname) {
    clientRes.writeHead(400, { 'Content-Type': 'text/plain' });
    clientRes.end('Invalid URL format. Use: http://proxyserver/https://example.com');
    return;
  }

  // Set up options for the proxied request
  const options = {
    hostname: targetUrl.hostname,
    port: targetUrl.protocol === 'https:' ? 443 : 80,
    path: targetUrl.path || '/',
    method: clientReq.method,
    headers: {
      ...clientReq.headers,
      host: targetUrl.hostname
    }
  };

  // Remove proxy-specific headers
  delete options.headers['proxy-connection'];
  
  // Create appropriate request based on protocol
  const proxyReq = (targetUrl.protocol === 'https:' ? https : http).request(options, (proxyRes) => {
    // Set headers from the target server response
    clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
    
    // Pipe the response data back to the client
    proxyRes.pipe(clientRes, { end: true });
  });

  // Forward client request body to the target server
  clientReq.pipe(proxyReq, { end: true });

  // Handle errors
  proxyReq.on('error', (err) => {
    console.error('Proxy request error:', err);
    clientRes.writeHead(500, { 'Content-Type': 'text/plain' });
    clientRes.end('Proxy request failed');
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Proxy server running on port ${PORT}`);
});