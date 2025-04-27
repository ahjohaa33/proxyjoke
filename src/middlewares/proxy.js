const http = require('http');
const https = require('https');
const net = require('net');
const { URL } = require('url');

function proxyjoke(req, res, next) {
  const stripHeaders = [
    'x-forwarded-for',
    'x-real-ip',
    'via',
    'forwarded',
    'proxy-connection',
    'origin',
    'referer',
  ];

  const defaultUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.78 Safari/537.36';

  if (req.method === 'CONNECT') {
    // Handle HTTPS tunneling
    const [host, port] = req.url.split(':');

    const clientSocket = req.socket;
    const serverSocket = net.connect(port || 443, host, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    });

    serverSocket.on('connect', () => {
      clientSocket.pipe(serverSocket);
      serverSocket.pipe(clientSocket);
    });

    serverSocket.on('error', (err) => {
      console.error('Tunnel Error:', err.message);
      clientSocket.end();
    });

    clientSocket.on('error', () => {
      serverSocket.end();
    });

  } else {
    // Handle regular HTTP/HTTPS requests
    const targetUrl = req.url.startsWith('http') ? req.url : `http://${req.headers.host}${req.url}`;
    const parsedUrl = new URL(targetUrl);

    const headers = { ...req.headers };
    for (const header of stripHeaders) {
      delete headers[header];
    }

    headers['host'] = parsedUrl.host;

    if (!headers['user-agent']) {
      headers['user-agent'] = defaultUserAgent;
    }

    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: req.method,
      headers,
    };

    const protocol = parsedUrl.protocol === 'https:' ? https : http;

    const proxyReq = protocol.request(options, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    });

    proxyReq.on('error', (err) => {
      console.error('Proxy Request Error:', err.message);
      res.writeHead(500);
      res.end('Proxy Error');
    });

    req.pipe(proxyReq);
  }
}

module.exports = proxyjoke;
