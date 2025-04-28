const WebSocket = require('ws');
const http = require('http');
const url = require('url');

// Configuration
const PORT = process.env.PORT || 8080;
const TARGET_URL = process.env.TARGET_URL || 'ws://localhost:9000';

// Create HTTP server
const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('WebSocket Tunnel Server Running');
});

// Create WebSocket server
const wss = new WebSocket.Server({ server });

// Handle new WebSocket connections
wss.on('connection', (ws, req) => {
  console.log(`New connection from ${req.socket.remoteAddress}`);
  
  // Parse any query parameters
  const parsedUrl = url.parse(req.url, true);
  const targetUrl = parsedUrl.query.target || TARGET_URL;
  
  // Connect to target WebSocket server
  const targetWs = new WebSocket(targetUrl);
  
  // Error handling for target connection
  targetWs.on('error', (err) => {
    console.error(`Target connection error: ${err.message}`);
    ws.close(1011, 'Target connection failed');
  });
  
  // Forward messages from client to target
  ws.on('message', (data) => {
    if (targetWs.readyState === WebSocket.OPEN) {
      targetWs.send(data);
    }
  });
  
  // Forward messages from target to client
  targetWs.on('message', (data) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(data);
    }
  });
  
  // Handle client disconnect
  ws.on('close', (code, reason) => {
    console.log(`Client disconnected: ${code} - ${reason}`);
    targetWs.close();
  });
  
  // Handle target disconnect
  targetWs.on('close', (code, reason) => {
    console.log(`Target disconnected: ${code} - ${reason}`);
    ws.close();
  });
});

// Start the server
server.listen(PORT, () => {
  console.log(`WebSocket tunnel server running on port ${PORT}`);
  console.log(`Default target: ${TARGET_URL}`);
});