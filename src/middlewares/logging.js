// 📁 /middlewares/logRequests.js

const fs = require('fs');
const path = require('path');

const logFile = path.join(__dirname, '../logs/requestLogs.json');

// Ensure logs directory exists
if (!fs.existsSync(path.dirname(logFile))) {
  fs.mkdirSync(path.dirname(logFile), { recursive: true });
}

function logToFile(data) {
  let logs = [];
  if (fs.existsSync(logFile)) {
    try {
      logs = JSON.parse(fs.readFileSync(logFile, 'utf8'));
    } catch (err) {
      console.error('Could not parse log file:', err.message);
    }
  }

  logs.push(data);

  if (logs.length > 5000) logs = logs.slice(-5000); // Optional: keep only latest 5000

  fs.writeFileSync(logFile, JSON.stringify(logs, null, 2));
}

module.exports = function requestLogger(req, res, next) {
  const start = process.hrtime();

  // Capture original writeHead to hook into response headers
  const originalWriteHead = res.writeHead;
  const responseHeaders = {};

  res.writeHead = function (statusCode, headers) {
    if (headers) {
      Object.assign(responseHeaders, headers);
    }
    return originalWriteHead.apply(res, arguments);
  };

  res.on('finish', () => {
    const [sec, nano] = process.hrtime(start);
    const responseTimeMs = (sec * 1e3 + nano / 1e6).toFixed(2);

    const logEntry = {
      timestamp: new Date().toISOString(),
      method: req.method,
      url: req.originalUrl || req.url,
      ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
      headers: req.headers,
      query: req.query,
      params: req.params,
      body: req.body,
      statusCode: res.statusCode,
     // responseHeaders: { ...res.getHeaders(), ...responseHeaders },
      responseTimeMs: `${responseTimeMs} ms`
    };

    logToFile(logEntry);
  });

  next();
};
