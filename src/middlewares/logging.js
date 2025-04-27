/**
 * Simple request logging middleware for Express/Node.js
 * @param {Object} options Configuration options
 * @returns {Function} Express middleware function
 */
const requestLogger = (options = {}) => {
  const { logger = console } = options;
  
  return (req, res, next) => {
    // Capture request start time
    const startTime = process.hrtime();
    
    // Store original end method
    const originalEnd = res.end;
    
    // Override end method to log after response is complete
    res.end = function(chunk, encoding) {
      // Calculate response time
      const hrTime = process.hrtime(startTime);
      const responseTimeMs = hrTime[0] * 1000 + hrTime[1] / 1000000;
      
      // Log request details
      logger.info({
        method: req.method,
        url: req.originalUrl || req.url,
        status: res.statusCode,
        responseTime: `${responseTimeMs.toFixed(2)}ms`,
        contentLength: res.getHeader('content-length'),
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('user-agent')
      });
      
      // Call the original end method
      originalEnd.apply(res, arguments);
    };
    
    next();
  };
};

module.exports = requestLogger;
