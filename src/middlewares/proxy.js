// 📁 /middlewares/superSmartProxy.js

const { Resolver } = require('dns').promises;
const profiles = require('../data/browserProfiles.json');
const http = require('http');
const https = require('https');

// DNS resolvers to randomize
const dnsResolvers = [
  '8.8.8.8',           // Google
  '1.1.1.1',           // Cloudflare
  '9.9.9.9',           // Quad9
  '208.67.222.222'     // OpenDNS
];

function getRandomResolver() {
  const resolver = new Resolver();
  resolver.setServers([dnsResolvers[Math.floor(Math.random() * dnsResolvers.length)]]);
  return resolver;
}

function getRandomProfile() {
  return profiles[Math.floor(Math.random() * profiles.length)];
}

function sanitizeUrl(url) {
  if (!/^https?:\/\//i.test(url)) {
    return 'https://' + url;
  }
  return url;
}

// Small randomized delay to make requests appear more natural
function randomizeRequestTiming() {
  const delay = Math.floor(Math.random() * 200) + 50; // Random delay between 50-250ms
  return new Promise(resolve => setTimeout(resolve, delay));
}

// Fetch implementation with redirect following
async function customFetch(url, options = {}, redirectCount = 0) {
  await randomizeRequestTiming();
  
  const maxRedirects = 5; // Limit redirects to prevent infinite loops
  
  if (redirectCount > maxRedirects) {
    throw new Error(`Maximum redirect count (${maxRedirects}) exceeded`);
  }

  console.log(`Making request to: ${url} (redirect: ${redirectCount})`);
  
  return new Promise((resolve, reject) => {
    try {
      const urlObj = new URL(url);
      const isHttps = urlObj.protocol === 'https:';
      
      const requestOptions = {
        method: options.method || 'GET',
        headers: options.headers || {},
        hostname: urlObj.hostname,
        port: urlObj.port || (isHttps ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        timeout: 30000, // 30 second timeout
        rejectUnauthorized: false
      };
  
      let rawData = Buffer.alloc(0);
      const clientRequest = (isHttps ? https : http).request(requestOptions, async (response) => {
        const { statusCode, headers } = response;
        
        // Handle redirects (301, 302, 307, 308)
        if ([301, 302, 307, 308].includes(statusCode) && headers.location) {
          console.log(`Redirect ${statusCode} to: ${headers.location}`);
          
          let redirectUrl = headers.location;
          
          // Handle relative URLs in redirects
          if (redirectUrl.startsWith('/')) {
            redirectUrl = `${urlObj.protocol}//${urlObj.host}${redirectUrl}`;
          }
          
          try {
            // Follow the redirect
            const redirectResponse = await customFetch(
              redirectUrl,
              {
                ...options,
                headers: {
                  ...options.headers,
                  // Add referer for the redirect
                  'Referer': url
                }
              },
              redirectCount + 1
            );
            resolve(redirectResponse);
          } catch (redirectError) {
            reject(redirectError);
          }
          return;
        }
        
        response.on('data', (chunk) => {
          rawData = Buffer.concat([rawData, chunk]);
        });
        
        response.on('end', () => {
          resolve({
            status: statusCode,
            headers: response.headers,
            rawBody: rawData,
            text: async () => rawData.toString(),
            url: url // Include the final URL
          });
        });
      });
  
      // Error handling
      clientRequest.on('error', (err) => {
        console.error('Request Error:', err.message);
        reject(new Error(`Request failed: ${err.message}`));
      });
  
      clientRequest.on('timeout', () => {
        clientRequest.destroy(new Error(`Request timeout after ${requestOptions.timeout}ms`));
      });
  
      if (options.body) {
        clientRequest.write(options.body);
      }
  
      clientRequest.end();
    } catch (err) {
      console.error('Error in request setup:', err);
      reject(err);
    }
  });
}

// Fetch with randomized browser profile
async function fetchWithRandomProfile(url) {
  const profile = getRandomProfile();
  const resolver = getRandomResolver(); // Keep DNS randomization
  const urlObj = new URL(url);
  
  console.log(`Using profile: ${profile.name || 'Unknown'}`);
  
  // Standard browser headers based on the random profile
  const headers = {
    'User-Agent': profile.userAgent,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': profile.acceptLanguage || 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Host': urlObj.hostname
  };

  try {
    // Main request
    return await customFetch(url, {
      headers: headers
    });
  } catch (err) {
    console.error('Primary request failed:', err.message);
    
    // Simplified fallback with minimal headers
    try {
      return await customFetch(url, {
        headers: {
          'User-Agent': profile.userAgent,
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Host': urlObj.hostname
        }
      });
    } catch (err2) {
      console.error('Fallback request failed:', err2.message);
      throw err2;
    }
  }
}

module.exports = async function superSmartProxy(req, res) {
  const rawUrl = req.query.targetUrl;
  if (!rawUrl) return res.status(400).send('Missing URL');

  const targetUrl = sanitizeUrl(rawUrl);

  try {
    await randomizeRequestTiming();
    
    const response = await fetchWithRandomProfile(targetUrl);
    
    // Handle binary content
    const contentType = response.headers['content-type'] || 'text/plain';
    
    // Pass through the response directly without any processing
    let processedBody = response.rawBody;
    
    // Set basic response headers
    res.removeHeader('X-Powered-By');
    res.set('Content-Type', contentType);
    
    // Pass through useful headers from the original response
    const passthroughHeaders = [
      'content-language',
      'content-encoding',
      'content-disposition',
      'cache-control',
      'expires',
      'last-modified',
      'etag'
    ];
    
    passthroughHeaders.forEach(header => {
      if (response.headers[header]) {
        res.set(header, response.headers[header]);
      }
    });
    
    // Set a generic server header
    res.set('Server', 'nginx');
    
    // Send the response
    res.status(response.status).send(processedBody);
  } catch (err) {
    console.error('Proxy error:', err.message);
    res.status(500).send(`Proxy error: ${err.message}`);
  }
};