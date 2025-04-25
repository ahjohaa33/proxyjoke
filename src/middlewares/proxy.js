// 📁 /middlewares/superSmartProxy.js

const { Resolver } = require('dns').promises;
const http = require('http');
const https = require('https');

const modernProfiles = require('../data/browserProfiles.json')


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
  return modernProfiles[Math.floor(Math.random() * modernProfiles.length)];
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

// Improved fetch implementation with better redirect handling
async function customFetch(url, options = {}, redirectCount = 0, redirectHistory = []) {
  await randomizeRequestTiming();
  
  const maxRedirects = 30; // Increased from 5 to 15
  
  if (redirectCount > maxRedirects) {
    throw new Error(`Maximum redirect count (${maxRedirects}) exceeded. Redirect path: ${redirectHistory.join(' -> ')}`);
  }

  // Track redirect history for debugging
  const newRedirectHistory = [...redirectHistory, url];
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
        timeout: 90000, // 90 second timeout
        rejectUnauthorized: false
      };
  
      let rawData = Buffer.alloc(0);
      const clientRequest = (isHttps ? https : http).request(requestOptions, async (response) => {
        const { statusCode, headers } = response;
        
        // Improved redirect handling
        if ([301, 302, 303, 307, 308].includes(statusCode) && headers.location) {
          console.log(`Redirect ${statusCode} to: ${headers.location}`);
          
          let redirectUrl = headers.location;
          
          // Handle relative URLs in redirects
          if (redirectUrl.startsWith('/')) {
            redirectUrl = `${urlObj.protocol}//${urlObj.host}${redirectUrl}`;
          } else if (!redirectUrl.match(/^https?:\/\//i)) {
            // Handle protocol-relative URLs (//example.com/path)
            if (redirectUrl.startsWith('//')) {
              redirectUrl = urlObj.protocol + redirectUrl;
            } else {
              // Handle path-relative URLs (path/to/resource)
              const basePath = urlObj.pathname.substring(0, urlObj.pathname.lastIndexOf('/') + 1);
              redirectUrl = `${urlObj.protocol}//${urlObj.host}${basePath}${redirectUrl}`;
            }
          }
          
          // Create new headers for the redirect
          const redirectHeaders = {...options.headers};
          
          // Update referer for the redirect
          redirectHeaders['Referer'] = url;
          
          // For POST -> GET redirects (status 303)
          const redirectMethod = statusCode === 303 ? 'GET' : options.method;
          
          try {
            // Follow the redirect
            const redirectResponse = await customFetch(
              redirectUrl,
              {
                ...options,
                method: redirectMethod,
                headers: redirectHeaders,
                // Don't send body on GET requests
                body: redirectMethod === 'GET' ? undefined : options.body
              },
              redirectCount + 1,
              newRedirectHistory
            );
            resolve(redirectResponse);
          } catch (redirectError) {
            reject(redirectError);
          }
          return;
        }
        
        // Handle content encoding (gzip, deflate)
        if (headers['content-encoding']) {
          console.log(`Content encoding: ${headers['content-encoding']}`);
        }
        
        response.on('data', (chunk) => {
          rawData = Buffer.concat([rawData, chunk]);
        });
        
        response.on('end', () => {
          console.log(`Response complete: ${statusCode}, size: ${rawData.length} bytes`);
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

// Fetch with randomized modern browser profile
async function fetchWithRandomProfile(url) {
  const profile = getRandomProfile();
  const resolver = getRandomResolver(); // Keep DNS randomization
  const urlObj = new URL(url);
  
  console.log(`Using profile: ${profile.name}`);
  
  // Modern browser headers
  const headers = {
    'User-Agent': profile.userAgent,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': profile.acceptLanguage || 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Sec-Ch-Ua': '"Not.A/Brand";v="99", "Google Chrome";v="124", "Chromium";v="124"',
    'Sec-Ch-Ua-Mobile': '?0',
    'Sec-Ch-Ua-Platform': '"Windows"',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
    'Priority': 'u=0, i',
    'Connection': 'keep-alive',
    'Host': urlObj.hostname
  };

  // Adjust headers based on browser type
  if (profile.userAgent.includes('Firefox')) {
    delete headers['Sec-Ch-Ua'];
    delete headers['Sec-Ch-Ua-Mobile'];
    delete headers['Sec-Ch-Ua-Platform'];
    delete headers['Priority'];
  } else if (profile.userAgent.includes('Safari') && !profile.userAgent.includes('Chrome')) {
    delete headers['Sec-Ch-Ua'];
    delete headers['Sec-Ch-Ua-Mobile'];
    delete headers['Sec-Ch-Ua-Platform'];
    delete headers['Sec-Fetch-Dest'];
    delete headers['Sec-Fetch-Mode'];
    delete headers['Sec-Fetch-Site'];
    delete headers['Sec-Fetch-User'];
    delete headers['Priority'];
  }

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

// Handle compressed responses if content-encoding is present
function handleCompressedResponse(rawBody, contentEncoding) {
  // This is a placeholder - Node.js HTTP/HTTPS modules handle
  // decompression automatically when you set Accept-Encoding
  // If you're having issues with compressed content, you may need
  // to implement decompression logic here using zlib
  return rawBody;
}

module.exports = async function superSmartProxy(req, res) {
  const rawUrl = req.query.targetUrl;
  if (!rawUrl) return res.status(400).send('Missing URL');

  const targetUrl = sanitizeUrl(rawUrl);

  try {
    await randomizeRequestTiming();
    
    const response = await fetchWithRandomProfile(targetUrl);
    
    // Handle encoding if needed
    let processedBody = response.rawBody;
    if (response.headers['content-encoding']) {
      processedBody = handleCompressedResponse(
        processedBody, 
        response.headers['content-encoding']
      );
    }
    
    // Set content type
    const contentType = response.headers['content-type'] || 'text/plain';
    res.removeHeader('X-Powered-By');
    res.set('Content-Type', contentType);
    
    // Pass through useful headers from the original response
    const passthroughHeaders = [
      'content-language',
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
    
    // Explicitly set content-encoding to identity (uncompressed)
    // since we're handling decompression ourselves if needed
    res.set('Content-Encoding', 'identity');
    
    // Set a generic server header
    res.set('Server', 'nginx');
    
    // Send the response
    res.status(response.status).send(processedBody);
  } catch (err) {
    console.error('Proxy error:', err.message);
    res.status(500).send(`Proxy error: ${err.message}`);
  }
};