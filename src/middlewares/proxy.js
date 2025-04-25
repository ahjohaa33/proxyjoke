// 📁 /middlewares/superSmartProxy.js

const { Resolver } = require('dns').promises;
const http = require('http');
const https = require('https');
const zlib = require('zlib');
const Stream = require('stream');
const { URL } = require('url');
const crypto = require('crypto');

const modernProfiles = require('../data/browserProfiles.json');

// DNS resolvers to randomize
const dnsResolvers = [
  '8.8.8.8',           // Google
  '1.1.1.1',           // Cloudflare
  '9.9.9.9',           // Quad9
  '208.67.222.222'     // OpenDNS
];

// Create a cache for cookies
const cookieCache = new Map();

// Create a cache for successful requests to avoid redirect loops
const redirectCache = new Map();

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

// Parse cookies from Set-Cookie header
function parseCookies(setCookieHeader) {
  if (!setCookieHeader) return [];
  
  // Handle array or single string
  const cookieHeaders = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
  
  return cookieHeaders.map(header => {
    const parts = header.split(';');
    const cookiePart = parts[0];
    const [name, value] = cookiePart.split('=').map(s => s.trim());
    
    return { name, value };
  });
}

// Stores cookies for a domain
function storeCookies(domain, setCookieHeader) {
  if (!setCookieHeader) return;
  
  const cookies = parseCookies(setCookieHeader);
  
  if (!cookieCache.has(domain)) {
    cookieCache.set(domain, new Map());
  }
  
  const domainCookies = cookieCache.get(domain);
  cookies.forEach(cookie => {
    domainCookies.set(cookie.name, cookie.value);
  });
}

// Gets cookie string for a domain
function getCookieString(domain) {
  // Check if we have cookies for this domain or its parent domains
  const parts = domain.split('.');
  let cookieStr = '';
  
  for (let i = 0; i < parts.length - 1; i++) {
    const testDomain = parts.slice(i).join('.');
    if (cookieCache.has(testDomain)) {
      const cookies = cookieCache.get(testDomain);
      const domainCookies = Array.from(cookies.entries())
        .map(([name, value]) => `${name}=${value}`)
        .join('; ');
      
      if (domainCookies) {
        cookieStr += (cookieStr ? '; ' : '') + domainCookies;
      }
    }
  }
  
  return cookieStr;
}

// Safe decompression function that prevents zlib errors
function createSafeDecompressionStream(contentEncoding) {
  if (!contentEncoding) return null;
  
  let decompressionStream;
  
  try {
    if (contentEncoding.includes('gzip')) {
      decompressionStream = zlib.createGunzip({
        flush: zlib.Z_SYNC_FLUSH,
        finishFlush: zlib.Z_SYNC_FLUSH
      });
    } else if (contentEncoding.includes('deflate')) {
      decompressionStream = zlib.createInflate({
        flush: zlib.Z_SYNC_FLUSH,
        finishFlush: zlib.Z_SYNC_FLUSH
      });
    } else if (contentEncoding.includes('br')) {
      decompressionStream = zlib.createBrotliDecompress({
        flush: zlib.BROTLI_OPERATION_FLUSH
      });
    }

    // Add error handler to prevent crashes
    if (decompressionStream) {
      decompressionStream.on('error', (err) => {
        console.error('Decompression error:', err.message);
        // Instead of crashing, just end the stream
        decompressionStream.end();
      });
    }
    
    return decompressionStream;
  } catch (err) {
    console.error('Error creating decompression stream:', err);
    return null;
  }
}

// Improved fetch implementation with better error handling
async function customFetch(url, options = {}, redirectCount = 0, redirectHistory = []) {
  await randomizeRequestTiming();

  // Tracking circular redirects with hash
  const requestHash = crypto.createHash('md5').update(url).digest('hex');
  if (redirectHistory.includes(requestHash)) {
    throw new Error(`Circular redirect detected: ${url}`);
  }
  
  const maxRedirects = 50; // Increased for sites with many redirects
  
  if (redirectCount > maxRedirects) {
    console.error(`Excessive redirects for: ${url}`);
    console.error(`Redirect history: ${redirectHistory.join(' -> ')}`);
    throw new Error(`Maximum redirect count (${maxRedirects}) exceeded.`);
  }

  // Track redirect history for debugging
  const newRedirectHistory = [...redirectHistory, requestHash];
  
  // Skip already processed redirects if they're in the cache
  const urlObj = new URL(url);
  const hostname = urlObj.hostname;
  const cacheKey = `${urlObj.hostname}${urlObj.pathname}`;
  
  // If we've seen this exact URL successfully before in a redirect chain
  if (redirectCount > 0 && redirectCache.has(cacheKey)) {
    console.log(`Using cached redirect result for: ${url}`);
    return redirectCache.get(cacheKey);
  }
  
  console.log(`Making request to: ${url} (redirect: ${redirectCount})`);
  
  return new Promise((resolve, reject) => {
    try {
      const isHttps = urlObj.protocol === 'https:';
      
      // Get cookies for this domain
      const cookieStr = getCookieString(hostname);
      
      const requestOptions = {
        method: options.method || 'GET',
        headers: { ...options.headers } || {},
        hostname: urlObj.hostname,
        port: urlObj.port || (isHttps ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        timeout: 120000, // 2 minute timeout for heavy sites
        rejectUnauthorized: false
      };
      
      // Add cookies if we have them
      if (cookieStr) {
        requestOptions.headers['Cookie'] = cookieStr;
      }
      
      const clientRequest = (isHttps ? https : http).request(requestOptions, async (response) => {
        const { statusCode, headers } = response;
        
        // Store any cookies returned by the server
        if (headers['set-cookie']) {
          storeCookies(hostname, headers['set-cookie']);
        }
        
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
          const redirectHeaders = { ...options.headers };
          
          // Update referer for the redirect
          redirectHeaders['Referer'] = url;
          redirectHeaders['Origin'] = `${urlObj.protocol}//${urlObj.host}`;
          
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
        
        // Create a response object with both buffer and streaming capabilities
        const responseObj = {
          status: statusCode,
          headers: response.headers,
          originalResponse: response, // Store original response
          
          // Method to get content as a buffer
          getBuffer: () => {
            return new Promise((resolveBuffer, rejectBuffer) => {
              const chunks = [];
              
              response.on('data', (chunk) => {
                chunks.push(chunk);
              });
              
              response.on('end', () => {
                const buffer = Buffer.concat(chunks);
                console.log(`Response complete: ${statusCode}, size: ${buffer.length} bytes`);
                
                // Decompress if needed
                try {
                  const contentEncoding = headers['content-encoding'];
                  if (!contentEncoding) {
                    return resolveBuffer(buffer);
                  }
                  
                  // Handle different compression types
                  if (contentEncoding.includes('gzip')) {
                    zlib.gunzip(buffer, (err, result) => {
                      if (err) {
                        console.error('Gunzip error:', err);
                        // Return the original buffer on error
                        resolveBuffer(buffer);
                      } else {
                        resolveBuffer(result);
                      }
                    });
                  } else if (contentEncoding.includes('deflate')) {
                    zlib.inflate(buffer, (err, result) => {
                      if (err) {
                        console.error('Inflate error:', err);
                        // Return the original buffer on error
                        resolveBuffer(buffer);
                      } else {
                        resolveBuffer(result);
                      }
                    });
                  } else if (contentEncoding.includes('br')) {
                    zlib.brotliDecompress(buffer, (err, result) => {
                      if (err) {
                        console.error('Brotli decompression error:', err);
                        // Return the original buffer on error
                        resolveBuffer(buffer);
                      } else {
                        resolveBuffer(result);
                      }
                    });
                  } else {
                    // Unknown encoding, return as-is
                    resolveBuffer(buffer);
                  }
                } catch (err) {
                  console.error('Decompression error:', err);
                  resolveBuffer(buffer); // Return original buffer on error
                }
              });
              
              response.on('error', (err) => {
                console.error('Response stream error:', err);
                rejectBuffer(err);
              });
            });
          },
          
          // Method to get raw stream (without decompression)
          getRawStream: () => {
            return response;
          },
          
          // Method to get decompressed stream
          getStream: () => {
            const contentEncoding = headers['content-encoding'];
            const decompressionStream = createSafeDecompressionStream(contentEncoding);
            
            if (decompressionStream) {
              // We need to create a fresh response clone to pipe through the decompression stream
              // since response streams can only be consumed once
              return response.pipe(decompressionStream);
            } else {
              return response;
            }
          },
          
          url: url // Include the final URL
        };
        
        // Cache this response for future redirect chains
        if (statusCode === 200) {
          redirectCache.set(cacheKey, responseObj);
        }
        
        resolve(responseObj);
      });
      
      // Error handling
      clientRequest.on('error', (err) => {
        console.error(`Request Error for ${url}:`, err.message);
        reject(new Error(`Request failed: ${err.message}`));
      });
      
      clientRequest.on('timeout', () => {
        clientRequest.destroy(new Error(`Request timeout after ${requestOptions.timeout}ms for ${url}`));
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
async function fetchWithRandomProfile(url, parentUrl = null) {
  const profile = getRandomProfile();
  const resolver = getRandomResolver();
  const urlObj = new URL(url);
  
  console.log(`Using profile: ${profile.name}`);
  
  // Modern browser headers
  const headers = {
    'User-Agent': profile.userAgent,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': profile.acceptLanguage || 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Cache-Control': 'max-age=0',
    'Sec-Ch-Ua': '"Not.A/Brand";v="99", "Google Chrome";v="124", "Chromium";v="124"',
    'Sec-Ch-Ua-Mobile': '?0',
    'Sec-Ch-Ua-Platform': '"Windows"',
    'Sec-Fetch-Dest': parentUrl ? 'iframe' : 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': parentUrl ? 'same-origin' : 'none',
    'Sec-Fetch-User': parentUrl ? '?0' : '?1',
    'Upgrade-Insecure-Requests': '1',
    'Priority': 'u=0, i',
    'Connection': 'keep-alive',
    'Host': urlObj.hostname,
    'DNT': '1' // Do Not Track
  };

  // Add referer if this is a subresource
  if (parentUrl) {
    headers['Referer'] = parentUrl;
  }

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
          'Accept-Encoding': 'gzip, deflate',  // Removed 'br' to avoid brotli issues
          'Host': urlObj.hostname,
          'Connection': 'keep-alive'
        }
      });
    } catch (err2) {
      console.error('Fallback request failed:', err2.message);
      throw err2;
    }
  }
}

// Helper function to rewrite URLs in HTML content
function rewriteHtml(html, targetUrl, proxyPath, protocol, host) {
  try {
    const baseUrl = new URL(targetUrl);
    
    // Replace src, href, and other attributes
    const urlRegex = /(src|href|action|data-src)=["'](?!data:|blob:|javascript:|#|mailto:)([^"']+)["']/gi;
    html = html.replace(urlRegex, (match, attr, url) => {
      try {
        let absoluteUrl;
        
        if (url.startsWith('//')) {
          // Protocol-relative URL
          absoluteUrl = `${baseUrl.protocol}${url}`;
        } else if (url.startsWith('/')) {
          // Absolute path
          absoluteUrl = `${baseUrl.protocol}//${baseUrl.host}${url}`;
        } else if (!url.match(/^https?:\/\//i)) {
          // Relative path
          let basePath = baseUrl.pathname;
          // Ensure basePath ends with a slash if it's not pointing to a file
          if (!basePath.endsWith('/') && !basePath.includes('.')) {
            basePath += '/';
          } else {
            basePath = basePath.substring(0, basePath.lastIndexOf('/') + 1);
          }
          absoluteUrl = `${baseUrl.protocol}//${baseUrl.host}${basePath}${url}`;
        } else {
          // Already absolute
          absoluteUrl = url;
        }
        
        const encodedUrl = encodeURIComponent(absoluteUrl);
        return `${attr}="${protocol}://${host}${proxyPath}?targetUrl=${encodedUrl}"`;
      } catch (e) {
        console.error('URL rewrite error:', e);
        return match; // Return original on error
      }
    });
    
    // Replace URLs in inline styles
    const styleRegex = /url\(['"]?(?!data:|blob:)([^'")\s]+)['"]?\)/gi;
    html = html.replace(styleRegex, (match, url) => {
      try {
        let absoluteUrl;
        
        if (url.startsWith('//')) {
          absoluteUrl = `${baseUrl.protocol}${url}`;
        } else if (url.startsWith('/')) {
          absoluteUrl = `${baseUrl.protocol}//${baseUrl.host}${url}`;
        } else if (!url.match(/^https?:\/\//i)) {
          let basePath = baseUrl.pathname;
          if (!basePath.endsWith('/') && !basePath.includes('.')) {
            basePath += '/';
          } else {
            basePath = basePath.substring(0, basePath.lastIndexOf('/') + 1);
          }
          absoluteUrl = `${baseUrl.protocol}//${baseUrl.host}${basePath}${url}`;
        } else {
          absoluteUrl = url;
        }
        
        const encodedUrl = encodeURIComponent(absoluteUrl);
        return `url("${protocol}://${host}${proxyPath}?targetUrl=${encodedUrl}")`;
      } catch (e) {
        console.error('Style URL rewrite error:', e);
        return match; // Return original on error
      }
    });
    
    // Add our own base tag to ensure relative URLs work correctly
    const baseTag = `<base href="${baseUrl.protocol}//${baseUrl.host}${baseUrl.pathname}" />`;
    html = html.replace(/<head>/i, `<head>${baseTag}`);
    
    return html;
  } catch (err) {
    console.error('HTML rewrite error:', err);
    return html; // Return original on error
  }
}

// Main proxy handler
module.exports = async function superSmartProxy(req, res) {
  const rawUrl = req.query.targetUrl;
  if (!rawUrl) return res.status(400).send('Missing URL');

  const targetUrl = sanitizeUrl(rawUrl);
  const proxyPath = req.originalUrl.split('?')[0]; // Get base path of proxy

  try {
    await randomizeRequestTiming();
    
    // Track if this is the main page or a subresource
    const isMainRequest = !req.headers['x-requested-with'] || 
                           req.headers['x-requested-with'] !== 'XMLHttpRequest';
    const parentUrl = req.headers['referer'];
    
    const response = await fetchWithRandomProfile(targetUrl, parentUrl);
    
    // Handle timeout or no response
    if (!response) {
      return res.status(504).send('Gateway Timeout: No response from target server');
    }
    
    // Set content type
    const contentType = response.headers['content-type'] || 
                       (targetUrl.match(/\.(jpg|jpeg|png|gif|webp|svg)$/i) ? 'image/'+RegExp.$1.toLowerCase() : 'text/plain');
    
    res.removeHeader('X-Powered-By');
    res.set('Content-Type', contentType);
    
    // Pass through useful headers from the original response
    const passthroughHeaders = [
      'content-language',
      'content-disposition',
      'cache-control',
      'expires',
      'last-modified',
      'etag',
      'vary'
    ];
    
    passthroughHeaders.forEach(header => {
      if (response.headers[header]) {
        res.set(header, response.headers[header]);
      }
    });
    
    // Explicitly set content-encoding to identity (uncompressed)
    res.set('Content-Encoding', 'identity');
    
    // Set a generic server header
    res.set('Server', 'nginx');
    
    // Set status code
    res.status(response.status);
    
    // Special handling for HTML content - rewrite URLs to go through our proxy
    if (contentType && contentType.includes('text/html') && isMainRequest) {
      console.log('Rewriting HTML content');
      try {
        // Use buffer approach for HTML content to process it
        const buffer = await response.getBuffer();
        let html = buffer.toString();
        
        // Get the current hostname and protocol for constructing proxy URLs
        const protocol = req.protocol;
        const host = req.get('host');
        
        // Rewrite HTML to fix URLs
        html = rewriteHtml(html, targetUrl, proxyPath, protocol, host);
        
        // Send the modified HTML
        return res.send(html);
      } catch (err) {
        console.error('Error processing HTML:', err);
        // Fallback to raw response if HTML processing fails
        return res.send(await response.getBuffer());
      }
    }
    
    // For binary files and non-HTML content, use buffer approach
    // to avoid streaming issues
    if (contentType && 
        (contentType.includes('image/') || 
         contentType.includes('video/') || 
         contentType.includes('audio/') ||
         contentType.includes('application/octet-stream') ||
         contentType.includes('application/pdf'))) {
      console.log('Sending binary content as buffer');
      try {
        const buffer = await response.getBuffer();
        return res.send(buffer);
      } catch (err) {
        console.error('Error processing binary content:', err);
        return res.status(500).send('Error processing binary content');
      }
    }
    
    // For everything else, try the buffer approach
    try {
      console.log('Sending content as buffer');
      const buffer = await response.getBuffer();
      res.send(buffer);
    } catch (streamErr) {
      console.error('Buffer send error:', streamErr);
      res.status(500).send('Error sending content');
    }
  } catch (err) {
    console.error('Proxy error:', err.message);
    res.status(500).send(`Proxy error: ${err.message}`);
  }
};