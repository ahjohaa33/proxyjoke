// 📁 /middlewares/superSmartProxy.js

const { Resolver } = require('dns').promises;
const http = require('http');
const https = require('https');
const zlib = require('zlib');
const Stream = require('stream');
const url = require('url');
const querystring = require('querystring');
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

// Get normalized hostname for cache
function getNormalizedHostname(urlString) {
  const parsed = new URL(urlString);
  return parsed.hostname;
}

// Use sockets that won't hang
function setupAgents() {
  const httpAgent = new http.Agent({
    keepAlive: true,
    maxSockets: 50,
    timeout: 60000
  });
  
  const httpsAgent = new https.Agent({
    keepAlive: true,
    maxSockets: 50,
    timeout: 60000,
    rejectUnauthorized: false
  });
  
  return { httpAgent, httpsAgent };
}

// Improved fetch implementation with better redirect handling
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
      const { httpAgent, httpsAgent } = setupAgents();
      
      // Get cookies for this domain
      const cookieStr = getCookieString(hostname);
      
      const requestOptions = {
        method: options.method || 'GET',
        headers: { ...options.headers } || {},
        hostname: urlObj.hostname,
        port: urlObj.port || (isHttps ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        timeout: 120000, // 2 minute timeout for heavy sites
        rejectUnauthorized: false,
        agent: isHttps ? httpsAgent : httpAgent,
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
        
        // Special case for certain sites that might use JavaScript redirects
        if (statusCode === 200 && 
            (headers['content-type'] && headers['content-type'].includes('text/html'))) {
          // We'll handle potential JS redirects by analyzing the content
          // But we need to set up our stream pipeline first
        }
        
        // Setup decompression streams based on content-encoding
        let decompressionStream = null;
        const contentEncoding = headers['content-encoding'];
        if (contentEncoding) {
          console.log(`Content encoding: ${contentEncoding}`);
          if (contentEncoding.includes('gzip')) {
            decompressionStream = zlib.createGunzip();
          } else if (contentEncoding.includes('deflate')) {
            decompressionStream = zlib.createInflate();
          } else if (contentEncoding.includes('br')) {
            decompressionStream = zlib.createBrotliDecompress();    
          }
        }
        
        const responseObj = {
          status: statusCode,
          headers: response.headers,
          stream: decompressionStream ? response.pipe(decompressionStream) : response,
          getBuffer: () => {
            return new Promise((resolveBuffer, rejectBuffer) => {
              let rawData = Buffer.alloc(0);
              const dataStream = decompressionStream ? response.pipe(decompressionStream) : response;
              
              dataStream.on('data', (chunk) => {
                rawData = Buffer.concat([rawData, chunk]);
              });
              
              dataStream.on('end', () => {
                console.log(`Response complete: ${statusCode}, size: ${rawData.length} bytes`);
                resolveBuffer(rawData);
              });
              
              dataStream.on('error', (err) => {
                console.error('Stream error:', err);
                rejectBuffer(err);
              });
            });
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
          'Accept-Encoding': 'gzip, deflate, br',
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

// Handle resource mapping for subresources
function mapResourceUrl(originalUrl, baseUrl) {
  try {
    // Already absolute URL
    if (/^https?:\/\//i.test(originalUrl)) {
      return originalUrl;
    }
    
    // Protocol relative URL
    if (originalUrl.startsWith('//')) {
      const baseUrlObj = new URL(baseUrl);
      return `${baseUrlObj.protocol}${originalUrl}`;
    }
    
    // Absolute path
    if (originalUrl.startsWith('/')) {
      const baseUrlObj = new URL(baseUrl);
      return `${baseUrlObj.protocol}//${baseUrlObj.host}${originalUrl}`;
    }
    
    // Relative path
    const baseUrlObj = new URL(baseUrl);
    const basePath = baseUrlObj.pathname.substring(0, baseUrlObj.pathname.lastIndexOf('/') + 1);
    return `${baseUrlObj.protocol}//${baseUrlObj.host}${basePath}${originalUrl}`;
  } catch (err) {
    console.error('Error mapping resource URL:', err);
    return originalUrl; // Return as-is if there's an error
  }
}

// Stream mode with content replacement for proxied URLs
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
      'etag',
      'vary',
      'access-control-allow-origin',
      'content-security-policy'
    ];
    
    passthroughHeaders.forEach(header => {
      if (response.headers[header]) {
        res.set(header, response.headers[header]);
      }
    });
    
    // Explicitly set content-encoding to identity (uncompressed)
    // since we're handling decompression ourselves
    res.set('Content-Encoding', 'identity');
    
    // Set a generic server header
    res.set('Server', 'nginx');
    
    // Set status code
    res.status(response.status);
    
    // Special handling for HTML content - rewrite URLs to go through our proxy
    if (contentType && contentType.includes('text/html') && isMainRequest) {
      const buffer = await response.getBuffer();
      let html = buffer.toString();
      
      // Get the current hostname and protocol for constructing proxy URLs
      const protocol = req.protocol;
      const host = req.get('host');
      
      // Replace resource URLs to go through our proxy
      const urlRegex = /(src|href|action|data-src)=["'](?!data:|blob:|javascript:|#|mailto:)([^"']+)["']/gi;
      html = html.replace(urlRegex, (match, attr, url) => {
        const absoluteUrl = mapResourceUrl(url, targetUrl);
        const encodedUrl = encodeURIComponent(absoluteUrl);
        return `${attr}="${protocol}://${host}${proxyPath}?targetUrl=${encodedUrl}"`;
      });
      
      // Replace URLs in inline styles
      const styleRegex = /url\(['"]?(?!data:|blob:)([^'")\s]+)['"]?\)/gi;
      html = html.replace(styleRegex, (match, url) => {
        const absoluteUrl = mapResourceUrl(url, targetUrl);
        const encodedUrl = encodeURIComponent(absoluteUrl);
        return `url("${protocol}://${host}${proxyPath}?targetUrl=${encodedUrl}")`;
      });
      
      // Replace URLs in JavaScript
      const jsUrlRegex = /['"]https?:\/\/[^'"]+['"]/gi;
      html = html.replace(jsUrlRegex, (match) => {
        // Only replace if it's not already pointing to our proxy
        if (match.includes(host + proxyPath)) return match;
        
        const url = match.slice(1, -1); // Remove quotes
        const encodedUrl = encodeURIComponent(url);
        return `"${protocol}://${host}${proxyPath}?targetUrl=${encodedUrl}"`;
      });
      
      // Add our own base tag to ensure relative URLs work correctly
      const baseUrl = new URL(targetUrl);
      const baseTag = `<base href="${baseUrl.protocol}//${baseUrl.host}${baseUrl.pathname}" />`;
      html = html.replace(/<head>/i, `<head>${baseTag}`);
      
      // Send the modified HTML
      return res.send(html);
    }
    
    // For non-HTML content or XHR requests, stream directly
    response.stream.pipe(res);
    
    // Handle errors on the stream
    response.stream.on('error', (err) => {
      console.error('Stream error:', err);
      // Only send error if headers haven't been sent yet
      if (!res.headersSent) {
        res.status(500).send(`Stream error: ${err.message}`);
      } else {
        // If headers already sent, just end the response
        res.end();
      }
    });
  } catch (err) {
    console.error('Proxy error:', err.message);
    res.status(500).send(`Proxy error: ${err.message}`);
  }
};