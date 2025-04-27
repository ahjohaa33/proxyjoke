const http = require('http');
const https = require('https');

const proxyUrl = 'http://localhost:5000';

async function testHttpRequest() {
  console.log('Testing HTTP request through proxy...');
  
  // Configure the HTTP request options
  const options = {
    host: 'localhost',
    port: 5000,
    path: 'http://httpbin.org/get',
    method: 'GET',
    headers: {
      'Host': 'httpbin.org'
    }
  };

  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        console.log('HTTP Response Status:', res.statusCode);
        console.log('HTTP Response Data:', data.substring(0, 200) + '...');
        resolve(res.statusCode === 200);
      });
    });
    
    req.on('error', (err) => {
      console.error('HTTP Request Error:', err.message);
      reject(err);
    });
    
    req.end();
  });
}

async function testHttpsRequest() {
  console.log('\nTesting HTTPS request through proxy...');
  
  // For HTTPS requests via HTTP CONNECT tunnel
  const options = {
    host: 'localhost',
    port: 5000,
    path: 'https://httpbin.org/get',
    method: 'GET',
    headers: {
      'Host': 'httpbin.org'
    }
  };

  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        console.log('HTTPS Response Status:', res.statusCode);
        console.log('HTTPS Response Data:', data.substring(0, 200) + '...');
        resolve(res.statusCode === 200);
      });
    });
    
    req.on('error', (err) => {
      console.error('HTTPS Request Error:', err.message);
      reject(err);
    });
    
    req.end();
  });
}

async function runTests() {
  try {
    const httpResult = await testHttpRequest();
    const httpsResult = await testHttpsRequest();
    
    console.log('\n--- Test Results ---');
    console.log('HTTP Test:', httpResult ? 'PASSED' : 'FAILED');
    console.log('HTTPS Test:', httpsResult ? 'PASSED' : 'FAILED');
  } catch (error) {
    console.error('Test execution failed:', error);
  }
}

// Run the tests
runTests();