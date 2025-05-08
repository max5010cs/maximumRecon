// /analyzers/httpxAnalyzer.js

/**
 * Parses HTTPX output and returns a structured pentest-style report.
 * @param {string} rawOutput - Raw output from httpx tool.
 * @returns {Object} - Structured report object.
 */
function analyzeHttpxOutput(rawOutput) {
    const lines = rawOutput.trim().split('\n');
  
    const liveHosts = [];
    const suggestions = [];
  
    for (const line of lines) {
      const match = line.match(/(https?:\/\/[^\s]+)\s+(\d+)\s+(\d+)\s+([^]+)/);
  
      if (match) {
        const [, url, statusCode, contentLength, server] = match;
  
        const hostData = {
          url,
          statusCode: parseInt(statusCode),
          contentLength: parseInt(contentLength),
          server,
        };
  
        liveHosts.push(hostData);
  
        // Analyze for potential issues
        if (statusCode === 403) {
          suggestions.push(`${url} returned 403 Forbidden — check for authorization issues.`);
        }
        if (statusCode >= 500) {
          suggestions.push(`${url} returned ${statusCode} — potential server-side error.`);
        }
        if (url.startsWith('http://')) {
          suggestions.push(`${url} uses HTTP — consider redirecting to HTTPS.`);
        }
        if (server.toLowerCase().includes('apache') || server.toLowerCase().includes('nginx')) {
          suggestions.push(`${url} uses ${server}. Check for version disclosure or misconfigurations.`);
        }
      }
    }
  
    return {
      scannedHost: liveHosts.length ? liveHosts[0].url : 'Unknown',
      summary: `Found ${liveHosts.length} live hosts.`,
      openPorts: [], // httpx doesn't report ports directly
      findings: liveHosts.length
        ? `Detected ${liveHosts.length} live HTTP(s) endpoints.`
        : 'No live HTTP endpoints detected.',
      suggestions: suggestions.length ? suggestions : ['No critical issues found.'],
    };
  }
  
  module.exports = analyzeHttpxOutput;