// /analyzers/nmapAnalyzer.js

/**
 * Parses Nmap output and returns a structured pentest-style report.
 * @param {string} rawOutput - The raw output from Nmap scan.
 * @returns {Object} - Structured report object with findings.
 */
function analyzeNmapOutput(rawOutput) {
    const lines = rawOutput.split('\n');
  
    const openPorts = [];
    const metadata = {
      scannedHost: null,
      scanSummary: null
    };
  
    for (let line of lines) {
      line = line.trim();
  
      // Capture scanned host/IP
      if (line.startsWith('Nmap scan report for')) {
        metadata.scannedHost = line.replace('Nmap scan report for', '').trim();
      }
  
      // Extract open ports (e.g., 80/tcp open  http Apache 2.4.7)
      const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+open\s+([\w\-]+)(.*)$/);
      if (portMatch) {
        const [_, port, protocol, service, versionInfo] = portMatch;
        openPorts.push({
          port: parseInt(port),
          protocol,
          service,
          versionInfo: versionInfo.trim(),
          notes: versionInfo.includes('outdated') ? 'Possibly outdated' : null
        });
      }
  
      // Scan summary (last line)
      if (line.startsWith('Nmap done:')) {
        metadata.scanSummary = line;
      }
    }
  
    return {
      scannedHost: metadata.scannedHost || 'Unknown',
      summary: metadata.scanSummary || 'No summary available.',
      openPorts,
      findings: openPorts.length
        ? `Detected ${openPorts.length} open ports.`
        : 'No open ports detected.',
      suggestions: openPorts.length
        ? generateSuggestions(openPorts)
        : ['No actionable issues detected.']
    };
  }
  
  /**
   * Generates security suggestions based on open ports and services.
   * @param {Array} openPorts - List of open port objects.
   * @returns {Array} - List of pentest-style recommendations.
   */
  function generateSuggestions(openPorts) {
    const suggestions = [];
  
    for (const portObj of openPorts) {
      if (portObj.versionInfo.toLowerCase().includes('apache')) {
        suggestions.push(
          `Check if Apache version on port ${portObj.port} is up to date.`
        );
      }
      if (portObj.service === 'ftp') {
        suggestions.push(
          `FTP found on port ${portObj.port}. Consider disabling if not in use or switching to SFTP.`
        );
      }
      if (portObj.port === 23) {
        suggestions.push(
          'Telnet (port 23) is insecure. Disable or replace with SSH if possible.'
        );
      }
    }
  
    return suggestions.length ? suggestions : ['No major issues detected.'];
  }
  
  module.exports = analyzeNmapOutput;