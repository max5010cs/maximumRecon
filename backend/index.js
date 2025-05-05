const express = require('express');
const cors = require('cors');
const nmap = require('node-nmap');
const url = require('url');
const { exec } = require('child_process');

const app = express();
const port = 5000;

app.use(cors());
app.use(express.json());

const sanitizeDomain = (domain) => {
  // Sanitize domain: Remove 'http://', 'https://' if user includes them
  const parsedUrl = url.parse(domain);
  return parsedUrl.hostname || domain;
};

const runNmapScan = (domain) => {
  return new Promise((resolve, reject) => {
    // Advanced nmap scan command with service version and OS detection
    const nmapCommand = `nmap -sV -O --script=vuln ${domain}`;  // You can adjust this command if needed
    console.log(`Running nmap scan on ${domain}...`);

    exec(nmapCommand, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error during nmap scan: ${error.message}`);
        return reject(error.message);
      }
      if (stderr) {
        console.error(`stderr: ${stderr}`);
        return reject(stderr);
      }
      resolve(stdout);
    });
  });
};

// Helper to analyze nmap output for vulnerabilities
const analyzeScanResults = (output) => {
  const vulnerabilities = [];
  const openPorts = [];
  const lines = output.split('\n');

  lines.forEach((line) => {
    if (line.includes('open')) {
      const portInfo = line.split('/');
      const port = portInfo[0];
      const service = portInfo[1]?.trim();
      openPorts.push({ port, service });
      
      // Simple vulnerability check for specific services
      if (service && (service.includes('ftp') || service.includes('telnet'))) {
        vulnerabilities.push(`Warning: Insecure service detected - ${service}`);
      }

      // Detect version-related vulnerabilities (simplified check)
      if (service && service.includes('Apache')) {
        vulnerabilities.push('Potential vulnerability: Apache service detected');
      }
    }
  });

  return { openPorts, vulnerabilities };
};

app.get('/scan', async (req, res) => {
  const { domain } = req.query;

  if (!domain) {
    return res.status(400).json({ error: 'Domain is required.' });
  }

  const sanitizedDomain = sanitizeDomain(domain);
  try {
    const nmapResults = await runNmapScan(sanitizedDomain);
    const { openPorts, vulnerabilities } = analyzeScanResults(nmapResults);
    
    res.json({
      openPorts,
      vulnerabilities,
      message: 'Scan completed successfully',
    });
  } catch (error) {
    console.error('Scan failed:', error);
    res.status(500).json({ error: 'Scan failed. Please try again later.' });
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});