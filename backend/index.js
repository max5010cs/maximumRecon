const express = require('express');
const cors = require('cors');
const url = require('url');
const { exec } = require('child_process');

const app = express();
const port = 5000;

app.use(cors());
app.use(express.json());

// Sanitize domain input
const sanitizeDomain = (domain) => {
  const parsedUrl = url.parse(domain);
  return parsedUrl.hostname || domain;
};

// Run the nmap scan
const runNmapScan = (domain) => {
  return new Promise((resolve, reject) => {
    const nmapCommand = `nmap -T4 -sV -O --top-ports 100 --script=vuln --min-rate=1000 -Pn ${domain}`;
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
      console.log("Nmap scan results received.");
      resolve(stdout);
    });
  });
};

// Analyze Nmap results
const analyzeScanResults = (output) => {
  const vulnerabilities = [];
  const openPorts = [];
  const lines = output.split('\n');

  lines.forEach((line) => {
    if (line.includes('open')) {
      const parts = line.trim().split(/\s+/);
      const portProto = parts[0]; // e.g., 80/tcp
      const port = portProto.split('/')[0];
      const protocol = portProto.split('/')[1];
      const service = parts[2] || '';
      const product = parts.slice(3).join(' ') || '';

      openPorts.push({ port, protocol, service, product });

      // Check for insecure services
      if (service.match(/ftp|telnet|rsh/i)) {
        vulnerabilities.push(`Insecure service detected on port ${port}: ${service}`);
      }

      // Check for outdated versions (simple logic)
      if (product.match(/Apache.*2\.2/)) {
        vulnerabilities.push(`Outdated Apache version on port ${port}: ${product}`);
      }
      if (product.match(/OpenSSH.*6\./)) {
        vulnerabilities.push(`Potential outdated OpenSSH on port ${port}: ${product}`);
      }
    }
  });

  return { openPorts, vulnerabilities };
};

// Endpoint to run scan
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
      rawOutput: nmapResults,
      analysis: {
        openPorts,
        vulnerabilities,
      },
      message: 'Scan completed successfully',
    });
  } catch (error) {
    console.error('Scan failed:', error);
    res.status(500).json({ error: 'Scan failed. Please try again later.' });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});