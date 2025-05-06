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

  const riskyServices = [
    { keyword: /ftp/i, risk: 'FTP is insecure by default (no encryption).', severity: 'High', recommendation: 'Use SFTP or FTPS instead.' },
    { keyword: /telnet/i, risk: 'Telnet transmits data in plaintext.', severity: 'High', recommendation: 'Replace with SSH.' },
    { keyword: /rsh/i, risk: 'Remote Shell (rsh) is obsolete and insecure.', severity: 'High', recommendation: 'Disable and use SSH instead.' },
    { keyword: /smb/i, risk: 'SMBv1 is vulnerable to EternalBlue.', severity: 'Critical', recommendation: 'Use SMBv2/v3 or disable SMB altogether.' },
    { keyword: /rdp/i, risk: 'RDP can be vulnerable without strong policies.', severity: 'Medium', recommendation: 'Enforce strong passwords and enable NLA/2FA.' },
  ];

  const outdatedPatterns = [
    { regex: /Apache.*2\.2/, message: 'Apache 2.2 is outdated.', severity: 'High', recommendation: 'Upgrade to Apache 2.4 or newer.' },
    { regex: /OpenSSH.*6\./, message: 'Outdated OpenSSH version detected.', severity: 'Medium', recommendation: 'Upgrade to OpenSSH 9.x or newer.' },
    { regex: /nginx.*1\.14/, message: 'Nginx 1.14 is old.', severity: 'Medium', recommendation: 'Update to 1.24+.' },
    { regex: /MySQL.*5\.5/, message: 'MySQL 5.5 is no longer maintained.', severity: 'High', recommendation: 'Upgrade to MySQL 8.x.' },
  ];

  lines.forEach((line) => {
    if (line.includes('open')) {
      const parts = line.trim().split(/\s+/);
      const portProto = parts[0];
      const port = portProto.split('/')[0];
      const protocol = portProto.split('/')[1];
      const service = parts[2] || '';
      const product = parts.slice(3).join(' ') || '';

      openPorts.push({ port, protocol, service, product });

      // Detect risky services
      riskyServices.forEach(({ keyword, risk, severity, recommendation }) => {
        if (service.match(keyword)) {
          vulnerabilities.push({
            description: `${risk} on port ${port} (${service})`,
            severity,
            recommendation,
            affectedPort: port
          });
        }
      });

      // Detect outdated versions
      outdatedPatterns.forEach(({ regex, message, severity, recommendation }) => {
        if (product.match(regex)) {
          vulnerabilities.push({
            description: `${message} on port ${port}: ${product}`,
            severity,
            recommendation,
            affectedPort: port
          });
        }
      });

      // Signature-based banner checks (extendable)
      if (product.includes('MiniServ/0.01')) {
        vulnerabilities.push({
          description: 'MiniServ/0.01 has known vulnerabilities.',
          severity: 'Medium',
          recommendation: 'Update to a secure version or disable unused services.',
          affectedPort: port
        });
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