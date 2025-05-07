//import * as React from 'react';
import { useState } from 'react';
import axios from 'axios';
import './toolpage.css';

type Flag = {
  flag: string;
  label: string;
  description: string;
};

type ToolConfig = {
  name: string;
  key: string;
  description: string;
  flags: Flag[];
};

const tools: ToolConfig[] = [
  {
    name: 'Nmap',
    key: 'nmap',
    description: 'Network exploration tool and security scanner.',
    flags: [
      { flag: '-sS', label: 'TCP SYN Scan', description: 'Performs a stealthy TCP SYN scan.' },
      { flag: '-sT', label: 'TCP Connect Scan', description: 'Performs a TCP connect scan.' },
      { flag: '-sV', label: 'Service Version Detection', description: 'Detects service versions on open ports.' },
      { flag: '-O', label: 'OS Detection', description: 'Attempts to determine the OS of the target.' },
      { flag: '-A', label: 'Aggressive Scan', description: 'Enables OS detection, version detection, script scanning, and traceroute.' },
      { flag: '-p-', label: 'Scan All Ports', description: 'Scans all 65535 ports.' },
      { flag: '-Pn', label: 'No Ping', description: 'Treats all hosts as online — skip host discovery.' },
      { flag: '-T4', label: 'Timing Template 4', description: 'Speeds up the scan; may be less stealthy.' },
    ],
  },
  {
    name: 'Httpx',
    key: 'httpx',
    description: 'Fast and multi-purpose HTTP toolkit.',
    flags: [
      { flag: '-status-code', label: 'Status Code', description: 'Displays HTTP response codes.' },
      { flag: '-title', label: 'Title', description: 'Shows page titles.' },
      { flag: '-tech-detect', label: 'Tech Detection', description: 'Tries to detect technologies used.' },
      { flag: '-server', label: 'Server Header', description: 'Displays the server header.' },
      { flag: '-location', label: 'Location Header', description: 'Displays the location header.' },
      { flag: '-favicon', label: 'Favicon Hash', description: 'Calculates the favicon hash.' },
      { flag: '-screenshot', label: 'Screenshot', description: 'Takes a screenshot of the page.' },
      { flag: '-no-color', label: 'No Color', description: 'Disables colored output.' },
    ],
  },
  {
    name: 'WhatWeb',
    key: 'whatweb',
    description: 'Identifies websites and their technologies.',
    flags: [
      { flag: '-v', label: 'Verbose', description: 'Increases verbosity level.' },
      { flag: '-a 1', label: 'Aggression Level 1', description: 'Minimal requests; passive detection.' },
      { flag: '-a 3', label: 'Aggression Level 3', description: 'Aggressive detection with more requests.' },
      { flag: '-a 4', label: 'Aggression Level 4', description: 'Very aggressive detection; many requests.' },
      { flag: '--log-brief', label: 'Brief Logging', description: 'Logs URL and plugins found.' },
      { flag: '--user-agent', label: 'Custom User-Agent', description: 'Sets a custom user-agent string.' },
      { flag: '-o json', label: 'JSON Output', description: 'Outputs results in JSON format.' },
    ],
  },
];

const ToolPage = () => {
  const [domain, setDomain] = useState('');
  const [selectedTools, setSelectedTools] = useState<{ [key: string]: boolean }>({});
  const [selectedFlags, setSelectedFlags] = useState<{ [key: string]: string[] }>({});
  const [log, setLog] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleToolChange = (toolKey: string) => {
    setSelectedTools((prev) => ({
      ...prev,
      [toolKey]: !prev[toolKey],
    }));
  };

  const handleFlagChange = (toolKey: string, flag: string) => {
    setSelectedFlags((prev) => {
      const currentFlags = prev[toolKey] || [];
      const updatedFlags = currentFlags.includes(flag)
        ? currentFlags.filter((f) => f !== flag)
        : [...currentFlags, flag];
      return { ...prev, [toolKey]: updatedFlags };
    });
  };

  const handleScan = async () => {
    setError('');
    setLog('');
    setLoading(true);
    const selected = Object.keys(selectedTools).filter((key) => selectedTools[key]);
    const flagsForSelected = selected.reduce((acc: any, key) => {
      acc[key] = selectedFlags[key] || [];
      return acc;
    }, {});

    setLog('Sending scan request to backend...');

    try {
      const res = await axios.post('http://localhost:5000/scan', {
        domain,
        tools: selected,
        flags: flagsForSelected,
      });

      setLog(`Scan successful:\n${res.data.message || 'See backend logs for results.'}`);
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Scan failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="toolpage-container">
      <h2 className="toolpage-header">MaxRecon Scanner</h2>

      <input
        className="domain-input"
        type="text"
        value={domain}
        onChange={(e) => setDomain(e.target.value)}
        placeholder="Enter domain (example.com)"
      />

      <div className="tools-section">
        {tools.map((tool) => (
          <div key={tool.key} className="tool-card">
            <label className="tool-label">
              <input
                type="checkbox"
                checked={selectedTools[tool.key] || false}
                onChange={() => handleToolChange(tool.key)}
              />
              <span className="tool-name">{tool.name}</span>
            </label>
            <p className="tool-desc">{tool.description}</p>

            {selectedTools[tool.key] && (
              <div className="flags-section">
<table className="flags-table">
  <thead>
    <tr>
      <th></th>
      <th>Flag</th>
      <th>Label</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    {tool.flags.map((f) => (
      <tr key={f.flag}>
        <td>
          <input
            type="checkbox"
            checked={(selectedFlags[tool.key] || []).includes(f.flag)}
            onChange={() => handleFlagChange(tool.key, f.flag)}
          />
        </td>
        <td className="flag-code">{f.flag}</td>
        <td className="flag-label">{f.label}</td>
        <td className="flag-description">{f.description}</td>
      </tr>
    ))}
  </tbody>
</table>
              </div>
            )}
          </div>
        ))}
      </div>

      <button className="scan-btn" onClick={handleScan} disabled={loading || !domain}>
        {loading ? 'Scanning...' : 'Start Scan'}
      </button>

      {error && <p className="error-msg">{error}</p>}
      {log && <pre className="log-output">{log}</pre>}
    </div>
  );
};

export default ToolPage;