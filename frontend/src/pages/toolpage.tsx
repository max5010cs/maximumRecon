
import { useState } from 'react';
import axios from 'axios';
import './toolpage.css';

type Flag = { flag: string; label: string; description: string; };
type ToolConfig = { name: string; key: string; description: string; flags: Flag[]; };

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
      { flag: '--status-code', label: 'Status Code', description: 'Displays HTTP response codes.' },
      { flag: '--title', label: 'Title', description: 'Shows page titles.' },
      { flag: '--tech-detect', label: 'Tech Detection', description: 'Tries to detect technologies used.' },
      { flag: '--server', label: 'Server Header', description: 'Displays the server header.' },
      { flag: '--location', label: 'Location Header', description: 'Displays the location header.' },
      { flag: '--favicon', label: 'Favicon Hash', description: 'Calculates the favicon hash.' },
      { flag: '--screenshot', label: 'Screenshot', description: 'Takes a screenshot of the page.' },
      { flag: '--no-color', label: 'No Color', description: 'Disables colored output.' },
      { flag: '--follow-redirects', label: 'Follow Redirects', description: 'Follows HTTP redirects.' },
      { flag: '--retries', label: 'Retries', description: 'Sets the number of retries for failed requests.' },
      { flag: '--output', label: 'Output', description: 'Saves output to a file.' },
      { flag: '--rate-limit', label: 'Rate Limit', description: 'Limits the request rate per second.' },
      { flag: '--random-agent', label: 'Random User-Agent', description: 'Randomizes the User-Agent header.' },
      { flag: '--random-ua', label: 'Random User Agent', description: 'Randomizes the user-agent for each request.' },
      { flag: '--proxy', label: 'Proxy', description: 'Uses a specified proxy for the requests.' },
      { flag: '--timeout', label: 'Timeout', description: 'Sets the connection timeout duration.' },
      { flag: '--web-fingerprints', label: 'Web Fingerprints', description: 'Identifies common web technology fingerprints.' },
      { flag: '--web-title', label: 'Web Title', description: 'Shows title of the web page.' },
      { flag: '--no-protocol', label: 'No Protocol', description: 'Strips the protocol from the URL.' },
      { flag: '--method', label: 'HTTP Method', description: 'Allows you to specify a custom HTTP method (e.g., GET, POST).' },
      { flag: '--head', label: 'HEAD Request', description: 'Sends a HEAD request instead of GET.' },
      { flag: '--silent', label: 'Silent', description: 'Disables output except for errors.' },
      { flag: '--json', label: 'JSON Output', description: 'Outputs results in JSON format.' },
      { flag: '--verbose', label: 'Verbose Output', description: 'Enables verbose output for debugging.' },
      { flag: '--cdn-detect', label: 'CDN Detection', description: 'Attempts to detect if the site is behind a CDN.' },
      { flag: '--ignore-ssl-errors', label: 'Ignore SSL Errors', description: 'Ignores SSL certificate verification errors.' },
      { flag: '--http2', label: 'HTTP/2 Support', description: 'Enables HTTP/2 support for requests.' },
      { flag: '--no-defaults', label: 'No Defaults', description: 'Disables the use of default options for requests.' },
      { flag: '--banner', label: 'Banner', description: 'Displays a banner message for the scan results.' },
      { flag: '--include-body', label: 'Include Body', description: 'Includes the response body in the results.' },
      { flag: '--exclude-body', label: 'Exclude Body', description: 'Excludes the response body from the results.' },
      { flag: '--json-line', label: 'JSON Line', description: 'Output each result as a separate line in JSON format.' },
      { flag: '--non-interactive', label: 'Non-Interactive', description: 'Runs the tool in non-interactive mode (no user input needed).' },
      { flag: '--secure', label: 'Secure Requests', description: 'Uses secure protocols for making requests (e.g., HTTPS).' },
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
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [results, setResults] = useState<{ [key: string]: { raw?: string; report?: string; error?: string } }>({});
  const [showModal, setShowModal] = useState(false);

  const handleToolChange = (toolKey: string) => {
    setSelectedTools((prev) => ({ ...prev, [toolKey]: !prev[toolKey] }));
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
    setLoading(true);
    setResults({});
    const selected = Object.keys(selectedTools).filter((key) => selectedTools[key]);
    const flagsForSelected = selected.reduce((acc: Record<string, string[]>, key) => {
      acc[key] = selectedFlags[key] || [];
      return acc;
    }, {});

    try {
      const res = await axios.post('http://localhost:3000/scan', {
        domain,
        tools: selected,
        flags: flagsForSelected,
      });
      setResults(res.data);
      setShowModal(true);
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Scan failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const handleDownload = (text: string, tool: string, type: string) => {
    const blob = new Blob([text], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${tool}_${type}.txt`;
    a.click();
    window.URL.revokeObjectURL(url);
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

      {showModal && (
        <div className="modal-backdrop" onClick={() => setShowModal(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>Scan Results</h3>
            {Object.entries(results).map(([tool, result]) => (
              <div key={tool} className="result-block">
                <h4>{tool.toUpperCase()}</h4>
                {result.error ? (
                  <p className="error-msg">{result.error}</p>


                ) : (
                  <>
                    {
                      ['raw', 'report'].map((type) => {
                        const safeType = type as 'raw' | 'report';
                      
                        return (
                          <div key={type} className="result-section">
                            <h5>{type.toUpperCase()}</h5>
                            <button onClick={() => handleCopy(result[safeType] || '')}>Copy</button>
                            <button onClick={() => handleDownload(result[safeType] || '', tool, type)}>Download</button>
                            <pre className="log-output">
  {typeof result[safeType] === 'string'
    ? result[safeType]
    : JSON.stringify(result[safeType], null, 2)}
</pre>
                          </div>
                        );
                      })
                    }
                  </>
                )}
              </div>
            ))}
            <button className="close-modal" onClick={() => setShowModal(false)}>Close</button>
          </div>
        </div>
      )}
    </div>
  );
};

export default ToolPage;