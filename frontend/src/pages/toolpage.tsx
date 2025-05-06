import { useState } from 'react';
import axios from 'axios';
import './toolpage.css';

const ToolPage = () => {
  const [domain, setDomain] = useState('');
  const [status, setStatus] = useState('');
  const [ports, setPorts] = useState<{ port: string; service: string }[]>([]);
  const [vulns, setVulns] = useState<string[]>([]);
  const [rawOutput, setRawOutput] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [showRaw, setShowRaw] = useState(false);
  const [showVulns, setShowVulns] = useState(true);

  const sanitizeDomain = (input: string) => {
    try {
      const url = new URL(input.includes('http') ? input : `http://${input}`);
      return url.hostname;
    } catch {
      return input;
    }
  };

  const handleScan = async () => {
    setError('');
    setStatus('');
    setPorts([]);
    setVulns([]);
    setRawOutput('');
    setLoading(true);
    setShowModal(false);
    setShowRaw(false);
    setShowVulns(true);

    const sanitized = sanitizeDomain(domain);
    setStatus(`Starting scan for ${sanitized}...`);

    try {
      const res = await axios.get('http://localhost:5000/scan', {
        params: { domain: sanitized },
      });

      setPorts(res.data.analysis.openPorts || []);
      setVulns(res.data.analysis.vulnerabilities || []);
      setRawOutput(res.data.rawOutput || '');
      setStatus('Scan complete.');
      setShowModal(true);
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Scan failed.');
      setStatus('');
    } finally {
      setLoading(false);
    }
  };

  const copyRawOutput = () => {
    navigator.clipboard.writeText(rawOutput);
    alert('Copied to clipboard!');
  };

  const downloadRawOutput = () => {
    const blob = new Blob([rawOutput], { type: 'text/plain' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'nmap_output.txt';
    link.click();
  };

  return (
    <div className="tool-container">
      <h2>SCAN</h2>

      <input
        type="text"
        value={domain}
        onChange={(e) => setDomain(e.target.value)}
        placeholder="Enter domain or URL"
      />

      <button onClick={handleScan} disabled={loading || !domain}>
        {loading ? (
          <>
            Scanning...
            <span className="spinner" />
          </>
        ) : (
          'Start Scan'
        )}
      </button>

      {status && <p className="status">{status}</p>}
      {error && <p className="status error">{error}</p>}

      {showModal && (
        <div className="modal-overlay fade-in">
          <div className="modal slide-up">
            <h3>Scan Results</h3>

            {ports.length > 0 ? (
              <>
                <h4>Open Ports</h4>
                <ul>
                  {ports.map((portObj, idx) => (
                    <li key={idx}>
                      Port: {portObj.port} — Service: {portObj.service}
                    </li>
                  ))}
                </ul>
              </>
            ) : (
              <p>No open ports found.</p>
            )}

            {vulns.length > 0 && (
              <>
                <button className="toggle-btn" onClick={() => setShowVulns(!showVulns)}>
                  {showVulns ? 'Hide Vulnerabilities' : 'Show Vulnerabilities'}
                </button>
                {showVulns && (
                  <>
                    <h4>Vulnerability Analysis</h4>
                    <ul className="fade-in">
                      {vulns.map((v, i) => (
                        <li key={i}>{v}</li>
                      ))}
                    </ul>
                  </>
                )}
              </>
            )}
            {rawOutput && (
              <>
                <button className="toggle-btn" onClick={() => setShowRaw(!showRaw)}>
                  {showRaw ? 'Hide Raw Output' : 'Show Raw Output'}
                </button>
                {showRaw && (
                  <div className="raw-container fade-in">
                    <div className="raw-actions">
                      <button onClick={copyRawOutput}>Copy</button>
                      <button onClick={downloadRawOutput}>Download</button>
                    </div>
                    <pre className="raw-output">{rawOutput}</pre>
                  </div>
                )}
              </>
            )}

            <button className="close-btn" onClick={() => setShowModal(false)}>Close</button>
          </div>
        </div>
      )}
    </div>
  );
};

export default ToolPage;