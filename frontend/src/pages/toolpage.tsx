import { useState } from 'react';
import axios from 'axios';
import './toolpage.css';

const ToolPage = () => {
  const [domain, setDomain] = useState('');
  const [status, setStatus] = useState('');
  const [ports, setPorts] = useState<{ port: string; service: string }[]>([]);  
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showModal, setShowModal] = useState(false);

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
    setLoading(true);
    setShowModal(false);

    const sanitized = sanitizeDomain(domain);
    setStatus(`Starting scan for ${sanitized}...`);

    try {
      const res = await axios.get('http://localhost:5000/scan', {
        params: { domain: sanitized },
      });
      setPorts(res.data.openPorts);  
      setStatus('Scan complete.');
      setShowModal(true);
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Scan failed.');
      setStatus('');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="tool-container">
      <h2>Port Scanner with Nmap</h2>

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
        <div className="modal-overlay">
          <div className="modal">
            <h3>Scan Results</h3>
            {ports.length > 0 ? (
              <ul>
                {ports.map((portObj, idx) => (
                  <li key={idx}>
                    Port: {portObj.port} — Service: {portObj.service}
                  </li>
                ))}
              </ul>
            ) : (
              <p>No open ports found.</p>
            )}
            <button onClick={() => setShowModal(false)}>Close</button>
          </div>
        </div>
      )}
    </div>
  );
};

export default ToolPage;