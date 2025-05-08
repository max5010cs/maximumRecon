// /routes/scanRouter.js
const express = require('express');
const router = express.Router();

// Import executors and analyzers
const runNmapScan = require('./executors/nmapExecutor');
const analyzeNmapOutput = require('./analyzers/nmapAnalyzer');
const runHttpxScan = require('./executors/httpxExecutor');
const analyzeHttpxOutput = require('./analyzers/httpxAnalyzer');


// Later: import other tools like httpx, whatweb, etc.

router.post('/', async (req, res) => {
  const { tools, domain, flags } = req.body;

  if (!tools || !domain) {
    return res.status(400).json({ error: 'Tools and domain are required.' });
  }

  const results = {};

  for (const tool of tools) {
    try {
      const toolFlags = flags[tool] || [];

      switch (tool) {
        case 'nmap': {
          const rawOutput = await runNmapScan(domain, toolFlags);
          const analyzed = analyzeNmapOutput(rawOutput);
          results[tool] = {
            raw: rawOutput,
            report: analyzed,
          };
          break;
        };

        case 'httpx': {
          const rawOutput = await runHttpxScan(domain, toolFlags);
          const analyzed = analyzeHttpxOutput(rawOutput);
          results[tool] = {
            raw: rawOutput,
            report: analyzed,
          };
          break;
        }

        // Future tools go here...
        // case 'httpx': ...
        // case 'whatweb': ...

        default:
          results[tool] = { error: `Tool '${tool}' is not supported.` };
      }
    } catch (err) {
      console.error(`Error running ${tool}:`, err);
      results[tool] = { error: `Failed to run ${tool}.` };
    }
  }

  res.json(results);
});

module.exports = router;