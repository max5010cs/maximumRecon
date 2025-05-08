// /executors/httpxExecutor.js
const { exec } = require('child_process');

/**
 * Executes the httpx command with selected flags.
 * @param {string} domain - The domain to scan.
 * @param {string[]} flags - Array of flags for httpx.
 * @returns {Promise<string>} - Raw httpx output.
 */
function runHttpx(domain, flags = []) {
  return new Promise((resolve, reject) => {
    const flagString = flags.join(' ');
    const command = `echo ${domain} | httpx ${flagString}`;

    exec(command, (error, stdout, stderr) => {
      if (error) {
        console.error(`httpx error: ${stderr}`);
        return reject(`Error running httpx: ${stderr}`);
      }
      resolve(stdout);
    });
  });
}

module.exports = runHttpx;