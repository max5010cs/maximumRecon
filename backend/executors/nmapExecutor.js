// /executors/nmapExecutor.js
const { exec } = require('child_process');

/**
 * Executes the Nmap command with selected flags.
 * @param {string} domain - The domain or IP to scan.
 * @param {string[]} flags - Array of flags selected by the user.
 * @returns {Promise<string>} - Raw Nmap output as a string.
 */
function runNmap(domain, flags = []) {
  return new Promise((resolve, reject) => {
    const flagString = flags.join(' ');
    const command = `nmap ${flagString} ${domain}`;

    exec(command, (error, stdout, stderr) => {
      if (error) {
        console.error(`Nmap error: ${stderr}`);
        return reject(`Error running Nmap: ${stderr}`);
      }
      resolve(stdout);
    });
  });
}

module.exports = runNmap;