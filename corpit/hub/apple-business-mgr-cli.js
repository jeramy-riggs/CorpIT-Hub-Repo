// CLI runner for apple-business-mgr.js. Run: node apple-business-mgr-cli.js
require('dotenv').config({ path: '/var/www/corpit-hub-api/.env', quiet: true });

const required = ['ABM_CLIENT_ID', 'ABM_KEY_ID', 'ABM_PRIVATE_KEY_PATH', 'DB_USER'];
const missing = required.filter(k => !process.env[k]);
if (missing.length) {
  console.error('FAIL: missing env vars:', missing.join(', '));
  process.exit(1);
}

const { fullSync } = require('./apple-business-mgr');

(async () => {
  console.log('=== ABM full sync (CLI mode) ===');
  const t0 = Date.now();
  try {
    const result = await fullSync({ verbose: true });
    console.log('Result:', JSON.stringify(result, null, 2));
    console.log(`Elapsed: ${((Date.now() - t0) / 1000).toFixed(1)}s`);
    process.exit(0);
  } catch (err) {
    console.error('FAIL:', err.message);
    process.exit(2);
  }
})();
