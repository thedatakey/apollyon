#!/usr/bin/env node
'use strict';
const {spawnSync} = require('node:child_process');
const platform = `${process.platform}-${process.arch}`;
if (!['linux-x64', 'darwin-arm64', 'darwin-x64', 'win32-x64'].includes(platform)) {
  console.error(`Apollyon has no prebuilt npm binary for ${platform}. Install with Cargo.`);
  process.exit(2);
}
let binary;
try {
  binary = require.resolve(`apollyon-${platform}/bin/apollyon${process.platform === 'win32' ? '.exe' : ''}`);
} catch {
  console.error(`Missing native package for ${platform}. Reinstall with optional dependencies enabled.`);
  process.exit(2);
}
const result = spawnSync(binary, process.argv.slice(2), {stdio: 'inherit', shell: false});
if (result.error) {console.error(result.error.message); process.exit(2);}
if (result.signal) {process.kill(process.pid, result.signal);} else {process.exit(result.status ?? 2);}
