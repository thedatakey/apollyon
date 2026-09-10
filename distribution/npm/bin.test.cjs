'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const wrapper = path.join(__dirname, 'bin.cjs');
test('missing native package gives actionable exit 2', () => {
  const r=spawnSync(process.execPath,[wrapper,'--version'],{encoding:'utf8'});
  assert.equal(r.status,2); assert.match(r.stderr,/Missing native package|no prebuilt/);
});
test('wrapper forwards literal arguments and native exit status', {skip:process.platform==='win32'}, () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'apollyon-npm-'));
  try {
    fs.copyFileSync(wrapper,path.join(root,'bin.cjs'));
    fs.writeFileSync(path.join(root,'launch.cjs'),"Object.defineProperty(process, 'arch', {value: 'x64'}); require('./bin.cjs');\n");
    const bin=path.join(root,'node_modules',`apollyon-${process.platform}-x64`,'bin');
    fs.mkdirSync(bin,{recursive:true});
    const native=path.join(bin,'apollyon');
    fs.writeFileSync(native,'#!/bin/sh\nprintf "%s\\n" "$@"\nexit 7\n',{mode:0o755});
    const args=['scan','space and ; literal','$(false)','--json'];
    const r=spawnSync(process.execPath,[path.join(root,'launch.cjs'),...args],{encoding:'utf8'});
    assert.equal(r.status,7);assert.equal(r.stdout,args.join('\n')+'\n');
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});
