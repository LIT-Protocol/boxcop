// Run only with the signed Cursor executable in the synthetic macOS VM:
// ELECTRON_RUN_AS_NODE=1 Cursor credential_exception_probe.cjs NEW_RESULT_DIRECTORY
// While it runs, use BoxCop's "Allow for 5 minutes" on this process's block.
// The result contains booleans/timing only, never file contents.
const fs = require('fs'), path = require('path'), cp = require('child_process');
if (!cp.execFileSync('/usr/sbin/sysctl', ['-n', 'hw.model'], {encoding:'utf8'}).startsWith('VirtualMac')) throw Error('VM required');
if (!cp.execFileSync('/usr/bin/csrutil', ['status'], {encoding:'utf8'}).includes('enabled')) throw Error('SIP required');
const directory = process.argv[2];
fs.mkdirSync(directory, {mode:0o700});
const cache = path.join(process.env.HOME, '.aws/sso/cache');
fs.mkdirSync(cache, {recursive:true});
const id = require('crypto').randomUUID();
const target = path.join(cache, `boxcop-exception-${id}.json`);
const other = path.join(cache, `boxcop-other-${id}.json`);
for (const file of [target,other]) fs.writeFileSync(file, 'SYNTHETIC BOXCop fixture\n', {flag:'wx',mode:0o600});
const start = process.hrtime.bigint();
let firstAllowed = null, deniedBefore = false, expired = false, childDenied = null, otherDenied = null;
function reads(file) {try { fs.readFileSync(file); return true; } catch(e) { if(['EACCES','EPERM'].includes(e.code)) return false; throw e; }}
function finish() {
 clearInterval(timer);
 const result = {deniedBefore, firstAllowedSeconds:firstAllowed, expired, childDenied, otherDenied,
   passed:deniedBefore && firstAllowed !== null && expired && childDenied === true && otherDenied === true};
 fs.writeFileSync(path.join(directory,'result.json'), JSON.stringify(result,null,2));
 for(const file of [target,other]) fs.unlinkSync(file);
}
const timer = setInterval(() => {
 const elapsed = Number(process.hrtime.bigint()-start)/1e9;
 const allowed = reads(target);
 if(firstAllowed === null && !allowed) deniedBefore = true;
 if(allowed && firstAllowed === null) {
  firstAllowed = elapsed;
  const child = cp.spawnSync('/bin/cat',[target],{encoding:'utf8'});
  childDenied = child.status !== 0 && /Operation not permitted|Permission denied/.test(child.stderr);
  otherDenied = !reads(other);
 }
 if(firstAllowed !== null && !allowed && elapsed-firstAllowed >= 298) expired = true;
 fs.appendFileSync(path.join(directory,'samples.jsonl'),JSON.stringify({elapsed,allowed})+'\n');
 if(expired || elapsed > 600) finish();
},1000);
process.on('SIGTERM', () => {finish();process.exit(0);});
