# Install script protection

Packages can run their own scripts while npm installs them. Those scripts start
as ordinary processes with the developer's full network access. Install script
protection contains them: **a dependency's install script, and everything it
starts, can only connect to approved destinations.** The decision is made before
any connection to the destination is opened.

This is **opt-in** and independent of the [package registry firewall](package-registry-firewall.md).
It needs no Endpoint Security entitlement, Network Extension change, private API
or TLS interception. It works locally without an account.

## How it works

1. **Routing.** Enabling adds one marked, reversible line to the user `~/.npmrc`:
   `script-shell=<BoxCop data folder>/script-protection/boxcop-script-shell`. npm
   then runs every lifecycle script through that wrapper, however npm was
   launched (any Node version, absolute path, `npx`, an agent or an IDE). No PATH
   shim or symlink over `npm` is involved.
2. **Selection.** The wrapper contains a script only when npm reports an
   install-family event (`preinstall`, `install`, `postinstall`, `prepare` and
   the pack events used for git dependencies) *and* the script runs inside
   `node_modules` or npm's cache. Everything else (`npm run`, `npm test`, `npx`,
   the project's own scripts) is passed straight to `/bin/sh`.
3. **Containment.** A contained script is re-executed under `sandbox-exec` with
   a profile that denies all network access except BoxCop's two loopback
   listeners. The kernel applies the profile to every descendant, including
   detached processes that outlive npm, and a process cannot remove it.
4. **Approved destinations.** The wrapper sets the standard proxy variables to
   BoxCop's loopback proxy (`127.0.0.1:8795`). The proxy allows a destination
   only if it is on the built-in list for all packages (`registry.npmjs.org`,
   `nodejs.org`), on the built-in list for that package, or approved by the user
   for that package. Otherwise it refuses and records the attempt. It never
   connects to loopback, private or link-local addresses.
5. **Verified context.** Before sandboxing, the wrapper registers the run with
   the engine over a Unix socket that the sandbox cannot reach, and receives a
   random token that it places in the proxy URL. The package name, version and
   event come from npm before the script has run, so a script cannot claim
   another package's approvals. The coding agent label (Claude Code, Codex,
   Cursor) is read from the live process ancestry at that moment and is used for
   display only.

The profile also denies writes to `~/.npmrc`, shell startup files,
`~/Library/LaunchAgents` and BoxCop's own script-protection folder, so a
contained script cannot turn the protection off or schedule itself to run later
through those paths.

## What the developer sees

When a destination is refused, BoxCop shows a panel and lists the attempt under
**Install script protection**:

> Claude Code started an install of some-package@1.0.0, whose postinstall script
> tried to connect to unknown-domain.example. BoxCop blocked the connection
> because package install scripts can only reach approved destinations.

**Allow for this package** approves that one hostname for that one package name.
Run the install again afterwards. Approvals are listed and removable, and are
stored in `exceptions.json` in the script-protection folder.

## When BoxCop is not running

Routing stays in place. Contained scripts still run, sandboxed, but the proxy is
gone, so they have **no network access at all** until BoxCop protection starts
again or the feature is disabled. Installs that need no downloads are unaffected.
Uninstalling BoxCop without disabling the feature leaves the wrapper in the data
folder; remove the marked block from `~/.npmrc` to stop using it.

## Limits

- **Outbound connections only.** A contained script can still read files, change
  the project, and use any approved destination, including to upload data. Hosts
  that accept uploads from anyone, such as GitHub, are approved only for named
  packages for that reason.
- **Install time only.** Code that a package leaves behind runs with normal
  access when the project later imports or executes it.
- **Declared identity.** The package name is the one in the installed manifest.
  Registry packages are bound to their name by the registry; a tarball or git
  dependency can declare any name and would receive that name's approvals.
- **Unreported blocks.** Connections that ignore the proxy variables (raw
  sockets, DNS lookups, clients without proxy support) are denied by the sandbox
  but are not listed, because only the proxy sees a destination. Node 24 and
  later honor the variables through `NODE_USE_ENV_PROXY`.
- **Existing sandboxes.** macOS does not allow nested sandboxes. Inside an
  agent's own sandbox (Codex, or Claude Code with sandboxing on) the wrapper
  passes the script through and that outer sandbox's rules apply instead.
- **Overrides.** A project `.npmrc`, an `npm_config_script_shell` environment
  variable or `--script-shell` replaces the user setting. A dependency cannot do
  this; a repository or the person running npm can. An existing user
  `script-shell` setting is preserved and prevents enabling.
- **Other escapes.** A contained script may be able to ask a process outside the
  sandbox to act for it (for example through Apple Events or a writable file
  that something else later executes). Only the paths listed above are denied.
- **Coverage.** Tested with npm 11. pnpm documents the same setting but is not
  yet tested. Yarn, Bun and Python installers are not covered.
- **Built-in package list.** `PACKAGE_HOSTS` in `server/package_scripts.py` is a
  short starting list. Packages that download binaries and are not on it will be
  blocked until approved.
- `sandbox-exec` is marked deprecated by Apple. It is present and working on
  macOS 27; enabling fails with an explanation if it is unavailable.

## Validation

```sh
python -m pytest -q tests/test_package_scripts.py tests/test_desktop.py -k "script"
```

On macOS with npm installed, `test_real_npm_install_script_is_contained_including_subprocesses`
installs a harmless local package whose `postinstall` tries a direct `fetch`, a
child `curl` with and without the proxy, a detached orphan process, the control
socket, and writes to `~/.npmrc` and `~/.zshenv`. Without protection all of it
succeeds. With protection the install still completes and the script runs, but
no request reaches the unapproved receiver, the approved receiver gets exactly
one request, both writes fail, the attempt is reported with the package name,
and the project's own `npm run` script is unaffected. Elsewhere the sandbox
tests are skipped; the routing, policy and proxy tests run on any platform.

Not yet established: behavior in a signed, installed build; popular packages
with native builds or binary downloads at scale; pnpm; and performance
on installs with many scripts (each contained script adds two short process
launches and one local request).
