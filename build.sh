#!/bin/bash
# Signed, notarized distribution build; never falls back to ad-hoc signing.
set -euo pipefail

usage() {
  cat <<'HELP'
Usage: ./build.sh [OUTPUT_DIRECTORY]

Build the current working tree as a Developer ID signed, notarized BoxCop build (beta channel by default; all shipping protections included).
Defaults to a new BoxCop-beta-TIMESTAMP directory in ~/Downloads.
Share BoxCop.dmg from that directory after a successful build.

Requires macOS 14+, Xcode/Command Line Tools, CMake, Python 3.12, a Developer ID
Application certificate with its private key, app and network Developer ID
provisioning profiles, and saved notarytool credentials.

Optional environment variables:
  BOXCOP_SIGNING_IDENTITY  Certificate SHA-1 (required if multiple identities exist)
  BOXCOP_NOTARY_PROFILE    Saved Keychain profile (default: sentinel-beta)
  BOXCOP_KEYCHAIN_PATH     Optional temporary CI keychain for notarization
  BOXCOP_PYTHON            Python 3.12 executable (default: python3.12)
  BOXCOP_VERSION           Optional display version (major.minor.patch; required by release CI)
  BOXCOP_CHANNEL           beta (default) or stable; both include outgoing protection
  BOXCOP_APP_PROFILE       App profile (default: ~/.sentinel-lab/profiles/Allay_Developer_ID.provisionprofile)
  BOXCOP_NETWORK_PROFILE   Network profile (default: ~/.sentinel-lab/profiles/Allay_Network_Developer_ID.provisionprofile)
  BOXCOP_EXTENSION_VERSION Override extension build number (default: current Unix timestamp)

The script tests, builds, signs, notarizes, staples, and checks Gatekeeper.
It does not publish, install, or launch the app. Existing builds are not overwritten.
HELP
}

if [[ "${1:-}" == '--help' || "${1:-}" == '-h' ]]; then
  usage
  exit 0
fi
if [[ $# -gt 1 || "${1:-}" == -* ]]; then
  usage >&2
  exit 2
fi
fail() { printf 'Build stopped: %s\n' "$*" >&2; exit 1; }
[[ "$(uname -s)" == Darwin ]] || fail 'Run this on a Mac.'
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
python="${BOXCOP_PYTHON:-python3.12}"
command -v "$python" >/dev/null || fail 'Install Python 3.12 or set BOXCOP_PYTHON to its executable.'
"$python" -c 'import sys; sys.exit(0 if sys.version_info[:2] == (3, 12) else "Python 3.12 is required")'
command -v cmake >/dev/null || fail 'Install CMake to build the bundled inference engine.'
command -v security >/dev/null || fail 'macOS security tool is unavailable.'
command -v xcrun >/dev/null || fail 'Install Xcode Command Line Tools.'

# Public certificate fingerprints only; never read or export private keys/passwords.
identities="$(security find-identity -v -p codesigning)"
fingerprints="$(printf '%s\n' "$identities" | awk '/"Developer ID Application:/ {print $2}')"
identity="${BOXCOP_SIGNING_IDENTITY:-}"
if [[ -z "$identity" ]]; then
  count="$(printf '%s\n' "$fingerprints" | awk 'NF {n++} END {print n+0}')"
  [[ "$count" != 0 ]] || fail 'No valid Developer ID Application identity. Install its certificate and private key in Keychain.'
  [[ "$count" == 1 ]] || fail 'Multiple Developer ID Application identities. Set BOXCOP_SIGNING_IDENTITY to the intended certificate SHA-1.'
  identity="$fingerprints"
else
  [[ "$identity" =~ ^[[:xdigit:]]{40}$ ]] || fail 'BOXCOP_SIGNING_IDENTITY must be a Developer ID certificate SHA-1, not an ad-hoc identity.'
  identity="$(printf '%s' "$identity" | tr '[:lower:]' '[:upper:]')"
  printf '%s\n' "$fingerprints" | awk -v wanted="$identity" '$0 == wanted {found=1} END {exit !found}' || fail 'Selected Developer ID identity is not available in Keychain.'
fi
[[ -z "${BOXCOP_PROFILE+x}" ]] || fail 'BOXCOP_PROFILE has been retired. Use BOXCOP_CHANNEL=beta or stable; both build the full distribution. For limited development builds use build_app.py --profile limited-development.'
channel="${BOXCOP_CHANNEL:-beta}"
[[ "$channel" == beta || "$channel" == stable ]] || fail 'BOXCOP_CHANNEL must be beta or stable.'
app_profile="${BOXCOP_APP_PROFILE:-$HOME/.sentinel-lab/profiles/Allay_Developer_ID.provisionprofile}"
network_profile="${BOXCOP_NETWORK_PROFILE:-$HOME/.sentinel-lab/profiles/Allay_Network_Developer_ID.provisionprofile}"
[[ -f "$app_profile" && -f "$network_profile" ]] || fail 'Distribution profiles missing from ~/.sentinel-lab/profiles. Set BOXCOP_APP_PROFILE and BOXCOP_NETWORK_PROFILE to override. Endpoint Security approval is not required.'
# Share one version scheme with CI so switching build sources preserves ordering.
extension_version="${BOXCOP_EXTENSION_VERSION-$(date +%s)}"
[[ "$extension_version" =~ ^[1-9][0-9]*$ ]] || fail 'BOXCOP_EXTENSION_VERSION must be an increasing positive integer.'
protection_args=(--app-profile "$app_profile" --network-profile "$network_profile" --extension-version "$extension_version")
profile="${BOXCOP_NOTARY_PROFILE:-sentinel-beta}"
printf 'Checking notarization credentials for Keychain profile: %s\n' "$profile"
notary_args=(history --keychain-profile "$profile" --output-format json)
if [[ -n "${BOXCOP_KEYCHAIN_PATH:-}" ]]; then notary_args+=(--keychain "$BOXCOP_KEYCHAIN_PATH"); fi
xcrun notarytool "${notary_args[@]}" >/dev/null || fail 'Notarization credentials unavailable. Configure the Keychain profile with xcrun notarytool store-credentials, then retry.'

output="${1:-$HOME/Downloads/BoxCop-${channel}-$(date +%Y%m%d-%H%M%S)}"
printf 'Building current source: %s\nDistribution output: %s\n' "$repo_root" "$output"
build_args=(--profile distribution --channel "$channel" --output "$output" --signing-identity "$identity" --notary-profile "$profile")
build_args+=("${protection_args[@]}")
exec "$python" "$repo_root/desktop/macos/scripts/build_app.py" "${build_args[@]}"
