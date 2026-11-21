#!/bin/bash
# Signed, notarized distribution build; never falls back to ad-hoc signing.
set -euo pipefail

usage() {
  cat <<'HELP'
Usage: ./build.sh [OUTPUT_DIRECTORY]

Build the current working tree as a Developer ID signed, notarized BoxCop.app with
the network extension embedded. Defaults to a new BoxCop-CHANNEL-TIMESTAMP directory
in ~/Downloads. Share BoxCop.dmg from that directory after a successful build.

Requires macOS 14+, Xcode/Command Line Tools, CMake, Python 3.12, a Developer ID
Application certificate with its private key, app and network Developer ID
provisioning profiles, and saved notarytool credentials.

Optional environment variables:
  BOXCOP_SIGNING_IDENTITY  Certificate SHA-1 (required if multiple identities exist)
  BOXCOP_NOTARY_PROFILE    Saved Keychain profile (default: sentinel-beta)
  BOXCOP_KEYCHAIN_PATH     Optional temporary CI keychain for notarization
  BOXCOP_PYTHON            Python 3.12 executable (default: python3.12)
  BOXCOP_VERSION           Optional display version (major.minor.patch; set by release CI)
  BOXCOP_CHANNEL           beta (default) or stable; both include every protection
  BOXCOP_APP_PROFILE       App profile (default: ~/.sentinel-lab/profiles/BoxCop_Developer_ID.provisionprofile)
  BOXCOP_NETWORK_PROFILE   Network profile (default: ~/.sentinel-lab/profiles/BoxCop_Network_Developer_ID.provisionprofile)
  BOXCOP_EXTENSION_VERSION Override extension build number (default: current Unix timestamp)
  BOXCOP_PACKAGE_FEED_URL                 Override the official signed package malware feed
  BOXCOP_PACKAGE_FEED_PUBLIC_KEY_BASE64   Ed25519 key that feed is verified with
  BOXCOP_PACKAGE_FEED_MINIMUM_SEQUENCE    Lowest feed sequence this build accepts (default: 1)
  BOXCOP_UPDATE_FEED_URL   Sparkle appcast URL. Unset (default): the build has no in-app updates
  BOXCOP_UPDATE_PUBLIC_KEY Ed25519 public key for that appcast; required with the URL

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
app_profile="${BOXCOP_APP_PROFILE:-$HOME/.sentinel-lab/profiles/BoxCop_Developer_ID.provisionprofile}"
network_profile="${BOXCOP_NETWORK_PROFILE:-$HOME/.sentinel-lab/profiles/BoxCop_Network_Developer_ID.provisionprofile}"
[[ -f "$app_profile" && -f "$network_profile" ]] || fail 'Distribution profiles missing from ~/.sentinel-lab/profiles. Set BOXCOP_APP_PROFILE and BOXCOP_NETWORK_PROFILE to override.'
# The provisioning profiles are bound to the original bundle identifiers and still
# carry their original file names. BoxCop keeps both until it has profiles of its own.
# Share one version scheme with CI so switching build sources preserves ordering.
extension_version="${BOXCOP_EXTENSION_VERSION-$(date +%s)}"
[[ "$extension_version" =~ ^[1-9][0-9]*$ ]] || fail 'BOXCOP_EXTENSION_VERSION must be an increasing positive integer.'
protection_args=(--app-profile "$app_profile" --network-profile "$network_profile" --extension-version "$extension_version")
# The lab Mac has had its notary credentials saved under either of these names.
notary_ok() {
  local args=(history --keychain-profile "$1" --output-format json)
  if [[ -n "${BOXCOP_KEYCHAIN_PATH:-}" ]]; then args+=(--keychain "$BOXCOP_KEYCHAIN_PATH"); fi
  xcrun notarytool "${args[@]}" >/dev/null 2>&1
}
profile=''
for candidate in ${BOXCOP_NOTARY_PROFILE:-sentinel-beta}; do
  printf 'Checking notarization credentials for Keychain profile: %s\n' "$candidate"
  if notary_ok "$candidate"; then profile="$candidate"; break; fi
done
[[ -n "$profile" ]] || fail 'Notarization credentials unavailable. Save a Keychain profile with xcrun notarytool store-credentials and set BOXCOP_NOTARY_PROFILE to its name, then retry.'

# Feed trust must be configured by the builder; no publisher is trusted by default.
export BOXCOP_PACKAGE_FEED_URL="${BOXCOP_PACKAGE_FEED_URL:-}"
export BOXCOP_PACKAGE_FEED_PUBLIC_KEY_BASE64="${BOXCOP_PACKAGE_FEED_PUBLIC_KEY_BASE64:-}"
export BOXCOP_PACKAGE_FEED_MINIMUM_SEQUENCE="${BOXCOP_PACKAGE_FEED_MINIMUM_SEQUENCE:-1}"

output="${1:-$HOME/Downloads/BoxCop-${channel}-$(date +%Y%m%d-%H%M%S)}"
printf 'Building current source: %s\nDistribution output: %s\n' "$repo_root" "$output"
build_args=(--profile distribution --channel "$channel" --output "$output" --signing-identity "$identity" --notary-profile "$profile")
build_args+=("${protection_args[@]}")
exec "$python" "$repo_root/desktop/macos/scripts/build_app.py" "${build_args[@]}"
