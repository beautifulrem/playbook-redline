#!/usr/bin/env bash
# Evidence / verify pages must be fully self-contained (offline-verifiable moat) and never
# render secret MATERIAL. Hardened per cross-model review (Codex): fails (not OK) when
# nothing is checked; bans ALL http(s) and protocol-relative external refs.
# Usage: check-frontend-zero-secret.sh <file.html | dir>   (console pages are NOT checked here)
set -euo pipefail

TARGET="${1:?usage: check-frontend-zero-secret.sh <html|dir>}"

fail=0
checked=0

check_file() {
  f="$1"
  if [ ! -f "$f" ]; then echo "ZERO-SECRET FAIL: not a regular file: $f" >&2; fail=1; return; fi
  checked=$((checked + 1))

  # A) a self-contained page must contain ZERO http(s) URLs (covers script/link/url()/@import/any quote)
  if grep -nEi 'https?://' "$f" >/dev/null 2>&1; then
    echo "ZERO-SECRET FAIL ($f): contains http(s):// URL (page must be self-contained)" >&2
    grep -nEi 'https?://' "$f" | head -5 >&2 || true
    fail=1
  fi

  # B) no protocol-relative external refs in src / href / url() / @import
  if grep -nEi '(src|srcset|href|poster)[[:space:]]*=[[:space:]]*["'"'"']?//|url\([[:space:]]*["'"'"']?//|@import[[:space:]]*["'"'"']?//|//[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}([^a-zA-Z0-9.-]|$)' "$f" >/dev/null 2>&1; then
    echo "ZERO-SECRET FAIL ($f): protocol-relative external reference" >&2
    fail=1
  fi

  # C) no secret MATERIAL rendered (private keys / key blocks / demo cred VALUES / embedded token value).
  #    NB: deliberately does NOT ban the innocent words token/secret/key — those appear in the
  #    legitimate COMMAND BLOCK and UI labels; we detect actual secret material instead.
  if grep -nE -- 'bg_[0-9a-fA-F]{32}' "$f" >/dev/null 2>&1; then
    echo "ZERO-SECRET FAIL ($f): looks like a raw Bitget access key value (bg_<32hex>)" >&2
    fail=1
  fi
  if grep -nEi -- '-----BEGIN[[:space:]A-Z]*PRIVATE|ed25519-private|REDLINE_BITGET_DEMO_(ACCESS_KEY|SECRET_KEY|PASSPHRASE)["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9_./+=-]{6,}|X-Redline-Token["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9_.-]{12,}' "$f" >/dev/null 2>&1; then
    echo "ZERO-SECRET FAIL ($f): secret-like material rendered" >&2
    fail=1
  fi
}

if [ -d "$TARGET" ]; then
  while IFS= read -r f; do check_file "$f"; done < <(find "$TARGET" -type f -name '*.html')
elif [ -e "$TARGET" ]; then
  check_file "$TARGET"
fi

if [ "$checked" -eq 0 ]; then
  echo "ZERO-SECRET FAIL: no html file checked for target: $TARGET (refusing to pass on nothing)" >&2
  exit 2
fi

if [ "$fail" -eq 0 ]; then echo "zero-secret OK ($checked file(s)): $TARGET"; exit 0; fi
exit 1
