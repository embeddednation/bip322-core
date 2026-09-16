#!/usr/bin/env bash
# One-shot setup from a fresh clone: virtualenv, hash-pinned dependencies,
# editable install of the bip322 / bip322-dev / bip322-refcheck commands, tests.
#
#   ./setup.sh                 # venv + deps + install + tests
#   ./setup.sh --with-refcheck # also download Core/Knots/Go and build the btcd wrapper (~200 MB)
#   ./setup.sh --no-tests
#
# Needs Python >= 3.10 and curl (only when python3 has no ensurepip).
set -euo pipefail
cd "$(dirname "$0")"
PY=${PYTHON:-python3}
WITH_REFCHECK=0
RUN_TESTS=1
for arg in "$@"; do
  case $arg in
    --with-refcheck) WITH_REFCHECK=1 ;;
    --no-tests) RUN_TESTS=0 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || { echo "error: Python >= 3.10 required (found $("$PY" --version))" >&2; exit 1; }

# --- virtualenv (Debian/Ubuntu often ship python3 without ensurepip) ---------
if [ ! -x .venv/bin/python ]; then
  if "$PY" -c 'import ensurepip' 2>/dev/null; then
    "$PY" -m venv .venv
  else
    echo "python3 has no ensurepip; bootstrapping pip from bootstrap.pypa.io"
    "$PY" -m venv --without-pip .venv
    curl -sSfL https://bootstrap.pypa.io/get-pip.py | .venv/bin/python - -q
  fi
fi
PIP=.venv/bin/pip

# --- dependencies, exact versions with sha256 hashes -------------------------
if .venv/bin/python -c 'import platform, sys; sys.exit(0 if sys.version_info[:2] == (3, 12) and platform.system() == "Linux" and platform.machine() == "x86_64" else 1)'; then
  "$PIP" install -q --require-hashes -r requirements.lock
else
  echo "note: the py-bitcoinkernel wheel in requirements.lock is for CPython 3.12 / Linux x86_64;"
  echo "      installing without the kernel engine (btclib remains; see 'bip322 engines')"
  awk '/^py-bitcoinkernel/ {skip = 2} skip > 0 {skip--; next} {print}' requirements.lock > .venv/requirements.nokernel.lock
  "$PIP" install -q --require-hashes -r .venv/requirements.nokernel.lock
fi
"$PIP" install -q --no-deps -e .
"$PIP" install -q "pytest==9.1.1" "ruff==0.16.7"   # pinned: CI and local lint must agree

# --- optional: reference implementations for bip322-refcheck ----------------
if [ "$WITH_REFCHECK" = 1 ]; then
  refcheck/fetch.sh
  refcheck/btcd/build.sh
fi

# --- tests -------------------------------------------------------------------
if [ "$RUN_TESTS" = 1 ]; then
  .venv/bin/python -m pytest -q
fi

echo
.venv/bin/bip322 --version
.venv/bin/bip322 engines
echo
echo "ready. put the commands on your PATH with:"
echo "  export PATH=\"$PWD/.venv/bin:\$PATH\""
echo "then: bip322 help, examples/walkthrough.sh"
