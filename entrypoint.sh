#!/bin/bash
set -eu

echo "SulgX entrypoint starting: uid=$(id -u) gid=$(id -g) user=$(id -un 2>/dev/null || echo unknown) HOME=${HOME:-unset}"

if [ -z "${HOME:-}" ] || [ ! -d "${HOME:-}" ] || [ ! -w "${HOME:-}" ]; then
  for candidate in "/tmp/sulgx-home-$(id -u)" "/tmp/sulgx-home" "/var/tmp/sulgx-home"; do
    if mkdir -p "$candidate" 2>/dev/null && [ -w "$candidate" ]; then
      export HOME="$candidate"
      break
    fi
  done
fi

if [ -z "${HOME:-}" ] || [ ! -w "${HOME:-}" ]; then
  echo "SulgX entrypoint: ERROR - no writable HOME found" >&2
  exit 1
fi

DATA_DIR=""
for candidate in "${SULGX_DATA_DIR:-/data}" "$HOME/data" "/tmp/sulgx-data-$(id -u)" "/tmp/sulgx-data" "/var/tmp/sulgx-data"; do
  if mkdir -p "$candidate" 2>/dev/null && touch "$candidate/.write-test" 2>/dev/null; then
    rm -f "$candidate/.write-test" 2>/dev/null || true
    DATA_DIR="$candidate"
    break
  fi
done

if [ -z "$DATA_DIR" ]; then
  echo "SulgX entrypoint: ERROR - no writable data directory found" >&2
  exit 1
fi

echo "SulgX entrypoint: HOME=$HOME DATA_DIR=$DATA_DIR"

export SULGX_DATA_DIR="$DATA_DIR"
ENV_FILE="$DATA_DIR/.sulgx-env"
CRED_FILE="$DATA_DIR/initial-credentials.txt"
export DB_PATH="${DB_PATH:-$DATA_DIR/panel.db}"

DB_DIR="$(dirname "$DB_PATH")"
mkdir -p "$DB_DIR" 2>/dev/null || true

chown -R sulgx:sulgx "$DATA_DIR" 2>/dev/null || true

if [ -f "$ENV_FILE" ]; then
  set -a
  . "$ENV_FILE" 2>/dev/null || true
  set +a
fi

SULGX_DB_HAS_ADMIN_HASH=no
SULGX_DB_HAS_SECRET=no

if [ -z "${DATABASE_URL:-}" ] && [ -f "$DB_PATH" ]; then
  SULGX_DB_CHECK="$(DB_PATH="$DB_PATH" python3 -c "
import os
import sqlite3
path = os.environ.get('DB_PATH', '')
admin = 'no'
secret = 'no'
try:
    con = sqlite3.connect('file:' + path + '?mode=ro', uri=True)
    try:
        row = con.execute(\"SELECT value FROM settings WHERE key = 'admin_password_hash'\").fetchone()
        if row is not None and row[0]:
            admin = 'yes'
        row = con.execute(\"SELECT value FROM settings WHERE key = 'jwt_secret_key'\").fetchone()
        if row is not None and row[0]:
            secret = 'yes'
    finally:
        con.close()
except Exception:
    admin = 'no'
    secret = 'no'
print('admin_hash=' + admin)
print('secret=' + secret)
" || true)"
  case "$SULGX_DB_CHECK" in
    *admin_hash=yes*) SULGX_DB_HAS_ADMIN_HASH=yes ;;
  esac
  case "$SULGX_DB_CHECK" in
    *secret=yes*) SULGX_DB_HAS_SECRET=yes ;;
  esac
fi

SULGX_GENERATED_ADMIN=no

if [ -z "${DATABASE_URL:-}" ]; then
  if [ "$SULGX_DB_HAS_ADMIN_HASH" = "no" ] && [ -n "${ADMIN_PASSWORD:-}" ]; then
    case "${ADMIN_PASSWORD}" in
      admin) ;;
      ????????*) ;;
      *)
        printf '%s\n' "SulgX entrypoint: ADMIN_PASSWORD must be at least 8 characters" >&2
        exit 1
        ;;
    esac
  fi
  if [ "$SULGX_DB_HAS_ADMIN_HASH" = "no" ] && [ -z "${ADMIN_PASSWORD:-}" ]; then
    SULGX_NEW_ADMIN_PASSWORD="admin"
    printf '%s\n' "ADMIN_PASSWORD='admin'" >> "$ENV_FILE" 2>/dev/null || true
    export ADMIN_PASSWORD="admin"
    SULGX_GENERATED_ADMIN=yes
  fi
  if [ "$SULGX_DB_HAS_SECRET" = "no" ] && [ -z "${SECRET_KEY:-}" ]; then
    SULGX_NEW_SECRET_KEY="$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")"
    SULGX_NEW_TG_PROXY_SECRET="$(SULGX_SECRET="$SULGX_NEW_SECRET_KEY" python3 -c "import hashlib, os; print('dd' + hashlib.sha256((os.environ.get('SULGX_SECRET', '') + 'mtproxy-secret').encode()).hexdigest()[:32])")"
    SULGX_NEW_TG_WEB_SECRET="$(SULGX_SECRET="$SULGX_NEW_SECRET_KEY" python3 -c "import hashlib, os; print(hashlib.sha256((os.environ.get('SULGX_SECRET', '') + 'tg-web-secret').encode()).hexdigest()[:32])")"
    printf '%s\n' "SECRET_KEY='$SULGX_NEW_SECRET_KEY'" >> "$ENV_FILE" 2>/dev/null || true
    printf '%s\n' "TG_PROXY_SECRET='$SULGX_NEW_TG_PROXY_SECRET'" >> "$ENV_FILE" 2>/dev/null || true
    printf '%s\n' "TG_WEB_SECRET='$SULGX_NEW_TG_WEB_SECRET'" >> "$ENV_FILE" 2>/dev/null || true
    export SECRET_KEY="$SULGX_NEW_SECRET_KEY"
    export TG_PROXY_SECRET="$SULGX_NEW_TG_PROXY_SECRET"
    export TG_WEB_SECRET="$SULGX_NEW_TG_WEB_SECRET"
  fi
fi

TG_WEB_SECRET_EFFECTIVE="${TG_WEB_SECRET:-}"
TG_WEB_SECRET_VALID="$(TG_WEB_SECRET_CHECK="$TG_WEB_SECRET_EFFECTIVE" python3 -c "import os, re; print('yes' if re.fullmatch(r'(dd)?[0-9a-fA-F]{32}', os.environ.get('TG_WEB_SECRET_CHECK', '').strip()) else 'no')")"

if [ "$TG_WEB_SECRET_VALID" != "yes" ]; then
  SULGX_NEW_TG_WEB_SECRET="$(python3 -c "import secrets; print(secrets.token_hex(16))")"
  if grep -q "^TG_WEB_SECRET=" "$ENV_FILE" 2>/dev/null; then
    sed -i "/^TG_WEB_SECRET=/d" "$ENV_FILE" 2>/dev/null || true
  fi
  printf '%s\n' "TG_WEB_SECRET=$SULGX_NEW_TG_WEB_SECRET" >> "$ENV_FILE" 2>/dev/null || true
  export TG_WEB_SECRET="$SULGX_NEW_TG_WEB_SECRET"
  printf '%s\n' "SulgX entrypoint: TG_WEB_SECRET was missing or invalid, a valid secret was generated and stored for this deployment"
fi

if [ -f "$ENV_FILE" ]; then
  chmod 600 "$ENV_FILE" 2>/dev/null || true
  chown sulgx:sulgx "$ENV_FILE" 2>/dev/null || true
fi

if [ "$SULGX_GENERATED_ADMIN" = "yes" ]; then
  printf '%s\n' "SulgX Panel first-boot admin credentials" "Admin password: $SULGX_NEW_ADMIN_PASSWORD" "Change this password from the panel after first login." > "$CRED_FILE" 2>/dev/null || true
  chmod 600 "$CRED_FILE" 2>/dev/null || true
  chown sulgx:sulgx "$CRED_FILE" 2>/dev/null || true
  printf '%s\n' "SulgX first boot: using default admin password 'admin' (change it after first login, also saved to $CRED_FILE)"
fi

if [ -z "${1:-}" ]; then
  set -- python main.py
fi

if [ "$(id -u)" = "0" ] && command -v gosu >/dev/null 2>&1 && id sulgx >/dev/null 2>&1; then
  echo "SulgX entrypoint: attempting gosu sulgx $*"
  if gosu sulgx "$@"; then
    exit 0
  else
    echo "SulgX entrypoint: WARNING - gosu failed (missing SETUID capability or no-new-privileges). Falling back to running as uid=$(id -u)." >&2
  fi
fi

echo "SulgX entrypoint: executing $* as uid=$(id -u)"
exec "$@"
