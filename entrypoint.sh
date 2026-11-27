#!/bin/bash
set -eu
export HOME=/home/sulgx
DATA_DIR="${SULGX_DATA_DIR:-/data}"
ENV_FILE="$DATA_DIR/.sulgx-env"
CRED_FILE="$DATA_DIR/initial-credentials.txt"
DB_PATH="${DB_PATH:-$DATA_DIR/panel.db}"
mkdir -p "$DATA_DIR"
DB_DIR="$(dirname "$DB_PATH")"
mkdir -p "$DB_DIR"
chown -R sulgx:sulgx "$DATA_DIR"
if [ -f "$ENV_FILE" ]; then
  set -a
  . "$ENV_FILE"
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
    printf '%s\n' "ADMIN_PASSWORD='admin'" >> "$ENV_FILE"
    export ADMIN_PASSWORD="admin"
    SULGX_GENERATED_ADMIN=yes
  fi
  if [ "$SULGX_DB_HAS_SECRET" = "no" ] && [ -z "${SECRET_KEY:-}" ]; then
    SULGX_NEW_SECRET_KEY="$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")"
    SULGX_NEW_TG_PROXY_SECRET="$(SULGX_SECRET="$SULGX_NEW_SECRET_KEY" python3 -c "import hashlib, os; print('dd' + hashlib.sha256((os.environ.get('SULGX_SECRET', '') + 'mtproxy-secret').encode()).hexdigest()[:32])")"
    SULGX_NEW_TG_WEB_SECRET="$(SULGX_SECRET="$SULGX_NEW_SECRET_KEY" python3 -c "import hashlib, os; print(hashlib.sha256((os.environ.get('SULGX_SECRET', '') + 'tg-web-secret').encode()).hexdigest()[:32])")"
    printf '%s\n' "SECRET_KEY='$SULGX_NEW_SECRET_KEY'" >> "$ENV_FILE"
    printf '%s\n' "TG_PROXY_SECRET='$SULGX_NEW_TG_PROXY_SECRET'" >> "$ENV_FILE"
    printf '%s\n' "TG_WEB_SECRET='$SULGX_NEW_TG_WEB_SECRET'" >> "$ENV_FILE"
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
    sed -i "/^TG_WEB_SECRET=/d" "$ENV_FILE"
    printf '%s\n' "TG_WEB_SECRET=$SULGX_NEW_TG_WEB_SECRET" >> "$ENV_FILE"
  else
    printf '%s\n' "TG_WEB_SECRET=$SULGX_NEW_TG_WEB_SECRET" >> "$ENV_FILE"
  fi
  export TG_WEB_SECRET="$SULGX_NEW_TG_WEB_SECRET"
  printf '%s\n' "SulgX entrypoint: TG_WEB_SECRET was missing or invalid, a valid secret was generated and stored for this deployment"
fi
if [ -f "$ENV_FILE" ]; then
  chmod 600 "$ENV_FILE"
  chown sulgx:sulgx "$ENV_FILE"
fi
if [ "$SULGX_GENERATED_ADMIN" = "yes" ]; then
  printf '%s\n' "SulgX Panel first-boot admin credentials" "Admin password: $SULGX_NEW_ADMIN_PASSWORD" "Change this password from the panel after first login." > "$CRED_FILE"
  chmod 600 "$CRED_FILE"
  chown sulgx:sulgx "$CRED_FILE"
  printf '%s\n' "SulgX first boot: using default admin password 'admin' (change it after first login, also saved to $CRED_FILE)"
fi
if [ -z "${1:-}" ]; then
  set -- python main.py
fi
exec gosu sulgx "$@"
