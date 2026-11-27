#!/bin/bash
set -eu
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
ENV_FILE="$SCRIPT_DIR/.env"
SULGX_ADMIN_GENERATED=no
SULGX_ADMIN_PASSWORD=
sulgx_generate_admin_password() {
  python3 -c "import secrets; alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@%^*()-_=+'; lower = secrets.choice('abcdefghijklmnopqrstuvwxyz'); upper = secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ'); digit = secrets.choice('0123456789'); symbol = secrets.choice('!@%^*()-_=+'); chars = [lower, upper, digit, symbol] + [secrets.choice(alphabet) for _ in range(16)]; secrets.SystemRandom().shuffle(chars); print(''.join(chars))"
}
sulgx_generate_secret_key() {
  python3 -c "import secrets; print(secrets.token_urlsafe(32))"
}
sulgx_derive_tg_proxy_secret() {
  SULGX_SECRET="$1" python3 -c "import hashlib, os; print('dd' + hashlib.sha256((os.environ.get('SULGX_SECRET', '') + 'mtproxy-secret').encode()).hexdigest()[:32])"
}
sulgx_derive_tg_web_secret() {
  SULGX_SECRET="$1" python3 -c "import hashlib, os; print(hashlib.sha256((os.environ.get('SULGX_SECRET', '') + 'tg-web-secret').encode()).hexdigest()[:32])"
}
sulgx_env_value() {
  grep "^$1=" "$ENV_FILE" | tail -n 1 | cut -d= -f2- | tr -d "'" | tr -d '"'
}
sulgx_wait_for_health() {
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    if PORT_CHECK="$1" python3 -c "import os, urllib.request; urllib.request.urlopen('http://localhost:' + os.environ.get('PORT_CHECK', '8000') + '/health', timeout=5)"; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 2
  done
  return 1
}
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' "SulgX installer: python3 is required but was not found" >&2
  exit 1
fi
DOCKER_OK=no
COMPOSE_CMD=
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  DOCKER_OK=yes
  COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DOCKER_OK=yes
  COMPOSE_CMD="docker-compose"
fi
if [ ! -f "$ENV_FILE" ]; then
  touch "$ENV_FILE"
  chmod 600 "$ENV_FILE"
fi
if ! grep -q "^ADMIN_PASSWORD=" "$ENV_FILE"; then
  SULGX_ADMIN_PASSWORD="$(sulgx_generate_admin_password)"
  printf '%s\n' "ADMIN_PASSWORD='$SULGX_ADMIN_PASSWORD'" >> "$ENV_FILE"
  SULGX_ADMIN_GENERATED=yes
fi
if ! grep -q "^SECRET_KEY=" "$ENV_FILE"; then
  SULGX_SECRET_KEY="$(sulgx_generate_secret_key)"
  printf '%s\n' "SECRET_KEY='$SULGX_SECRET_KEY'" >> "$ENV_FILE"
fi
SULGX_SECRET_KEY="$(sulgx_env_value SECRET_KEY)"
if ! grep -q "^TG_PROXY_SECRET=" "$ENV_FILE"; then
  printf '%s\n' "TG_PROXY_SECRET='$(sulgx_derive_tg_proxy_secret "$SULGX_SECRET_KEY")'" >> "$ENV_FILE"
fi
if ! grep -q "^TG_WEB_SECRET=" "$ENV_FILE"; then
  printf '%s\n' "TG_WEB_SECRET='$(sulgx_derive_tg_web_secret "$SULGX_SECRET_KEY")'" >> "$ENV_FILE"
fi
SULGX_TG_WEB_CURRENT="$(sulgx_env_value TG_WEB_SECRET)"
SULGX_TG_WEB_VALID="$(SULGX_TG_WEB_CHECK="$SULGX_TG_WEB_CURRENT" python3 -c "import os, re; print('yes' if re.fullmatch(r'(dd)?[0-9a-fA-F]{32}', os.environ.get('SULGX_TG_WEB_CHECK', '').strip()) else 'no')")"
if [ "$SULGX_TG_WEB_VALID" != "yes" ]; then
  SULGX_TG_WEB_DERIVED="$(sulgx_derive_tg_web_secret "$SULGX_SECRET_KEY")"
  SULGX_TMP_ENV="$(mktemp)"
  grep -v "^TG_WEB_SECRET=" "$ENV_FILE" > "$SULGX_TMP_ENV" || true
  printf '%s\n' "TG_WEB_SECRET=$SULGX_TG_WEB_DERIVED" >> "$SULGX_TMP_ENV"
  mv "$SULGX_TMP_ENV" "$ENV_FILE"
fi
if ! grep -q "^PORT=" "$ENV_FILE"; then
  printf '%s\n' "PORT=8000" >> "$ENV_FILE"
fi
if [ "$DOCKER_OK" = "yes" ]; then
  if ! grep -q "^DB_PATH=" "$ENV_FILE"; then
    printf '%s\n' "DB_PATH=/data/panel.db" >> "$ENV_FILE"
  fi
  if ! grep -q "^SOCKS_PORT=" "$ENV_FILE"; then
    printf '%s\n' "SOCKS_PORT=0" >> "$ENV_FILE"
  fi
  if ! grep -q "^TG_PROXY_PORT=" "$ENV_FILE"; then
    printf '%s\n' "TG_PROXY_PORT=0" >> "$ENV_FILE"
  fi
  if ! grep -q "^HTTP_PROXY_PORT=" "$ENV_FILE"; then
    printf '%s\n' "HTTP_PROXY_PORT=0" >> "$ENV_FILE"
  fi
else
  if ! grep -q "^DB_PATH=" "$ENV_FILE"; then
    printf '%s\n' "DB_PATH=$SCRIPT_DIR/data/panel.db" >> "$ENV_FILE"
  fi
  mkdir -p "$SCRIPT_DIR/data"
fi
chmod 600 "$ENV_FILE"
PORT_VALUE="$(sulgx_env_value PORT)"
if [ -z "$PORT_VALUE" ]; then
  PORT_VALUE=8000
fi
if [ "$DOCKER_OK" = "yes" ]; then
  $COMPOSE_CMD up -d --build
  if sulgx_wait_for_health "$PORT_VALUE"; then
    printf '%s\n' "SulgX Panel is up: http://localhost:$PORT_VALUE"
  else
    printf '%s\n' "SulgX Panel container started but /health did not answer within 60 seconds; check docker compose logs" >&2
    exit 1
  fi
else
  SULGX_PYTHON=python3
  if [ -x .venv/bin/python ] && .venv/bin/python -c "import fastapi" 2>/dev/null; then
    SULGX_PYTHON=.venv/bin/python
  elif python3 -c "import fastapi" 2>/dev/null; then
    SULGX_PYTHON=python3
  elif python3 -m pip install -r requirements.txt 2>/dev/null; then
    SULGX_PYTHON=python3
  else
    if [ ! -x .venv/bin/python ]; then
      printf '%s\n' "SulgX installer: system pip is blocked, creating a local .venv instead"
      python3 -m venv .venv
    fi
    .venv/bin/python -m pip install -r requirements.txt
    SULGX_PYTHON=.venv/bin/python
  fi
  set -a
  . "$ENV_FILE"
  set +a
  nohup "$SULGX_PYTHON" main.py > sulgx.log 2>&1 &
  echo "$!" > sulgx.pid
  if sulgx_wait_for_health "$PORT_VALUE"; then
    printf '%s\n' "SulgX Panel is up: http://localhost:$PORT_VALUE"
    printf '%s\n' "Process id saved to sulgx.pid, logs to sulgx.log"
  else
    printf '%s\n' "SulgX Panel did not answer /health within 60 seconds; check sulgx.log" >&2
    exit 1
  fi
fi
if [ "$SULGX_ADMIN_GENERATED" = "yes" ]; then
  printf '%s\n' "Admin password (shown once, also saved in .env): $SULGX_ADMIN_PASSWORD"
else
  printf '%s\n' "Admin password unchanged (already set in .env)."
fi
