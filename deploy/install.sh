#!/usr/bin/env bash
# Install mini-siem as a systemd service under a dedicated user.
#
#   sudo ./deploy/install.sh            # install or upgrade, do not start
#   sudo ./deploy/install.sh --start    # ... and enable + start the service
#   sudo ./deploy/install.sh --uninstall [--purge]
#
# What it touches (and nothing else):
#   /opt/mini-siem             code + virtualenv (root-owned, read-only for the service)
#   /etc/mini-siem             config.yml and env (created only if missing)
#   /var/lib/mini-siem         database (created by systemd StateDirectory=)
#   /etc/systemd/system/mini-siem.service
#   system user "minisiem", added to group "adm" to read logs
#
# It does NOT install packages, change nginx, sshd or firewall settings,
# or open any port. The dashboard listens on 127.0.0.1 only.

set -euo pipefail

APP=mini-siem
USER_NAME=minisiem
PREFIX=/opt/$APP
CONF_DIR=/etc/$APP
STATE_DIR=/var/lib/$APP
UNIT=/etc/systemd/system/$APP.service
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

START=0
UNINSTALL=0
PURGE=0
for arg in "$@"; do
    case "$arg" in
        --start) START=1 ;;
        --uninstall) UNINSTALL=1 ;;
        --purge) PURGE=1 ;;
        -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo $0 $*)"
command -v systemctl >/dev/null || die "systemd is required for this install method; use Docker instead"

if [[ $UNINSTALL -eq 1 ]]; then
    log "stopping and removing the service"
    systemctl disable --now "$APP.service" 2>/dev/null || true
    rm -f "$UNIT"
    systemctl daemon-reload
    rm -rf "$PREFIX"
    if [[ $PURGE -eq 1 ]]; then
        log "purging configuration and data"
        rm -rf "$CONF_DIR" "$STATE_DIR"
        userdel "$USER_NAME" 2>/dev/null || true
    else
        log "kept $CONF_DIR and $STATE_DIR (use --purge to delete them)"
    fi
    exit 0
fi

# --- prerequisites ---------------------------------------------------------------
PY=${PYTHON:-python3}
command -v "$PY" >/dev/null || die "python3 not found (apt install python3 python3-venv)"
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
    || die "Python >= 3.11 required, found $("$PY" -V 2>&1). On Ubuntu 22.04 use the Docker setup."
"$PY" -c 'import venv, ensurepip' 2>/dev/null \
    || die "python3-venv is missing (apt install python3-venv), then re-run"

# --- user --------------------------------------------------------------------------
if ! id "$USER_NAME" >/dev/null 2>&1; then
    log "creating system user $USER_NAME"
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$USER_NAME"
fi
if getent group adm >/dev/null; then
    usermod -aG adm "$USER_NAME"
else
    log "warning: group 'adm' not found; make sure $USER_NAME can read your log files"
fi
# journald source: adm can read the journal on Debian/Ubuntu; systemd-journal elsewhere.
if getent group systemd-journal >/dev/null; then
    usermod -aG systemd-journal "$USER_NAME"
fi

# --- code --------------------------------------------------------------------------
log "installing code into $PREFIX"
install -d -m 0755 "$PREFIX"
rm -rf "$PREFIX/src" "$PREFIX/rules.default"
cp -r "$SRC_DIR/src" "$SRC_DIR/pyproject.toml" "$SRC_DIR/README.md" "$SRC_DIR/LICENSE" "$PREFIX/"
cp -r "$SRC_DIR/rules" "$PREFIX/rules.default"
if [[ ! -d "$PREFIX/rules" ]]; then
    cp -r "$SRC_DIR/rules" "$PREFIX/rules"
else
    log "keeping existing $PREFIX/rules (shipped rules are in $PREFIX/rules.default)"
fi
[[ -d "$PREFIX/venv" ]] || "$PY" -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --quiet --upgrade pip
"$PREFIX/venv/bin/pip" install --quiet "$PREFIX"
chown -R root:root "$PREFIX"
chmod -R go-w "$PREFIX"

# --- configuration -------------------------------------------------------------------
install -d -m 0750 -o root -g "$USER_NAME" "$CONF_DIR"
if [[ ! -f "$CONF_DIR/config.yml" ]]; then
    log "writing $CONF_DIR/config.yml"
    sed -e "s|^database: .*|database: $STATE_DIR/siem.db|" \
        -e "s|^rules: .*|rules: $PREFIX/rules|" \
        "$SRC_DIR/config.yml" > "$CONF_DIR/config.yml"
    chown root:"$USER_NAME" "$CONF_DIR/config.yml"
    chmod 0640 "$CONF_DIR/config.yml"
else
    log "keeping existing $CONF_DIR/config.yml"
fi
if [[ ! -f "$CONF_DIR/env" ]]; then
    install -m 0640 -o root -g "$USER_NAME" "$SRC_DIR/.env.example" "$CONF_DIR/env"
    log "created $CONF_DIR/env - add TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID there"
fi

# --- service -------------------------------------------------------------------------
install -m 0644 "$SRC_DIR/deploy/mini-siem.service" "$UNIT"
systemctl daemon-reload

log "checking rules"
(cd / && runuser -u "$USER_NAME" -- env SIEM_CONFIG="$CONF_DIR/config.yml" \
    "$PREFIX/venv/bin/siem" check-rules >/dev/null) || die "rule validation failed"

for f in /var/log/auth.log /var/log/nginx/access.log; do
    if [[ -e $f ]] && ! runuser -u "$USER_NAME" -- test -r "$f"; then
        log "warning: $USER_NAME cannot read $f yet (group membership applies on service start)"
    fi
done

if [[ $START -eq 1 ]]; then
    systemctl enable --now "$APP.service"
    systemctl restart "$APP.service"
    log "started; logs: journalctl -u $APP -f"
else
    log "installed. Review $CONF_DIR/config.yml and $CONF_DIR/env, then:"
    echo "      sudo systemctl enable --now $APP"
    echo "      journalctl -u $APP -f"
fi
echo "    Dashboard (from your laptop): ssh -N -L 8080:127.0.0.1:8080 <you>@<server>  ->  http://localhost:8080"
