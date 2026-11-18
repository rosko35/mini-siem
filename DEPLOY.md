# Deploying mini-siem on a VPS

🇹🇷 [Türkçe](DEPLOY.tr.md)

This guide assumes a Debian/Ubuntu VPS that already serves a production
website through nginx. mini-siem is designed to be a **passive, read-only
guest** on that machine:

| It does | It does not |
|---|---|
| read `/var/log/auth.log` and `/var/log/nginx/access.log` (or journald) | modify nginx, sshd, the firewall, fail2ban or the website |
| write its own SQLite database (Docker volume or `/var/lib/mini-siem`) | open any public port (the dashboard binds to `127.0.0.1`) |
| make outbound HTTPS requests to `api.telegram.org` (only if configured) | block IPs or take any active response |
| use at most 0.5 CPU and ~256-300 MB RAM (enforced limits) | run as root |

Pick **one** of the two install methods: Docker (A) or systemd (B).

---

## 0. Before you start

1. Check which logs exist:

   ```bash
   ls -l /var/log/auth.log /var/log/nginx/access.log
   # -rw-r----- 1 syslog   adm ... /var/log/auth.log
   # -rw-r----- 1 www-data adm ... /var/log/nginx/access.log
   ```

   Both should be readable by group `adm` (the Debian/Ubuntu default).
   If there is **no** `/var/log/auth.log` (Debian 12 minimal and other
   rsyslog-less systems), use the journald source with the systemd install
   (B), or `apt install rsyslog` if you prefer files.

2. Check the nginx log format. mini-siem expects the default `combined`
   format. If your site is behind Cloudflare or another proxy, make sure
   nginx logs the real client IP (`set_real_ip_from` + `real_ip_header`),
   otherwise every request appears to come from the proxy. That is an nginx
   change you make yourself, deliberately; mini-siem never edits nginx.

3. Note your own IP address(es) so you can add them to `ignore_networks`
   in `config.yml` and never alert on yourself.

4. (Optional) Create a Telegram bot: talk to `@BotFather`, `/newbot`, copy
   the token. Send your bot any message, then open
   `https://api.telegram.org/bot<TOKEN>/getUpdates` and copy `chat.id`.

5. (Optional) GeoIP: see the README section "GeoIP". Without a database,
   countries show as "unknown" and everything else works.

---

## A. Docker install

Requires Docker Engine with Compose v2.24 or newer (`docker compose version`).

```bash
# 1. Get the code (as your normal user)
git clone https://github.com/rosko35/mini-siem.git ~/mini-siem
cd ~/mini-siem

# 2. Secrets
cp .env.example .env
chmod 600 .env
nano .env            # TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, optional dashboard auth

# 3. Review config.yml: ignore_networks, retention_days, log paths
nano config.yml

# 4. Optional GeoIP database
cp /path/to/GeoLite2-Country.mmdb geoip/

# 5. Build and start
docker compose up -d --build
docker compose logs -f          # look for "monitoring 2 source(s) with 11 rules"
```

What the compose file guarantees (read `docker-compose.yml` to verify):

- `/var/log` is mounted **read-only**; `/etc/localtime` read-only so classic
  syslog timestamps are interpreted in the host's timezone.
- The container runs as uid 10001 with supplementary group `adm` (gid 4),
  `cap_drop: ALL`, `no-new-privileges`, a read-only root filesystem.
- The only published port is `127.0.0.1:8080`, which is not reachable from
  the internet. Docker's iptables rules for a loopback-bound port do not
  expose anything publicly.
- CPU, memory, PID and log-size limits keep it from competing with the site.

Upgrade: `git pull && docker compose up -d --build`. Data lives in the
`siem-data` volume and survives upgrades. Remove everything:
`docker compose down -v`.

Check that the container can read the logs:

```bash
docker compose exec siem head -n1 /var/log/auth.log /var/log/nginx/access.log
```

---

## B. systemd install (no Docker)

Requires Python 3.11+ (Debian 12, Ubuntu 24.04). On Ubuntu 22.04 (Python
3.10) use Docker.

```bash
sudo apt install python3-venv            # if not already present
git clone https://github.com/rosko35/mini-siem.git
cd mini-siem
sudo ./deploy/install.sh                 # installs, does not start yet
sudo nano /etc/mini-siem/config.yml      # paths, ignore_networks, retention
sudo nano /etc/mini-siem/env             # Telegram token / chat id, dashboard auth
sudo systemctl enable --now mini-siem
journalctl -u mini-siem -f
```

The script creates the system user `minisiem` (no shell, no home, member of
`adm`), installs code and a virtualenv into `/opt/mini-siem` (root-owned),
writes `/etc/mini-siem/config.yml` and `/etc/mini-siem/env` only if they do
not exist, and installs `deploy/mini-siem.service`. It does not install
packages or touch any other service.

The unit is heavily sandboxed (`ProtectSystem=strict`, `ReadOnlyPaths=/var/log`,
no capabilities, `MemoryMax=300M`, `CPUQuota=50%`, `Nice=10`). Inspect it with
`systemd-analyze security mini-siem`.

**journald instead of auth.log:** in `/etc/mini-siem/config.yml`, remove the
`auth` file source and enable:

```yaml
  - type: journald
    identifiers: [sshd, sshd-session]
```

Upgrade: `git pull && sudo ./deploy/install.sh && sudo systemctl restart mini-siem`
(your config, env and rules are kept). Uninstall: `sudo ./deploy/install.sh --uninstall`
(add `--purge` to also delete config, data and the user).

---

## Reaching the dashboard

The dashboard never listens on a public interface. Use an SSH tunnel from
your own machine:

```bash
ssh -N -L 8080:127.0.0.1:8080 you@your-server
# then open http://localhost:8080
```

Setting `SIEM_DASHBOARD_USER` / `SIEM_DASHBOARD_PASSWORD` adds HTTP basic
auth as a second layer (useful if other people have shell access to the VPS).

Do **not** add an nginx `location` that proxies to it unless you understand
the consequences; it is not designed to face the internet.

---

## Verifying it works

```bash
# from another machine: a few failed SSH logins with a made-up user
for i in 1 2 3 4 5 6; do ssh -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no nosuchuser@your-server true; done
```

Within seconds you should see `ALERT HIGH ssh-bruteforce` in the logs
(`docker compose logs` / `journalctl -u mini-siem`) and a Telegram message
within `batch_interval` seconds. If your own IP is in `ignore_networks`,
nothing fires; that is intended. With fail2ban active you might ban
yourself, so test from a throwaway address.

## Operations

| Task | Docker | systemd |
|---|---|---|
| Logs | `docker compose logs -f` | `journalctl -u mini-siem -f` |
| Validate rules after editing | `docker compose exec siem siem check-rules` | `sudo -u minisiem SIEM_CONFIG=/etc/mini-siem/config.yml /opt/mini-siem/venv/bin/siem check-rules` |
| Apply rule changes | `docker compose restart` | `sudo systemctl restart mini-siem` |
| README statistics | `docker compose exec siem siem stats --days 30` | `sudo -u minisiem SIEM_CONFIG=/etc/mini-siem/config.yml /opt/mini-siem/venv/bin/siem stats --days 30` |
| Prune now | `docker compose exec siem siem prune` | `... siem prune` |

Retention is applied automatically every hour (`retention_days`).

## Troubleshooting

- **No events at all** - check the source paths and permissions (step 0),
  and that `log_timezone` is right: a wrong timezone does not stop
  detection, but makes times look shifted.
- **"tailing ... from end"** - on first start mini-siem begins at the end of
  each file (no backfill). To import history once:
  `siem replay --parser auth /var/log/auth.log.1` (add `-q` to silence alerts).
- **Telegram silent** - `TELEGRAM_*` set? `min_severity` too high? The log
  says "Telegram notifications enabled" on start. HTTP errors are logged
  without the token.
- **Everything comes from one IP** - nginx is behind a proxy; see step 0.2.
