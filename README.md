# dsh-hub

A [JupyterHub](https://jupyterhub.readthedocs.io)-style multi-user front for
[DeepSeek Harness (dsh)](https://github.com/deepseek-ai/deepseek-harness) —
PAM login, one isolated dsh instance per system user, and a cookie-routed
HTTP/WebSocket proxy. **Zero modifications to dsh**: upstream upgrades and
per-user plugin installs keep working.

```
browser ──http://<server-ip>:3080──▶ dsh-hub ──cookie──▶ 127.0.0.1:<port> ──▶ dsh (user A)
                                        │                127.0.0.1:<port> ──▶ dsh (user B)
                                        └─ spawn as uid/gid + iptables owner-guard
```

## Architecture (the JupyterHub analogy)

| JupyterHub | dsh-hub |
|---|---|
| Authenticator (PAM) | PAM via `authenticate-pam` (optional) with a `su`-based fallback; HMAC-signed session cookie |
| Spawner | `dsh web --port <random>` spawned with the user's uid/gid and a per-user `DSH_HOME` |
| Configurable HTTP proxy | `http-proxy` routes HTTP + WebSocket by session cookie |
| Idle culler (jupyterhub-idle-culler) | built-in culler, `IDLE_CULL_MS` (0 = never, tmux-style always-on) |
| Single-user server trusts the hub | dsh's official `--trusted-host` flag — the upstream deployment contract |

### Trust model (upstream-native)

dsh's web server enforces a browser trust fence (`Origin`/`Host` authority
checks) against DNS-rebinding and CSRF. Instead of forging headers, dsh-hub
spawns each instance with:

```
dsh web --port <N> --trusted-host <lan-ip> --trusted-host <extra>...
```

The proxy then forwards `Host`/`Origin` **untouched**, so the browser ↔ dsh
trust chain is real end-to-end and dsh's own fence remains the security
boundary — exactly the deployment shape the flag was designed for. The hub's
`SameSite=Lax` cookie adds the cross-site protection on top.

For dsh versions predating `--trusted-host`, set `TRUST_MODE=origin-rewrite`
to fall back to loopback Host/Origin rewriting at the proxy.

### Insecure-context polyfill

Browsers only expose `crypto.randomUUID()` in secure contexts (HTTPS or
localhost). On bare `http://<server-ip>:3080`, dsh-hub injects a self-guarding
v4-UUID polyfill into every proxied HTML page (a no-op once dsh fixes its
remaining direct call or you serve over HTTPS).

## Isolation guarantees (run as root)

- Each dsh instance runs as the user's own **uid/gid** with `DSH_HOME=~/.dsh`
- Instances bind `127.0.0.1:<random port>`; an **iptables owner-guard**
  (loopback, `--uid-owner`) DROPs connections from other local users
- Login rate-limiting (5 failures → 1 min lockout per IP)
- Optional `ALLOW_USERS` allow-list

## Quick start

```bash
git clone https://github.com/Mpaperlee/dsh-hub.git /opt/dsh-hub
cd /opt/dsh-hub && npm install

# dev run (no root: no setuid/iptables, single-user semantics)
DSH_BIN=/path/to/deepseek-harness/apps/cli/lib/bin.js HUB_PORT=3080 \
  HUB_LOG_DIR=/tmp npm start
```

Production (root, systemd):

```bash
sudo cp dsh-hub.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now dsh-hub
```

Users browse to `http://<server-ip>:3080`, log in with their **system
username/password**, and get a private dsh instance.

## Configuration

| Env | Default | Meaning |
|---|---|---|
| `DSH_BIN` | *(required)* | dsh CLI entry (built checkout: `apps/cli/lib/bin.js`) |
| `HUB_HOST` / `HUB_PORT` | `0.0.0.0` / `3080` | hub listen address |
| `TRUST_MODE` | `trusted-host` | `origin-rewrite` for older dsh |
| `TRUSTED_HOSTS` | auto (LAN IPv4s) | extra authorities for `--trusted-host` (hostnames/DNS names) |
| `IDLE_CULL_MS` | `14400000` (4h) | `0` disables culling — backends keep running with the browser closed |
| `SESSION_TTL_MS` | 7 days | cookie lifetime |
| `ALLOW_USERS` | *(all)* | comma-separated username allow-list |
| `HUB_LOG_DIR` | `/var/log/dsh-hub` | per-user backend logs |
| `COOKIE_SECRET_FILE` | `./.cookie-secret` | HMAC secret (auto-generated, `0600`) |

## Notes

- Conversations survive browser close: goal/server-side drivers keep running
  in the spawned dsh process; re-login reattaches to the same instance.
- `sudo systemctl restart dsh-hub` after config changes.
- Non-root runs are degraded (dev) mode: no setuid spawn, no iptables guard.

## License

MIT
