# Lvau API and lattes.jp Deployment

This deployment uses direct browser calls from `https://lattee.jp` to `https://api.lattee.jp/lvau`. Do not rely on the Vercel API proxy as the primary path.

## Security Model

Server API mode is not E2EE and is not zero-knowledge. Files and passwords are processed on the Oracle API server. Use it only for files that are acceptable to send to the server. Use the local CLI/GUI for the strongest privacy.

Lvau Transport Envelope is planned as defense in depth on top of HTTPS only. It is not implemented yet and the transport endpoints must keep returning `501` with `NOT_IMPLEMENTED`.

## DNS

Create these records:

```text
api.lattee.jp  A     <Oracle IPv4 address>
api.lattee.jp  AAAA  <Oracle IPv6 address, only if Nginx listens on IPv6 correctly>
```

Cloudflare proxy is optional. If it is enabled, set SSL/TLS mode to Full strict. If Certbot HTTP challenge fails while proxied, temporarily switch `api.lattee.jp` to DNS-only.

Recommended Cloudflare WAF/rate limits:

```text
/lvau/decrypt  strict
/lvau/encrypt  strict
/lvau/inspect  moderate
/lvau/health   lenient
```

## Oracle Manual Setup

```sh
ssh -i ~/.ssh/oracle.key ubuntu@sandvpn.lattee.jp
sudo apt update
sudo apt install -y nginx certbot python3-certbot-nginx curl
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw status
```

Do not close existing admin ports unless explicitly intended.

Build locally or in CI:

```sh
cargo build --release -p lvau-api
scp -i ~/.ssh/oracle.key target/release/lvau-api ubuntu@sandvpn.lattee.jp:/tmp/lvau-api
scp -i ~/.ssh/oracle.key scripts/deploy_oracle_lvau_api.sh ubuntu@sandvpn.lattee.jp:/tmp/deploy_oracle_lvau_api.sh
ssh -i ~/.ssh/oracle.key ubuntu@sandvpn.lattee.jp 'chmod +x /tmp/deploy_oracle_lvau_api.sh && sudo -E /tmp/deploy_oracle_lvau_api.sh /tmp/lvau-api'
```

If target architecture differs, check Oracle with:

```sh
ssh -i ~/.ssh/oracle.key ubuntu@sandvpn.lattee.jp 'uname -m'
```

For `aarch64`, build an ARM64 Linux binary or build directly on Oracle.

## Nginx

Use `deploy/nginx-lvau-api.conf` as a separate `api.lattee.jp` site. Do not mix it with wg-easy, AdGuard, Basic auth, client certificate admin blocks, or `sandvpn.lattee.jp` admin services.

```sh
sudo cp deploy/nginx-lvau-api.conf /etc/nginx/sites-available/lvau-api
sudo ln -s /etc/nginx/sites-available/lvau-api /etc/nginx/sites-enabled/lvau-api
sudo certbot --nginx -d api.lattee.jp
sudo nginx -t
sudo systemctl reload nginx
```

The `api.lattee.jp` Lvau API server block must not contain `auth_basic` or `ssl_verify_client`.

## GitHub Actions Backend Deploy

Workflow: `.github/workflows/deploy-lvau-api.yml`.

Required GitHub Secrets:

```text
ORACLE_HOST=sandvpn.lattee.jp
ORACLE_USER=ubuntu
ORACLE_SSH_KEY=<private SSH key contents>
ORACLE_PORT=22
LVAU_ALLOWED_ORIGIN=https://lattee.jp
LVAU_MAX_UPLOAD_MB=50
LVAU_MAX_CONCURRENT_JOBS=2
LVAU_API_KEYS=<optional comma-separated bearer tokens>
```

The workflow builds `cargo build --release -p lvau-api`, uploads the binary to Oracle, keeps `/opt/lvau-api/lvau-api.previous`, restarts systemd, and restores the previous binary if the local health check fails.

## Frontend Vercel

Set this Vercel environment variable:

```text
VITE_LVAU_API_BASE=https://api.lattee.jp/lvau
```

Deploy the `lattes.jp` frontend through Vercel GitHub integration. `vercel.json` keeps SPA rewrites for `/lvau`, `/lvau/ja`, `/ja/lvau`, and `/toolbox`. Optional API rewrites may exist, but browser code should prefer `VITE_LVAU_API_BASE`.

Do not expose backend API keys in browser code. If API keys become required for the public site, add a server-side proxy and keep the token server-side.

## Verification

On Oracle:

```sh
curl -i http://127.0.0.1:8787/lvau/health
systemctl status lvau-api --no-pager
journalctl -u lvau-api -n 80 --no-pager
```

Through Nginx:

```sh
curl -i http://api.lattee.jp/lvau/health
curl -i https://api.lattee.jp/lvau/health
```

Frontend:

```text
https://lattee.jp/lvau
https://lattee.jp/lvau/ja
```

The API status should show online. Then run a small-file encrypt/decrypt smoke test and compare decrypted output to the original.

## Rollback

Backend:

```sh
ssh -i ~/.ssh/oracle.key ubuntu@sandvpn.lattee.jp
sudo cp /opt/lvau-api/lvau-api.previous /opt/lvau-api/lvau-api
sudo systemctl restart lvau-api
curl -i http://127.0.0.1:8787/lvau/health
```

Frontend:

Use the Vercel dashboard to promote the last known-good deployment.
