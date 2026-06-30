# Deployment Guide: Lvau API Server & Frontend

This guide covers the deployment of the `lvau-api` server to an Oracle Cloud VPS (Ubuntu Linux) and the `lattes.jp` frontend to Vercel.

## 1. Backend: Oracle Cloud VPS (Ubuntu Linux)

### 1.1 Server Setup
Connect to your Oracle VPS and install dependencies:
```sh
sudo apt update && sudo apt upgrade -y
sudo apt install curl build-essential libssl-dev pkg-config nginx -y

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### 1.2 Build the API
```sh
git clone https://github.com/lasder-ca/lvau.git
cd lvau
cargo build --release --bin lvau-api
```

### 1.3 System User and Permissions
Create a dedicated user and copy the binary:
```sh
sudo useradd -r -s /usr/sbin/nologin lvau
sudo mkdir -p /opt/lvau-api/tmp
sudo cp target/release/lvau-api /opt/lvau-api/
sudo chown -R lvau:lvau /opt/lvau-api
sudo chmod 750 /opt/lvau-api
```

### 1.4 Environment Configuration
Create the `.env` file:
```sh
sudo nano /opt/lvau-api/.env
```
Add the following content:
```env
LVAU_BIND=127.0.0.1:8787
LVAU_ALLOWED_ORIGIN=https://lattee.jp
LVAU_MAX_UPLOAD_MB=100
LVAU_API_KEYS=
RUST_LOG=info
```
```sh
sudo chown lvau:lvau /opt/lvau-api/.env
sudo chmod 600 /opt/lvau-api/.env
```

### 1.5 Systemd Service Installation
Create the systemd service file:
```sh
sudo nano /etc/systemd/system/lvau-api.service
```
Add the following content (including strict systemd hardening):
```ini
[Unit]
Description=Lvau API Server
After=network.target

[Service]
Type=simple
User=lvau
Group=lvau
WorkingDirectory=/opt/lvau-api
ExecStart=/opt/lvau-api/lvau-api
EnvironmentFile=/opt/lvau-api/.env
Restart=always

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=true
MemoryDenyWriteExecute=true
ReadWritePaths=/opt/lvau-api/tmp
Environment=TMPDIR=/opt/lvau-api/tmp

[Install]
WantedBy=multi-user.target
```
Start and enable the service:
```sh
sudo systemctl daemon-reload
sudo systemctl start lvau-api
sudo systemctl enable lvau-api
```

### 1.6 Nginx Reverse Proxy Config
Create the Nginx config:
```sh
sudo nano /etc/nginx/sites-available/lvau-api
```
Add the following:
```nginx
server {
    server_name api.lattee.jp;

    location /lvau/ {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # Performance & Streaming
        proxy_request_buffering off;
        proxy_read_timeout 300;
        proxy_send_timeout 300;
        client_max_body_size 100M;
        
        # Security headers
        add_header X-Content-Type-Options nosniff;
        add_header X-Frame-Options DENY;
        add_header X-XSS-Protection "1; mode=block";
    }
}
```
Enable the site and HTTPS:
```sh
sudo ln -s /etc/nginx/sites-available/lvau-api /etc/nginx/sites-enabled/
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d api.lattee.jp
sudo systemctl restart nginx
```

### 1.7 Firewall Configuration
```sh
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### 1.8 Test the Endpoint
```sh
curl https://api.lattee.jp/lvau/health
# Should return OK
```

---

## 2. Frontend: Vercel Deployment

1. Copy the `LvauWeb.tsx` component into your React repository (`frontend/src/components/`).
2. Include the `vercel.json` provided in the `frontend/` directory at the root of your Vercel project repository.
3. Push the code to GitHub and trigger a Vercel deployment.
4. Verify the rewrites map `/api/lvau/*` to `https://api.lattee.jp/lvau/*` successfully.

---

## 3. Rollback Procedures

If an API deployment fails:
1. Revert to the previous binary:
```sh
sudo cp /opt/lvau-api/lvau-api.backup /opt/lvau-api/lvau-api
sudo systemctl restart lvau-api
```
*(Tip: Always copy the working binary to `.backup` before overwriting).*

If the frontend deployment fails:
1. Open the Vercel dashboard.
2. Go to Deployments.
3. Select the last working deployment.
4. Click **Redeploy** or **Promote to Production**.
