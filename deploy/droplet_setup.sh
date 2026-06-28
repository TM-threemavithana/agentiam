#!/bin/bash
set -e

echo "🚀 Setting up AgentIAM on DigitalOcean Droplet..."

# Update and install dependencies
apt-get update
apt-get install -y git build-essential postgresql-client

# Install Go 1.23.0 (or later)
echo "🐹 Installing Go..."
cd /tmp
wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo "export PATH=\$PATH:/usr/local/go/bin" >> /etc/profile

# Create agentiam service user
if id "agentiam" &>/dev/null; then
    echo "User agentiam already exists."
else
    useradd -m -s /bin/bash agentiam
fi

# Clone or copy repo (Assuming it's cloned to /opt/agentiam)
if [ ! -d "/opt/agentiam" ]; then
    echo "📦 Cloning AgentIAM..."
    # Replace with your actual github repo
    git clone https://github.com/TM-threemavithana/agentiam.git /opt/agentiam
fi

# Build
echo "🔨 Building AgentIAM..."
cd /opt/agentiam
/usr/local/go/bin/go build -o /usr/local/bin/agentiam ./cmd/agentiam

# Set up Policies
mkdir -p /etc/agentiam
cp demo/policies.yaml /etc/agentiam/policies.yaml
chown -R agentiam:agentiam /etc/agentiam

# Generate Systemd Service
echo "⚙️ Configuring Systemd Service..."
cat <<EOF > /etc/systemd/system/agentiam.service
[Unit]
Description=AgentIAM Postgres Proxy
After=network.target

[Service]
Type=simple
User=agentiam
# EXPORT your Neon DSN before starting or put it in a .env file!
Environment="AGENTIAM_TARGET_URL=postgres://YOUR_NEON_USER:YOUR_NEON_PASSWORD@YOUR_NEON_HOST/neondb"
Environment="AGENTIAM_LISTEN_PORT=5432"
Environment="AGENTIAM_POLICIES_PATH=/etc/agentiam/policies.yaml"
# Ensure the proxy binds to the public Droplet IP
Environment="AGENTIAM_LISTEN_HOST=0.0.0.0"
ExecStart=/usr/local/bin/agentiam
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable agentiam

echo "✅ Setup complete!"
echo "To start the service:"
echo "1. Edit /etc/systemd/system/agentiam.service and replace YOUR_NEON_USER... with your actual Neon DSN."
echo "2. Run: systemctl daemon-reload && systemctl start agentiam"
echo "3. Check logs: journalctl -u agentiam -f"
