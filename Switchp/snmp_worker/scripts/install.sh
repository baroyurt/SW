#!/bin/bash
# Installation script for SNMP Worker

set -e

echo "================================"
echo "SNMP Worker Installation Script"
echo "================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Variables
INSTALL_DIR="/opt/snmp_worker"
SERVICE_USER="snmpworker"
SERVICE_FILE="/etc/systemd/system/snmp-worker.service"

echo ""
echo "Step 1: Installing system dependencies..."
apt-get update
apt-get install -y python3 python3-pip python3-venv postgresql-client

echo ""
echo "Step 2: Creating service user..."
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
    echo "User $SERVICE_USER created"
else
    echo "User $SERVICE_USER already exists"
fi

echo ""
echo "Step 3: Creating installation directory..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/logs"

echo ""
echo "Step 4: Copying files..."
cp -r snmp_worker "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"

echo ""
echo "Step 5: Installing Python dependencies..."
cd "$INSTALL_DIR"
python3 -m pip install --upgrade pip
pip3 install -r requirements.txt

echo ""
echo "Step 6: Setting up configuration..."
if [ ! -f "$INSTALL_DIR/snmp_worker/config/config.yml" ]; then
    cp "$INSTALL_DIR/snmp_worker/config/config.example.yml" "$INSTALL_DIR/snmp_worker/config/config.yml"
    echo "Configuration file created. Please edit $INSTALL_DIR/snmp_worker/config/config.yml"
else
    echo "Configuration file already exists"
fi

echo ""
echo "Step 7: Setting permissions..."
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/snmp_worker/worker.py"

echo ""
echo "Step 8: Installing systemd service..."
cp "$INSTALL_DIR/snmp_worker/systemd/snmp-worker.service" "$SERVICE_FILE"
systemctl daemon-reload

echo ""
echo "================================"
echo "Installation Complete!"
echo "================================"
echo ""
echo "Next steps:"
echo "1. Configure PostgreSQL database:"
echo "   sudo -u postgres createdb switchdb"
echo "   sudo -u postgres psql -c \"CREATE USER snmpuser WITH PASSWORD 'your_password';\""
echo "   sudo -u postgres psql -c \"GRANT ALL PRIVILEGES ON DATABASE switchdb TO snmpuser;\""
echo ""
echo "2. Edit configuration file:"
echo "   sudo nano $INSTALL_DIR/snmp_worker/config/config.yml"
echo ""
echo "3. Run database migration:"
echo "   sudo -u $SERVICE_USER python3 $INSTALL_DIR/snmp_worker/migrations/create_tables.py"
echo ""
echo "4. Start the service:"
echo "   sudo systemctl start snmp-worker"
echo "   sudo systemctl enable snmp-worker"
echo ""
echo "5. Check status:"
echo "   sudo systemctl status snmp-worker"
echo "   sudo journalctl -u snmp-worker -f"
echo ""
