#!/bin/bash
# Start script for SNMP Worker (development)

# Change to script directory
cd "$(dirname "$0")/.."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -q -r requirements.txt

# Check if config exists
if [ ! -f "snmp_worker/config/config.yml" ]; then
    echo "Configuration file not found. Creating from example..."
    cp snmp_worker/config/config.example.yml snmp_worker/config/config.yml
    echo "Please edit snmp_worker/config/config.yml before running"
    exit 1
fi

# Create logs directory
mkdir -p logs

# Run worker
echo "Starting SNMP Worker..."
python3 snmp_worker/worker.py "$@"
