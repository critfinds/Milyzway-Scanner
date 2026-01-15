#!/bin/bash
set -e

echo "=============================="
echo "  Milyzway-Scanner Installer"
echo "=============================="

#############################################################
# Helper: Check if command exists
#############################################################
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

echo "[*] Updating system..."
sudo apt-get update

echo "[*] Installing system dependencies..."
sudo apt-get install -y \
    git curl wget unzip build-essential python3 python3-pip python3-venv \
    software-properties-common libssl-dev pkg-config


#############################################################
#  PYTHON ENVIRONMENT
#############################################################

echo "[*] Creating Python virtual environment..."

if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

source venv/bin/activate

echo "[*] Upgrading pip..."
pip install --upgrade pip

echo "[*] Installing Python packages from pyproject.toml..."
pip install -e .

echo "[*] Installing Playwright browsers..."
playwright install chromium


#############################################################
#  FINISHED
#############################################################
echo ""
echo "===================================="
echo "  Installation complete successfully!"
echo "===================================="
echo ""
echo "Activate your environment with:"
echo "      source venv/bin/activate"
echo ""
