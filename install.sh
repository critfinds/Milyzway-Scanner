#!/bin/bash

# Milyzway-Scanner Installer

# Exit on error
set -e

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install dependencies
echo "[*] Installing dependencies..."

if ! command_exists git; then
    echo "[+] git not found. Installing..."
    sudo apt-get update
    sudo apt-get install -y git
fi

if ! command_exists python3; then
    echo "[+] python3 not found. Installing..."
    sudo apt-get update
    sudo apt-get install -y python3
fi

if ! command_exists pip; then
    echo "[+] pip not found. Installing..."
    sudo apt-get update
    sudo apt-get install -y python3-pip
fi

# Create and activate virtual environment
echo "[*] Creating and activating virtual environment..."

if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

source venv/bin/activate

# Install Python packages
echo "[*] Installing Python packages..."

pip install -r requirements.txt

# Install solc-select and Slither
echo "[*] Installing solc-select and Slither..."

if ! command_exists solc-select; then
    pip install solc-select
fi

solc-select install latest
solc-select use latest

if ! command_exists slither; then
    pip install slither-analyzer
fi

echo "[+] Installation complete!"
