#!/bin/bash

echo "╔═══════════════════════════════════════╗"
echo "║      xssed Setup Script               ║"
echo "╚═══════════════════════════════════════╝"
echo ""

# Create directory structure
echo "[*] Creating directory structure..."
mkdir -p xssed/{core,engines,utils,config}

# Create __init__.py files
echo "[*] Creating Python package files..."
touch xssed/__init__.py
touch xssed/core/__init__.py
touch xssed/engines/__init__.py
touch xssed/utils/__init__.py
touch xssed/config/__init__.py

# Create main files (these should contain the code from artifacts)
echo "[*] Creating source files..."
echo "    Note: Copy the code from artifacts into these files:"
echo "    - xssed.py (main entry point)"
echo "    - xssed/core/scanner.py"
echo "    - xssed/core/payload_manager.py"
echo "    - xssed/core/waf_detector.py"
echo "    - xssed/engines/reflection_detector.py"
echo "    - xssed/engines/execution_verifier.py"
echo "    - xssed/utils/url_processor.py"
echo "    - xssed/utils/report_generator.py"
echo "    - xssed/config/payloads.py"

# Install dependencies
echo ""
echo "[*] Installing Python dependencies..."
pip install -r requirements.txt

# Install Playwright
echo ""
echo "[*] Installing Playwright browsers..."
sudo python3 -m pip install --upgrade --force-reinstall playwright --break-system-packages 
playwright install chromium

pipx run --spec playwright playwright install chromium

# Make main script executable
chmod +x xssed.py

echo ""
echo "╔═══════════════════════════════════════╗"
echo "║      Setup Complete!                  ║"
echo "╚═══════════════════════════════════════╝"
echo ""
echo "Usage: python xssed.py -t example.com"
echo ""