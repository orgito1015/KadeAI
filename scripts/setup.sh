#!/bin/bash
# KadeAI setup script

set -e

echo "Setting up KadeAI..."

# Check Python version
python3 --version || { echo "Python 3 is required."; exit 1; }

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Copy .env if it doesn't exist
if [ ! -f .env ]; then
  cp .env.example .env
  echo ".env created — add your API keys before running KadeAI."
fi

# Check for nmap
if command -v nmap &> /dev/null; then
  echo "Nmap found."
else
  echo "Nmap not found. Install with: sudo apt install nmap"
fi

echo ""
echo "Setup complete. Run KadeAI with:"
echo "  source venv/bin/activate && python main.py"
