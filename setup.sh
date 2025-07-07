#!/bin/bash
echo "Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
echo "Setup complete."
echo "Copy .env.example to .env and fill in your API keys and credentials."