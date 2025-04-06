#!/bin/bash
# setup_poc.sh - Script to set up a local SecureDrop instance and test the vulnerability

set -e

echo "SecureDrop File Upload Vulnerability - Proof of Concept Setup"
echo "============================================================="
echo ""
echo "This script will:"
echo "1. Install necessary dependencies"
echo "2. Clone the SecureDrop repository"
echo "3. Set up a development environment"
echo "4. Generate a malicious PDF file"
echo "5. Guide you through testing the vulnerability"
echo ""
echo "WARNING: This is for educational purposes only. Use in a controlled environment."
echo ""

read -p "Press Enter to continue or Ctrl+C to abort..."

echo ""
echo "Installing dependencies..."
sudo apt-get update
sudo apt-get install -y git python3-pip python3-venv libssl-dev

# Install Python dependencies for our PoC
pip3 install PyPDF2 reportlab

# Clone SecureDrop repository
echo ""
echo "Cloning SecureDrop repository..."
if [ ! -d "securedrop" ]; then
    git clone https://github.com/freedomofpress/securedrop.git
    cd securedrop
else
    echo "SecureDrop directory already exists, using existing clone."
    cd securedrop
    git pull
fi

# Set up development environment
echo ""
echo "Setting up SecureDrop development environment..."
echo "This may take some time..."

# Follow the development guide
# We're using a virtualized environment with Vagrant as recommended
# by the SecureDrop documentation

# Check if Vagrant is installed
if ! command -v vagrant &> /dev/null; then
    echo "Vagrant is not installed. Installing now..."
    sudo apt-get install -y vagrant virtualbox
fi

# Start the SecureDrop dev environment
echo "Starting SecureDrop development environment with Vagrant..."
# Use the 'prod' environment as it most closely mimics a production installation
vagrant up prod

echo ""
echo "Generating malicious PDF..."
cd ..
python3 make_malicious_pdf.py

echo ""
echo "===================================================================="
echo "Setup complete! Now you can test the vulnerability:"
echo ""
echo "1. Access the source interface at http://localhost:8080"
echo "   (This would normally be accessed through Tor in a real deployment)"
echo ""
echo "2. Create a new source account and upload the 'malicious.pdf' file"
echo ""
echo "3. Access the journalist interface at http://localhost:8081"
echo "   Login with the default credentials:"
echo "   Username: journalist"
echo "   Password: correct horse battery staple profanity oil"
echo "   TOTP: 123456"
echo ""
echo "4. Download the submitted file and decrypt it"
echo ""
echo "5. When opened in a PDF viewer, check the /tmp directory for evidence"
echo "   of code execution (a file named securedrop_poc_execution_confirmed.txt)"
echo ""
echo "Troubleshooting:"
echo "- If you face issues with the dev environment, refer to the SecureDrop"
echo "  Development Guide at: https://docs.securedrop.org/en/latest/development/setup_development.html"
echo "- Make sure PDF readers (like Evince) are installed in the environment"
echo "===================================================================="