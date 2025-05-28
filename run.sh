#!/bin/bash

# Ensure sudo is available
if ! command -v sudo &> /dev/null
then
    echo "sudo could not be found, please install it."
    exit 1
fi

# Ensure Python dependencies are installed
pip install Flask Flask-SocketIO Scapy python-iptables

# Initialize the database (creates ids.db and tables if they don't exist)
# python -c 'from database import init_db; init_db()'

# IMPORTANT: You might need to explicitly tell Flask to allow unsafe Werkzeug
# for SocketIO in debug mode on certain systems.
# Use host='0.0.0.0' to make it accessible from other devices on your network.

echo "Starting Flask IDS with SocketIO..."
echo "WARNING: This application requires root privileges for network sniffing and iptables management."
echo "You will be prompted for your sudo password."

# Run the Flask app with sudo (for sniffing and iptables)
# The `python -u` flag prevents output buffering, which is good for real-time logs.
sudo python3 -u main.py