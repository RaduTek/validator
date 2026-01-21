#!/bin/bash

# Script to sync validator files to Raspberry Pi and install/start the service

PI_USER="user"
PI_HOST="validator.local"
PI_PASSWORD="validator"
PI_DEST="/home/user/validator"
LOCAL_DIR="."

# Function to print message to both console and Pi screen
print_to_screen() {
    local msg="$1"
    sshpass -p "$PI_PASSWORD" ssh "$PI_USER@$PI_HOST" "echo '$msg' | sudo tee /dev/tty0" 2>/dev/null >/dev/null
}

echo "Starting sync to Raspberry Pi..."
print_to_screen "=== Validator Update Started ==="

# 1. Stop the validator service if present
echo "Stopping validator service if running..."
print_to_screen "Stopping validator service..."
sshpass -p "$PI_PASSWORD" ssh "$PI_USER@$PI_HOST" "sudo systemctl stop validator 2>/dev/null"
print_to_screen "Service stopped"

# 2. Delete existing files in /home/user/validator
echo "Deleting existing files in $PI_DEST..."
print_to_screen "Deleting old files..."
sshpass -p "$PI_PASSWORD" ssh "$PI_USER@$PI_HOST" "rm -rf $PI_DEST/*"

if [ $? -eq 0 ]; then
    echo "Files deleted successfully"
    print_to_screen "Old files deleted"
else
    echo "Error: Failed to delete files"
    print_to_screen "ERROR: Failed to delete files"
    exit 1
fi

# 3. Copy new files to /home/user/validator
echo "Transferring new files..."
print_to_screen "Transferring new files..."
sshpass -p "$PI_PASSWORD" scp -r "$LOCAL_DIR"/* "$PI_USER@$PI_HOST:$PI_DEST/"

if [ $? -eq 0 ]; then
    echo "Files transferred successfully"
    print_to_screen "Files transferred successfully"
else
    echo "Error: Failed to transfer files"
    print_to_screen "ERROR: Failed to transfer files"
    exit 1
fi

# 4. Run install_service.sh script
echo "Running install_service.sh..."
print_to_screen "Installing and starting service..."
sshpass -p "$PI_PASSWORD" ssh "$PI_USER@$PI_HOST" "cd $PI_DEST && bash install_service.sh"

if [ $? -eq 0 ]; then
    echo "Service installed and started successfully"
    print_to_screen "Service installed and started successfully"
else
    echo "Error: Failed to install and start service"
    print_to_screen "ERROR: Failed to install service"
    exit 1
fi

echo "Sync complete!"
print_to_screen "=== Validator Update Complete ==="
