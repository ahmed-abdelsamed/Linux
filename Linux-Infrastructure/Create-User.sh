#sudo ./create_sudo_user.sh core
#sudo ./create_sudo_user.sh -k "ssh-rsa AAAAB3..." -n core
#sudo ./create_sudo_user.sh -e 2024-12-31 -g docker core


#!/bin/bash

# Script to create a user with sudo privileges
# Usage: ./create_sudo_user.sh [options] <username>

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
SSH_KEY=""
NO_PASSWORD="false"
EXPIRE_DATE=""
GROUP=""

# Function to display usage
usage() {
    echo "Usage: $0 [options] <username>"
    echo "Options:"
    echo "  -k, --ssh-key KEY    Add SSH public key for user"
    echo "  -n, --no-password    Allow sudo without password (NOPASSWD)"
    echo "  -e, --expire DATE    Set account expiration date (YYYY-MM-DD)"
    echo "  -g, --group GROUP    Additional group to add user to"
    echo "  -h, --help           Show this help message"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -k|--ssh-key)
            SSH_KEY="$2"
            shift 2
            ;;
        -n|--no-password)
            NO_PASSWORD="true"
            shift
            ;;
        -e|--expire)
            EXPIRE_DATE="$2"
            shift 2
            ;;
        -g|--group)
            GROUP="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        -*)
            echo "Error: Unknown option $1"
            usage
            ;;
        *)
            USERNAME="$1"
            shift
            ;;
    esac
done

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root (use sudo)${NC}" 
   exit 1
fi

# Check if username is provided
if [ -z "$USERNAME" ]; then
    echo -e "${RED}Error: Please provide a username${NC}"
    usage
fi

# Check if user already exists
if id "$USERNAME" &>/dev/null; then
    echo -e "${RED}Error: User $USERNAME already exists${NC}"
    exit 1
fi

echo -e "${YELLOW}Creating user $USERNAME...${NC}"

# Create the user with home directory
if [ -n "$EXPIRE_DATE" ]; then
    useradd -m -s /bin/bash -e "$EXPIRE_DATE" "$USERNAME"
    echo -e "${GREEN}Account will expire on $EXPIRE_DATE${NC}"
else
    useradd -m -s /bin/bash "$USERNAME"
fi

# Set password
echo -e "${YELLOW}Set password for $USERNAME:${NC}"
passwd "$USERNAME"

# Determine sudo group based on distribution
if getent group sudo > /dev/null; then
    SUDO_GROUP="sudo"
elif getent group wheel > /dev/null; then
    SUDO_GROUP="wheel"
else
    SUDO_GROUP=""
fi

# Add to sudo group if found
if [ -n "$SUDO_GROUP" ]; then
    usermod -aG "$SUDO_GROUP" "$USERNAME"
    echo -e "${GREEN}Added $USERNAME to $SUDO_GROUP group${NC}"
    
    # Configure NOPASSWD if requested
    if [ "$NO_PASSWORD" = "true" ]; then
        echo "$USERNAME ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers.d/$USERNAME
        chmod 440 /etc/sudoers.d/$USERNAME
        echo -e "${GREEN}Configured sudo without password for $USERNAME${NC}"
    fi
else
    echo -e "${RED}Warning: No sudo group found${NC}"
fi

# Add to additional group if specified
if [ -n "$GROUP" ] && getent group "$GROUP" > /dev/null; then
    usermod -aG "$GROUP" "$USERNAME"
    echo -e "${GREEN}Added $USERNAME to $GROUP group${NC}"
fi

# Add SSH key if provided
if [ -n "$SSH_KEY" ]; then
    SSH_DIR="/home/$USERNAME/.ssh"
    mkdir -p "$SSH_DIR"
    echo "$SSH_KEY" >> "$SSH_DIR/authorized_keys"
    chown -R "$USERNAME:$USERNAME" "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    chmod 600 "$SSH_DIR/authorized_keys"
    echo -e "${GREEN}SSH key added for $USERNAME${NC}"
fi

echo -e "${GREEN}User $USERNAME created successfully with sudo privileges${NC}"

# Display user info
echo -e "\n${YELLOW}User Information:${NC}"
echo "Username: $USERNAME"
echo "Home: /home/$USERNAME"
echo "Shell: /bin/bash"
echo "Groups: $(groups $USERNAME)"
