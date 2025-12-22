#!/bin/bash

# Usage: ./export_module.sh <module_name>:<stream>
# Example: ./export_module.sh nodejs:20

MODULE_INPUT=$1
DEST_DIR="./offline_repo_${MODULE_INPUT//:/_}"

if [ -z "$MODULE_INPUT" ]; then
    echo "Usage: $0 <module_name>:<stream>"
    exit 1
fi

echo "--- Preparing to export module: $MODULE_INPUT ---"

# 1. Install necessary tools
sudo dnf install -y dnf-utils createrepo_c

# 2. Create destination directory
mkdir -p "$DEST_DIR"

# 3. Enable the module stream
echo "Enabling module stream..."
sudo dnf module enable -y "$MODULE_INPUT"

# 4. Download packages and dependencies
echo "Downloading packages to $DEST_DIR..."
# The @ symbol target the entire module profile
sudo dnf download --resolve --alldeps --destdir="$DEST_DIR" @"$MODULE_INPUT"

# 5. Create the repository metadata
echo "Generating repository metadata..."
createrepo_c "$DEST_DIR"

echo "--- Export Complete ---"
echo "Transfer the folder '$DEST_DIR' to your offline machine."
