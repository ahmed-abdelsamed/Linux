#!/bin/bash
################################################################################
# Script: setup-storage.sh
# Description: Professional storage provisioning script for Linux systems
# Author: Your Name
# Version: 1.0
# Usage: ./setup-storage.sh [OPTIONS]
################################################################################

set -o errexit      # Exit on any command failing
set -o nounset      # Exit on unset variables
set -o pipefail     # Exit on pipe failures
# set -o xtrace     # Uncomment for debugging (set -x)

# Script initialization
readonly SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
readonly TIMESTAMP=$(date "+%Y%m%d_%H%M%S")
readonly LOG_FILE="/var/log/${SCRIPT_NAME%.sh}_${TIMESTAMP}.log"

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Global variables
DISK=""
PARTITION=""
VG_NAME=""
LV_NAME=""
FS_TYPE=""
MOUNT_POINT=""
FORCE_MODE=false
QUIET_MODE=false

################################################################################
# Function: log_message
# Description: Logs messages to both console and log file with timestamp
# Parameters: $1 - Message type (INFO, WARN, ERROR, DEBUG)
#            $2 - Message text
################################################################################
log_message() {
    local type="$1"
    local message="$2"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local console_message=""
    
    # Format message based on type
    case "$type" in
        "INFO")
            console_message="${GREEN}[INFO]${NC} ${message}"
            ;;
        "WARN")
            console_message="${YELLOW}[WARN]${NC} ${message}"
            ;;
        "ERROR")
            console_message="${RED}[ERROR]${NC} ${message}"
            ;;
        "DEBUG")
            console_message="${BLUE}[DEBUG]${NC} ${message}"
            ;;
        *)
            console_message="[${type}] ${message}"
            ;;
    esac
    
    # Write to log file with timestamp
    echo "[${timestamp}] [${type}] ${message}" >> "$LOG_FILE"
    
    # Write to console unless quiet mode is enabled
    if [[ "$QUIET_MODE" == false ]]; then
        echo -e "$console_message"
    fi
}

################################################################################
# Function: usage
# Description: Display script usage information
################################################################################
usage() {
    cat << EOF
${SCRIPT_NAME} - Storage provisioning script for Linux systems

USAGE:
    ./${SCRIPT_NAME} [OPTIONS]

REQUIRED OPTIONS:
    -d, --disk DISK          Base disk name (e.g., sdb, vdb, nvme0n1)
    -p, --partition PART     Partition number (e.g., 1, 2, 3)
    -v, --vg-name NAME       Volume Group name (e.g., datavg, appvg)
    -l, --lv-name NAME       Logical Volume name (e.g., datalv, applv)
    -f, --fs-type TYPE       Filesystem type (xfs, ext4, etc.)
    -m, --mount-point PATH   Mount point path (e.g., /u01, /data)

OPTIONAL OPTIONS:
    --force                  Force execution without confirmation
    --quiet                  Suppress non-error output
    -h, --help               Show this help message

EXAMPLES:
    ./${SCRIPT_NAME} -d sdb -p 1 -v datavg -l datalv -f xfs -m /u01
    ./${SCRIPT_NAME} --disk nvme0n1 --partition 1 --vg-name appvg \\
                     --lv-name applv --fs-type ext4 --mount-point /data

NOTES:
    - Script must be run as root
    - All operations are logged to: ${LOG_FILE}
    - Existing filesystem entries in /etc/fstab are validated
    - Disk partitions are created with GPT label and LVM flag enabled
EOF
    exit 0
}

################################################################################
# Function: check_root
# Description: Verify script is running as root
################################################################################
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_message "ERROR" "This script must be run as root"
        exit 1
    fi
    log_message "INFO" "Root privileges verified"
}

################################################################################
# Function: validate_disk
# Description: Validate disk exists and is not in use
# Parameters: $1 - Disk name (e.g., sdb)
################################################################################
validate_disk() {
    local disk="$1"
    local disk_path="/dev/${disk}"
    
    # Check if disk exists
    if [[ ! -b "$disk_path" ]]; then
        log_message "ERROR" "Disk ${disk_path} does not exist or is not a block device"
        return 1
    fi
    
    # Check if disk is already partitioned
    if lsblk "${disk_path}" -o NAME,TYPE | grep -q "part"; then
        if [[ "$FORCE_MODE" == false ]]; then
            log_message "WARN" "Disk ${disk_path} already has partitions"
            read -p "Do you want to continue? This may destroy existing data (y/N): " confirm
            if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                log_message "INFO" "Operation cancelled by user"
                exit 0
            fi
        else
            log_message "WARN" "Disk ${disk_path} already has partitions, continuing due to force mode"
        fi
    fi
    
    log_message "INFO" "Disk ${disk_path} validated successfully"
    return 0
}

################################################################################
# Function: validate_partition
# Description: Validate partition number format
# Parameters: $1 - Partition number
################################################################################
validate_partition() {
    local partition="$1"
    
    if [[ ! "$partition" =~ ^[0-9]+$ ]]; then
        log_message "ERROR" "Partition number must be a positive integer"
        return 1
    fi
    
    if [[ "$partition" -lt 1 ]] || [[ "$partition" -gt 128 ]]; then
        log_message "ERROR" "Partition number must be between 1 and 128"
        return 1
    fi
    
    log_message "INFO" "Partition number ${partition} validated"
    return 0
}

################################################################################
# Function: validate_vg_name
# Description: Validate volume group name format
# Parameters: $1 - Volume group name
################################################################################
validate_vg_name() {
    local vg_name="$1"
    
    if [[ ! "$vg_name" =~ ^[a-zA-Z][a-zA-Z0-9_.-]+$ ]]; then
        log_message "ERROR" "Invalid volume group name. Must start with letter and contain only letters, numbers, _, ., -"
        return 1
    fi
    
    # Check if VG already exists
    if vgs "$vg_name" &>/dev/null; then
        if [[ "$FORCE_MODE" == false ]]; then
            log_message "ERROR" "Volume group ${vg_name} already exists"
            return 1
        else
            log_message "WARN" "Volume group ${vg_name} already exists, continuing due to force mode"
        fi
    fi
    
    log_message "INFO" "Volume group name ${vg_name} validated"
    return 0
}

################################################################################
# Function: validate_lv_name
# Description: Validate logical volume name format
# Parameters: $1 - Logical volume name
################################################################################
validate_lv_name() {
    local lv_name="$1"
    
    if [[ ! "$lv_name" =~ ^[a-zA-Z][a-zA-Z0-9_.-]+$ ]]; then
        log_message "ERROR" "Invalid logical volume name. Must start with letter and contain only letters, numbers, _, ., -"
        return 1
    fi
    
    log_message "INFO" "Logical volume name ${lv_name} validated"
    return 0
}

################################################################################
# Function: validate_fs_type
# Description: Validate filesystem type is supported
# Parameters: $1 - Filesystem type
################################################################################
validate_fs_type() {
    local fs_type="$1"
    local supported_fs=("xfs" "ext4" "ext3" "ext2" "btrfs")
    
    for fs in "${supported_fs[@]}"; do
        if [[ "$fs_type" == "$fs" ]]; then
            # Check if mkfs tool exists
            if ! command -v "mkfs.${fs_type}" &>/dev/null; then
                log_message "ERROR" "mkfs.${fs_type} tool not found"
                return 1
            fi
            log_message "INFO" "Filesystem type ${fs_type} validated"
            return 0
        fi
    done
    
    log_message "ERROR" "Unsupported filesystem type: ${fs_type}"
    log_message "INFO" "Supported types: ${supported_fs[*]}"
    return 1
}

################################################################################
# Function: validate_mount_point
# Description: Validate mount point path
# Parameters: $1 - Mount point path
################################################################################
validate_mount_point() {
    local mount_point="$1"
    
    if [[ ! "$mount_point" =~ ^/ ]]; then
        log_message "ERROR" "Mount point must be an absolute path starting with /"
        return 1
    fi
    
    # Check if mount point is already in /etc/fstab
    if grep -q "^[^#].*${mount_point}" /etc/fstab; then
        log_message "ERROR" "Mount point ${mount_point} already exists in /etc/fstab"
        return 1
    fi
    
    log_message "INFO" "Mount point ${mount_point} validated"
    return 0
}

################################################################################
# Function: create_partition
# Description: Create GPT partition with LVM flag
# Parameters: $1 - Disk name, $2 - Partition number
################################################################################
create_partition() {
    local disk="$1"
    local partition="$2"
    local disk_path="/dev/${disk}"
    local partition_path="${disk_path}${partition}"
    
    log_message "INFO" "Creating partition ${partition} on ${disk_path}"
    
    # Create GPT label
    if ! parted -s "$disk_path" mklabel gpt; then
        log_message "ERROR" "Failed to create GPT label on ${disk_path}"
        return 1
    fi
    
    # Create partition
    if ! parted -s "$disk_path" unit MiB mkpart primary 1 100%; then
        log_message "ERROR" "Failed to create partition on ${disk_path}"
        return 1
    fi
    
    # Set LVM flag
    if ! parted -s "$disk_path" set "$partition" lvm on; then
        log_message "ERROR" "Failed to set LVM flag on partition ${partition}"
        return 1
    fi
    
    # Wait for partition to be recognized
    udevadm settle
    
    # Verify partition was created
    if [[ ! -b "${partition_path}" ]]; then
        log_message "ERROR" "Partition ${partition_path} was not created successfully"
        return 1
    fi
    
    log_message "INFO" "Partition ${partition_path} created successfully"
    parted "$disk_path" print
    return 0
}

################################################################################
# Function: create_physical_volume
# Description: Create LVM physical volume
# Parameters: $1 - Partition path
################################################################################
create_physical_volume() {
    local partition_path="$1"
    
    log_message "INFO" "Creating physical volume on ${partition_path}"
    
    if ! pvcreate "$partition_path"; then
        log_message "ERROR" "Failed to create physical volume on ${partition_path}"
        return 1
    fi
    
    log_message "INFO" "Physical volume created successfully"
    pvs "$partition_path"
    return 0
}

################################################################################
# Function: create_volume_group
# Description: Create LVM volume group
# Parameters: $1 - Volume group name, $2 - Partition path
################################################################################
create_volume_group() {
    local vg_name="$1"
    local partition_path="$2"
    
    log_message "INFO" "Creating volume group ${vg_name} on ${partition_path}"
    
    if ! vgcreate "$vg_name" "$partition_path"; then
        log_message "ERROR" "Failed to create volume group ${vg_name}"
        return 1
    fi
    
    log_message "INFO" "Volume group ${vg_name} created successfully"
    vgs "$vg_name"
    return 0
}

################################################################################
# Function: create_logical_volume
# Description: Create LVM logical volume
# Parameters: $1 - Volume group name, $2 - Logical volume name
################################################################################
create_logical_volume() {
    local vg_name="$1"
    local lv_name="$2"
    
    log_message "INFO" "Creating logical volume ${lv_name} in volume group ${vg_name}"
    
    if ! lvcreate -n "$lv_name" -l 100%FREE "$vg_name"; then
        log_message "ERROR" "Failed to create logical volume ${lv_name}"
        return 1
    fi
    
    log_message "INFO" "Logical volume ${lv_name} created successfully"
    lvs "${vg_name}/${lv_name}"
    return 0
}

################################################################################
# Function: create_filesystem
# Description: Create filesystem on logical volume
# Parameters: $1 - Filesystem type, $2 - Volume group name, $3 - Logical volume name
################################################################################
create_filesystem() {
    local fs_type="$1"
    local vg_name="$2"
    local lv_name="$3"
    local lv_path="/dev/mapper/${vg_name}-${lv_name}"
    
    # Handle different device mapper naming conventions
    if [[ ! -e "$lv_path" ]]; then
        lv_path="/dev/${vg_name}/${lv_name}"
    fi
    
    log_message "INFO" "Creating ${fs_type} filesystem on ${lv_path}"
    
    if ! mkfs."$fs_type" "$lv_path"; then
        log_message "ERROR" "Failed to create ${fs_type} filesystem on ${lv_path}"
        return 1
    fi
    
    log_message "INFO" "Filesystem created successfully"
    return 0
}

################################################################################
# Function: mount_filesystem
# Description: Mount filesystem and add to /etc/fstab
# Parameters: $1 - Filesystem type, $2 - Volume group name, $3 - Logical volume name
#            $4 - Mount point
################################################################################
mount_filesystem() {
    local fs_type="$1"
    local vg_name="$2"
    local lv_name="$3"
    local mount_point="$4"
    local lv_path="/dev/mapper/${vg_name}-${lv_name}"
    local fstab_entry="${lv_path}   ${mount_point}   ${fs_type}   defaults   0 0"
    
    # Handle different device mapper naming conventions
    if [[ ! -e "$lv_path" ]]; then
        lv_path="/dev/${vg_name}/${lv_name}"
        fstab_entry="${lv_path}   ${mount_point}   ${fs_type}   defaults   0 0"
    fi
    
    log_message "INFO" "Setting up mount point ${mount_point}"
    
    # Create mount point directory
    if ! mkdir -p "$mount_point"; then
        log_message "ERROR" "Failed to create mount point directory ${mount_point}"
        return 1
    fi
    
    # Add to /etc/fstab
    log_message "INFO" "Adding entry to /etc/fstab"
    echo "$fstab_entry" >> /etc/fstab
    
    # Reload systemd
    systemctl daemon-reload
    
    # Mount filesystem
    log_message "INFO" "Mounting filesystem"
    if ! mount "$mount_point"; then
        log_message "ERROR" "Failed to mount ${mount_point}"
        return 1
    fi
    
    log_message "INFO" "Filesystem mounted successfully at ${mount_point}"
    return 0
}

################################################################################
# Function: display_summary
# Description: Display summary of operations performed
################################################################################
display_summary() {
    local disk_path="/dev/${DISK}${PARTITION}"
    local lv_path="/dev/mapper/${VG_NAME}-${LV_NAME}"
    
    cat << EOF

${GREEN}════════════════════════════════════════════════════════════════════${NC}
${GREEN}                    STORAGE PROVISIONING SUMMARY                     ${NC}
${GREEN}════════════════════════════════════════════════════════════════════${NC}

${YELLOW}Configuration:${NC}
  • Disk:           ${disk_path}
  • Volume Group:   ${VG_NAME}
  • Logical Volume: ${LV_NAME}
  • Filesystem:     ${FS_TYPE}
  • Mount Point:    ${MOUNT_POINT}

${YELLOW}Verification:${NC}
$(df -h "$MOUNT_POINT" | sed 's/^/  /')

${YELLOW}LVM Information:${NC}
$(lvs "${VG_NAME}/${LV_NAME}" | sed 's/^/  /')

${YELLOW}Log File:${NC}
  • ${LOG_FILE}

${GREEN}════════════════════════════════════════════════════════════════════${NC}
EOF
}

################################################################################
# Function: parse_arguments
# Description: Parse command line arguments
################################################################################
parse_arguments() {
    # No arguments provided
    if [[ $# -eq 0 ]]; then
        usage
    fi
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--disk)
                DISK="$2"
                shift 2
                ;;
            -p|--partition)
                PARTITION="$2"
                shift 2
                ;;
            -v|--vg-name)
                VG_NAME="$2"
                shift 2
                ;;
            -l|--lv-name)
                LV_NAME="$2"
                shift 2
                ;;
            -f|--fs-type)
                FS_TYPE="$2"
                shift 2
                ;;
            -m|--mount-point)
                MOUNT_POINT="$2"
                shift 2
                ;;
            --force)
                FORCE_MODE=true
                shift
                ;;
            --quiet)
                QUIET_MODE=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                log_message "ERROR" "Unknown option: $1"
                usage
                ;;
        esac
    done
    
    # Validate required parameters
    local missing_params=()
    [[ -z "$DISK" ]] && missing_params+=("--disk")
    [[ -z "$PARTITION" ]] && missing_params+=("--partition")
    [[ -z "$VG_NAME" ]] && missing_params+=("--vg-name")
    [[ -z "$LV_NAME" ]] && missing_params+=("--lv-name")
    [[ -z "$FS_TYPE" ]] && missing_params+=("--fs-type")
    [[ -z "$MOUNT_POINT" ]] && missing_params+=("--mount-point")
    
    if [[ ${#missing_params[@]} -gt 0 ]]; then
        log_message "ERROR" "Missing required parameters: ${missing_params[*]}"
        usage
    fi
}

################################################################################
# Function: cleanup
# Description: Cleanup function on script exit
################################################################################
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_message "ERROR" "Script failed with exit code ${exit_code}"
        log_message "INFO" "Check log file for details: ${LOG_FILE}"
    else
        log_message "INFO" "Script completed successfully"
    fi
    exit $exit_code
}

################################################################################
# Main script execution
################################################################################

# Set up trap for cleanup
trap cleanup EXIT

# Initialize log file
touch "$LOG_FILE"
log_message "INFO" "=== Starting ${SCRIPT_NAME} ==="

# Check root privileges
check_root

# Parse command line arguments
parse_arguments "$@"

# Display configuration in debug mode
log_message "DEBUG" "Configuration: DISK=${DISK}, PARTITION=${PARTITION}, VG=${VG_NAME}, LV=${LV_NAME}, FS=${FS_TYPE}, MOUNT=${MOUNT_POINT}"

# Validate all inputs
log_message "INFO" "Validating inputs..."
validate_disk "$DISK" || exit 1
validate_partition "$PARTITION" || exit 1
validate_vg_name "$VG_NAME" || exit 1
validate_lv_name "$LV_NAME" || exit 1
validate_fs_type "$FS_TYPE" || exit 1
validate_mount_point "$MOUNT_POINT" || exit 1

# Confirmation prompt unless force mode is enabled
if [[ "$FORCE_MODE" == false ]]; then
    echo
    log_message "INFO" "The following operations will be performed:"
    echo "  • Create partition ${PARTITION} on /dev/${DISK}"
    echo "  • Create physical volume on /dev/${DISK}${PARTITION}"
    echo "  • Create volume group ${VG_NAME}"
    echo "  • Create logical volume ${LV_NAME}"
    echo "  • Create ${FS_TYPE} filesystem"
    echo "  • Mount at ${MOUNT_POINT}"
    echo
    read -p "Do you want to continue? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_message "INFO" "Operation cancelled by user"
        exit 0
    fi
fi

# Execute storage provisioning steps
log_message "INFO" "Starting storage provisioning..."

create_partition "$DISK" "$PARTITION" || exit 1
create_physical_volume "/dev/${DISK}${PARTITION}" || exit 1
create_volume_group "$VG_NAME" "/dev/${DISK}${PARTITION}" || exit 1
create_logical_volume "$VG_NAME" "$LV_NAME" || exit 1
create_filesystem "$FS_TYPE" "$VG_NAME" "$LV_NAME" || exit 1
mount_filesystem "$FS_TYPE" "$VG_NAME" "$LV_NAME" "$MOUNT_POINT" || exit 1

# Display summary
display_summary

log_message "INFO" "Storage provisioning completed successfully"
exit 0

:'
# Basic usage
./setup-storage.sh -d sdb -p 1 -v datavg -l datalv -f xfs -m /u01

# With force mode (no confirmations)
./setup-storage.sh --disk nvme0n1 --partition 1 --vg-name appvg \
                   --lv-name applv --fs-type ext4 --mount-point /data --force

# Quiet mode for automation
./setup-storage.sh -d sdc -p 1 -v datavg -l datalv -f xfs -m /data --quiet

# Get help
./setup-storage.sh --help
'
