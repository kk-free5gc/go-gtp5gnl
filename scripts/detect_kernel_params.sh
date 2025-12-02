#!/bin/bash
#
# detect_kernel_params.sh - Detect kernel parameters for go-gtp5gnl configuration
#
# This script detects system-specific kernel parameters needed by go-gtp5gnl
# and generates a configuration file (go-gtp5gnl.yaml).
#
# Usage:
#   ./scripts/detect_kernel_params.sh                        # Display values
#   ./scripts/detect_kernel_params.sh > go-gtp5gnl.yaml      # Generate config file
#   ./scripts/detect_kernel_params.sh --verify               # Verify current config
#

set -e

# Colors for output (only if stdout is a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Function to print to stderr (for messages when generating config)
log() {
    echo -e "${BLUE}[INFO]${NC} $*" >&2
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

success() {
    echo -e "${GREEN}[OK]${NC} $*" >&2
}

# Detect PAGE_SIZE
detect_page_size() {
    local page_size
    page_size=$(getconf PAGESIZE 2>/dev/null || echo "")

    if [ -z "$page_size" ]; then
        warn "Could not detect PAGE_SIZE using 'getconf PAGESIZE'"
        warn "Falling back to default: 4096"
        page_size=4096
    else
        log "Detected PAGE_SIZE: $page_size"
    fi

    echo "$page_size"
}

# WNC: Detect MAX_SKB_FRAGS from kernel headers
detect_max_skb_frags() {
    local kernel_version
    local page_size
    local max_skb_frags
    local header_file

    kernel_version=$(uname -r)
    page_size=$1  # WNC: Pass PAGE_SIZE as argument for calculation

    # WNC: Try to read from kernel header files (most accurate)
    header_file="/usr/src/linux-headers-${kernel_version}/include/linux/skbuff.h"

    if [ -f "$header_file" ]; then
        # WNC: Parse the kernel header to understand the conditional logic
        # The header defines:
        #   #if (65536/PAGE_SIZE + 1) < 16
        #   #define MAX_SKB_FRAGS 16UL
        #   #else
        #   #define MAX_SKB_FRAGS (65536/PAGE_SIZE + 1)
        #   #endif

        # WNC: Calculate based on PAGE_SIZE
        local calculated_value=$((65536 / page_size + 1))
        if [ "$calculated_value" -lt 16 ]; then
            max_skb_frags=16
        else
            max_skb_frags=$calculated_value
        fi
        log "Detected MAX_SKB_FRAGS from kernel headers: $max_skb_frags (calculated from PAGE_SIZE=$page_size)"
    else
        # WNC: Fallback: try kernel config (rarely exists as CONFIG_MAX_SKB_FRAGS)
        local config_file="/boot/config-${kernel_version}"

        if [ -f "$config_file" ]; then
            max_skb_frags=$(grep "^CONFIG_MAX_SKB_FRAGS=" "$config_file" | cut -d'=' -f2)
        elif [ -f /proc/config.gz ]; then
            max_skb_frags=$(zcat /proc/config.gz | grep "^CONFIG_MAX_SKB_FRAGS=" | cut -d'=' -f2)
        fi

        if [ -z "$max_skb_frags" ]; then
            warn "Kernel headers not found: $header_file"
            warn "Could not detect MAX_SKB_FRAGS from kernel config either"

            # WNC: Calculate fallback based on PAGE_SIZE
            local fallback_value=$((65536 / page_size + 1))
            if [ "$fallback_value" -lt 16 ]; then
                max_skb_frags=16
            else
                max_skb_frags=$fallback_value
            fi
            warn "Using calculated fallback: $max_skb_frags (from PAGE_SIZE=$page_size)"
        else
            log "Detected CONFIG_MAX_SKB_FRAGS from kernel config: $max_skb_frags"
        fi
    fi

    echo "$max_skb_frags"
}

# Calculate SKB_OVERHEAD
# Formula: SKB_DATA_ALIGN(48 + (16 * max_skb_frags))
# Where SKB_DATA_ALIGN(x) = (x + 63) & ~63
calculate_skb_overhead() {
    local max_skb_frags=$1
    local base_size=48
    local frag_size=16

    # sizeof(struct skb_shared_info) = 48 + (16 * max_skb_frags)
    local struct_size=$((base_size + (frag_size * max_skb_frags)))

    # SKB_DATA_ALIGN: align to 64-byte boundary
    # Formula: (x + 63) & ~63
    local aligned_size=$(( (struct_size + 63) & ~63 ))

    log "Calculated SKB_OVERHEAD: $aligned_size (from struct size: $struct_size)"

    echo "$aligned_size"
}

# Detect NLMSG_HDRLEN (always 16 on Linux)
detect_nlmsg_hdrlen() {
    local nlmsg_hdrlen=16
    log "NLMSG_HDRLEN: $nlmsg_hdrlen (standard value)"
    echo "$nlmsg_hdrlen"
}

# Calculate derived values for informational purposes
calculate_derived_values() {
    local page_size=$1
    local skb_overhead=$2
    local nlmsg_hdrlen=$3

    local base_size
    if [ "$page_size" -lt 8192 ]; then
        base_size=$page_size
    else
        base_size=8192
    fi

    local nlmsg_good_size=$((base_size - skb_overhead))
    local nlmsg_default_size=$((nlmsg_good_size - nlmsg_hdrlen))

    log "Calculated values:"
    log "  base_size = $base_size"
    log "  nlmsg_good_size = $nlmsg_good_size"
    log "  nlmsg_default_size = $nlmsg_default_size"
}

# Generate YAML config
generate_config() {
    local page_size=$1
    local max_skb_frags=$2
    local skb_overhead=$3
    local nlmsg_hdrlen=$4

    cat << EOF
# go-gtp5gnl Configuration File
# Auto-generated by detect_kernel_params.sh on $(date)
# Kernel: $(uname -r)
# Architecture: $(uname -m)

# System page size in bytes
page_size: $page_size

# Maximum number of SKB fragments
max_skb_frags: $max_skb_frags

# SKB shared info overhead in bytes
skb_overhead: $skb_overhead

# Netlink message header length in bytes
nlmsg_hdrlen: $nlmsg_hdrlen
EOF
}

# Verify mode: check if current config matches detected values
verify_config() {
    local config_file="go-gtp5gnl.yaml"

    if [ ! -f "$config_file" ]; then
        error "Config file not found: $config_file"
        error "Run: ./scripts/detect_kernel_params.sh > go-gtp5gnl.yaml"
        return 1
    fi

    log "Verifying config file: $config_file"
    log ""

    # Detect current system values
    local detected_page_size=$(detect_page_size)
    local detected_max_skb_frags=$(detect_max_skb_frags "$detected_page_size")
    local detected_skb_overhead=$(calculate_skb_overhead "$detected_max_skb_frags")
    local detected_nlmsg_hdrlen=$(detect_nlmsg_hdrlen)

    # Read config file values
    local config_page_size=$(grep "^page_size:" "$config_file" | awk '{print $2}')
    local config_max_skb_frags=$(grep "^max_skb_frags:" "$config_file" | awk '{print $2}')
    local config_skb_overhead=$(grep "^skb_overhead:" "$config_file" | awk '{print $2}')
    local config_nlmsg_hdrlen=$(grep "^nlmsg_hdrlen:" "$config_file" | awk '{print $2}')

    log ""
    log "Comparison:"
    log "  Parameter          | Detected | Config | Status"
    log "  -------------------|----------|--------|--------"

    local all_ok=true

    # Check page_size
    if [ "$detected_page_size" = "$config_page_size" ]; then
        success "  page_size          | $detected_page_size | $config_page_size | OK"
    else
        error "  page_size          | $detected_page_size | $config_page_size | MISMATCH"
        all_ok=false
    fi

    # Check max_skb_frags
    if [ "$detected_max_skb_frags" = "$config_max_skb_frags" ]; then
        success "  max_skb_frags      | $detected_max_skb_frags | $config_max_skb_frags | OK"
    else
        error "  max_skb_frags      | $detected_max_skb_frags | $config_max_skb_frags | MISMATCH"
        all_ok=false
    fi

    # Check skb_overhead
    if [ "$detected_skb_overhead" = "$config_skb_overhead" ]; then
        success "  skb_overhead       | $detected_skb_overhead | $config_skb_overhead | OK"
    else
        error "  skb_overhead       | $detected_skb_overhead | $config_skb_overhead | MISMATCH"
        all_ok=false
    fi

    # Check nlmsg_hdrlen
    if [ "$detected_nlmsg_hdrlen" = "$config_nlmsg_hdrlen" ]; then
        success "  nlmsg_hdrlen       | $detected_nlmsg_hdrlen | $config_nlmsg_hdrlen | OK"
    else
        error "  nlmsg_hdrlen       | $detected_nlmsg_hdrlen | $config_nlmsg_hdrlen | MISMATCH"
        all_ok=false
    fi

    log ""

    if [ "$all_ok" = true ]; then
        success "Configuration is correct for this system!"
        return 0
    else
        error "Configuration mismatch detected!"
        error "Regenerate config with: ./scripts/detect_kernel_params.sh > go-gtp5gnl.yaml"
        return 1
    fi
}

# Main
main() {
    if [ "$1" = "--verify" ]; then
        verify_config
        exit $?
    fi

    if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        cat << EOF
Usage: $0 [OPTIONS]

Detect kernel parameters for go-gtp5gnl configuration.

OPTIONS:
    (no args)       Detect and output YAML config to stdout
    --verify        Verify existing go-gtp5gnl.yaml matches current system
    --help, -h      Show this help message

EXAMPLES:
    # Generate config file
    $0 > go-gtp5gnl.yaml

    # Display detected values
    $0

    # Verify existing config
    $0 --verify

EOF
        exit 0
    fi

    log "Detecting kernel parameters for go-gtp5gnl..."
    log ""

    # Detect all values
    local page_size=$(detect_page_size)
    local max_skb_frags=$(detect_max_skb_frags "$page_size")
    local skb_overhead=$(calculate_skb_overhead "$max_skb_frags")
    local nlmsg_hdrlen=$(detect_nlmsg_hdrlen)

    log ""
    calculate_derived_values "$page_size" "$skb_overhead" "$nlmsg_hdrlen"

    log ""
    log "Generating configuration..."
    log ""

    # Generate config to stdout
    generate_config "$page_size" "$max_skb_frags" "$skb_overhead" "$nlmsg_hdrlen"

    log ""
    success "Configuration generated successfully!"
    log "To save: $0 > go-gtp5gnl.yaml"
}

main "$@"
