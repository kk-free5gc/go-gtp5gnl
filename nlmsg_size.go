package gtp5gnl

import (
	"log"
	"os"
)

// WNC: NLMSG_GOODSIZE constants for netlink message size limits
//
// NLMSG_GOODSIZE is defined in kernel headers (/usr/src/linux-headers-XXX/include/linux/netlink.h):
//   #if PAGE_SIZE < 8192UL
//   #define NLMSG_GOODSIZE  SKB_WITH_OVERHEAD(PAGE_SIZE)
//   #else
//   #define NLMSG_GOODSIZE  SKB_WITH_OVERHEAD(8192UL)
//   #endif
//
// Where SKB_WITH_OVERHEAD(X) = X - SKB_DATA_ALIGN(sizeof(struct skb_shared_info))
//
// However, NLMSG_GOODSIZE is only available in kernel space (requires linux/skbuff.h
// which is not available in userspace). Therefore, we cannot use cgo to retrieve it.
//
// IMPORTANT: The value depends on system-specific kernel parameters:
//   - PAGE_SIZE: System page size (typically 4096, 8192, 16384, or 65536 bytes)
//   - CONFIG_MAX_SKB_FRAGS: Maximum number of SKB fragments (typically 16, 17, or 18)
//   - SKB_DATA_ALIGN(sizeof(struct skb_shared_info)): Aligned size of SKB shared info
//
// These values are now loaded from a configuration file (go-gtp5gnl.yaml) which must be
// generated on each target system using the provided detection script:
//
//   ./scripts/detect_kernel_params.sh > go-gtp5gnl.yaml
//
// See CONFIG.md for detailed instructions on how to generate and configure these values.

var (
	// nlmsgGoodSize is the safe maximum size for a single netlink message payload
	// Calculated as: SKB_WITH_OVERHEAD(baseSize) where baseSize = min(PAGE_SIZE, 8192)
	nlmsgGoodSize uint32

	// nlmsgDefaultSize is NLMSG_DEFAULT_SIZE from kernel
	// Defined as: NLMSG_GOODSIZE - NLMSG_HDRLEN
	nlmsgDefaultSize uint32
)

// WNC: init loads configuration and calculates netlink message size limits
func init() {
	var config *Config
	var err error

	// WNC: Try to load configuration from file
	config, err = loadConfig()
	if err != nil {
		// WNC: Config file not found or invalid, use default
		if os.Getenv("GTP5GNL_DEBUG") != "" {
			log.Printf("WNC: [go-gtp5gnl] WARNING: %v", err)
			log.Printf("WNC: [go-gtp5gnl] Using default configuration (may not be optimal for this system)")
			log.Printf("WNC: [go-gtp5gnl] Please run: ./scripts/detect_kernel_params.sh > go-gtp5gnl.yaml")
		}
		config = getDefaultConfig()
	}

	// WNC: Calculate netlink message sizes from config
	nlmsgGoodSize, nlmsgDefaultSize = calculateNlmsgSizes(config)

	// WNC: Log the calculated values for debugging
	if os.Getenv("GTP5GNL_DEBUG") != "" {
		log.Printf("WNC: [go-gtp5gnl] Configuration:")
		log.Printf("WNC: [go-gtp5gnl]   PAGE_SIZE = %d", config.PageSize)
		log.Printf("WNC: [go-gtp5gnl]   MAX_SKB_FRAGS = %d", config.MaxSKBFrags)
		log.Printf("WNC: [go-gtp5gnl]   SKB_OVERHEAD = %d", config.SKBOverhead)
		log.Printf("WNC: [go-gtp5gnl]   NLMSG_HDRLEN = %d", config.NlmsgHdrLen)
		log.Printf("WNC: [go-gtp5gnl] Calculated values:")
		log.Printf("WNC: [go-gtp5gnl]   nlmsgGoodSize = %d", nlmsgGoodSize)
		log.Printf("WNC: [go-gtp5gnl]   nlmsgDefaultSize = %d", nlmsgDefaultSize)
	}
}

// WNC: GetNlmsgGoodSize returns the current nlmsgGoodSize value (for testing/debugging)
func GetNlmsgGoodSize() uint32 {
	return nlmsgGoodSize
}

// WNC: GetNlmsgDefaultSize returns the current nlmsgDefaultSize value (for testing/debugging)
func GetNlmsgDefaultSize() uint32 {
	return nlmsgDefaultSize
}
