package gtp5gnl

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// WNC: Config holds the system-specific kernel parameters for netlink message sizing
type Config struct {
	PageSize     int `yaml:"page_size"`
	MaxSKBFrags  int `yaml:"max_skb_frags"`
	SKBOverhead  int `yaml:"skb_overhead"`
	NlmsgHdrLen  int `yaml:"nlmsg_hdrlen"`
}

// WNC: configPaths returns the list of paths to search for the config file
func configPaths() []string {
	paths := []string{}

	// 1. Environment variable override
	if envPath := os.Getenv("GTP5GNL_CONFIG"); envPath != "" {
		paths = append(paths, envPath)
	}

	// 2. Current working directory
	if cwd, err := os.Getwd(); err == nil {
		paths = append(paths, filepath.Join(cwd, "go-gtp5gnl.yaml"))
	}

	// 3. Executable directory
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		paths = append(paths, filepath.Join(exeDir, "go-gtp5gnl.yaml"))
	}

	// 4. System config directory
	paths = append(paths, "/etc/go-gtp5gnl/go-gtp5gnl.yaml")

	return paths
}

// WNC: loadConfig attempts to load configuration from file
func loadConfig() (*Config, error) {
	paths := configPaths()

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			// File exists, try to load it
			config, err := parseConfigFile(path)
			if err != nil {
				return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
			}

			// Validate config
			if err := validateConfig(config); err != nil {
				return nil, fmt.Errorf("invalid config in %s: %w", path, err)
			}

			if os.Getenv("GTP5GNL_DEBUG") != "" {
				log.Printf("WNC: [go-gtp5gnl] Loaded config from: %s", path)
				log.Printf("WNC: [go-gtp5gnl] Config: %+v", config)
			}

			return config, nil
		}
	}

	return nil, fmt.Errorf("config file not found in any of: %v", paths)
}

// WNC: parseConfigFile reads and parses a YAML config file
// WNC: Simple YAML parser for our specific use case (avoids external dependencies)
func parseConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := &Config{}
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		// Skip comments and empty lines
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse "key: value" format
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Parse integer value
		intVal, err := strconv.Atoi(value)
		if err != nil {
			return nil, fmt.Errorf("invalid integer value for %s: %s", key, value)
		}

		// Assign to config struct
		switch key {
		case "page_size":
			config.PageSize = intVal
		case "max_skb_frags":
			config.MaxSKBFrags = intVal
		case "skb_overhead":
			config.SKBOverhead = intVal
		case "nlmsg_hdrlen":
			config.NlmsgHdrLen = intVal
		}
	}

	return config, nil
}

// WNC: validateConfig checks if the config values are reasonable
func validateConfig(config *Config) error {
	if config.PageSize <= 0 {
		return fmt.Errorf("page_size must be positive, got %d", config.PageSize)
	}

	// Common page sizes: 4096, 8192, 16384, 65536
	validPageSizes := []int{4096, 8192, 16384, 32768, 65536}
	validPageSize := false
	for _, size := range validPageSizes {
		if config.PageSize == size {
			validPageSize = true
			break
		}
	}
	if !validPageSize {
		log.Printf("WNC: [go-gtp5gnl] WARNING: Unusual page_size=%d (expected one of %v)",
			config.PageSize, validPageSizes)
	}

	if config.MaxSKBFrags <= 0 || config.MaxSKBFrags > 256 {
		return fmt.Errorf("max_skb_frags must be between 1 and 256, got %d", config.MaxSKBFrags)
	}

	// WNC: Auto-calculate expected skb_overhead from max_skb_frags to prevent drift
	// WNC: Formula: SKB_DATA_ALIGN(sizeof(struct skb_shared_info))
	// WNC:   where sizeof(skb_shared_info) ≈ 48 + (16 * max_skb_frags)
	// WNC:   and SKB_DATA_ALIGN rounds up to 64-byte boundary
	expectedStructSize := 48 + (16 * config.MaxSKBFrags)
	expectedOverhead := (expectedStructSize + 63) & ^63 // WNC: SKB_DATA_ALIGN

	// WNC: Treat skb_overhead mismatch as FATAL to prevent silent corruption
	// WNC: The provided skb_overhead must match the calculated value from max_skb_frags
	if config.SKBOverhead != expectedOverhead {
		return fmt.Errorf("WNC: skb_overhead=%d doesn't match calculated value %d for max_skb_frags=%d. "+
			"Please regenerate go-gtp5gnl.yaml with detect_kernel_params.sh to fix this drift",
			config.SKBOverhead, expectedOverhead, config.MaxSKBFrags)
	}

	// WNC: Additional sanity check on the calculated overhead
	if config.SKBOverhead <= 0 || config.SKBOverhead > 4096 {
		return fmt.Errorf("calculated skb_overhead=%d is out of reasonable range (1-4096)", config.SKBOverhead)
	}

	if config.NlmsgHdrLen != 16 {
		return fmt.Errorf("nlmsg_hdrlen must be 16, got %d", config.NlmsgHdrLen)
	}

	return nil
}

// WNC: calculateNlmsgSizes calculates the netlink message size limits from config
func calculateNlmsgSizes(config *Config) (nlmsgGood uint32, nlmsgDefault uint32) {
	// WNC: Kernel logic: if PAGE_SIZE < 8192, use PAGE_SIZE, otherwise use 8192
	var baseSize int
	if config.PageSize < 8192 {
		baseSize = config.PageSize
	} else {
		baseSize = 8192
	}

	// WNC: Prevent integer underflow - fail fast if skb_overhead is invalid
	if config.SKBOverhead >= baseSize {
		// WNC: This would cause uint32 wraparound to huge value - abort immediately
		log.Fatalf("WNC: [go-gtp5gnl] FATAL: skb_overhead=%d >= baseSize=%d, would cause integer underflow. "+
			"Check go-gtp5gnl.yaml or regenerate with detect_kernel_params.sh",
			config.SKBOverhead, baseSize)
	}

	// WNC: NLMSG_GOODSIZE = SKB_WITH_OVERHEAD(baseSize) = baseSize - skb_overhead
	nlmsgGood = uint32(baseSize - config.SKBOverhead)

	// WNC: Sanity check - ensure we have a reasonable minimum payload size
	const minSafePayload = 1024 // WNC: Minimum 1KB payload to avoid degenerate cases
	if nlmsgGood < minSafePayload {
		log.Fatalf("WNC: [go-gtp5gnl] FATAL: calculated nlmsgGood=%d < minimum safe payload %d. "+
			"baseSize=%d, skb_overhead=%d. Check configuration.",
			nlmsgGood, minSafePayload, baseSize, config.SKBOverhead)
	}

	// WNC: NLMSG_DEFAULT_SIZE = NLMSG_GOODSIZE - NLMSG_HDRLEN
	nlmsgDefault = nlmsgGood - uint32(config.NlmsgHdrLen)

	return nlmsgGood, nlmsgDefault
}

// WNC: getDefaultConfig returns a conservative default configuration
// WNC: This is used as a fallback if no config file is found
func getDefaultConfig() *Config {
	return &Config{
		PageSize:    4096, // WNC: Most common x86_64 page size
		MaxSKBFrags: 17,   // WNC: Most common for modern kernels
		SKBOverhead: 320,  // WNC: Calculated for max_skb_frags=17
		NlmsgHdrLen: 16,   // WNC: Standard netlink header size
	}
}
