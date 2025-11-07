// WNC: Custom file for querying gtp5g kernel module feature capabilities
// This file implements GTP5G_CMD_GET_FEATURES support to properly detect
// runtime IPv6 support based on the ipv6_data_path module parameter
package gtp5gnl

import (
	"fmt"
	"syscall"

	"github.com/khirono/go-genl"
	"github.com/khirono/go-nl"
)

// Features represents gtp5g kernel module feature capabilities
type Features struct {
	Version         string
	IPv6DataPath    bool
}

// GetFeatures queries the gtp5g kernel module for supported features
func GetFeatures(c *Client) (*Features, error) {
	flags := syscall.NLM_F_ACK
	req := nl.NewRequest(c.ID, flags)
	err := req.Append(genl.Header{Cmd: CMD_GET_FEATURES})
	if err != nil {
		return nil, err
	}

	rsps, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if len(rsps) != 1 {
		return nil, fmt.Errorf("invalid Features response")
	}

	features, err := DecodeFeatures(rsps[0].Body[genl.SizeofHeader:])
	if err != nil {
		return nil, err
	}
	return features, nil
}
