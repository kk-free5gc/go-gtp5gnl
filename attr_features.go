// WNC: Custom file for decoding GTP5G_CMD_GET_FEATURES responses
// This file handles netlink attribute parsing for kernel feature capabilities
package gtp5gnl

import (
	"bytes"

	"github.com/khirono/go-nl"
)

const (
	FEATURES_VERSION = 1
	FEATURES_IPV6_DATAPATH = 2
)

// DecodeFeatures decodes the GTP5G_CMD_GET_FEATURES response
func DecodeFeatures(b []byte) (*Features, error) {
	features := &Features{}

	for len(b) > 0 {
		hdr, n, err := nl.DecodeAttrHdr(b)
		if err != nil {
			return nil, err
		}

		attrLen := int(hdr.Len)
		switch hdr.Type {
		case FEATURES_VERSION:
			features.Version = string(bytes.Trim(b[n:attrLen], "\x00"))
		case FEATURES_IPV6_DATAPATH:
			if attrLen-n >= 1 {
				features.IPv6DataPath = (b[n] != 0)
			}
		}

		b = b[hdr.Len.Align():]
	}

	return features, nil
}
