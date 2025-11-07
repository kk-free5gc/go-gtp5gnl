package gtp5gnl

import (
	"fmt"

	"github.com/khirono/go-nl"
)

// WNC: Router Advertisement injection for IPv6 UEs
// Sends ICMPv6 Router Advertisement to UE via gtp5g kernel module

// InjectRA sends a Router Advertisement packet to a UE
//
// Parameters:
//   - linkID: GTP5G device link ID
//   - seid: PFCP Session ID (identifies the PDU session)
//   - pdrID: PDR ID (identifies the specific UE/flow)
//   - raPacket: Raw ICMPv6 Router Advertisement packet (including IPv6 header)
//
// Returns:
//   - error: nil on success, error on failure
//
// The packet will be injected into the GTP-U tunnel and delivered to the UE.
// This corresponds to gtp5g_genl_inject_ra() in gtp5g/src/genl/genl_ra.c
func (c *Client) InjectRA(linkID int, seid uint64, pdrID uint16, raPacket []byte) error {
	if len(raPacket) < 48 {
		return fmt.Errorf("WNC: RA packet too short (%d bytes, minimum 48)", len(raPacket))
	}

	req := nl.NewRequest(c.ID, CMD_INJECT_RA)
	req.Append(&nl.AttrList{
		{
			Type:  LINK,
			Value: nl.AttrU32(linkID),
		},
		{
			Type:  ATTR_RA_SEID,
			Value: nl.AttrU64(seid),
		},
		{
			Type:  ATTR_RA_PDR_ID,
			Value: nl.AttrU16(pdrID),
		},
		{
			Type:  ATTR_RA_PACKET,
			Value: nl.AttrBytes(raPacket),
		},
	})

	_, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("WNC: Failed to inject RA via netlink: %w", err)
	}

	return nil
}
