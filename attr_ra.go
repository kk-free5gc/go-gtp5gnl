package gtp5gnl

// WNC: Router Advertisement injection attributes
// Corresponds to gtp5g/include/genl_ra.h enum gtp5g_ra_attrs

const (
	ATTR_RA_UNSPEC = iota
	ATTR_RA_SEID     // u64 - PFCP Session ID
	ATTR_RA_PDR_ID   // u16 - PDR ID to identify UE
	ATTR_RA_PACKET   // binary - Raw ICMPv6 RA packet
	ATTR_RA_MAX
)
