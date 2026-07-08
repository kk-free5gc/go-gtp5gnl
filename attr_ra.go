package gtp5gnl

// WNC: Router Advertisement injection attributes
// Corresponds to gtp5g/include/genl_ra.h enum gtp5g_ra_attrs

// WNC FIX: RA attrs share the single gtp5g attribute namespace. Type 1 (LINK) and
// 2 (NET_NS_FD) are reserved device attrs, and LINK is sent in the same inject-ra
// message, so RA attrs MUST start at 3 (mirrors PDR_ID = iota + 3 in attr_pdr.go).
// Previously ATTR_RA_SEID=1 collided with LINK=1, so the kernel rejected the
// message with EINVAL before the handler ran. These MUST match gtp5g genl_ra.h.
const (
	ATTR_RA_UNSPEC = iota // 0
	_                     // 1 = LINK (reserved device attr)
	_                     // 2 = NET_NS_FD (reserved device attr)
	ATTR_RA_SEID          // 3 - u64  PFCP Session ID
	ATTR_RA_PDR_ID        // 4 - u16  PDR ID to identify UE
	ATTR_RA_PACKET        // 5 - binary  Raw ICMPv6 RA packet
	ATTR_RA_MAX
)
