//go:build cgo && disabled

// NOTE: This file is NOT USED because NLMSG_GOODSIZE is only available in kernel space.
//
// NLMSG_GOODSIZE is defined in /usr/src/linux-headers-XXX/include/linux/netlink.h as:
//   #if PAGE_SIZE < 8192UL
//   #define NLMSG_GOODSIZE  SKB_WITH_OVERHEAD(PAGE_SIZE)
//   #else
//   #define NLMSG_GOODSIZE  SKB_WITH_OVERHEAD(8192UL)
//   #endif
//
// However, this macro depends on kernel-internal headers (linux/skbuff.h) that are
// not available in userspace. The SKB_WITH_OVERHEAD macro requires struct skb_shared_info
// which is a kernel-only structure.
//
// Therefore, we cannot use cgo to retrieve the actual NLMSG_GOODSIZE value at compile time.
// Instead, we use the hardcoded standard value (8192 bytes) directly in attr_report.go.
//
// This file is kept for documentation purposes to show what we attempted and why it
// doesn't work. The "disabled" build tag ensures it's never compiled.

package gtp5gnl

/*
#include <linux/netlink.h>
#include <linux/skbuff.h>

const unsigned int go_nlmsg_goodsize = NLMSG_GOODSIZE;
const unsigned int go_nlmsg_default_size = NLMSG_DEFAULT_SIZE;
*/
import "C"

var (
	nlmsgGoodSize    = uint32(C.go_nlmsg_goodsize)
	nlmsgDefaultSize = uint32(C.go_nlmsg_default_size)
)
