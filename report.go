package gtp5gnl

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

	"github.com/khirono/go-genl"
	"github.com/khirono/go-nl"
)

/*
WNC: Test hook to track chunk function calls during testing.

	When non-nil, getMultiReportsOIDChunk calls this instead of actual netlink I/O.
	Format: func(client, link, oids, chunkOffset) -> (reports, error)
	The chunkOffset parameter allows tests to verify chunk-level logging and offset tracking.
*/
var testChunkHook func(*Client, *Link, []OID, int) ([]USAReport, error)

/*
WNC: Test hook to intercept Client.Do() calls for testing netlink request serialization.

	When non-nil, this hook is called instead of the real netlink Do() operation.
	This allows tests to inspect the fully-built netlink request (after all TLV packing)
	without requiring a real kernel module. The hook receives the complete nl.Request
	and should return mock nl.Msg responses.
*/
var testClientDoHook func(*nl.Request) ([]nl.Msg, error)

/*
WNC: dumpNetlinkRequest serializes the netlink request buffer from Iovs and logs
the raw bytes in hex format, along with parsed attribute headers for debugging.
This helps identify TLV packing issues, padding problems, or incorrect message lengths.
*/
func dumpNetlinkRequest(req *nl.Request, chunkOffset int) {
	if !DebugLogging {
		return
	}

	// Serialize all Iovs into a single buffer
	var totalLen int
	for _, iov := range req.Iovs {
		totalLen += int(iov.Len)
	}

	buf := make([]byte, totalLen)
	offset := 0
	for _, iov := range req.Iovs {
		// Copy from iovec base pointer
		iovBytes := (*[1 << 30]byte)(unsafe.Pointer(iov.Base))[:iov.Len:iov.Len]
		copy(buf[offset:], iovBytes)
		offset += int(iov.Len)
	}

	log.Printf("[go-gtp5gnl] WNC: chunk[%d] netlink request dump:", chunkOffset)
	log.Printf("[go-gtp5gnl] WNC: chunk[%d]   Total buffer length: %d bytes", chunkOffset, len(buf))
	log.Printf("[go-gtp5gnl] WNC: chunk[%d]   Header.Len: %d", chunkOffset, req.Header.Len)
	log.Printf("[go-gtp5gnl] WNC: chunk[%d]   Raw hex dump:\n%s", chunkOffset, hex.Dump(buf))

	// Parse and log netlink attributes
	if len(buf) > 16 { // Skip netlink header (16 bytes) + genl header (4 bytes)
		parseNetlinkAttrs(buf[20:], chunkOffset, 0)
	}
}

/*
WNC: parseNetlinkAttrs recursively parses and logs netlink attributes for debugging.
This shows the TLV structure, types, and values to help identify packing issues.
*/
func parseNetlinkAttrs(buf []byte, chunkOffset, depth int) {
	indent := ""
	for i := 0; i < depth; i++ {
		indent += "  "
	}

	offset := 0
	attrIndex := 0
	for offset < len(buf) {
		if len(buf[offset:]) < 4 {
			log.Printf("[go-gtp5gnl] WNC: chunk[%d] %s  [remaining %d bytes - too short for attr header]",
				chunkOffset, indent, len(buf[offset:]))
			break
		}

		// Parse attribute header (4 bytes: 2 bytes len, 2 bytes type)
		attrLen := native.Uint16(buf[offset : offset+2])
		attrType := native.Uint16(buf[offset+2 : offset+4])

		if attrLen < 4 || int(attrLen) > len(buf[offset:]) {
			log.Printf("[go-gtp5gnl] WNC: chunk[%d] %s  [attr %d] INVALID: len=%d type=%d (remaining=%d)",
				chunkOffset, indent, attrIndex, attrLen, attrType, len(buf[offset:]))
			break
		}

		// Log attribute header
		attrName := getAttrName(attrType)
		log.Printf("[go-gtp5gnl] WNC: chunk[%d] %s  [attr %d] type=%d(%s) len=%d",
			chunkOffset, indent, attrIndex, attrType, attrName, attrLen)

		// For nested attributes (like URR_MULTI_SEID_URRID), recurse
		// Strip NLA_F_NESTED flag (0x8000) to get actual type
		actualType := attrType & 0x7FFF
		if actualType == URR_MULTI_SEID_URRID && attrLen > 4 {
			parseNetlinkAttrs(buf[offset+4:offset+int(attrLen)], chunkOffset, depth+1)
		} else if attrLen > 4 {
			// Log value for simple attributes
			valueLen := int(attrLen) - 4
			if valueLen <= 8 {
				value := buf[offset+4 : offset+int(attrLen)]
				log.Printf("[go-gtp5gnl] WNC: chunk[%d] %s    value: %v (hex: %x)",
					chunkOffset, indent, value, value)
			}
		}

		// Move to next attribute (with alignment)
		alignedLen := (int(attrLen) + 3) & ^3 // Align to 4 bytes
		offset += alignedLen
		attrIndex++
	}

	if depth == 0 {
		log.Printf("[go-gtp5gnl] WNC: chunk[%d]   Parsed %d top-level attributes, consumed %d bytes",
			chunkOffset, attrIndex, offset)
	}
}

/*
WNC: getAttrName returns a human-readable name for attribute types for debugging.
Handles the NLA_F_NESTED flag (0x8000) that netlink sets for nested attributes.
*/
func getAttrName(attrType uint16) string {
	// Strip the NLA_F_NESTED flag (0x8000) to get the actual type
	actualType := attrType & 0x7FFF
	nested := ""
	if attrType&0x8000 != 0 {
		nested = "|NESTED"
	}

	var name string
	switch actualType {
	case LINK:
		name = "LINK"
	case URR_NUM:
		name = "URR_NUM"
	case URR_MULTI_SEID_URRID:
		name = "URR_MULTI_SEID_URRID"
	case URR_ID:
		name = "URR_ID"
	case URR_SEID:
		name = "URR_SEID"
	default:
		name = "UNKNOWN"
	}

	return name + nested
}

/*
WNC: Debug flag to control verbose chunk logging. Set via environment variable

	GTP5GNL_DEBUG=1 or programmatically. When false, only errors are logged.
	This prevents flooding stdout in production environments with high-frequency
	periodic URR polling. Consumers of go-gtp5gnl can control this per their needs.
*/
var DebugLogging = false

func init() {
	// WNC: Check environment variable for debug logging
	if os.Getenv("GTP5GNL_DEBUG") == "1" {
		DebugLogging = true
	}
	// WNC: 25-11-28 VERSION MARKER - Always printed to verify correct go-gtp5gnl version is loaded
	log.Printf("[go-gtp5gnl] WNC: 25-11-28 go-gtp5gnl report.go loaded (DebugLogging=%v)", DebugLogging)
}

func GetReport(c *Client, link *Link, urrid uint64, seid uint64) ([]USAReport, error) {
	return GetReportOID(c, link, OID{uint64(urrid), seid})
}

func GetUsageStatistic(c *Client, link *Link) (*UsageStatistic, error) {
	flags := syscall.NLM_F_ACK
	req := nl.NewRequest(c.ID, flags)

	err := req.Append(genl.Header{Cmd: CMD_GET_USAGE_STATISTIC})
	if err != nil {
		return nil, err
	}

	err = req.Append(nl.AttrList{
		{
			Type:  LINK,
			Value: nl.AttrU32(link.Index),
		},
	})
	if err != nil {
		return nil, err
	}

	rsps, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if len(rsps) < 1 {
		return nil, fmt.Errorf("nil Usage Statistic")
	}
	ustat, err := DecodeUsageStatistic(rsps[0].Body[genl.SizeofHeader:])
	if err != nil {
		return nil, err
	}
	return ustat, err
}

func GetReportOID(c *Client, link *Link, oid OID) ([]USAReport, error) {
	flags := syscall.NLM_F_ACK
	req := nl.NewRequest(c.ID, flags)
	err := req.Append(genl.Header{Cmd: CMD_GET_REPORT})
	if err != nil {
		return nil, err
	}
	urrid, ok := oid.ID()
	if !ok {
		return nil, fmt.Errorf("invalid oid: %v", oid)
	}
	err = req.Append(nl.AttrList{
		{
			Type:  LINK,
			Value: nl.AttrU32(link.Index),
		},
		{
			Type:  URR_ID,
			Value: nl.AttrU32(urrid),
		},
	})
	if err != nil {
		return nil, err
	}
	seid, ok := oid.SEID()
	if ok {
		err = req.Append(&nl.Attr{
			Type:  URR_SEID,
			Value: nl.AttrU64(seid),
		})
		if err != nil {
			return nil, err
		}
	}
	rsps, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if len(rsps) < 1 {
		return nil, fmt.Errorf("nil Report of oid(%v)", oid)
	}
	reports, err := DecodeAllUSAReports(rsps[0].Body[genl.SizeofHeader:])
	if err != nil {
		return nil, err
	}
	return reports, err
}

// map[uint64][]uint32 // key: seid, value: urrids
func GetMultiReports(c *Client, link *Link, lSeidUrridsMap map[uint64][]uint32) ([]USAReport, error) {
	var oids []OID
	for seid, urrIds := range lSeidUrridsMap {
		for _, urrId := range urrIds {
			oids = append(oids, OID{seid, uint64(urrId)})
		}
	}
	return GetMultiReportsOID(c, link, oids)
}

/*
WNC: GetMultiReportsOID retrieves usage reports for multiple URRs, automatically chunking

	large requests to prevent netlink message overflow. The function uses byte-aware chunking
	to ensure each netlink message stays within NLMSG_GOODSIZE, with URR_NUM matching the actual
	TLV count sent, preventing kernel/userland disagreement on message size.
*/
func GetMultiReportsOID(c *Client, link *Link, oids []OID) ([]USAReport, error) {
	// WNC: Use byte-aware chunking - getMultiReportsOIDChunk will determine how many OIDs fit
	var allReports []USAReport

	for i := 0; i < len(oids); {
		// WNC: Pass remaining OIDs to chunk function, which will consume as many as fit in byte budget
		remainingOids := oids[i:]

		reports, consumed, err := getMultiReportsOIDChunk(c, link, remainingOids, i)
		if err != nil {
			return nil, fmt.Errorf("[go-gtp5gnl] WNC: failed to get reports for chunk starting at %d: %w", i, err)
		}

		// WNC: Guard against infinite loop if chunk function returns 0 consumed (should not happen)
		if consumed <= 0 {
			return nil, fmt.Errorf("[go-gtp5gnl] WNC: chunk[%d] consumed 0 OIDs, aborting to prevent infinite loop", i)
		}

		allReports = append(allReports, reports...)
		i += consumed // WNC: Advance by the number of OIDs actually consumed

		if DebugLogging {
			log.Printf("[go-gtp5gnl] WNC: chunk[%d] processed %d URRs, total collected: %d/%d",
				i-consumed, consumed, len(allReports), len(oids))
		}
	}

	return allReports, nil
}

/*
WNC: getMultiReportsOIDChunk sends a single netlink request for a chunk of OIDs.

	This is the internal implementation that sets URR_NUM to the actual chunk size,
	ensuring kernel and userland agree on the message structure.
	chunkOffset is the starting index of this chunk in the original OID list (for logging).

	Returns: (reports, consumedCount, error)
	  - reports: the URR reports received from kernel
	  - consumedCount: number of OIDs actually consumed (may be less than len(oids) if byte budget exceeded)
	  - error: any error encountered
*/
func getMultiReportsOIDChunk(c *Client, link *Link, oids []OID, chunkOffset int) ([]USAReport, int, error) {
	// WNC: Calculate byte budget for this chunk
	payloadBudget := maxURRPayload()
	tlvSize := estimateURRTLVSize()
	usedBytes := 0 // Track bytes consumed by TLVs

	// WNC: Validate OIDs and build TLV list, stopping when byte budget is exceeded
	type oidPair struct {
		SEID  uint64
		URRID uint32
	}
	var tlvPairs []oidPair

	for i, oid := range oids {
		urrid, ok := oid.ID()
		if !ok {
			return nil, 0, fmt.Errorf("[go-gtp5gnl] WNC: chunk[%d] OID[%d] has invalid ID: %v", chunkOffset, chunkOffset+i, oid)
		}

		seid, ok := oid.SEID()
		if !ok {
			// WNC: Fail fast - don't silently skip OIDs without SEID as that creates URR_NUM mismatch
			return nil, 0, fmt.Errorf("[go-gtp5gnl] WNC: chunk[%d] OID[%d] missing SEID (urrid=%d): %v - caller must provide valid SEID for CMD_GET_MULTI_REPORTS",
				chunkOffset, chunkOffset+i, urrid, oid)
		}

		// WNC: Check if adding this TLV would exceed the byte budget
		if usedBytes+tlvSize > payloadBudget {
			// WNC: Stop here - we've hit the byte budget limit
			if DebugLogging {
				log.Printf("[go-gtp5gnl] WNC: chunk[%d] byte budget limit reached: usedBytes=%d + tlvSize=%d > budget=%d, stopping at %d URRs",
					chunkOffset, usedBytes, tlvSize, payloadBudget, len(tlvPairs))
			}
			break
		}

		tlvPairs = append(tlvPairs, oidPair{SEID: seid, URRID: uint32(urrid)})
		usedBytes += tlvSize
	}

	// WNC: Handle edge case where even a single TLV exceeds budget (should not happen with current sizes)
	if len(tlvPairs) == 0 && len(oids) > 0 {
		log.Printf("[go-gtp5gnl] WNC: WARNING - chunk[%d] single TLV size (%d) exceeds budget (%d), sending anyway to avoid deadlock",
			chunkOffset, tlvSize, payloadBudget)
		// Send at least one TLV to avoid infinite loop
		oid := oids[0]
		urrid, _ := oid.ID()
		seid, _ := oid.SEID()
		tlvPairs = append(tlvPairs, oidPair{SEID: seid, URRID: uint32(urrid)})
		usedBytes = tlvSize
	}

	consumedCount := len(tlvPairs)

	// WNC: Use test hook if set (for unit testing without real netlink)
	if testChunkHook != nil {
		reports, err := testChunkHook(c, link, oids[:consumedCount], chunkOffset)
		return reports, consumedCount, err
	}

	// WNC: Log byte budget tracking when debug logging is enabled
	if DebugLogging {
		log.Printf("[go-gtp5gnl] WNC: chunk[%d] byte budget: used=%d / budget=%d, URR_NUM=%d, tlvSize=%d",
			chunkOffset, usedBytes, payloadBudget, consumedCount, tlvSize)
	}

	// WNC: 25-11-28 VERSION MARKER - Always printed to verify chunk function is being called
	log.Printf("[go-gtp5gnl] WNC: 25-11-28 getMultiReportsOIDChunk called chunk[%d] URR_NUM=%d (consumed=%d from %d requested)",
		chunkOffset, consumedCount, consumedCount, len(oids))

	var attrs []nl.Attr

	flags := syscall.NLM_F_ACK
	req := nl.NewRequest(c.ID, flags)
	err := req.Append(genl.Header{Cmd: CMD_GET_MULTI_REPORTS})
	if err != nil {
		return nil, 0, err
	}
	// WNC: Set URR_NUM to actual consumed count (byte-budget limited)
	err = req.Append(nl.AttrList{
		{
			Type:  LINK,
			Value: nl.AttrU32(link.Index),
		},
		{
			Type:  URR_NUM,
			Value: nl.AttrU32(consumedCount),
		},
	})
	if err != nil {
		return nil, 0, err
	}

	// WNC: Build TLV list from validated OIDs
	for _, pair := range tlvPairs {
		if DebugLogging {
			log.Printf("[go-gtp5gnl] WNC: chunk[%d] TLV[%d] building: SEID=%d URRID=%d",
				chunkOffset, len(attrs), pair.SEID, pair.URRID)
		}
		attrs = append(attrs, nl.Attr{
			Type: URR_MULTI_SEID_URRID,
			Value: nl.AttrList{
				{
					Type:  URR_ID,
					Value: nl.AttrU32(pair.URRID),
				},
				{
					Type:  URR_SEID,
					Value: nl.AttrU64(pair.SEID),
				},
			},
		})
	}

	/* WNC: Log the actual TLVs being sent for correlation with kernel logs.
	   Only logged when DebugLogging is enabled to avoid flooding stdout in production. */
	if DebugLogging {
		log.Printf("[go-gtp5gnl] WNC: chunk[%d] sending URR_NUM=%d link=%d TLVs=%v",
			chunkOffset, consumedCount, link.Index, tlvPairs)
		log.Printf("[go-gtp5gnl] WNC: chunk[%d] before Append: built %d TLV attributes",
			chunkOffset, len(attrs))
	}

	err = req.Append(nl.AttrList(attrs))
	if err != nil {
		return nil, 0, err
	}

	if DebugLogging {
		log.Printf("[go-gtp5gnl] WNC: chunk[%d] after Append: successfully appended %d TLVs to request",
			chunkOffset, len(attrs))
	}

	// WNC: Dump the netlink request buffer before sending to kernel for debugging
	dumpNetlinkRequest(req, chunkOffset)

	rsps, err := c.Do(req)
	if err != nil {
		log.Printf("[go-gtp5gnl] WNC: chunk[%d] netlink error URR_NUM=%d: %v", chunkOffset, consumedCount, err)
		return nil, 0, err
	}
	if len(rsps) < 1 {
		return nil, 0, fmt.Errorf("nil Report")
	}
	reports, err := DecodeAllUSAReports(rsps[0].Body[genl.SizeofHeader:])
	if err != nil {
		log.Printf("[go-gtp5gnl] WNC: chunk[%d] decode error URR_NUM=%d: %v", chunkOffset, consumedCount, err)
		return nil, 0, err
	}

	/* WNC: Validate kernel response and return error on rejection or truncation.
	   len(reports)==0 means kernel rejected the request (caller must check NLMSG_ERROR and dmesg).
	   Partial counts indicate truncation. Both are error conditions that callers must handle. */
	if len(reports) != consumedCount {
		if len(reports) == 0 {
			// WNC: Kernel rejected the entire request - return error so caller can handle it
			err := fmt.Errorf("chunk[%d] REJECTED - sent URR_NUM=%d TLVs=%v, kernel returned 0 reports (check NLMSG_ERROR and dmesg)",
				chunkOffset, consumedCount, tlvPairs)
			log.Printf("[go-gtp5gnl] WNC: %v", err)
			return nil, 0, err
		} else {
			// WNC: Kernel truncated the response - return error with partial data info
			err := fmt.Errorf("chunk[%d] TRUNCATION - sent URR_NUM=%d TLVs=%v, kernel returned %d reports (partial)",
				chunkOffset, consumedCount, tlvPairs, len(reports))
			log.Printf("[go-gtp5gnl] WNC: %v", err)
			return nil, 0, err
		}
	}

	if DebugLogging {
		log.Printf("[go-gtp5gnl] WNC: chunk[%d] SUCCESS - URR_NUM=%d, received %d reports",
			chunkOffset, consumedCount, len(reports))
	}

	return reports, consumedCount, nil
}
