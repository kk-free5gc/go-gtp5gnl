package gtp5gnl

import (
	"time"
	"unsafe"

	"github.com/khirono/go-nl"
)

// for UPF Usage Statistic
const (
	USTAT_UL_VOL_RX = iota + 1
	USTAT_UL_VOL_TX
	USTAT_DL_VOL_RX
	USTAT_DL_VOL_TX

	USTAT_UL_PKT_RX
	USTAT_UL_PKT_TX
	USTAT_DL_PKT_RX
	USTAT_DL_PKT_TX
)

type UsageStatistic struct {
	TotalVolRx uint64
	TotalVolTx uint64
	UlVolRx    uint64
	UlVolTx    uint64
	DlVolRx    uint64
	DlVolTx    uint64
	TotalPktRx uint64
	TotalPktTx uint64
	UlPktRx    uint64
	UlPktTx    uint64
	DlPktRx    uint64
	DlPktTx    uint64
}

const (
	UR = iota + 5
)

const (
	UR_URRID = iota + 3
	UR_USAGE_REPORT_TRIGGER
	UR_URSEQN
	UR_VOLUME_MEASUREMENT
	UR_QUERY_URR_REFERENCE
	UR_START_TIME
	UR_END_TIME
	UR_SEID
)

const (
	UR_VOLUME_MEASUREMENT_FLAGS = iota + 1

	UR_VOLUME_MEASUREMENT_TOVOL
	UR_VOLUME_MEASUREMENT_UVOL
	UR_VOLUME_MEASUREMENT_DVOL

	UR_VOLUME_MEASUREMENT_TOPACKET
	UR_VOLUME_MEASUREMENT_UPACKET
	UR_VOLUME_MEASUREMENT_DPACKET
)

const (
	TOVOL uint8 = 1 << iota
	ULVOL
	DLVOL
	TONOP
	ULNOP
	DLNOP
)

type USAReport struct {
	URRID          uint32
	URSEQN         uint32
	USARTrigger    uint32
	VolMeasurement VolumeMeasurement
	QueryUrrRef    uint32
	StartTime      time.Time
	EndTime        time.Time
	SEID           uint64
}

type VolumeMeasurement struct {
	Flag           uint8
	TotalVolume    uint64
	UplinkVolume   uint64
	DownlinkVolume uint64
	TotalPktNum    uint64
	UplinkPktNum   uint64
	DownlinkPktNum uint64
}

// WNC: Netlink message size constants
const (
	NETLIMK_ATTR_HDR_SIZE = 4

	/* WNC: maxUsageReportsPerMsg caps the URR batch size for safety.
	   The actual limit is calculated dynamically from available netlink message space,
	   but we cap at 64 URRs as a practical upper bound. This prevents:
	   - Memory exhaustion from extremely large batches
	   - Excessive processing time for single messages
	   - Edge cases in kernel netlink handling

	   With proper configuration (go-gtp5gnl.yaml), the system will use the maximum
	   safe batch size up to this cap based on actual kernel parameters. */
	maxUsageReportsPerMsg = 64
)

// WNC: getMaxNetlinkMsgBodySize returns the maximum netlink message body size
// based on the configured nlmsgGoodSize minus overhead for headers and fixed attributes.
//
// Calculation:
//   nlmsgGoodSize (from config) - netlink overhead = available payload space
//   Overhead = 16 (nl header) + 4 (genl header) + 8 (LINK attr) + 8 (URR_NUM attr) = 36 bytes
//
// This replaces the old hardcoded MAX_NETLINK_MSG_BODY_SIZE = 7856 which was incorrect
// for systems with different page sizes or kernel configurations.
func getMaxNetlinkMsgBodySize() int {
	const (
		nlHeaderSize   = 16 // nl.Header size
		genlHeaderSize = 4  // genl.Header size
		linkAttrSize   = 8  // LINK attribute: 4 (header) + 4 (u32) aligned
		urrNumAttrSize = 8  // URR_NUM attribute: 4 (header) + 4 (u32) aligned
	)

	overhead := nlHeaderSize + genlHeaderSize + linkAttrSize + urrNumAttrSize
	maxBodySize := int(nlmsgGoodSize) - overhead

	return maxBodySize
}

/*
WNC: Test hook to override MaxNetlinkUsageReportNum return value.

	When non-nil, MaxNetlinkUsageReportNum returns this value instead of calculating.
	Used to test guard logic for edge cases (zero/negative batch sizes).
*/
var testMaxBatchSizeHook *int

// The netlink attribute size of UR need to count the UR header(4) + size of the attributes (and it's header) in UR
func MaxNetlinkUsageReportNum() int {
	// WNC: Allow test override to force edge cases
	if testMaxBatchSizeHook != nil {
		return *testMaxBatchSizeHook
	}

	size := NETLIMK_ATTR_HDR_SIZE // UR attr header

	size += NETLIMK_ATTR_HDR_SIZE         // UR_URRID attr header
	size += int(unsafe.Sizeof(uint32(0))) // UR_URRID attr data

	size += NETLIMK_ATTR_HDR_SIZE         // UR_USAGE_REPORT_TRIGGER attr header
	size += int(unsafe.Sizeof(uint32(0))) // UR_USAGE_REPORT_TRIGGER attr data

	size += NETLIMK_ATTR_HDR_SIZE         // UR_URSEQN attr header
	size += int(unsafe.Sizeof(uint32(0))) // UR_URSEQN attr data

	size += NETLIMK_ATTR_HDR_SIZE         // UR_VOLUME_MEASUREMENT attr header
	size += NETLIMK_ATTR_HDR_SIZE         // UR_VOLUME_MEASUREMENT_TOVOL attr header
	size += int(unsafe.Sizeof(uint64(0))) // UR_VOLUME_MEASUREMENT_TOVOL attr data
	size += NETLIMK_ATTR_HDR_SIZE         // UR_VOLUME_MEASUREMENT_UVOL attr header
	size += int(unsafe.Sizeof(uint64(0))) // UR_VOLUME_MEASUREMENT_UVOL attr data
	size += NETLIMK_ATTR_HDR_SIZE         // UR_VOLUME_MEASUREMENT_DVOL attr header
	size += int(unsafe.Sizeof(uint64(0))) // UR_VOLUME_MEASUREMENT_DVOL attr data
	size += NETLIMK_ATTR_HDR_SIZE         // UR_VOLUME_MEASUREMENT_TOPACKET attr header
	size += int(unsafe.Sizeof(uint64(0))) // UR_VOLUME_MEASUREMENT_TOPACKET attr data
	size += NETLIMK_ATTR_HDR_SIZE         // UR_VOLUME_MEASUREMENT_UPACKET attr header
	size += int(unsafe.Sizeof(uint64(0))) // UR_VOLUME_MEASUREMENT_UPACKET attr data
	size += NETLIMK_ATTR_HDR_SIZE         // UR_VOLUME_MEASUREMENT_DPACKET attr header
	size += int(unsafe.Sizeof(uint64(0))) // UR_VOLUME_MEASUREMENT_DPACKET attr data

	size += NETLIMK_ATTR_HDR_SIZE         // UR_START_TIME attr header
	size += int(unsafe.Sizeof(uint64(0))) // UR_START_TIME attr data

	size += NETLIMK_ATTR_HDR_SIZE         // UR_END_TIME attr header
	size += int(unsafe.Sizeof(uint64(0))) // UR_END_TIME attr data

	size += NETLIMK_ATTR_HDR_SIZE         // UR_SEID attr header
	size += int(unsafe.Sizeof(uint64(0))) // UR_SEID attr data

	// WNC: Calculate maximum URRs based on dynamic netlink message size
	maxBodySize := getMaxNetlinkMsgBodySize()
	rawCalculatedLimit := maxBodySize / size

	// WNC: Return the minimum of calculated limit and safe batch size cap
	if rawCalculatedLimit > maxUsageReportsPerMsg {
		return maxUsageReportsPerMsg
	}
	return rawCalculatedLimit
}

/*
WNC: maxURRPayload returns the maximum safe payload size for URR batching.
This is NLMSG_GOODSIZE minus the overhead for netlink/genl headers and fixed attributes.

The calculation:
  - nlmsgGoodSize: typically 8192 bytes (from linux/netlink.h)
  - Netlink header: 16 bytes (nl.Header)
  - Generic netlink header: 4 bytes (genl.Header)
  - LINK attribute: 4 (attr header) + 4 (u32 value) = 8 bytes aligned
  - URR_NUM attribute: 4 (attr header) + 4 (u32 value) = 8 bytes aligned
  - Total overhead: 16 + 4 + 8 + 8 = 36 bytes
  - Available payload: nlmsgGoodSize - 36

This ensures each netlink message stays within the kernel's safe size limit.
*/
func maxURRPayload() int {
	const (
		nlHeaderSize   = 16 // nl.Header size (from msg.go)
		genlHeaderSize = 4  // genl.Header size (genl.SizeofHeader)
		linkAttrSize   = 8  // LINK attribute: 4 (header) + 4 (u32) aligned
		urrNumAttrSize = 8  // URR_NUM attribute: 4 (header) + 4 (u32) aligned
	)

	headerSlack := nlHeaderSize + genlHeaderSize + linkAttrSize + urrNumAttrSize
	return int(nlmsgGoodSize) - headerSlack
}

/*
WNC: estimateURRTLVSize calculates the serialized size of a single URR_MULTI_SEID_URRID TLV.

The structure is:
  URR_MULTI_SEID_URRID (nested attribute)
    ├─ Outer TLV header: 4 bytes
    ├─ URR_ID: 4 (header) + 4 (u32) = 8 bytes
    └─ URR_SEID: 4 (header) + 8 (u64) = 12 bytes
  Total unaligned: 4 + 8 + 12 = 24 bytes
  Total aligned: 24 bytes (already 4-byte aligned)

This matches the actual encoding in getMultiReportsOIDChunk where each TLV contains
nested URR_ID (u32) and URR_SEID (u64) attributes.
*/
func estimateURRTLVSize() int {
	const (
		attrHeaderSize = 4 // nl.AttrHdr size
	)

	// Outer URR_MULTI_SEID_URRID attribute header
	size := attrHeaderSize

	// URR_ID nested attribute: header + u32 value
	urrIdSize := attrHeaderSize + 4
	size += urrIdSize

	// URR_SEID nested attribute: header + u64 value
	urrSeidSize := attrHeaderSize + 8
	size += urrSeidSize

	// Align to 4-byte boundary (netlink requirement)
	alignedSize := (size + 3) &^ 3

	return alignedSize
}

func decodeVolumeMeasurement(b []byte) (VolumeMeasurement, error) {
	var VolMeasurement VolumeMeasurement
	for len(b) > 0 {
		hdr, n, err := nl.DecodeAttrHdr(b)
		if err != nil {
			return VolMeasurement, err
		}
		attrLen := int(hdr.Len)
		switch hdr.MaskedType() {
		case UR_VOLUME_MEASUREMENT_TOVOL:
			v := native.Uint64(b[n:attrLen])
			VolMeasurement.TotalVolume = v
			VolMeasurement.Flag |= TOVOL
		case UR_VOLUME_MEASUREMENT_UVOL:
			v := native.Uint64(b[n:attrLen])
			VolMeasurement.UplinkVolume = v
			VolMeasurement.Flag |= ULVOL
		case UR_VOLUME_MEASUREMENT_DVOL:
			v := native.Uint64(b[n:attrLen])
			VolMeasurement.DownlinkVolume = v
			VolMeasurement.Flag |= DLVOL
		case UR_VOLUME_MEASUREMENT_TOPACKET:
			v := native.Uint64(b[n:attrLen])
			VolMeasurement.TotalPktNum = v
			VolMeasurement.Flag |= TONOP
		case UR_VOLUME_MEASUREMENT_UPACKET:
			v := native.Uint64(b[n:attrLen])
			VolMeasurement.UplinkPktNum = v
			VolMeasurement.Flag |= ULNOP
		case UR_VOLUME_MEASUREMENT_DPACKET:
			v := native.Uint64(b[n:attrLen])
			VolMeasurement.DownlinkPktNum = v
			VolMeasurement.Flag |= DLNOP
		default:
			return VolMeasurement, nil
		}

		b = b[hdr.Len.Align():]
	}
	return VolMeasurement, nil
}

func DecodeUsageStatistic(b []byte) (*UsageStatistic, error) {
	ustat := new(UsageStatistic)

	for len(b) > 0 {
		hdr, n, err := nl.DecodeAttrHdr(b)
		if err != nil {
			return nil, err
		}
		attrLen := int(hdr.Len)
		switch hdr.MaskedType() {
		case USTAT_UL_VOL_RX:
			ustat.UlVolRx = native.Uint64(b[n:attrLen])
		case USTAT_UL_VOL_TX:
			ustat.UlVolTx = native.Uint64(b[n:attrLen])
		case USTAT_DL_VOL_RX:
			ustat.DlVolRx = native.Uint64(b[n:attrLen])
		case USTAT_DL_VOL_TX:
			ustat.DlVolTx = native.Uint64(b[n:attrLen])
		case USTAT_UL_PKT_RX:
			ustat.UlPktRx = native.Uint64(b[n:attrLen])
		case USTAT_UL_PKT_TX:
			ustat.UlPktTx = native.Uint64(b[n:attrLen])
		case USTAT_DL_PKT_RX:
			ustat.DlPktRx = native.Uint64(b[n:attrLen])
		case USTAT_DL_PKT_TX:
			ustat.DlPktTx = native.Uint64(b[n:attrLen])
		}

		b = b[hdr.Len.Align():]
	}

	// total volume count
	ustat.TotalVolRx = ustat.UlVolRx + ustat.DlVolRx
	ustat.TotalVolTx = ustat.UlVolTx + ustat.DlVolTx

	// total packet count
	ustat.TotalPktRx = ustat.UlPktRx + ustat.DlPktRx
	ustat.TotalPktTx = ustat.UlPktTx + ustat.DlPktTx

	return ustat, nil
}

func DecodeAllUSAReports(b []byte) ([]USAReport, error) {
	var usars []USAReport

	for len(b) > 0 {
		hdr, n, err := nl.DecodeAttrHdr(b)
		if err != nil {
			return nil, err
		}
		attrLen := int(hdr.Len)
		switch hdr.MaskedType() {
		case UR:
			r, err := decodeUSAReport(b[n:attrLen])
			if err != nil {
				return nil, err
			}
			usars = append(usars, *r)
		}

		b = b[hdr.Len.Align():]
	}
	return usars, nil
}

func decodeUSAReport(b []byte) (*USAReport, error) {
	report := new(USAReport)

	for len(b) > 0 {
		hdr, n, err := nl.DecodeAttrHdr(b)
		if err != nil {
			return nil, err
		}
		attrLen := int(hdr.Len)
		switch hdr.MaskedType() {
		case UR_URRID:
			report.URRID = native.Uint32(b[n:attrLen])
		case UR_USAGE_REPORT_TRIGGER:
			report.USARTrigger = native.Uint32(b[n:attrLen])
		case UR_URSEQN:
			report.URSEQN = native.Uint32(b[n:attrLen])
		case UR_VOLUME_MEASUREMENT:
			volMeasurement, err := decodeVolumeMeasurement(b[n:attrLen])
			if err != nil {
				return nil, err
			}
			report.VolMeasurement = volMeasurement
		case UR_START_TIME:
			v := native.Uint64(b[n:attrLen])
			report.StartTime = time.Unix(0, int64(v))
		case UR_END_TIME:
			v := native.Uint64(b[n:attrLen])
			report.EndTime = time.Unix(0, int64(v))
		case UR_SEID:
			report.SEID = native.Uint64(b[n:attrLen])
		}

		b = b[hdr.Len.Align():]
	}
	return report, nil
}
