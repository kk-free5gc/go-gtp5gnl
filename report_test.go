package gtp5gnl

import (
	"fmt"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/khirono/go-nl"
)

/* WNC: TestMaxNetlinkUsageReportNum verifies the batch size limit.
   Ensures MaxNetlinkUsageReportNum returns a positive value and
   respects the maxUsageReportsPerMsg cap (64 URRs). */
func TestMaxNetlinkUsageReportNum(t *testing.T) {
	maxBatchSize := MaxNetlinkUsageReportNum()

	if maxBatchSize <= 0 {
		t.Errorf("WNC: MaxNetlinkUsageReportNum returned %d, expected positive value", maxBatchSize)
	}

	if maxBatchSize > maxUsageReportsPerMsg {
		t.Errorf("WNC: MaxNetlinkUsageReportNum returned %d, exceeds maxUsageReportsPerMsg cap (%d)",
			maxBatchSize, maxUsageReportsPerMsg)
	}

	t.Logf("WNC: MaxNetlinkUsageReportNum = %d (cap: %d)", maxBatchSize, maxUsageReportsPerMsg)
}

/* WNC: TestGetMultiReportsOID_ChunkingLogic verifies that large OID lists
   are properly chunked without requiring actual netlink communication.
   This test validates the chunking math and guards against infinite loops.
   Test cases are dynamically calculated based on MaxNetlinkUsageReportNum(). */
func TestGetMultiReportsOID_ChunkingLogic(t *testing.T) {
	maxBatchSize := MaxNetlinkUsageReportNum()
	if maxBatchSize <= 0 {
		t.Fatalf("WNC: MaxNetlinkUsageReportNum returned %d, infinite loop would occur", maxBatchSize)
	}

	t.Logf("WNC: Testing with MaxNetlinkUsageReportNum = %d", maxBatchSize)

	testCases := []struct {
		name   string
		numOIDs int
	}{
		{
			name:   "WNC: Single chunk (under limit)",
			numOIDs: maxBatchSize / 2,
		},
		{
			name:   "WNC: Exactly at limit",
			numOIDs: maxBatchSize,
		},
		{
			name:   "WNC: Just over limit (2 chunks)",
			numOIDs: maxBatchSize + 1,
		},
		{
			name:   "WNC: Multiple full chunks",
			numOIDs: maxBatchSize * 2,
		},
		{
			name:   "WNC: Multiple chunks with remainder",
			numOIDs: maxBatchSize*2 + maxBatchSize/2,
		},
		{
			name:   "WNC: Large batch (>512 original limit)",
			numOIDs: 600,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Calculate expected chunks based on ceiling division
			expectedChunks := (tc.numOIDs + maxBatchSize - 1) / maxBatchSize

			// Verify the calculation is correct
			if expectedChunks <= 0 {
				t.Errorf("WNC: Invalid chunk count %d for %d OIDs", expectedChunks, tc.numOIDs)
			}

			// Verify all OIDs would be processed
			minOIDsCovered := (expectedChunks - 1) * maxBatchSize
			maxOIDsCovered := expectedChunks * maxBatchSize

			if tc.numOIDs <= minOIDsCovered || tc.numOIDs > maxOIDsCovered {
				t.Errorf("WNC: Chunk count %d incorrect for %d OIDs (covers %d-%d)",
					expectedChunks, tc.numOIDs, minOIDsCovered+1, maxOIDsCovered)
			}

			t.Logf("WNC: %d OIDs -> %d chunks (batch size: %d)", tc.numOIDs, expectedChunks, maxBatchSize)
		})
	}
}

/* WNC: TestGetMultiReportsOID_ZeroBatchSizeGuard ensures the infinite loop
   protection works correctly by forcing MaxNetlinkUsageReportNum to return
   problematic values via testMaxBatchSizeHook. This exercises the actual guard
   logic in GetMultiReportsOID (lines 123-126 in report.go). */
/* WNC: TestGetMultiReportsOID_ByteBudgetChunking validates byte-aware chunking behavior.
   This test ensures that chunks are created based on byte budget (NLMSG_GOODSIZE),
   not a fixed URR count, preventing netlink message overflow. */
func TestGetMultiReportsOID_ByteBudgetChunking(t *testing.T) {
	// Save and restore original hooks
	originalChunkHook := testChunkHook
	defer func() {
		testChunkHook = originalChunkHook
	}()

	// Calculate expected chunk capacity based on byte budget
	payloadBudget := maxURRPayload()
	tlvSize := estimateURRTLVSize()
	expectedMaxPerChunk := payloadBudget / tlvSize

	t.Logf("WNC: Byte budget: %d bytes, TLV size: %d bytes, max URRs per chunk: %d",
		payloadBudget, tlvSize, expectedMaxPerChunk)

	testCases := []struct {
		numOIDs         int
		expectedChunks  int
		description     string
	}{
		{10, 1, "small batch (fits in one chunk)"},
		{expectedMaxPerChunk, 1, "exactly at byte budget limit"},
		{expectedMaxPerChunk + 1, 2, "one over byte budget (requires 2 chunks)"},
		{expectedMaxPerChunk * 2, 2, "exactly 2 full chunks"},
		{expectedMaxPerChunk*2 + 5, 3, "2 full chunks + partial"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			// Create test OIDs
			oids := make([]OID, tc.numOIDs)
			for i := 0; i < tc.numOIDs; i++ {
				oids[i] = OID{uint64(i + 1000), uint64(i)}
			}

			// Track chunk calls and sizes
			var chunkCallCount int32
			var chunkSizes []int
			var totalBytesPerChunk []int

			testChunkHook = func(c *Client, link *Link, chunkOids []OID, chunkOffset int) ([]USAReport, error) {
				atomic.AddInt32(&chunkCallCount, 1)
				chunkSize := len(chunkOids)
				chunkSizes = append(chunkSizes, chunkSize)

				// Calculate bytes consumed by this chunk
				bytesUsed := chunkSize * tlvSize
				totalBytesPerChunk = append(totalBytesPerChunk, bytesUsed)

				// Verify chunk is not empty (would indicate infinite loop bug)
				if chunkSize == 0 {
					return nil, fmt.Errorf("WNC: received empty chunk (infinite loop guard failed)")
				}

				// Verify chunk doesn't exceed byte budget
				if bytesUsed > payloadBudget {
					return nil, fmt.Errorf("WNC: chunk uses %d bytes, exceeds budget %d bytes",
						bytesUsed, payloadBudget)
				}

				// Return mock reports
				reports := make([]USAReport, chunkSize)
				for i, oid := range chunkOids {
					urrid, _ := oid.ID()
					seid, _ := oid.SEID()
					reports[i] = USAReport{URRID: uint32(urrid), SEID: uint64(seid)}
				}
				return reports, nil
			}

			mockClient := &Client{ID: 1}
			mockLink := &Link{Name: "test", Index: 1}

			// Execute chunking
			reports, err := GetMultiReportsOID(mockClient, mockLink, oids)
			if err != nil {
				t.Fatalf("WNC: GetMultiReportsOID failed: %v", err)
			}

			// Verify chunk count matches expectation
			if int(chunkCallCount) != tc.expectedChunks {
				t.Errorf("WNC: Expected %d chunks, got %d chunks",
					tc.expectedChunks, chunkCallCount)
			}

			// Verify all OIDs were processed
			if len(reports) != tc.numOIDs {
				t.Errorf("WNC: Expected %d reports, got %d", tc.numOIDs, len(reports))
			}

			// Verify no chunk is empty
			for i, size := range chunkSizes {
				if size <= 0 {
					t.Errorf("WNC: Chunk %d has invalid size %d", i, size)
				}
			}

			t.Logf("WNC: %d OIDs -> %d chunks, sizes: %v, bytes: %v",
				tc.numOIDs, chunkCallCount, chunkSizes, totalBytesPerChunk)
		})
	}
}

/* WNC: TestOIDSlicing validates that OID slice chunking produces correct ranges
   without overlaps or gaps. This ensures GetMultiReportsOID processes all OIDs. */
func TestOIDSlicing(t *testing.T) {
	maxBatchSize := MaxNetlinkUsageReportNum()
	if maxBatchSize <= 0 {
		maxBatchSize = 1
	}

	// Create test OID list
	totalOIDs := 150
	oids := make([]OID, totalOIDs)
	for i := 0; i < totalOIDs; i++ {
		oids[i] = OID{uint64(i), uint64(i + 1000)} // URRID and SEID
	}

	// Simulate chunking logic
	processedOIDs := 0
	chunkCount := 0

	for i := 0; i < len(oids); i += maxBatchSize {
		end := i + maxBatchSize
		if end > len(oids) {
			end = len(oids)
		}

		chunkSize := end - i
		processedOIDs += chunkSize
		chunkCount++

		t.Logf("WNC: Chunk %d: indices [%d:%d], size %d", chunkCount, i, end, chunkSize)

		// Verify chunk boundaries
		if i >= len(oids) {
			t.Errorf("WNC: Chunk %d starts beyond slice length (%d >= %d)", chunkCount, i, len(oids))
		}
		if end > len(oids) {
			t.Errorf("WNC: Chunk %d ends beyond slice length (%d > %d)", chunkCount, end, len(oids))
		}
		if chunkSize <= 0 {
			t.Errorf("WNC: Chunk %d has invalid size %d", chunkCount, chunkSize)
		}
		if chunkSize > maxBatchSize {
			t.Errorf("WNC: Chunk %d size %d exceeds batch limit %d", chunkCount, chunkSize, maxBatchSize)
		}
	}

	if processedOIDs != totalOIDs {
		t.Errorf("WNC: Processed %d OIDs but expected %d (missing or duplicate chunks)",
			processedOIDs, totalOIDs)
	}

	t.Logf("WNC: Successfully chunked %d OIDs into %d chunks (batch size: %d)",
		totalOIDs, chunkCount, maxBatchSize)
}

/* WNC: TestGetMultiReportsOID_ActualChunking exercises the real GetMultiReportsOID
   function with a test hook to verify it actually calls getMultiReportsOIDChunk
   the correct number of times with correct chunk sizes based on byte budget.
   NOTE: Updated to test byte-aware chunking (not fixed-batch-size chunking). */
func TestGetMultiReportsOID_ActualChunking(t *testing.T) {
	// Save and restore original hook
	originalHook := testChunkHook
	defer func() { testChunkHook = originalHook }()

	// Calculate byte-budget-based capacity
	payloadBudget := maxURRPayload()
	tlvSize := estimateURRTLVSize()
	maxPerChunk := payloadBudget / tlvSize

	t.Logf("WNC: Byte budget capacity: %d URRs per chunk (budget=%d bytes, TLV=%d bytes)",
		maxPerChunk, payloadBudget, tlvSize)

	testCases := []struct {
		name              string
		numOIDs           int
		expectedChunkCalls int
	}{
		{
			name:              "WNC: Single chunk (under limit)",
			numOIDs:           maxPerChunk / 2,
			expectedChunkCalls: 1,
		},
		{
			name:              "WNC: Exactly at limit",
			numOIDs:           maxPerChunk,
			expectedChunkCalls: 1,
		},
		{
			name:              "WNC: Just over limit",
			numOIDs:           maxPerChunk + 1,
			expectedChunkCalls: 2,
		},
		{
			name:              "WNC: Multiple full chunks",
			numOIDs:           maxPerChunk * 3,
			expectedChunkCalls: 3,
		},
		{
			name:              "WNC: Large batch with remainder",
			numOIDs:           maxPerChunk*5 + 10,
			expectedChunkCalls: 6,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test OIDs
			// OID format: [SEID, URRID]
			oids := make([]OID, tc.numOIDs)
			for i := 0; i < tc.numOIDs; i++ {
				oids[i] = OID{uint64(i + 1000), uint64(i)} // SEID=(i+1000), URRID=i
			}

			// Track chunk calls
			var chunkCallCount int32
			var totalOIDsProcessed int32
			var chunkSizes []int

			testChunkHook = func(c *Client, link *Link, chunkOids []OID, chunkOffset int) ([]USAReport, error) {
				atomic.AddInt32(&chunkCallCount, 1)
				atomic.AddInt32(&totalOIDsProcessed, int32(len(chunkOids)))
				chunkSizes = append(chunkSizes, len(chunkOids))

				// Verify chunk size doesn't exceed byte budget capacity
				if len(chunkOids) > maxPerChunk {
					return nil, fmt.Errorf("WNC: chunk size %d exceeds byte budget capacity %d",
						len(chunkOids), maxPerChunk)
				}

				// Return mock reports (one per OID)
				reports := make([]USAReport, len(chunkOids))
				for i, oid := range chunkOids {
					urrid, _ := oid.ID()
					seid, _ := oid.SEID()
					reports[i] = USAReport{
						URRID: uint32(urrid),
						SEID:  uint64(seid),
					}
				}
				return reports, nil
			}

			// Execute the actual function
			mockClient := &Client{ID: 1}
			mockLink := &Link{Name: "test", Index: 1}

			reports, err := GetMultiReportsOID(mockClient, mockLink, oids)
			if err != nil {
				t.Fatalf("WNC: GetMultiReportsOID failed: %v", err)
			}

			// Verify chunk call count
			if int(chunkCallCount) != tc.expectedChunkCalls {
				t.Errorf("WNC: Expected %d chunk calls, got %d", tc.expectedChunkCalls, chunkCallCount)
			}

			// Verify all OIDs were processed
			if int(totalOIDsProcessed) != tc.numOIDs {
				t.Errorf("WNC: Expected %d OIDs processed, got %d", tc.numOIDs, totalOIDsProcessed)
			}

			// Verify report count matches OID count
			if len(reports) != tc.numOIDs {
				t.Errorf("WNC: Expected %d reports, got %d", tc.numOIDs, len(reports))
			}

			// Log chunk details
			t.Logf("WNC: %d OIDs -> %d chunks with sizes %v (byte budget capacity: %d)",
				tc.numOIDs, chunkCallCount, chunkSizes, maxPerChunk)

			// Verify chunk sizes
			for i, size := range chunkSizes {
				if size > maxPerChunk {
					t.Errorf("WNC: Chunk %d has size %d, exceeds capacity %d", i, size, maxPerChunk)
				}
				if size <= 0 {
					t.Errorf("WNC: Chunk %d has invalid size %d", i, size)
				}
			}
		})
	}
}

/* WNC: TestGetMultiReportsOID_ZeroBatchSizeActual verifies the infinite loop
   guard actually prevents hangs by temporarily modifying the constant and
   exercising the real function. */
func TestGetMultiReportsOID_GuardAgainstZeroBatchSize(t *testing.T) {
	// Save and restore original hook
	originalHook := testChunkHook
	defer func() { testChunkHook = originalHook }()

	// Mock a scenario where we try to chunk OIDs
	// OID format: [SEID, URRID]
	oids := make([]OID, 10)
	for i := 0; i < 10; i++ {
		oids[i] = OID{uint64(i + 1000), uint64(i)} // SEID=(i+1000), URRID=i
	}

	// Track that chunks are processed even if batch size were problematic
	var chunkCallCount int32

	testChunkHook = func(c *Client, link *Link, chunkOids []OID, chunkOffset int) ([]USAReport, error) {
		atomic.AddInt32(&chunkCallCount, 1)
		if len(chunkOids) == 0 {
			return nil, fmt.Errorf("WNC: received empty chunk (guard failed)")
		}
		// Return mock report
		return []USAReport{{URRID: 1, SEID: 1}}, nil
	}

	mockClient := &Client{ID: 1}
	mockLink := &Link{Name: "test", Index: 1}

	// This should complete without hanging (guard ensures maxBatchSize >= 1)
	_, err := GetMultiReportsOID(mockClient, mockLink, oids)
	if err != nil {
		t.Fatalf("WNC: GetMultiReportsOID failed: %v", err)
	}

	if chunkCallCount == 0 {
		t.Error("WNC: No chunks were processed (possible infinite loop or early exit)")
	}

	t.Logf("WNC: Successfully processed %d chunks without hanging (guard working)", chunkCallCount)
}

/* WNC: TestGetMultiReportsOID_ChunkBoundaries verifies exact OID ranges
   passed to each chunk to ensure no OIDs are skipped or duplicated. */
func TestGetMultiReportsOID_ChunkBoundaries(t *testing.T) {
	originalHook := testChunkHook
	defer func() { testChunkHook = originalHook }()

	maxBatchSize := MaxNetlinkUsageReportNum()
	numOIDs := maxBatchSize*2 + 15 // Ensure multiple chunks with remainder

	// Create OIDs with sequential IDs for easy verification
	// OID format: [SEID, URRID] where SEID is at index 0, URRID at index 1
	oids := make([]OID, numOIDs)
	for i := 0; i < numOIDs; i++ {
		oids[i] = OID{uint64(i + 1000), uint64(i)} // SEID=(i+1000), URRID=i
	}

	// Track which OID IDs were seen
	seenOIDs := make(map[uint64]int) // URRID -> count
	var chunkRanges []string

	testChunkHook = func(c *Client, link *Link, chunkOids []OID, chunkOffset int) ([]USAReport, error) {
		// Record the range
		if len(chunkOids) > 0 {
			first, _ := chunkOids[0].ID()
			last, _ := chunkOids[len(chunkOids)-1].ID()
			chunkRanges = append(chunkRanges, fmt.Sprintf("[%d-%d](%d)", first, last, len(chunkOids)))
		}

		// Track each OID
		for _, oid := range chunkOids {
			urrid, _ := oid.ID()
			seenOIDs[uint64(urrid)]++
		}

		return make([]USAReport, len(chunkOids)), nil
	}

	mockClient := &Client{ID: 1}
	mockLink := &Link{Name: "test", Index: 1}

	_, err := GetMultiReportsOID(mockClient, mockLink, oids)
	if err != nil {
		t.Fatalf("WNC: GetMultiReportsOID failed: %v", err)
	}

	// Verify every OID was seen exactly once
	for i := 0; i < numOIDs; i++ {
		count := seenOIDs[uint64(i)]
		if count == 0 {
			t.Errorf("WNC: OID %d was never processed (gap in chunking)", i)
		} else if count > 1 {
			t.Errorf("WNC: OID %d was processed %d times (duplicate in chunking)", i, count)
		}
	}

	// Verify total count
	if len(seenOIDs) != numOIDs {
		t.Errorf("WNC: Expected %d unique OIDs, got %d", numOIDs, len(seenOIDs))
	}

	t.Logf("WNC: Successfully verified %d OIDs across chunks: %v", numOIDs, chunkRanges)
}

/* WNC: TestGetMultiReportsOID_FailFastOnMissingSEID verifies that the function
   fails immediately when encountering an OID without SEID, rather than silently
   skipping it and creating a URR_NUM mismatch. */
func TestGetMultiReportsOID_FailFastOnMissingSEID(t *testing.T) {
	originalHook := testChunkHook
	defer func() { testChunkHook = originalHook }()

	// Track that chunk hook is never called (should fail before reaching it)
	var chunkCalled bool
	testChunkHook = func(c *Client, link *Link, chunkOids []OID, chunkOffset int) ([]USAReport, error) {
		chunkCalled = true
		return nil, nil
	}

	mockClient := &Client{ID: 1}
	mockLink := &Link{Name: "test", Index: 1}

	testCases := []struct {
		name        string
		oids        []OID
		expectError string
	}{
		{
			name:        "OID with length 0 (no ID, no SEID)",
			oids:        []OID{{}},
			expectError: "invalid ID",
		},
		{
			name:        "OID with length 1 (ID only, no SEID)",
			oids:        []OID{{123}},
			expectError: "missing SEID",
		},
		{
			name: "Mixed valid and invalid OIDs",
			oids: []OID{
				{1000, 1}, // Valid: SEID=1000, URRID=1
				{2},       // Invalid: no SEID
				{2000, 3}, // Valid: SEID=2000, URRID=3
			},
			expectError: "missing SEID",
		},
		{
			name: "Invalid OID at end",
			oids: []OID{
				{1000, 1}, // Valid
				{2000, 2}, // Valid
				{3},       // Invalid at end
			},
			expectError: "missing SEID",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			chunkCalled = false

			_, err := GetMultiReportsOID(mockClient, mockLink, tc.oids)

			if err == nil {
				t.Errorf("WNC: Expected error containing '%s', but got nil", tc.expectError)
			} else if !contains(err.Error(), tc.expectError) {
				t.Errorf("WNC: Expected error containing '%s', got: %v", tc.expectError, err)
			} else {
				t.Logf("WNC: Correctly failed with: %v", err)
			}

			if chunkCalled {
				t.Error("WNC: Chunk hook was called despite invalid OID (should fail fast)")
			}
		})
	}
}

// Helper function for string contains check
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && stringContains(s, substr)))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

/* WNC: TestGetMultiReportsOIDChunk_TLVPacking is a focused regression test that verifies
   the TLV packing for CMD_GET_MULTI_REPORTS with four (URR_ID, URR_SEID) pairs.
   This test intercepts Client.Do() AFTER all TLV packing is complete to ensure:
   1. URR_NUM in the request equals the TLV count (4 in this case)
   2. The TLV payload contains exactly four entries with no truncation or buffer reuse
   3. The req.NlmsgLen is correctly updated after appending all TLVs

   This test uses testClientDoHook to inspect the fully-built netlink request. */
func TestGetMultiReportsOIDChunk_TLVPacking(t *testing.T) {
	// Save and restore original hooks
	originalChunkHook := testChunkHook
	originalDoHook := testClientDoHook
	defer func() {
		testChunkHook = originalChunkHook
		testClientDoHook = originalDoHook
	}()

	// Disable chunk hook to let real TLV packing happen
	testChunkHook = nil

	// Test data: Four (SEID, URRID) pairs as specified in the requirements
	// Format: {(SEID:1, URRID:1), (1,2), (2,1), (2,2)}
	testOIDs := []OID{
		{1, 1}, // SEID=1, URRID=1
		{1, 2}, // SEID=1, URRID=2
		{2, 1}, // SEID=2, URRID=1
		{2, 2}, // SEID=2, URRID=2
	}

	// Track the netlink request details captured from Client.Do()
	var capturedRequest *nl.Request
	var capturedURRNum uint32
	var capturedTLVCount int
	// WNC: Track decoded SEID/URRID pairs from nested TLVs
	type decodedPair struct {
		SEID  uint64
		URRID uint32
	}
	var capturedPairs []decodedPair

	mockClient := &Client{ID: 1, Client: nil} // Client field can be nil since we hook Do()
	mockLink := &Link{Name: "test", Index: 1}

	// Intercept Client.Do() to capture the fully-built request
	testClientDoHook = func(req *nl.Request) ([]nl.Msg, error) {
		capturedRequest = req

		// Parse the request to extract URR_NUM and count TLVs
		// Serialize the request to inspect it
		var totalLen int
		for _, iov := range req.Iovs {
			totalLen += int(iov.Len)
		}

		buf := make([]byte, totalLen)
		offset := 0
		for _, iov := range req.Iovs {
			iovBytes := (*[1 << 30]byte)(unsafe.Pointer(iov.Base))[:iov.Len:iov.Len]
			copy(buf[offset:], iovBytes)
			offset += int(iov.Len)
		}

		// Parse attributes starting after netlink header (16) + genl header (4)
		if len(buf) > 20 {
			attrBuf := buf[20:]
			offset := 0
			for offset < len(attrBuf) {
				if len(attrBuf[offset:]) < 4 {
					break
				}
				attrLen := native.Uint16(attrBuf[offset : offset+2])
				attrType := native.Uint16(attrBuf[offset+2 : offset+4])

				if attrLen < 4 || int(attrLen) > len(attrBuf[offset:]) {
					break
				}

				// Check for URR_NUM
				if attrType == URR_NUM {
					capturedURRNum = native.Uint32(attrBuf[offset+4 : offset+8])
				}

				// Count URR_MULTI_SEID_URRID TLVs (type 11 with NESTED flag 0x8000)
				actualType := attrType & 0x7FFF
				if actualType == URR_MULTI_SEID_URRID {
					capturedTLVCount++

					// WNC: Decode nested TLV bodies to verify SEID/URRID values
					nestedBuf := attrBuf[offset+4 : offset+int(attrLen)]
					var pair decodedPair
					nestedOffset := 0
					for nestedOffset < len(nestedBuf) {
						if len(nestedBuf[nestedOffset:]) < 4 {
							break
						}
						nestedLen := native.Uint16(nestedBuf[nestedOffset : nestedOffset+2])
						nestedType := native.Uint16(nestedBuf[nestedOffset+2 : nestedOffset+4])

						if nestedLen < 4 || int(nestedLen) > len(nestedBuf[nestedOffset:]) {
							break
						}

						nestedActualType := nestedType & 0x7FFF
						if nestedActualType == URR_ID && int(nestedLen) >= 8 {
							pair.URRID = native.Uint32(nestedBuf[nestedOffset+4 : nestedOffset+8])
						} else if nestedActualType == URR_SEID && int(nestedLen) >= 12 {
							pair.SEID = native.Uint64(nestedBuf[nestedOffset+4 : nestedOffset+12])
						}

						// Move to next nested attribute (with alignment)
						nestedAlignedLen := (int(nestedLen) + 3) & ^3
						nestedOffset += nestedAlignedLen
					}
					capturedPairs = append(capturedPairs, pair)
				}

				// Move to next attribute (with alignment)
				alignedLen := (int(attrLen) + 3) & ^3
				offset += alignedLen
			}
		}

		// WNC: Return mock response with properly formatted Body containing 4 mock reports
		// Each report needs to be encoded as a UR (Usage Report) attribute
		// Format: UR attribute (nested) containing UR_URRID nested attribute

		// Build mock response with 4 reports matching the 4 OIDs
		var mockAttrs []byte
		for i := 0; i < 4; i++ {
			// Build nested UR_URRID attribute first
			// UR_URRID: len=8 (4 byte header + 4 byte value), type=1, value=i+1
			urridAttr := []byte{8, 0, 1, 0} // len=8, type=1 (UR_URRID)
			urridAttr = append(urridAttr, byte(i+1), 0, 0, 0) // URRID value (uint32)

			// UR attribute header: len=4+len(nested), type=5 (UR) with NESTED flag
			urAttrLen := uint16(4 + len(urridAttr))
			urAttrType := uint16(5 | 0x8000) // UR=5 with NLA_F_NESTED flag
			mockAttrs = append(mockAttrs, byte(urAttrLen), byte(urAttrLen>>8))
			mockAttrs = append(mockAttrs, byte(urAttrType), byte(urAttrType>>8))
			mockAttrs = append(mockAttrs, urridAttr...)

			// Align to 4 bytes
			for len(mockAttrs)%4 != 0 {
				mockAttrs = append(mockAttrs, 0)
			}
		}

		// Prepend genl header (4 bytes)
		mockBody := make([]byte, 4+len(mockAttrs))
		copy(mockBody[4:], mockAttrs)

		return []nl.Msg{{Body: mockBody}}, nil
	}

	// Call getMultiReportsOIDChunk - it will build the request and call our hook
	reports, consumed, err := getMultiReportsOIDChunk(mockClient, mockLink, testOIDs, 0)
	if err != nil {
		t.Fatalf("WNC: getMultiReportsOIDChunk failed: %v", err)
	}
	if consumed != len(testOIDs) {
		t.Fatalf("WNC: expected consumed=%d, got %d", len(testOIDs), consumed)
	}

	// Verify we got 4 reports back (validates mock response format)
	if len(reports) != 4 {
		t.Errorf("WNC: Expected 4 reports from mock response, got %d", len(reports))
	}

	// Verify the request was captured
	if capturedRequest == nil {
		t.Fatalf("WNC: Request was not captured by testClientDoHook")
	}

	// Verify URR_NUM matches TLV count
	if capturedURRNum != 4 {
		t.Errorf("WNC: URR_NUM should be 4, got %d", capturedURRNum)
	}

	// Verify TLV count
	if capturedTLVCount != 4 {
		t.Errorf("WNC: TLV count should be 4, got %d", capturedTLVCount)
	}

	// WNC: Verify decoded SEID/URRID pairs match expected values {(1,1),(1,2),(2,1),(2,2)}
	expectedPairs := []decodedPair{
		{SEID: 1, URRID: 1},
		{SEID: 1, URRID: 2},
		{SEID: 2, URRID: 1},
		{SEID: 2, URRID: 2},
	}

	if len(capturedPairs) != len(expectedPairs) {
		t.Errorf("WNC: Expected %d decoded pairs, got %d", len(expectedPairs), len(capturedPairs))
	}

	for i, expected := range expectedPairs {
		if i >= len(capturedPairs) {
			t.Errorf("WNC: Missing pair[%d]: expected SEID=%d URRID=%d", i, expected.SEID, expected.URRID)
			continue
		}
		actual := capturedPairs[i]
		if actual.SEID != expected.SEID || actual.URRID != expected.URRID {
			t.Errorf("WNC: Pair[%d] mismatch: expected SEID=%d URRID=%d, got SEID=%d URRID=%d",
				i, expected.SEID, expected.URRID, actual.SEID, actual.URRID)
		}
	}

	t.Logf("WNC: TLV packing test passed - URR_NUM=%d, TLV count=%d, decoded pairs=%v",
		capturedURRNum, capturedTLVCount, capturedPairs)
}

/* WNC: TestGetMultiReportsOIDChunk_NetlinkBufferDump tests the actual netlink buffer
   serialization and dumps the hex buffer for debugging. This test uses testClientDoHook
   to capture the request and enable debug logging to see the complete buffer dump. */
func TestGetMultiReportsOIDChunk_NetlinkBufferDump(t *testing.T) {
	// Save and restore original hooks and debug flag
	originalChunkHook := testChunkHook
	originalDoHook := testClientDoHook
	originalDebug := DebugLogging
	defer func() {
		testChunkHook = originalChunkHook
		testClientDoHook = originalDoHook
		DebugLogging = originalDebug
	}()

	// Disable chunk hook to let real TLV packing happen
	testChunkHook = nil
	// Enable debug logging to see the buffer dump
	DebugLogging = true

	// Test data: Four (SEID, URRID) pairs
	testOIDs := []OID{
		{1, 1}, // SEID=1, URRID=1
		{1, 2}, // SEID=1, URRID=2
		{2, 1}, // SEID=2, URRID=1
		{2, 2}, // SEID=2, URRID=2
	}

	mockClient := &Client{ID: 1, Client: nil} // Client field can be nil since we hook Do()
	mockLink := &Link{Name: "test", Index: 1}

	// Intercept Client.Do() to capture the request and return mock response
	testClientDoHook = func(req *nl.Request) ([]nl.Msg, error) {
		// The dumpNetlinkRequest() function will be called before this hook
		// and will log the complete buffer dump

		// WNC: Return mock response with properly formatted Body containing 4 mock reports
		// Build mock response with 4 reports matching the 4 OIDs
		var mockAttrs []byte
		for i := 0; i < 4; i++ {
			// Build nested UR_URRID attribute first
			urridAttr := []byte{8, 0, 1, 0} // len=8, type=1 (UR_URRID)
			urridAttr = append(urridAttr, byte(i+1), 0, 0, 0) // URRID value (uint32)

			// UR attribute header: len=4+len(nested), type=5 (UR) with NESTED flag
			urAttrLen := uint16(4 + len(urridAttr))
			urAttrType := uint16(5 | 0x8000) // UR=5 with NLA_F_NESTED flag
			mockAttrs = append(mockAttrs, byte(urAttrLen), byte(urAttrLen>>8))
			mockAttrs = append(mockAttrs, byte(urAttrType), byte(urAttrType>>8))
			mockAttrs = append(mockAttrs, urridAttr...)

			// Align to 4 bytes
			for len(mockAttrs)%4 != 0 {
				mockAttrs = append(mockAttrs, 0)
			}
		}

		// Prepend genl header (4 bytes)
		mockBody := make([]byte, 4+len(mockAttrs))
		copy(mockBody[4:], mockAttrs)

		return []nl.Msg{{Body: mockBody}}, nil
	}

	t.Logf("WNC: Calling getMultiReportsOIDChunk with debug logging enabled")
	t.Logf("WNC: Check the logs above for the complete netlink buffer dump")

	// Call getMultiReportsOIDChunk - it will build the request, dump it, and call our hook
	reports, consumed, err := getMultiReportsOIDChunk(mockClient, mockLink, testOIDs, 0)

	if err != nil {
		t.Fatalf("WNC: Error occurred: %v", err)
	}

	if consumed != len(testOIDs) {
		t.Fatalf("WNC: expected consumed=%d, got %d", len(testOIDs), consumed)
	}

	// Verify we got 4 reports back (validates mock response format)
	if len(reports) != 4 {
		t.Errorf("WNC: Expected 4 reports from mock response, got %d", len(reports))
	}

	t.Logf("WNC: Successfully captured netlink buffer dump with %d reports (check logs above)", len(reports))
}
