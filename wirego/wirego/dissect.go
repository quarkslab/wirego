package wirego

import "C"
import (
	"fmt"
	"unsafe"
)

type DissectResultFlattenEntry struct {
	Protocol string
	Info     string
	fields   []DissectResultFlatten
}
type DissectResultFlatten struct {
	parentIdx     int
	wiregoFieldId FieldId
	offset        int
	length        int
}

/*
  Note: there's probably a way to return the complete DissectResult structure
	to the C environment. At the end of the day, this would be super opaque so for now
	let's use some dummy accessors and a result cache.
*/
//export wirego_dissect_packet
func wirego_dissect_packet(packetNumber C.int, src *C.char, dst *C.char, layer *C.char, packet *C.char, packetSize C.int) C.int {
	if wg.listener == nil || wg.resultsCache == nil {
		return C.int(-1)
	}

	if (src == nil) || (dst == nil) || (layer == nil) || (packet == nil) || packetSize == 0 {
		return C.int(-1)
	}

	wg.lock.Lock()
	_, found := wg.resultsCache[packetNumber]
	wg.lock.Unlock()

	if found {
		return packetNumber
	}

	result := wg.listener.DissectPacket(int(packetNumber), C.GoString(src), C.GoString(dst), C.GoString(layer), C.GoBytes(unsafe.Pointer(packet), packetSize))

	if result == nil {
		return C.int(-1)
	}

	//Check results
	for _, r := range result.Fields {
		if C.int(r.Offset) >= packetSize {
			fmt.Printf("Wirego plugin did return an invalid Offset : %d (packet size is %d bytes)\n", r.Offset, packetSize)
			return C.int(-1)
		}
		if C.int(r.Offset+r.Length) > packetSize {
			fmt.Printf("Wirego plugin did return an invalid Length : %d (offset is %d and packet size is %d bytes)\n", r.Length, r.Offset, packetSize)
			return C.int(-1)
		}
		_, found := wg.wiregoFieldIds[int(r.WiregoFieldId)]
		if !found {
			fmt.Printf("Wirego plugin did return an invalid WiregoFieldId : %d\n", r.WiregoFieldId)
			return C.int(-1)
		}
	}

	//Flatten results to a simple list with parenIdx pointing to parent's entry
	var flatten DissectResultFlattenEntry
	flatten.Info = result.Info
	flatten.Protocol = result.Protocol
	for _, r := range result.Fields {
		addFieldsRec(&flatten, -1, &r)
	}

	//Add to cache
	pinner.Pin(&flatten)
	wg.lock.Lock()
	defer wg.lock.Unlock()
	wg.resultsCache[packetNumber] = &flatten
	return packetNumber
}

func addFieldsRec(flatten *DissectResultFlattenEntry, parentIdx int, field *DissectField) {
	flatten.fields = append(flatten.fields, DissectResultFlatten{parentIdx: parentIdx, wiregoFieldId: field.WiregoFieldId, offset: field.Offset, length: field.Length})
	newParentIdx := len(flatten.fields) - 1

	for _, sub := range field.SubFields {
		addFieldsRec(flatten, newParentIdx, &sub)
	}
}
