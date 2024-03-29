package wirego

import "C"
import (
	"fmt"
	"unsafe"
)

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

	//Add to cache
	pinner.Pin(&result)
	wg.lock.Lock()
	defer wg.lock.Unlock()
	wg.resultsCache[packetNumber] = result
	return packetNumber
}
