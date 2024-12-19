package wirego

import (
	"encoding/binary"
	"errors"
	"fmt"

	zmq "github.com/go-zeromq/zmq4"
)

/*
This is the implementation of the Wirego's ZMQ specification.
Since this is pretty straightforward, please refer to the associated doc for details about REQ/REP, frames, encoding etc.
*/

// Define the implemented ZMQ spec version
const (
	WiregoVersionMajor = 2
	WiregoVersionMinor = 0
)

func (wg *Wirego) processPing(msg *zmq.Msg) error {
	response := zmq.NewMsg(getResultMsg(true))
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processVersion(msg *zmq.Msg) error {
	response := zmq.NewMsgFrom(getResultMsg(true), []byte{byte(WiregoVersionMajor)}, []byte{byte(WiregoVersionMinor)})
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processGetName(msg *zmq.Msg) error {
	response := zmq.NewMsgFrom(getResultMsg(true), []byte(wg.pluginName+"\x00"))
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processGetFilter(msg *zmq.Msg) error {
	response := zmq.NewMsgFrom(getResultMsg(true), []byte(wg.pluginFilter+"\x00"))
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processGetFieldsCount(msg *zmq.Msg) error {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(len(wg.pluginFields)))

	response := zmq.NewMsgFrom(getResultMsg(true), b)
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processGetField(msg *zmq.Msg) error {
	if len(msg.Frames) != 2 {
		return wg.returnFailure(errors.New("get_field failed, invalid arguments count in request"))
	}

	//Frame one contains index
	if len(msg.Frames[1]) != 4 {
		return wg.returnFailure(errors.New("get_field failed, index too short"))
	}
	index := binary.LittleEndian.Uint32(msg.Frames[1])
	if index >= uint32(len(wg.pluginFields)) {
		return wg.returnFailure(errors.New("get_field failed, index too high"))
	}

	f := wg.pluginFields[index]

	wg.wiregoFieldIds[int(f.WiregoFieldId)] = true //FIXME : backported from Wirego v1. But why?

	//Response
	//Frame 1 : wiregoFieldId
	wiregoFieldId := make([]byte, 4)
	binary.LittleEndian.PutUint32(wiregoFieldId, uint32(f.WiregoFieldId))
	//Frame 2 : name
	name := f.Name
	//Frame 3 : filter
	filter := f.Filter
	//Frame 4 : valueType
	valueType := make([]byte, 4)
	binary.LittleEndian.PutUint32(valueType, uint32(f.ValueType))
	//Frame 5 : DisplayMode
	displayMode := make([]byte, 4)
	binary.LittleEndian.PutUint32(displayMode, uint32(f.DisplayMode))

	response := zmq.NewMsgFrom(getResultMsg(true), wiregoFieldId, append([]byte(name), 0x00), append([]byte(filter), 0x00), valueType, displayMode)
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processDetectInt(msg *zmq.Msg) error {
	var matchValue int
	var filterString string
	matchValue = -1

	if len(msg.Frames) != 2 {
		return wg.returnFailure(errors.New("detect_int failed, invalid arguments count in request"))
	}

	//Frame one contains index
	if len(msg.Frames[1]) != 4 {
		return wg.returnFailure(errors.New("detect_int failed, index too short"))
	}
	idx := binary.LittleEndian.Uint32(msg.Frames[1])

	//Search for detection filter of type "int" with index idx
	cnt := 0
	for _, f := range wg.pluginDetectionFilters {
		if f.FilterType == DetectionFilterTypeInt {
			if cnt == int(idx) {
				matchValue = f.ValueInt
				filterString = f.Name
				break
			}
			cnt++
		}
	}

	//Gone too far, index is invalid
	if matchValue == -1 {
		return wg.returnFailure(nil)
	}

	//Response
	matchValueSlc := make([]byte, 4)
	binary.LittleEndian.PutUint32(matchValueSlc, uint32(matchValue))

	response := zmq.NewMsgFrom(getResultMsg(true), append([]byte(filterString), 0x00), matchValueSlc)
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processDetectString(msg *zmq.Msg) error {
	var matchValue string
	var filterString string

	if len(msg.Frames) != 2 {
		return wg.returnFailure(errors.New("detect_string failed, invalid arguments count in request"))
	}

	//Frame one contains index
	if len(msg.Frames[1]) != 4 {
		return wg.returnFailure(errors.New("detect_string failed, index too short"))
	}
	idx := binary.LittleEndian.Uint32(msg.Frames[1])

	//Search for detection filter of type "int" with index idx
	cnt := 0
	for _, f := range wg.pluginDetectionFilters {
		if f.FilterType == DetectionFilterTypeString {
			if cnt == int(idx) {
				matchValue = f.ValueString
				filterString = f.Name
				break
			}
			cnt++
		}
	}

	//Gone too far, index is invalid
	if len(matchValue) == 0 {
		return wg.returnFailure(nil)
	}

	//Response
	response := zmq.NewMsgFrom(getResultMsg(true), append([]byte(filterString), 0x00), append([]byte(matchValue), 0x00))
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processDetectHeuristicParent(msg *zmq.Msg) error {
	if len(msg.Frames) != 2 {
		return wg.returnFailure(errors.New("detect_heuristic_parent failed, invalid arguments count in request"))
	}

	//Frame one contains index
	if len(msg.Frames[1]) != 4 {
		return wg.returnFailure(errors.New("detect_heuristic_parent failed, index too short"))
	}
	idx := binary.LittleEndian.Uint32(msg.Frames[1])

	//Gone too far, index is invalid
	if idx >= uint32(len(wg.pluginDetectionHeuristicsParents)) {
		response := zmq.NewMsg(getResultMsg(false))
		return wg.zmqSocket.Send(response)
	}

	//Response
	response := zmq.NewMsgFrom(getResultMsg(true), append([]byte(wg.pluginDetectionHeuristicsParents[idx]), 0x00))
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processDetectionHeuristic(msg *zmq.Msg) error {
	var packetNumber uint32
	var src string
	var dst string
	var layer string
	var packet []byte

	if len(msg.Frames) != 6 {
		return wg.returnFailure(errors.New("detection_heuristic failed, invalid arguments count in request"))
	}

	//Frame one contains packet number
	if len(msg.Frames[1]) != 4 {
		return wg.returnFailure(errors.New("detection_heuristic failed, packet_number too short"))
	}
	packetNumber = binary.LittleEndian.Uint32(msg.Frames[1])
	src = getStringFromFrame(msg.Frames[2])
	dst = getStringFromFrame(msg.Frames[3])
	layer = getStringFromFrame(msg.Frames[4])
	packet = msg.Frames[5]

	result := wg.listener.DetectionHeuristic(int(packetNumber), src, dst, layer, packet)

	if result {
		response := zmq.NewMsgFrom(getResultMsg(true), []byte{0x01})
		return wg.zmqSocket.Send(response)
	} else {
		response := zmq.NewMsgFrom(getResultMsg(true), []byte{0x00})
		return wg.zmqSocket.Send(response)
	}
}

func (wg *Wirego) processDissectPacket(msg *zmq.Msg) error {
	var packetNumber uint32
	var src string
	var dst string
	var layer string
	var packet []byte

	if len(msg.Frames) != 6 {
		return wg.returnFailure(errors.New("dissect_packet failed, invalid arguments count in request"))
	}

	//Frame one contains packet number
	if len(msg.Frames[1]) != 4 {
		return wg.returnFailure(errors.New("dissect_packet failed, packet_number too short"))
	}
	packetNumber = binary.LittleEndian.Uint32(msg.Frames[1])
	src = getStringFromFrame(msg.Frames[2])
	dst = getStringFromFrame(msg.Frames[3])
	layer = getStringFromFrame(msg.Frames[4])
	packet = msg.Frames[5]

	//Look into the cache, if found no need to process again
	_, found := wg.resultsCache[int(packetNumber)]
	if found {
		res := make([]byte, 4)
		binary.LittleEndian.PutUint32(res, packetNumber)
		response := zmq.NewMsgFrom(getResultMsg(true), res)
		return wg.zmqSocket.Send(response)
	}

	//New packet (or cache disabled), dissect it
	result := wg.listener.DissectPacket(int(packetNumber), src, dst, layer, packet)

	if result == nil {
		return wg.returnFailure(nil)
	}

	//Check results
	for _, r := range result.Fields {
		if r.Offset >= len(packet) {
			return wg.returnFailure(fmt.Errorf("Wirego plugin did return an invalid Offset : %d (packet size is %d bytes)", r.Offset, len(packet)))
		}
		if r.Offset+r.Length > len(packet) {
			return wg.returnFailure(fmt.Errorf("Wirego plugin did return an invalid Length : %d (offset is %d and packet size is %d bytes)", r.Length, r.Offset, len(packet)))
		}
		_, found := wg.wiregoFieldIds[int(r.WiregoFieldId)]
		if !found {
			return wg.returnFailure(fmt.Errorf("Wirego plugin did return an invalid WiregoFieldId : %d", r.WiregoFieldId))
		}
	}

	//Flatten results to a simple list with parenIdx pointing to parent's entry
	var flatten DissectResultFlattenEntry
	flatten.Info = result.Info
	flatten.Protocol = result.Protocol
	for _, r := range result.Fields {
		wg.addFieldsRecursive(&flatten, -1, &r)
	}

	//Add to cache
	wg.resultsCache[int(packetNumber)] = &flatten

	res := make([]byte, 4)
	binary.LittleEndian.PutUint32(res, packetNumber)
	response := zmq.NewMsgFrom(getResultMsg(true), res)
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processResultGetProtocol(msg *zmq.Msg) error {
	if len(msg.Frames) != 2 {
		return wg.returnFailure(errors.New("result_get_protocol failed, packet_number too short"))
	}

	//Frame one contains dissect handle (ie packet number)
	if len(msg.Frames[1]) != 4 {
		return wg.returnFailure(errors.New("result_get_protocol failed, dissect_handle too short"))
	}
	dissectHandle := binary.LittleEndian.Uint32(msg.Frames[1])

	//Dissect did update the cache, so pick value from there
	desc, found := wg.resultsCache[int(dissectHandle)]
	if !found {
		return wg.returnFailure(fmt.Errorf("accessing unknown result for packet %d", dissectHandle))
	}

	//Response
	response := zmq.NewMsgFrom(getResultMsg(true), append([]byte(desc.Protocol), 0x00))
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processResultGetInfo(msg *zmq.Msg) error {
	if len(msg.Frames) != 2 {
		return wg.returnFailure(errors.New("result_get_info failed, packet_number too short"))
	}
	//Frame one contains dissect handle (ie packet number)
	if len(msg.Frames[1]) != 4 {
		return wg.returnFailure(errors.New("result_get_info failed, dissectHandle too short"))
	}
	dissectHandle := binary.LittleEndian.Uint32(msg.Frames[1])

	//Dissect did update the cache, so pick value from there
	desc, found := wg.resultsCache[int(dissectHandle)]
	if !found {
		return wg.returnFailure(fmt.Errorf("accessing unknown result for packet %d", dissectHandle))
	}

	//Response
	response := zmq.NewMsgFrom(getResultMsg(true), append([]byte(desc.Info), 0x00))
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processResultGetFieldsCount(msg *zmq.Msg) error {
	if len(msg.Frames) != 2 {
		return wg.returnFailure(errors.New("result_get_fields_count failed, packet_number too short"))
	}
	//Frame one contains dissect handle (ie packet number)
	if len(msg.Frames[1]) != 4 {
		return wg.returnFailure(errors.New("result_get_fields_count failed, dissectHandle too short"))
	}
	dissectHandle := binary.LittleEndian.Uint32(msg.Frames[1])

	//Dissect did update the cache, so pick value from there
	desc, found := wg.resultsCache[int(dissectHandle)]
	if !found {
		return wg.returnFailure(fmt.Errorf("accessing unknown result for packet %d", dissectHandle))
	}

	//Response
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(len(desc.fields)))
	response := zmq.NewMsgFrom(getResultMsg(true), b)
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processResultGetField(msg *zmq.Msg) error {
	if len(msg.Frames) != 3 {
		return wg.returnFailure(errors.New("result_get_field failed, packet_number too short"))
	}

	//Frame 1 contains dissect handle (ie packet number)
	if len(msg.Frames[1]) != 4 {
		return wg.returnFailure(errors.New("result_get_field failed, dissectHandle too short"))
	}
	dissectHandle := binary.LittleEndian.Uint32(msg.Frames[1])

	//Frame 2 contains index
	if len(msg.Frames[2]) != 4 {
		return wg.returnFailure(errors.New("result_get_field failed, index too short"))
	}
	idx := binary.LittleEndian.Uint32(msg.Frames[2])

	//Dissect did update the cache, so pick value from there
	desc, found := wg.resultsCache[int(dissectHandle)]
	if !found {
		return wg.returnFailure(fmt.Errorf("accessing unknown result for packet %d", dissectHandle))
	}

	if idx >= uint32(len(desc.fields)) {
		return wg.returnFailure(errors.New("accessing invalid result field index"))
	}
	field := desc.fields[idx]

	//Response
	parentIdx := make([]byte, 4)
	binary.LittleEndian.PutUint32(parentIdx, uint32(field.parentIdx))
	wiregoFieldId := make([]byte, 4)
	binary.LittleEndian.PutUint32(wiregoFieldId, uint32(field.wiregoFieldId))
	offset := make([]byte, 4)
	binary.LittleEndian.PutUint32(offset, uint32(field.offset))
	length := make([]byte, 4)
	binary.LittleEndian.PutUint32(length, uint32(field.length))

	response := zmq.NewMsgFrom(getResultMsg(true), parentIdx, wiregoFieldId, offset, length)
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processResultRelease(msg *zmq.Msg) error {
	if len(msg.Frames) != 2 {
		return wg.returnFailure(errors.New("result_release failed, packet_number too short"))
	}

	//Frame 1 contains dissect handle (ie packet number)
	if len(msg.Frames[1]) != 4 {
		return wg.returnFailure(errors.New("result_release failed, dissectHandle too short"))
	}
	dissectHandle := binary.LittleEndian.Uint32(msg.Frames[1])

	if !wg.resultsCacheEnable {
		delete(wg.resultsCache, int(dissectHandle))
	}

	//Response
	response := zmq.NewMsg(getResultMsg(true))
	return wg.zmqSocket.Send(response)
}

// getResultMsg returns a preset result status to be sent to the remote ZMQ endpoint
func getResultMsg(success bool) []byte {
	if success {
		return []byte{0x01}
	} else {
		return []byte{0x00}
	}
}

// returnFailure logs given error message (if any) and returns an error to the remote ZMQ endpoint
func (wg *Wirego) returnFailure(err error) error {
	if err != nil {
		wg.logs.Print("/!\\ Error:", err)
	}

	response := zmq.NewMsg(getResultMsg(false))
	return wg.zmqSocket.Send(response)
}

// getStringFromFrame extrazcts a C-String from a given frame. Upon error, an empty string is returned.
func getStringFromFrame(frame []byte) string {
	//Make sure it's a C string
	if frame[len(frame)-1] != 0x00 {
		return ""
	}

	return string(frame[:len(frame)-1])
}
