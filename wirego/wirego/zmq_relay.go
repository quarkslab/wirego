package wirego

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	zmq "github.com/go-zeromq/zmq4"
)

type ZMQCommand func(msg *zmq.Msg) error

const (
	WiregoVersionMajor = 2
	WiregoVersionMinor = 0
)

func getStringFromFrame(frame []byte) string {
	//Make sure it's a C string
	if frame[len(frame)-1] != 0x00 {
		return ""
	}

	return string(frame[:len(frame)-1])
}

func (wg *Wirego) zmqSetup() error {
	wg.zmqContext = context.Background()
	wg.zmqSocket = zmq.NewRep(wg.zmqContext, zmq.WithDialerRetry(time.Second))

	err := wg.zmqSocket.Listen(wg.zqmEndpoint)
	if err != nil {
		return err
	}

	return nil
}

func (wg *Wirego) Listen() {
	if wg.listener == nil {
		return
	}

	dispatcher := make(map[string]ZMQCommand)

	//Utility commands, not dispatched to the Wirego plugin interface
	dispatcher["ping"] = wg.processPing
	dispatcher["version"] = wg.processVersion

	//ZMQ interface commands
	dispatcher["get_name"] = wg.processGetName
	dispatcher["get_plugin_filter"] = wg.processGetFilter
	dispatcher["get_fields_count"] = wg.processGetFieldsCount
	dispatcher["get_field"] = wg.processGetField
	dispatcher["detect_int"] = wg.processDetectInt
	dispatcher["detect_string"] = wg.processDetectString
	dispatcher["detect_heuristic_parent"] = wg.processDetectHeuristicParent
	dispatcher["detection_heuristic"] = wg.processDetectionHeuristic
	dispatcher["dissect_packet"] = wg.processDissectPacket
	dispatcher["result_get_protocol"] = wg.processResultGetProtocol
	dispatcher["result_get_info"] = wg.processResultGetInfo
	dispatcher["result_get_fields_count"] = wg.processResultGetFieldsCount
	dispatcher["result_get_field"] = wg.processResultGetField
	dispatcher["result_release"] = wg.processResultRelease

	for {
		fmt.Println("Wait...")

		msg, err := wg.zmqSocket.Recv()
		if err != nil {
			fmt.Println(err)
			return
		}
		if len(msg.Frames) == 0 {
			continue
		}

		//Frame 0 contains the command. Get rid of trailing /x00 C-string
		cmd := getStringFromFrame(msg.Frames[0])
		cb, found := dispatcher[cmd]
		if !found {
			fmt.Println("Unknown command: '" + cmd + "'")
		} else {
			fmt.Println("Processing command", cmd, "...")
			err = cb(&msg)
			if err != nil {
				fmt.Println("-> Failed:", err)
			} else {
				fmt.Println("-> Success.")
			}
		}
	}
}

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

	//Frame one contains index
	if len(msg.Frames) != 2 {
		wg.returnFailure()
		return errors.New("get_field failed, index missing from request")
	}
	if len(msg.Frames[1]) != 4 {
		wg.returnFailure()
		return errors.New("get_field failed, index too short")
	}
	index := binary.LittleEndian.Uint32(msg.Frames[1])
	if index >= uint32(len(wg.pluginFields)) {
		wg.returnFailure()
		return errors.New("get_field failed, index too high")
	}

	f := wg.pluginFields[index]

	wg.wiregoFieldIds[int(f.WiregoFieldId)] = true //FIXME : why?

	//Response
	//Frame 0 : wiregoFieldId
	wiregoFieldId := make([]byte, 4)
	binary.LittleEndian.PutUint32(wiregoFieldId, uint32(f.WiregoFieldId))
	//Frame 1 : name
	name := f.Name
	//Frame 2 : filter
	filter := f.Filter
	//Frame 3 : valueType
	valueType := make([]byte, 4)
	binary.LittleEndian.PutUint32(valueType, uint32(f.ValueType))
	//Frame 4 : DisplayMode
	displayMode := make([]byte, 4)
	binary.LittleEndian.PutUint32(displayMode, uint32(f.DisplayMode))

	response := zmq.NewMsgFrom(getResultMsg(true), wiregoFieldId, append([]byte(name), 0x00), append([]byte(filter), 0x00), valueType, displayMode)
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processDetectInt(msg *zmq.Msg) error {
	var matchValue int
	var filterString string
	matchValue = -1

	//Frame one contains index
	if len(msg.Frames) != 2 {
		wg.returnFailure()
		return errors.New("detect_int failed, index missing from request")
	}
	if len(msg.Frames[1]) != 4 {
		wg.returnFailure()
		return errors.New("detect_int failed, index too short")
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

	if matchValue == -1 {
		return wg.returnFailure()
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

	//Frame one contains index
	if len(msg.Frames) != 2 {
		wg.returnFailure()
		return errors.New("detect_string failed, index missing from request")
	}
	if len(msg.Frames[1]) != 4 {
		wg.returnFailure()
		return errors.New("detect_string failed, index too short")
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

	if len(matchValue) == 0 {
		return wg.returnFailure()
	}

	//Response
	response := zmq.NewMsgFrom(getResultMsg(true), append([]byte(filterString), 0x00), append([]byte(matchValue), 0x00))
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processDetectHeuristicParent(msg *zmq.Msg) error {
	//Frame one contains index
	if len(msg.Frames) != 2 {
		wg.returnFailure()
		return errors.New("detect_heuristic_parent failed, index missing from request")
	}
	if len(msg.Frames[1]) != 4 {
		wg.returnFailure()
		return errors.New("detect_heuristic_parent failed, index too short")
	}
	idx := binary.LittleEndian.Uint32(msg.Frames[1])

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
		wg.returnFailure()
		return errors.New("detection_heuristic failed, missing arguments")
	}
	if len(msg.Frames[1]) != 4 {
		wg.returnFailure()
		return errors.New("detection_heuristic failed, packet_number too short")
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
		wg.returnFailure()
		return errors.New("dissect_packet failed, missing arguments")
	}
	if len(msg.Frames[1]) != 4 {
		wg.returnFailure()
		return errors.New("dissect_packet failed, packet_number too short")
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
		return wg.returnFailure()
	}

	//Check results
	for _, r := range result.Fields {
		if r.Offset >= len(packet) {
			fmt.Printf("Wirego plugin did return an invalid Offset : %d (packet size is %d bytes)\n", r.Offset, len(packet))
			return wg.returnFailure()
		}
		if r.Offset+r.Length > len(packet) {
			fmt.Printf("Wirego plugin did return an invalid Length : %d (offset is %d and packet size is %d bytes)\n", r.Length, r.Offset, len(packet))
			return wg.returnFailure()
		}
		_, found := wg.wiregoFieldIds[int(r.WiregoFieldId)]
		if !found {
			fmt.Printf("Wirego plugin did return an invalid WiregoFieldId : %d\n", r.WiregoFieldId)
			return wg.returnFailure()
		}
	}

	//Flatten results to a simple list with parenIdx pointing to parent's entry
	var flatten DissectResultFlattenEntry
	flatten.Info = result.Info
	flatten.Protocol = result.Protocol
	for _, r := range result.Fields {
		wg.addFieldsRec(&flatten, -1, &r)
	}

	//Add to cache
	wg.resultsCache[int(packetNumber)] = &flatten

	res := make([]byte, 4)
	binary.LittleEndian.PutUint32(res, packetNumber)
	response := zmq.NewMsgFrom(getResultMsg(true), res)
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processResultGetProtocol(msg *zmq.Msg) error {
	//Frame one contains index
	if len(msg.Frames) != 2 {
		wg.returnFailure()
		return errors.New("result_get_protocol failed, dissect_handle missing from request")
	}
	if len(msg.Frames[1]) != 4 {
		wg.returnFailure()
		return errors.New("result_get_protocol failed, dissect_handle too short")
	}
	dissectHandle := binary.LittleEndian.Uint32(msg.Frames[1])

	desc, found := wg.resultsCache[int(dissectHandle)]
	if !found {
		return wg.returnFailure()
	}

	//Response
	response := zmq.NewMsgFrom(getResultMsg(true), append([]byte(desc.Protocol), 0x00))
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processResultGetInfo(msg *zmq.Msg) error {
	//Frame one contains index
	if len(msg.Frames) != 2 {
		wg.returnFailure()
		return errors.New("result_get_info failed, dissect_handle missing from request")
	}
	if len(msg.Frames[1]) != 4 {
		wg.returnFailure()
		return errors.New("result_get_info failed, dissectHandle too short")
	}
	dissectHandle := binary.LittleEndian.Uint32(msg.Frames[1])

	desc, found := wg.resultsCache[int(dissectHandle)]
	if !found {
		return wg.returnFailure()
	}

	//Response
	response := zmq.NewMsgFrom(getResultMsg(true), append([]byte(desc.Info), 0x00))
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processResultGetFieldsCount(msg *zmq.Msg) error {
	//Frame one contains index
	if len(msg.Frames) != 2 {
		wg.returnFailure()
		return errors.New("result_get_fields_count failed, dissect_handle missing from request")
	}
	if len(msg.Frames[1]) != 4 {
		wg.returnFailure()
		return errors.New("result_get_fields_count failed, dissectHandle too short")
	}
	dissectHandle := binary.LittleEndian.Uint32(msg.Frames[1])

	desc, found := wg.resultsCache[int(dissectHandle)]
	if !found {
		return wg.returnFailure()
	}

	//Response
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(len(desc.fields)))
	response := zmq.NewMsgFrom(getResultMsg(true), b)
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processResultGetField(msg *zmq.Msg) error {
	if len(msg.Frames) != 3 {
		wg.returnFailure()
		return errors.New("result_get_field failed, missing args from request")
	}
	//Frame 1 contains dissect_handle
	if len(msg.Frames[1]) != 4 {
		wg.returnFailure()
		return errors.New("result_get_field failed, dissectHandle too short")
	}
	dissectHandle := binary.LittleEndian.Uint32(msg.Frames[1])

	//Frame 2 contains index
	if len(msg.Frames) != 2 {
		wg.returnFailure()
		return errors.New("result_get_field failed, index missing from request")
	}
	if len(msg.Frames[1]) != 4 {
		wg.returnFailure()
		return errors.New("result_get_field failed, index too short")
	}
	idx := binary.LittleEndian.Uint32(msg.Frames[2])

	desc, found := wg.resultsCache[int(dissectHandle)]
	if !found {
		return wg.returnFailure()
	}

	if idx >= uint32(len(desc.fields)) {
		return wg.returnFailure()
	}
	field := desc.fields[idx]

	//Response
	parentIdx := make([]byte, 4)
	binary.LittleEndian.PutUint32(parentIdx, uint32(field.parentIdx))
	wiregoFieldId := make([]byte, 4)
	binary.LittleEndian.PutUint32(wiregoFieldId, uint32(field.wiregoFieldId))
	offset := make([]byte, 4)
	binary.LittleEndian.PutUint32(parentIdx, uint32(field.offset))
	length := make([]byte, 4)
	binary.LittleEndian.PutUint32(parentIdx, uint32(field.length))

	response := zmq.NewMsgFrom(getResultMsg(true), parentIdx, wiregoFieldId, offset, length)
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processResultRelease(msg *zmq.Msg) error {
	//Frame one contains index
	if len(msg.Frames) != 2 {
		wg.returnFailure()
		return errors.New("result_release failed, dissect_handle missing from request")
	}
	if len(msg.Frames[1]) != 4 {
		wg.returnFailure()
		return errors.New("result_release failed, dissectHandle too short")
	}
	dissectHandle := binary.LittleEndian.Uint32(msg.Frames[1])

	if !wg.resultsCacheEnable {
		delete(wg.resultsCache, int(dissectHandle))
	}

	//Response
	response := zmq.NewMsg(getResultMsg(true))
	return wg.zmqSocket.Send(response)
}

func getResultMsg(success bool) []byte {
	if success {
		return []byte{0x01}
	} else {
		return []byte{0x00}
	}
}

func (wg *Wirego) returnFailure() error {
	response := zmq.NewMsg(getResultMsg(false))
	return wg.zmqSocket.Send(response)
}
