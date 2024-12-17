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
		cmd := string(msg.Frames[0][:len(msg.Frames[0])-1])
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
	response := zmq.NewMsgFromString([]string{"echo reply\x00"})
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processVersion(msg *zmq.Msg) error {
	response := zmq.NewMsgFrom([]byte{byte(WiregoVersionMajor)}, []byte{byte(WiregoVersionMinor)})
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processGetName(msg *zmq.Msg) error {
	response := zmq.NewMsgFromString([]string{wg.pluginName + "\x00"})
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processGetFilter(msg *zmq.Msg) error {
	response := zmq.NewMsgFromString([]string{wg.pluginFilter + "\x00"})
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processGetFieldsCount(msg *zmq.Msg) error {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(len(wg.pluginFields)))

	response := zmq.NewMsg(b)
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processGetField(msg *zmq.Msg) error {

	//Frame one contains index
	if len(msg.Frames) != 2 {
		return errors.New("get_field failed, index missing from request")
	}
	if len(msg.Frames[1]) != 4 {
		return errors.New("get_field failed, index too short")
	}
	index := binary.LittleEndian.Uint32(msg.Frames[1])
	if index >= uint32(len(wg.pluginFields)) {
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

	response := zmq.NewMsgFrom(wiregoFieldId, append([]byte(name), 0x00), append([]byte(filter), 0x00), valueType, displayMode)
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processDetectInt(msg *zmq.Msg) error {
	var matchValue int
	var filterString string
	matchValue = -1

	//Frame one contains index
	if len(msg.Frames) != 2 {
		return errors.New("detect_int failed, index missing from request")
	}
	if len(msg.Frames[1]) != 4 {
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

	//Response
	matchValueSlc := make([]byte, 4)
	binary.LittleEndian.PutUint32(matchValueSlc, uint32(matchValue))

	response := zmq.NewMsgFrom(append([]byte(filterString), 0x00), matchValueSlc)
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processDetectString(msg *zmq.Msg) error {
	var matchValue string
	var filterString string

	//Frame one contains index
	if len(msg.Frames) != 2 {
		return errors.New("detect_string failed, index missing from request")
	}
	if len(msg.Frames[1]) != 4 {
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

	//Response
	response := zmq.NewMsgFrom(append([]byte(filterString), 0x00), append([]byte(matchValue), 0x00))
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processDetectHeuristics(msg *zmq.Msg) error {
	var matchValue string
	var filterString string

	//Frame one contains index
	if len(msg.Frames) != 2 {
		return errors.New("detect_heuristics failed, index missing from request")
	}
	if len(msg.Frames[1]) != 4 {
		return errors.New("detect_heuristics failed, index too short")
	}
	idx := binary.LittleEndian.Uint32(msg.Frames[1])

	if idx >= uint32(len(wg.pluginDetectionHeuristicsParents)) {
		response := zmq.NewMsg([]byte{})
		return wg.zmqSocket.Send(response)
	}

	//Response
	response := zmq.NewMsg(append([]byte(wg.pluginDetectionHeuristicsParents[idx]), 0x00))
	return wg.zmqSocket.Send(response)
}
