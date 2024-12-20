package wirego

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"
	"time"

	zmq "github.com/go-zeromq/zmq4"
)

const (
	zmqTestEndpointFile = "./wirego0"
	zmqTestEndpoint     = "ipc://" + zmqTestEndpointFile
)

type Plug struct {
}

func (p *Plug) GetName() string {
	return "Test"
}

func (p *Plug) GetFilter() string {
	return "testfilter"
}

func (p *Plug) GetFields() []WiresharkField {
	var fields []WiresharkField
	fields = append(fields, WiresharkField{WiregoFieldId: 1, Name: "Custom01", Filter: "custom01", ValueType: ValueTypeInt8, DisplayMode: DisplayModeHexadecimal})
	fields = append(fields, WiresharkField{WiregoFieldId: 2, Name: "Custom02", Filter: "custom02", ValueType: ValueTypeString, DisplayMode: DisplayModeNone})

	return fields
}

func (p *Plug) GetDetectionFilters() []DetectionFilter {
	var d []DetectionFilter

	return d
}

func (p *Plug) GetDetectionHeuristicsParents() []string {
	return []string{"parent1", "parent2"}
}

func (p *Plug) DetectionHeuristic(packetNumber int, src string, dst string, stack string, packet []byte) bool {
	return false
}

func (p *Plug) DissectPacket(packetNumber int, src string, dst string, stack string, packet []byte) *DissectResult {
	var dr DissectResult

	return &dr
}

func TestNew(t *testing.T) {
	var pl Plug
	defer os.Remove(zmqTestEndpointFile)

	//Nil listener
	wg, err := New(zmqTestEndpoint, true, nil)
	if wg != nil || err == nil {
		t.Fatal("New without listener fails")
	}

	//Bad endpoint
	wg, err = New("zmq://badendpoint:666", true, &pl)
	if wg != nil || err == nil {
		t.Fatal("New with bad endpoint fails")
	}

	//Valid
	wg, err = New(zmqTestEndpoint, true, &pl)
	if wg == nil || err != nil {
		t.Fatal("New with valid endpoint and listener succeeds")
	}
}

func TestInvalidCommand(t *testing.T) {
	var request [][]byte
	var response [][]byte
	request = append(request, []byte("invalid command\x00")) //Command name
	response = append(response, []byte{0x00})                //Invalid
	checkZMQCommand(request, response, t)
}

func TestPing(t *testing.T) {
	var request [][]byte
	var response [][]byte
	request = append(request, []byte("ping\x00")) //Command name
	response = append(response, []byte{0x01})     //Valid
	checkZMQCommand(request, response, t)
}

func TestVersion(t *testing.T) {
	var request [][]byte
	var response [][]byte
	request = append(request, []byte("version\x00")) //Command name
	response = append(response, []byte{0x01})        //Valid
	response = append(response, []byte{0x02})        //Major
	response = append(response, []byte{0x00})        //Minor
	checkZMQCommand(request, response, t)
}

func TestGetName(t *testing.T) {
	var request [][]byte
	var response [][]byte
	request = append(request, []byte("get_name\x00")) //Command name
	response = append(response, []byte{0x01})         //Valid
	response = append(response, []byte("Test\x00"))   //Name
	checkZMQCommand(request, response, t)
}

func TestGetPluginFilter(t *testing.T) {
	var request [][]byte
	var response [][]byte
	request = append(request, []byte("get_plugin_filter\x00")) //Command name
	response = append(response, []byte{0x01})                  //Valid
	response = append(response, []byte("testfilter\x00"))      //Filter
	checkZMQCommand(request, response, t)
}

func TestGetFieldsCount(t *testing.T) {
	var request [][]byte
	var response [][]byte
	request = append(request, []byte("get_fields_count\x00"))                  //Command name
	response = append(response, []byte{0x01})                                  //Valid
	response = append(response, binary.LittleEndian.AppendUint32([]byte{}, 2)) //Fields count
	checkZMQCommand(request, response, t)
}

func TestGetField(t *testing.T) {
	var request [][]byte
	var response [][]byte

	//Check field 0
	request = append(request, []byte("get_field\x00"))                       //Command name
	request = append(request, binary.LittleEndian.AppendUint32([]byte{}, 0)) //Field index

	response = append(response, []byte{0x01})                                                               //Valid
	response = append(response, binary.LittleEndian.AppendUint32([]byte{}, 1))                              //WiregoFieldId
	response = append(response, []byte("Custom01\x00"))                                                     //Field name
	response = append(response, []byte("custom01\x00"))                                                     //Field filter
	response = append(response, binary.LittleEndian.AppendUint32([]byte{}, uint32(ValueTypeInt8)))          //Value type
	response = append(response, binary.LittleEndian.AppendUint32([]byte{}, uint32(DisplayModeHexadecimal))) //Display mode
	checkZMQCommand(request, response, t)

	//Check field 1
	request = make([][]byte, 0)
	response = make([][]byte, 0)
	request = append(request, []byte("get_field\x00"))                       //Command name
	request = append(request, binary.LittleEndian.AppendUint32([]byte{}, 1)) //Field index

	response = append(response, []byte{0x01})                                                        //Valid
	response = append(response, binary.LittleEndian.AppendUint32([]byte{}, 2))                       //WiregoFieldId
	response = append(response, []byte("Custom02\x00"))                                              //Field name
	response = append(response, []byte("custom02\x00"))                                              //Field filter
	response = append(response, binary.LittleEndian.AppendUint32([]byte{}, uint32(ValueTypeString))) //Value type
	response = append(response, binary.LittleEndian.AppendUint32([]byte{}, uint32(DisplayModeNone))) //Display mode

	checkZMQCommand(request, response, t)
}

func checkZMQCommand(sendFrames [][]byte, resultFrames [][]byte, t *testing.T) {
	var pl Plug
	defer os.Remove(zmqTestEndpointFile)

	t.Log("Testing", t.Name())
	//Setup Wirego package
	wg, err := New(zmqTestEndpoint, true, &pl)
	if err != nil {
		t.Fatal("Can create Wirego instance")
	}

	//Listen in background
	go wg.Listen()

	//Make sure zmq server is ready
	time.Sleep(100 * time.Millisecond)

	//Connect to Wirego's ZMQ (fake Wirego bridge)
	ctx := context.Background()
	sock := zmq.NewReq(ctx)
	err = sock.Dial(zmqTestEndpoint)
	if err != nil {
		t.Fatal("Can connect to Wirego's ZMQ endpoint")
	}

	//Sent test frames
	msg := zmq.NewMsgFrom(sendFrames...)
	err = sock.Send(msg)
	if err != nil {
		t.Fatal("Can call get name")
	}

	//Receive test reponses
	response, err := sock.Recv()
	if err != nil {
		t.Fatal("Can receive command result", err)
	}

	if len(response.Frames) != len(resultFrames) {
		t.Fatal("Received proper response frame count (received ", len(response.Frames), "expected", len(resultFrames), ")")
	}

	for i := 0; i < len(response.Frames); i++ {
		if !bytes.Equal(response.Frames[i], resultFrames[i]) {
			t.Fatalf("Frame %d is as expected (received %s / expected %s)", i, hex.EncodeToString(response.Frames[i]), hex.EncodeToString(resultFrames[i]))
		}
	}

	//Close
	wg.zmqSocket.Close()
	time.Sleep(100 * time.Millisecond)
}
