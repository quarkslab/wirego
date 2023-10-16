package main

import (
	"encoding/hex"
	"fmt"
	"wirego/wirego"
)

/*
	Do your stuff here.
*/

const (
	WIREGO_PLUGIN_NAME   = "Wirego template" // Your plugin name
	WIREGO_PLUGIN_FILTER = "wiregotpl"       // You protocol filter
)

var fields []wirego.WiresharkField

// Define here enum identifiers, used to refer to a specific field
const (
	FieldIdCustom1 wirego.FieldId = 1
	FieldIdCustom2 wirego.FieldId = 2
)

type WiregoExample struct {
}

// Unused
func main() {}

func init() {
	var wge WiregoExample
	wirego.Init(wge)
}

// This function is called when the plugin is loaded.
func (WiregoExample) Setup() error {

	//Setup our wireshark custom fields
	fields = append(fields, wirego.WiresharkField{InternalId: FieldIdCustom1, Name: "Custom1", Filter: "wirego.custom01", ValueType: wirego.ValueTypeUInt8, DisplayMode: wirego.DisplayModeHexadecimal})
	fields = append(fields, wirego.WiresharkField{InternalId: FieldIdCustom2, Name: "Custom2", Filter: "wirego.custom02", ValueType: wirego.ValueTypeUInt16, DisplayMode: wirego.DisplayModeDecimal})

	return nil
}

func (WiregoExample) GetName() string {
	return WIREGO_PLUGIN_NAME
}

func (WiregoExample) GetFilter() string {
	return WIREGO_PLUGIN_FILTER
}

// getDetectFilterInteger returns a wireshark filter with an integer value,
// that will select which packets will be sent to your dissector for parsing.
// If you don't have any, just return ("", 0)
func (WiregoExample) GetDetectFilterInteger() (string, int) {
	return "udp.port", 17
}

func (WiregoExample) GetFields() []wirego.WiresharkField {
	return fields
}

func (WiregoExample) DissectPacket(packet []byte) *wirego.DissectResult {
	var res wirego.DissectResult

	res.Protocol = "Wirego sample"
	res.Info = "wiresgo pkt info"

	res.Fields = append(res.Fields, wirego.DissectField{InternalId: FieldIdCustom1, Offset: 0, Length: 2})
	res.Fields = append(res.Fields, wirego.DissectField{InternalId: FieldIdCustom2, Offset: 2, Length: 4})
	fmt.Println(hex.Dump(packet))
	return &res
}
