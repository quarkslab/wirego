package main

import (
	"encoding/hex"
	"fmt"
)

/*
	Do your stuff here.
*/

const (
	WIREGO_PLUGIN_NAME   = "Wirego template" // Your plugin name
	WIREGO_PLUGIN_FILTER = "wiregotpl"       // You protocol filter
)

var fields []WiresharkField

// Define here enum identifiers, used to refer to a specific field
const (
	FieldIdCustom1 FieldId = 1
	FieldIdCustom2 FieldId = 2
)

// This function is called when the plugin is loaded.
func setup() error {

	//Setup our wireshark custom fields
	fields = append(fields, WiresharkField{InternalId: FieldIdCustom1, Name: "Custom1", Filter: "wirego.custom01", ValueType: ValueTypeUInt8, DisplayMode: DisplayModeHexadecimal})
	fields = append(fields, WiresharkField{InternalId: FieldIdCustom2, Name: "Custom2", Filter: "wirego.custom02", ValueType: ValueTypeUInt16, DisplayMode: DisplayModeDecimal})

	return nil
}

// getDetectFilterInteger returns a wireshark filter with an integer value,
// that will select which packets will be sent to your dissector for parsing.
// If you don't have any, just return ("", 0)
func getDetectFilterInteger() (string, int) {
	return "udp.port", 17
}

func getFields() []WiresharkField {
	return fields
}

func dissectPacket(packet []byte) *DissectResult {
	var res DissectResult

	res.Protocol = "Wirego sample"
	res.Info = "wiresgo pkt info"

	res.Fields = append(res.Fields, DissectField{InternalId: FieldIdCustom1, Offset: 0, Length: 2})
	res.Fields = append(res.Fields, DissectField{InternalId: FieldIdCustom2, Offset: 2, Length: 4})
	fmt.Println(hex.Dump(packet))
	return &res
}
