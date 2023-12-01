package main

import (
	"encoding/hex"
	"fmt"
	"wirego/wirego"
)

var fields []wirego.WiresharkField

// Define here enum identifiers, used to refer to a specific field
const (
	FieldIdCustom1 wirego.FieldId = 1
	FieldIdCustom2 wirego.FieldId = 2
)

// Since we implement the wirego.WiregoInterface we need some structure to hold it.
type WiregoExample struct {
}

// Unused (but mandatory)
func main() {}

// Called at golang environment initialization (you should probably not touch this)
func init() {
	var wge WiregoExample

	//Register to the wirego package
	wirego.Register(wge)
}

// This function is called when the plugin is loaded.
func (WiregoExample) Setup() error {

	//Setup our wireshark custom fields
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldIdCustom1, Name: "Custom1", Filter: "wirego.custom01", ValueType: wirego.ValueTypeUInt8, DisplayMode: wirego.DisplayModeHexadecimal})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldIdCustom2, Name: "Custom2", Filter: "wirego.custom02", ValueType: wirego.ValueTypeUInt16, DisplayMode: wirego.DisplayModeDecimal})

	return nil
}

// This function shall return the plugin name
func (WiregoExample) GetName() string {
	return "Wirego Example"
}

// This function shall return the wireshark filter
func (WiregoExample) GetFilter() string {
	return "wgexample"
}

// GetFields returns the list of fields descriptor that we may eventually return
// when dissecting a packet payload
func (WiregoExample) GetFields() []wirego.WiresharkField {
	return fields
}

// GetDissectorFilter returns a wireshark filter that will select which packets
// will be sent to your dissector for parsing.
// Two types of filters can be defined: Integers or Strings
func (WiregoExample) GetDissectorFilter() []wirego.DissectorFilter {
	var filters []wirego.DissectorFilter

	filters = append(filters, wirego.DissectorFilter{FilterType: wirego.DissectorFilterTypeInt, Name: "udp.port", ValueInt: 137})
	filters = append(filters, wirego.DissectorFilter{FilterType: wirego.DissectorFilterTypeInt, Name: "dns.srv.instance", ValueString: "ff:ff:ff:ff:ff:ff"})

	return filters
}

// DissectPacket provides the packet payload to be parsed.
func (WiregoExample) DissectPacket(src string, dst string, layer string, packet []byte) *wirego.DissectResult {
	var res wirego.DissectResult

	//This string will appear on the packet being parsed
	res.Protocol = "Wirego example"
	//This (optional) string will appear in the info section
	res.Info = "wiresgo pkt info"

	//Add a few fields and refer to them using our own "internalId"
	res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldIdCustom1, Offset: 0, Length: 2})
	res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldIdCustom2, Offset: 2, Length: 4})
	fmt.Println(layer, " ", src, " to ", dst)
	fmt.Println(hex.Dump(packet))
	return &res
}
