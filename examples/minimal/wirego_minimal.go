package main

import (
	"fmt"

	"github.com/quarkslab/wirego/wirego_remote/go/wirego/wirego"
)

// Define here enum identifiers, used to refer to a specific field
const (
	FieldIdCustom1             wirego.FieldId = 1
	FieldIdCustom2             wirego.FieldId = 2
	FieldIdCustomWithSubFields wirego.FieldId = 3
)

// Since we implement the wirego.WiregoInterface we need some structure to hold it.
type WiregoMinimalExample struct {
}

func main() {
	var wge WiregoMinimalExample

	wg, err := wirego.New("ipc:///tmp/wirego0", false, wge)
	if err != nil {
		fmt.Println(err)
		return
	}
	wg.ResultsCacheEnable(false)

	wg.Listen()
}

// This function shall return the plugin name
func (WiregoMinimalExample) GetName() string {
	return "Wirego Minimal Example"
}

// This function shall return the wireshark filter
func (WiregoMinimalExample) GetFilter() string {
	return "wgminexample"
}

// GetFields returns the list of fields descriptor that we may eventually return
// when dissecting a packet payload
func (WiregoMinimalExample) GetFields() []wirego.WiresharkField {
	var fields []wirego.WiresharkField

	//Setup our wireshark custom fields
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldIdCustom1, Name: "Custom1", Filter: "wirego.custom01", ValueType: wirego.ValueTypeUInt8, DisplayMode: wirego.DisplayModeHexadecimal})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldIdCustom2, Name: "Custom2", Filter: "wirego.custom02", ValueType: wirego.ValueTypeUInt16, DisplayMode: wirego.DisplayModeDecimal})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldIdCustomWithSubFields, Name: "CustomWith Subs", Filter: "wirego.custom_subs", ValueType: wirego.ValueTypeUInt32, DisplayMode: wirego.DisplayModeHexadecimal})

	return fields
}

// GetDetectionFilters returns a wireshark filter that will select which packets
// will be sent to your dissector for parsing.
// Two types of filters can be defined: Integers or Strings
func (WiregoMinimalExample) GetDetectionFilters() []wirego.DetectionFilter {
	var filters []wirego.DetectionFilter

	filters = append(filters, wirego.DetectionFilter{FilterType: wirego.DetectionFilterTypeInt, Name: "udp.port", ValueInt: 137})
	filters = append(filters, wirego.DetectionFilter{FilterType: wirego.DetectionFilterTypeString, Name: "bluetooth.uuid", ValueString: "1234"})

	return filters
}

// GetDetectionHeuristicsParents returns a list of protocols on top of which detection heuristic
// should be called.
func (WiregoMinimalExample) GetDetectionHeuristicsParents() []string {
	//We want to apply our detection heuristic on all tcp payloads
	return []string{"udp", "http"}
}

// DetectionHeuristic applies an heuristic to identify the protocol.
func (WiregoMinimalExample) DetectionHeuristic(packetNumber int, src string, dst string, layer string, packet []byte) bool {
	//All packets starting with 0x00 should be passed to our dissector (super advanced heuristic)
	if len(packet) != 0 && packet[0] == 0x00 {
		return true
	}
	return false
}

// DissectPacket provides the packet payload to be parsed.
func (WiregoMinimalExample) DissectPacket(packetNumber int, src string, dst string, layer string, packet []byte) *wirego.DissectResult {
	var res wirego.DissectResult

	//This string will appear on the packet being parsed
	res.Protocol = "Protocol name example"
	//This (optional) string will appear in the info section
	res.Info = fmt.Sprintf("Info example pkt %d", packetNumber)

	//Add a few fields and refer to them using our own "internalId"
	if len(packet) > 6 {
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldIdCustom1, Offset: 0, Length: 2})
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldIdCustom2, Offset: 2, Length: 4})
	}
	//Add a field with two sub field
	if len(packet) > 10 {
		subField1 := wirego.DissectField{WiregoFieldId: FieldIdCustom1, Offset: 6, Length: 2}
		subField2 := wirego.DissectField{WiregoFieldId: FieldIdCustom1, Offset: 8, Length: 2}
		field := wirego.DissectField{WiregoFieldId: FieldIdCustomWithSubFields, Offset: 6, Length: 4, SubFields: []wirego.DissectField{subField1, subField2}}
		res.Fields = append(res.Fields, field)
	}
	//Dump packet contents
	//fmt.Println(layer, " ", src, " to ", dst)
	//fmt.Println(hex.Dump(packet))
	return &res
}
