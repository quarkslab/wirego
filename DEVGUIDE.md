# Wirego plugin development guide

Writing a Wirego plugin is quite simple.

A minimalistic example can be found here: [minimalistic](./examples/minimal/)
This guide actually just provides some details on how this example works under the hood.

Before going any further, you should build the example and try to load it with the wirego Wireshark plugin.

    cd examples/minimal/
    make



Your plugin in Go will need to import the "wirego" package and register to wirego during init():

```golang
package main

import (
  "encoding/hex"
  "fmt"
  "wirego/wirego"
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
```

Now we just need to implement the WiregoInterface interface:

```golang
// Define here enum identifiers, used to refer to a specific field
const (
  FieldIdCustom1 wirego.FieldId = 1
  FieldIdCustom2 wirego.FieldId = 2
)

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
  var fields []wirego.WiresharkField
  //First field is named "Custom1", I will refer it later using enum value "FieldIdCustom1"
  //I want to be able to filter matching values in Wireshark using the filter "wirego.custom01"
  //and it's an 8bits value, that should be displayed in hexadecimal
  fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldIdCustom1, Name: "Custom1", Filter: "wirego.custom01", ValueType: wirego.ValueTypeUInt8, DisplayMode: wirego.DisplayModeHexadecimal})
  fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldIdCustom2, Name: "Custom2", Filter: "wirego.custom02", ValueType: wirego.ValueTypeUInt16, DisplayMode: wirego.DisplayModeDecimal})


  return fields
}
```


In order to tell Wireshark which packets should be sent to your dissector, two methods are available:

  - use Wireshark filters to match on a given traffic (ex. udp.port == 137)
  - register a detection function which will be called on a given protocol (ex. "apply my heuristic function on all TCP payloads")

The first method is faster but not always relevant. If your protocol works on a given HTTP traffic, you probably don't want to redirect all TCP port 80 to your dissector.
The second option lets you register on HTTP traffic and apply an heuristic function to detect if this packet should be redirected to your dissector or not.
You can use both method at the same time, but need to used at least one.

```golang
// GetDetectionFilters returns a wireshark filter that will select which packets
// will be sent to your dissector for parsing.
// Two types of filters can be defined: Integers or Strings
func (WiregoExample) GetDetectionFilters() []wirego.DetectionFilter {
  var filters []wirego.DetectionFilter

  filters = append(filters, wirego.DetectionFilter{FilterType: wirego.DetectionFilterTypeInt, Name: "udp.port", ValueInt: 137})
  filters = append(filters, wirego.DetectionFilter{FilterType: wirego.DetectionFilterTypeString, Name: "bluetooth.uuid", ValueString: "1234"})

  return filters
}

// GetDetectionHeuristicsParents returns a list of protocols on top of which detection heuristic
// should be called.
func (WiregoExample) GetDetectionHeuristicsParents() []string {
	//We want to apply our detection heuristic on all tcp and http payloads
	return []string{"udp", "http"}
}
```

When using detection heuristics mode, if a packet matches the "heuristics parent" previously defined, a detection function will be called. Return true if the packet is yours and false otherwise.

```golang
func (WiregoExample) DetectionHeuristic(packetNumber int, src string, dst string, layer string, packet []byte) bool {
	//All packets starting with 0x00 should be passed to our dissector (super advanced heuristic)
	if len(packet) != 0 && packet[0] == 0x00 {
		return true
	}
	return false
}
```


The most interesting part is the DissectPacket function, where you will implement your parser:

```golang
// DissectPacket provides the packet payload to be parsed.
func (WiregoExample) DissectPacket(packetNumber int, src string, dst string, layer string, packet []byte) *wirego.DissectResult {
  var res wirego.DissectResult

  //This string will appear on the packet being parsed
  res.Protocol = "Protocol name example"
  //This (optional) string will appear in the info section
  res.Info = fmt.Sprintf("Info example pkt %d", packetNumber)

  //Add a few fields and refer to them using our own "internalId"
  res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldIdCustom1, Offset: 0, Length: 2})
  res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldIdCustom2, Offset: 2, Length: 4})

  //And add a field "Custom 1" with a sub-field "Custom 2"
  subField := wirego.DissectField{WiregoFieldId: FieldIdCustom2, Offset: 8, Length: 2}
  res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldIdCustom1, Offset: 0, Length: 2, SubFields: []wirego.DissectField{subField})

  return &res
}
```

The last step is to build your plugin using:

      go build -o wirego_example.so -buildmode=c-shared

And... that's all!

Run Wireshark, to go Preferences -> Wirego and point to your freshly built golang plugin.

