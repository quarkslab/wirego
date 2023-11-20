package wirego

/*
	!DO NOT EDIT THIS FILE!

	If you plan to create a golang plugin for Wireshark,
	you're looking at the wrong file.
	Take your chance with "example/wirego_example.go".

	You probably don't want to look at this file actually.
	Trust me.
*/

import "C"
import (
	"math/rand"
	"unsafe"
)

// WiregoInterface is implemented by the actual wirego plugin
type WiregoInterface interface {
	GetName() string
	GetFilter() string
	Setup() error
	GetFields() []WiresharkField
	GetDissectorFilter() []DissectorFilter
	DissectPacket(src string, dst string, stack string, packet []byte) *DissectResult
}

// Just a simple holder
type Wirego struct {
	listener     WiregoInterface
	resultsCache map[int]*DissectResult
}

// We use a static "object" here
var wg Wirego

// Wirego version, for API compability issues management
const (
	WIREGO_VERSION_MAJOR = 1
	WIREGO_VERSION_MINOR = 0
)

// Fields types
type ValueType int

const (
	ValueTypeNone ValueType = 0x01
	ValueTypeBool ValueType = 0x02

	ValueTypeUInt8 ValueType = 0x03
	ValueTypeInt8  ValueType = 0x04

	ValueTypeUInt16 ValueType = 0x05
	ValueTypeInt16  ValueType = 0x06

	ValueTypeUInt32 ValueType = 0x07
	ValueTypeInt32  ValueType = 0x08

	ValueTypeCString ValueType = 0x09
	ValueTypeString  ValueType = 0x10
)

// Display types
type DisplayMode int

const (
	DisplayModeNone        DisplayMode = 0x01
	DisplayModeDecimal     DisplayMode = 0x02
	DisplayModeHexadecimal DisplayMode = 0x03
)

// A field descriptor, to be provided by the actual plugin
type FieldId int
type WiresharkField struct {
	InternalId  FieldId
	Name        string
	Filter      string
	ValueType   ValueType
	DisplayMode DisplayMode
}

// A field, as returned by the dissector
type DissectField struct {
	InternalId FieldId
	Offset     int
	Length     int
}

// A dissector result is a protocol name, an info string and a list of extracted fields
type DissectResult struct {
	Protocol string
	Info     string
	Fields   []DissectField
}

type DissectorFilterType int

const (
	DissectorFilterTypeInt    DissectorFilterType = iota
	DissectorFilterTypeString DissectorFilterType = iota
)

type DissectorFilter struct {
	FilterType  DissectorFilterType
	Name        string
	ValueInt    int
	ValueString string
}

func Register(listener WiregoInterface) error {
	wg.listener = listener
	return nil
}

//export wirego_setup
func wirego_setup() C.int {
	err := wg.listener.Setup()
	if err != nil {
		return C.int(-1)
	}

	wg.resultsCache = make(map[int]*DissectResult)
	return C.int(0)
}

//export wirego_version_major
func wirego_version_major() C.int {
	return WIREGO_VERSION_MAJOR
}

//export wirego_version_minor
func wirego_version_minor() C.int {
	return WIREGO_VERSION_MINOR
}

//export wirego_plugin_name
func wirego_plugin_name() *C.char {
	return C.CString(wg.listener.GetName())
}

//export wirego_plugin_filter
func wirego_plugin_filter() *C.char {
	return C.CString(wg.listener.GetFilter())
}

//export wirego_detect_int
func wirego_detect_int(i *C.int, idx C.int) *C.char {
	filters := wg.listener.GetDissectorFilter()

	cnt := 0
	for _, f := range filters {
		if f.FilterType == DissectorFilterTypeInt {
			if cnt == int(idx) {
				*i = C.int(f.ValueInt)
				return C.CString(f.Name)
			}
			cnt++
		}
	}

	*i = 0
	return nil
}

//export wirego_detect_string
func wirego_detect_string(value **C.char, idx C.int) *C.char {
	filters := wg.listener.GetDissectorFilter()

	cnt := 0
	for _, f := range filters {
		if f.FilterType == DissectorFilterTypeString {
			*value = C.CString(f.ValueString)
			return C.CString(f.Name)
		}
		cnt++
	}

	*value = nil
	return nil
}

//export wirego_get_fields_count
func wirego_get_fields_count() int {
	return len(wg.listener.GetFields())
}

//export wirego_get_field
func wirego_get_field(index int, internalId *C.int, name **C.char, filter **C.char, valueType *C.int, display *C.int) int {
	fields := wg.listener.GetFields()
	*internalId = -1
	*name = nil
	*filter = nil
	*valueType = -1
	*display = -1

	if (index < 0) || (index >= len(fields)) {
		return -1
	}

	f := fields[index]

	*internalId = C.int(f.InternalId)
	*name = C.CString(f.Name)
	*filter = C.CString(f.Filter)
	*valueType = C.int(f.ValueType)
	*display = C.int(f.DisplayMode)

	return 0
}

/*
  Note: there's probably a way to return the complete DissectResult structure
	to the C environment. At the end of the day, this would be super opaque so for now
	let's use some dummy accessors and a result cache.
*/
//export wirego_dissect_packet
func wirego_dissect_packet(src *C.char, dst *C.char, layer *C.char, packet *C.char, packetSize C.int) int {

	h := rand.Int()
	result := wg.listener.DissectPacket(C.GoString(src), C.GoString(dst), C.GoString(layer), C.GoBytes(unsafe.Pointer(packet), packetSize))
	wg.resultsCache[h] = result
	return h
}

//export wirego_result_get_protocol
func wirego_result_get_protocol(h int) *C.char {
	desc, found := wg.resultsCache[h]
	if !found {
		return nil
	}

	return C.CString(desc.Protocol)
}

//export wirego_result_get_info
func wirego_result_get_info(h int) *C.char {
	desc, found := wg.resultsCache[h]
	if !found {
		return nil
	}

	return C.CString(desc.Info)
}

//export wirego_result_get_fields_count
func wirego_result_get_fields_count(h int) C.int {
	desc, found := wg.resultsCache[h]
	if !found {
		return C.int(0)
	}

	return C.int(len(desc.Fields))
}

//export wirego_result_get_field
func wirego_result_get_field(h int, idx int, internalId *C.int, offset *C.int, length *C.int) {
	*internalId = -1
	*offset = -1
	*length = -1

	desc, found := wg.resultsCache[h]
	if !found {
		return
	}

	if idx >= len(desc.Fields) {
		return
	}
	*internalId = C.int(desc.Fields[idx].InternalId)
	*offset = C.int(desc.Fields[idx].Offset)
	*length = C.int(desc.Fields[idx].Length)

	return
}

//export wirego_result_release
func wirego_result_release(h int) {
	delete(wg.resultsCache, h)
}
