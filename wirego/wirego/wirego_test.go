package wirego

import (
	"errors"
	"fmt"
	"testing"
	"unsafe"
)

type FakeListener struct {
	setupCount  int
	setupReturn error

	getNameCount  int
	getNameReturn string

	getFilterCount  int
	getFilterReturn string

	getDissectorFilterCount  int
	getDissectorFilterReturn []DissectorFilter

	getFieldsCount  int
	getFieldsReturn []WiresharkField

	dissectCount  int
	dissectResult DissectResult
}

func (l *FakeListener) GetName() string {
	l.getNameCount++
	return l.getNameReturn
}

func (l *FakeListener) GetFilter() string {
	l.getFilterCount++
	return l.getFilterReturn
}
func (l *FakeListener) Setup() error {
	l.setupCount++
	return l.setupReturn
}

func (l *FakeListener) GetFields() []WiresharkField {
	l.getFieldsCount++
	return l.getFieldsReturn
}
func (l *FakeListener) GetDissectorFilter() []DissectorFilter {
	l.getDissectorFilterCount++
	return l.getDissectorFilterReturn
}
func (l *FakeListener) DissectPacket(src string, dst string, stack string, packet []byte) *DissectResult {
	l.dissectCount++
	return &l.dissectResult
}

func (fake *FakeListener) Reset() {
	fake.setupCount = 0
	fake.setupReturn = nil
	fake.getNameCount = 0
	fake.getNameReturn = ""
	fake.getFilterCount = 0
	fake.getFilterReturn = ""
	fake.getFieldsCount = 0
	fake.getFieldsReturn = []WiresharkField{}
	fake.getDissectorFilterCount = 0
	fake.getDissectorFilterReturn = []DissectorFilter{}
	fake.dissectCount = 0
	fake.dissectResult = DissectResult{}

}

func toString(cString *_Ctype_char) string {
	var res string
	if cString == nil {
		return res
	}

	p := unsafe.Pointer(cString)
	idx := 0
	for {
		if (*(*_Ctype_char)(p)) == 0x00 {
			break
		}

		res += string(byte(*(*_Ctype_char)(p)))
		p = unsafe.Add(p, 1)
		idx++
	}

	return res
}

// There's may be a simpler way to do this, but cannot import C here.
func checkCString(cString *_Ctype_char, str string) bool {

	return toString(cString) == str
}

func TestSetup(t *testing.T) {
	var fake FakeListener
	fake.Reset()

	//Standard setup
	Register(&fake)

	if wirego_setup() != 0 {
		t.Fatal("wirego_setup succeeds")
	}
	if fake.setupCount != 1 {
		t.Fatal("Setup is called when plugin is loaded")
	}

	//Setup failure
	fake.Reset()
	fake.setupReturn = errors.New("failure") //setup will return an error
	Register(&fake)
	if wirego_setup() == 0 {
		t.Fatal("wirego_setup fails if plugin setup fails")
	}
	if fake.setupCount != 1 {
		t.Fatal("Setup is called when plugin is loaded")
	}

}

func TestVersion(t *testing.T) {
	if wirego_version_major() != WIREGO_VERSION_MAJOR {
		t.Fatal("version major is fine")
	}
	if wirego_version_minor() != WIREGO_VERSION_MINOR {
		t.Fatal("version minor is fine")
	}
}

func TestName(t *testing.T) {
	var fake FakeListener
	fake.Reset()

	fake.getNameReturn = "Test"
	Register(&fake)
	if wirego_setup() == -1 {
		t.Fatal("wirego_setup works fine for this test.")
	}

	name := wirego_plugin_name()
	if name == nil {
		t.Fatal("wirego_plugin_name returns plugin name")
	}

	if checkCString(name, fake.getNameReturn) == false {
		t.Fatal("wirego_plugin_name looks fine")
	}

}

func TestPluginFilter(t *testing.T) {
	var fake FakeListener
	fake.Reset()

	fake.getFilterReturn = "ut.test"
	Register(&fake)
	if wirego_setup() == -1 {
		t.Fatal("wirego_setup works fine for this test.")
	}

	filter := wirego_plugin_filter()
	if filter == nil {
		t.Fatal("wirego_plugin_filter returns plugin filter")
	}

	if checkCString(filter, fake.getFilterReturn) == false {
		t.Fatal("wirego_plugin_filter looks fine")
	}

}

func TestDetectInt(t *testing.T) {
	var fake FakeListener
	fake.Reset()
	if wirego_setup() == -1 {
		t.Fatal("wirego_setup works fine for this test.")
	}

	fake.getDissectorFilterReturn = append(fake.getDissectorFilterReturn, DissectorFilter{FilterType: DissectorFilterTypeInt, Name: "tcp.port", ValueInt: 11})
	fake.getDissectorFilterReturn = append(fake.getDissectorFilterReturn, DissectorFilter{FilterType: DissectorFilterTypeString, Name: "ip.addr", ValueString: "1.1.1.1"})
	fake.getDissectorFilterReturn = append(fake.getDissectorFilterReturn, DissectorFilter{FilterType: DissectorFilterTypeInt, Name: "tcp.port", ValueInt: 11})
	Register(&fake)

	idx := 0
	for {
		var value _Ctype_int
		filter := wirego_detect_int(&value, _Ctype_int(idx))
		if filter == nil {
			break
		}
		if value != 11 {
			t.Fatal("filter integer value matches defined value")
		}
		if !checkCString(filter, "tcp.port") {
			t.Fatal("dissector filter value matches defined value")
		}
		idx++
	}

	if idx != 2 {
		t.Fatal("two integer dissector filter values are defined")
	}
}

func TestDetectString(t *testing.T) {
	var fake FakeListener
	fake.Reset()

	fake.getDissectorFilterReturn = append(fake.getDissectorFilterReturn, DissectorFilter{FilterType: DissectorFilterTypeInt, Name: "tcp.port", ValueInt: 11})
	fake.getDissectorFilterReturn = append(fake.getDissectorFilterReturn, DissectorFilter{FilterType: DissectorFilterTypeString, Name: "ip.addr", ValueString: "1.1.1.1"})
	fake.getDissectorFilterReturn = append(fake.getDissectorFilterReturn, DissectorFilter{FilterType: DissectorFilterTypeInt, Name: "tcp.port", ValueInt: 11})
	Register(&fake)
	if wirego_setup() == -1 {
		t.Fatal("wirego_setup works fine for this test.")
	}

	idx := 0
	for {
		var value *_Ctype_char
		filter := wirego_detect_string(&value, _Ctype_int(idx))

		if filter == nil || value == nil {
			break
		}
		if !checkCString(value, "1.1.1.1") {
			t.Fatal("filter integer value matches defined value")
		}
		if !checkCString(filter, "ip.addr") {
			t.Fatal("dissector filter value matches defined value")
		}
		idx++
	}

	if idx != 1 {
		t.Fatal("one string dissector filter values are defined")
	}
}

func TestGetFieldsCount(t *testing.T) {
	var fake FakeListener
	fake.Reset()

	fake.getFieldsReturn = append(fake.getFieldsReturn, WiresharkField{InternalId: 1, Name: "Field 1", Filter: "field1", ValueType: ValueTypeInt8, DisplayMode: DisplayModeDecimal})
	fake.getFieldsReturn = append(fake.getFieldsReturn, WiresharkField{InternalId: 2, Name: "Field 2", Filter: "field2", ValueType: ValueTypeUInt32, DisplayMode: DisplayModeHexadecimal})
	Register(&fake)
	if wirego_setup() == -1 {
		t.Fatal("wirego_setup works fine for this test.")
	}

	if wirego_get_fields_count() != 2 {
		t.Fatal("two fields are defined and returned by wirego_get_fields_count")
	}
}

func TestGetField(t *testing.T) {
	var fake FakeListener
	fake.Reset()

	fake.getFieldsReturn = append(fake.getFieldsReturn, WiresharkField{InternalId: 1, Name: "Field 1", Filter: "field1", ValueType: ValueTypeInt8, DisplayMode: DisplayModeDecimal})
	fake.getFieldsReturn = append(fake.getFieldsReturn, WiresharkField{InternalId: 2, Name: "Field 2", Filter: "field2", ValueType: ValueTypeUInt32, DisplayMode: DisplayModeHexadecimal})
	Register(&fake)
	if wirego_setup() == -1 {
		t.Fatal("wirego_setup works fine for this test.")
	}

	var internalId _Ctype_int
	var name *_Ctype_char
	var filter *_Ctype_char
	var valueType _Ctype_int
	var display _Ctype_int

	for idx := 0; idx < 2; idx++ {

		h := wirego_get_field(idx, &internalId, &name, &filter, &valueType, &display)
		if h == -1 {
			t.Fatal("wirego_get_field returns no error")
		}
		if internalId != _Ctype_int(fake.getFieldsReturn[idx].InternalId) {
			t.Fatal("wirego_get_field returns proper field internal id for index" + fmt.Sprintf(" %d", idx))
		}
		if !checkCString(name, fake.getFieldsReturn[idx].Name) {
			t.Fatal("wirego_get_field returns proper field name for index" + fmt.Sprintf(" %d", idx))
		}
		if !checkCString(filter, fake.getFieldsReturn[idx].Filter) {
			t.Fatal("wirego_get_field returns proper filter name for index" + fmt.Sprintf(" %d", idx))
		}
		if valueType != _Ctype_int(fake.getFieldsReturn[idx].ValueType) {
			t.Fatal("wirego_get_field returns proper value type for index" + fmt.Sprintf(" %d", idx))
		}
		if display != _Ctype_int(fake.getFieldsReturn[idx].DisplayMode) {
			t.Fatal("wirego_get_field returns proper display mode for index" + fmt.Sprintf(" %d", idx))
		}
	}

	h := wirego_get_field(2, &internalId, &name, &filter, &valueType, &display)
	if h != -1 {
		t.Fatal("wirego_get_field returns an error for an invalid field index")
	}
}

func TestGetFieldFailure(t *testing.T) {
	var fake FakeListener
	fake.Reset()

	fake.getFieldsReturn = append(fake.getFieldsReturn, WiresharkField{InternalId: 1, Name: "Field 1", Filter: "field1", ValueType: ValueTypeInt8, DisplayMode: DisplayModeDecimal})
	fake.getFieldsReturn = append(fake.getFieldsReturn, WiresharkField{InternalId: 1, Name: "Field 1", Filter: "field1", ValueType: ValueTypeInt8, DisplayMode: DisplayModeDecimal})
	fake.getFieldsReturn = append(fake.getFieldsReturn, WiresharkField{InternalId: 2, Name: "Field 2", Filter: "field2", ValueType: ValueTypeUInt32, DisplayMode: DisplayModeHexadecimal})
	Register(&fake)
	if wirego_setup() != -1 {
		t.Fatal("wirego_get_field returns an error if duplicate InternalIds are found")
	}
}

func TestDissectPacket(t *testing.T) {
	var fake FakeListener
	fake.Reset()

	fake.dissectResult.Protocol = "Test Proto"
	fake.dissectResult.Info = "Much information"
	fake.dissectResult.Fields = append(fake.dissectResult.Fields, DissectField{InternalId: 1, Offset: 0, Length: 14})
	fake.dissectResult.Fields = append(fake.dissectResult.Fields, DissectField{InternalId: 2, Offset: 10, Length: 1})
	fake.getFieldsReturn = append(fake.getFieldsReturn, WiresharkField{InternalId: 1, Name: "Field 1", Filter: "field1", ValueType: ValueTypeInt8, DisplayMode: DisplayModeDecimal})
	fake.getFieldsReturn = append(fake.getFieldsReturn, WiresharkField{InternalId: 2, Name: "Field 2", Filter: "field2", ValueType: ValueTypeUInt32, DisplayMode: DisplayModeHexadecimal})
	Register(&fake)
	if wirego_setup() == -1 {
		t.Fatal("wirego_setup works fine for this test.")
	}

	var src _Ctype_char
	var dst _Ctype_char
	var layer _Ctype_char
	var packetSize _Ctype_int
	var packet _Ctype_char

	var internalId _Ctype_int
	var offset _Ctype_int
	var length _Ctype_int

	//Tester's note: since I don't want to waste time building C.char*
	//buffers (without the C package), let's fake everything.
	//Similar code would obviously crash in production (packet size is 1, and provided length is 255).
	packetSize = 255
	packet = 0x12
	src = 0x00
	dst = 0x00
	layer = 0x00

	handle := wirego_dissect_packet(&src, &dst, &layer, &packet, packetSize)

	if handle == -1 {
		t.Fatal("wirego_dissect_packet doesn't fail")
	}

	if fake.dissectCount != 1 {
		t.Fatal("Dissect is called")
	}

	//Valid calls
	proto := wirego_result_get_protocol(handle)
	if !checkCString(proto, fake.dissectResult.Protocol) {
		t.Fatal("wirego_result_get_protocol returns protocol")
	}
	info := wirego_result_get_info(handle)
	if !checkCString(info, fake.dissectResult.Info) {
		t.Fatal("wirego_result_get_info returns info")
	}
	count := wirego_result_get_fields_count(handle)
	if count != _Ctype_int(len(fake.dissectResult.Fields)) {
		t.Fatal("wirego_result_get_fields_count returns number of returned fields")
	}
	for i := 0; i < len(fake.dissectResult.Fields); i++ {
		wirego_result_get_field(handle, _Ctype_int(i), &internalId, &offset, &length)
		if internalId != _Ctype_int(fake.dissectResult.Fields[i].InternalId) {
			t.Fatal("wirego_result_get_field has proper InternalId for result" + fmt.Sprintf(" %d", i))
		}
		if offset != _Ctype_int(fake.dissectResult.Fields[i].Offset) {
			t.Fatal("wirego_result_get_field has proper Offset for result" + fmt.Sprintf(" %d", i))
		}
		if length != _Ctype_int(fake.dissectResult.Fields[i].Length) {
			t.Fatal("wirego_result_get_field has proper Length for result" + fmt.Sprintf(" %d", i))
		}
	}
}

func TestDissectPacketAccessorFailures(t *testing.T) {
	var fake FakeListener
	fake.Reset()

	fake.dissectResult.Protocol = "Test Proto"
	fake.dissectResult.Info = "Much information"
	fake.dissectResult.Fields = append(fake.dissectResult.Fields, DissectField{InternalId: 1, Offset: 0, Length: 14})
	fake.dissectResult.Fields = append(fake.dissectResult.Fields, DissectField{InternalId: 2, Offset: 10, Length: 1})
	fake.getFieldsReturn = append(fake.getFieldsReturn, WiresharkField{InternalId: 1, Name: "Field 1", Filter: "field1", ValueType: ValueTypeInt8, DisplayMode: DisplayModeDecimal})
	fake.getFieldsReturn = append(fake.getFieldsReturn, WiresharkField{InternalId: 2, Name: "Field 2", Filter: "field2", ValueType: ValueTypeUInt32, DisplayMode: DisplayModeHexadecimal})
	Register(&fake)

	var internalId _Ctype_int
	var offset _Ctype_int
	var length _Ctype_int

	//Accessor failures
	invalidHandle := _Ctype_int(56467)
	proto := wirego_result_get_protocol(invalidHandle)
	if !checkCString(proto, "") {
		t.Fatal("wirego_result_get_protocol fails when called with invalid handle")
	}
	info := wirego_result_get_info(invalidHandle)
	if !checkCString(info, "") {
		t.Fatal("wirego_result_get_info fails when called with invalid handle")
	}
	count := wirego_result_get_fields_count(invalidHandle)
	if count != 0 {
		t.Fatal("wirego_result_get_fields_count fails when called with invalid handle")
	}
	wirego_result_get_field(invalidHandle, 0, &internalId, &offset, &length)
	if (internalId != -1) || (offset != -1) || (length != -1) {
		t.Fatal("wirego_result_get_field fails when called with invalid handle")
	}

}

func TestDissectPacketResultsInvalidOffset(t *testing.T) {
	var fake FakeListener
	fake.Reset()

	fake.dissectResult.Protocol = "Test Proto"
	fake.dissectResult.Info = "Much information"
	fake.dissectResult.Fields = append(fake.dissectResult.Fields, DissectField{InternalId: 1, Offset: 3012, Length: 14})
	fake.getFieldsReturn = append(fake.getFieldsReturn, WiresharkField{InternalId: 1, Name: "Field 1", Filter: "field1", ValueType: ValueTypeInt8, DisplayMode: DisplayModeDecimal})
	Register(&fake)
	if wirego_setup() == -1 {
		t.Fatal("wirego_setup works fine for this test.")
	}

	var src _Ctype_char
	var dst _Ctype_char
	var layer _Ctype_char
	var packetSize _Ctype_int
	var packet _Ctype_char

	//Tester's note: since I don't want to waste time building C.char*
	//buffers (without the C package), let's fake everything.
	//Similar code would obviously crash in production (packet size is 1, and provided length is 255).
	packetSize = 255
	packet = 0x12
	src = 0x00
	dst = 0x00
	layer = 0x00

	handle := wirego_dissect_packet(&src, &dst, &layer, &packet, packetSize)

	if handle != -1 {
		t.Fatal("wirego_dissect_packet fails if returned field offset is invalid")
	}
}

func TestDissectPacketResultsInvalidLength(t *testing.T) {
	var fake FakeListener
	fake.Reset()

	fake.dissectResult.Protocol = "Test Proto"
	fake.dissectResult.Info = "Much information"
	fake.dissectResult.Fields = append(fake.dissectResult.Fields, DissectField{InternalId: 1, Offset: 100, Length: 3012})
	fake.getFieldsReturn = append(fake.getFieldsReturn, WiresharkField{InternalId: 1, Name: "Field 1", Filter: "field1", ValueType: ValueTypeInt8, DisplayMode: DisplayModeDecimal})
	Register(&fake)
	if wirego_setup() == -1 {
		t.Fatal("wirego_setup works fine for this test.")
	}

	var src _Ctype_char
	var dst _Ctype_char
	var layer _Ctype_char
	var packetSize _Ctype_int
	var packet _Ctype_char

	//Tester's note: since I don't want to waste time building C.char*
	//buffers (without the C package), let's fake everything.
	//Similar code would obviously crash in production (packet size is 1, and provided length is 255).
	packetSize = 255
	packet = 0x12
	src = 0x00
	dst = 0x00
	layer = 0x00

	handle := wirego_dissect_packet(&src, &dst, &layer, &packet, packetSize)

	if handle != -1 {
		t.Fatal("wirego_dissect_packet fails if returned field length is invalid")
	}
}

func TestDissectPacketResultsInvalidInternalId(t *testing.T) {
	var fake FakeListener
	fake.Reset()

	fake.dissectResult.Protocol = "Test Proto"
	fake.dissectResult.Info = "Much information"
	fake.dissectResult.Fields = append(fake.dissectResult.Fields, DissectField{InternalId: 1, Offset: 100, Length: 10})
	fake.getFieldsReturn = append(fake.getFieldsReturn, WiresharkField{InternalId: 733, Name: "Field 1", Filter: "field1", ValueType: ValueTypeInt8, DisplayMode: DisplayModeDecimal})
	Register(&fake)
	if wirego_setup() == -1 {
		t.Fatal("wirego_setup works fine for this test.")
	}

	var src _Ctype_char
	var dst _Ctype_char
	var layer _Ctype_char
	var packetSize _Ctype_int
	var packet _Ctype_char

	//Tester's note: since I don't want to waste time building C.char*
	//buffers (without the C package), let's fake everything.
	//Similar code would obviously crash in production (packet size is 1, and provided length is 255).
	packetSize = 255
	packet = 0x12
	src = 0x00
	dst = 0x00
	layer = 0x00

	handle := wirego_dissect_packet(&src, &dst, &layer, &packet, packetSize)

	if handle != -1 {
		t.Fatal("wirego_dissect_packet fails if returned field uses invalid internalId")
	}
}
