package main

/*
	!DO NOT EDIT THIS FILE!

	If you plan to create a golang plugin for Wireshark,
	you're looking at the wrong file.
	Take your chance with "wirego_template.go".

	You probably don't want to look at this file actually.
	Thust me.
*/
// extern int wirego_setup();
// extern int wirego_version_major();
// extern int wirego_version_minor();
// extern char* wirego_plugin_name();
// extern char* wirego_plugin_filter();
// extern int wirego_detect_int(char *);

import "C"

const (
	WIREGO_VERSION_MAJOR = 1
	WIREGO_VERSION_MINOR = 0
)

// Not used
func main() {}

type ValueType int

const (
	ValueTypeNone   ValueType = iota
	ValueTypeBool   ValueType = iota
	ValueTypeUInt8  ValueType = iota
	ValueTypeInt8   ValueType = iota
	ValueTypeInt16  ValueType = iota
	ValueTypeUInt16 ValueType = iota
	ValueTypeInt32  ValueType = iota
	ValueTypeUInt32 ValueType = iota
)

type DisplayMode int

const (
	DisplayModeDecimal     DisplayMode = iota
	DisplayModeHexadecimal DisplayMode = iota
)

type FieldId int
type WiresharkField struct {
	InternalId  FieldId
	Name        string
	Filter      string
	ValueType   ValueType
	DisplayMode DisplayMode
}

//export wirego_setup
func wirego_setup() C.int {
	return C.int(setup())
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
	return C.CString(WIREGO_PLUGIN_NAME)
}

//export wirego_plugin_filter
func wirego_plugin_filter() *C.char {
	return C.CString(WIREGO_PLUGIN_FILTER)
}

//export wirego_detect_int
func wirego_detect_int(i *C.int) *C.char {
	filterName, filterValue := getDetectFilterInteger()

	if len(filterName) == 0 {
		*i = 0
		return nil
	}
	*i = C.int(filterValue)
	return C.CString(filterName)
}

//export wirego_get_fields_count
func wirego_get_fields_count() int {
	return len(getFields())
}

//export wirego_get_field
func wirego_get_field(index int, internalId *C.int, name **C.char, filter **C.char, valueType *C.int, display *C.int) int {
	fields := getFields()
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
	*valueType = 0
	*display = 0

	//TODO

	return 0
}

// https://stackoverflow.com/questions/6125683/call-go-functions-from-c
