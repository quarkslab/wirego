package main

// extern int wirego_version_major();
// extern int wirego_version_minor();
// extern char* wirego_name();
// extern char* wirego_filter();
import "C"

const (
	WIREGO_VERSION_MAJOR = 1
	WIREGO_VERSION_MINOR = 0
)

// Not used
func main() {}

//export wirego_version_major
func wirego_version_major() C.int {
	return WIREGO_VERSION_MAJOR
}

//export wirego_version_minor
func wirego_version_minor() C.int {
	return WIREGO_VERSION_MINOR
}

//export wirego_name
func wirego_name() *C.char {
	return C.CString(WIREGO_PLUGIN_NAME)
}

//export wirego_filter
func wirego_filter() *C.char {
	return C.CString(WIREGO_PLUGIN_FILTER)
}

// https://stackoverflow.com/questions/6125683/call-go-functions-from-c
