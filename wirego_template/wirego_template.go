package main

/*
	Do your stuff here.
*/

const (
	WIREGO_PLUGIN_NAME   = "Wirego template" // Your plugin name
	WIREGO_PLUGIN_FILTER = "wiregotpl"       // You protocol filter
)

// getDetectFilterInteger returns a wireshark filter with an integer value,
// that will select which packets will be sent to your dissector for parsing.
// If you don't have any, just return ("", 0)
func getDetectFilterInteger() (string, int) {
	return "udp.port", 17
}
