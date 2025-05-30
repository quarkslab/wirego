# Reolink Credentials example plugin

The complete code of this example can be found [here](./wirego_reolinkcreds.go)
Before getting deep in this example, you should probably take a look at the [minimalist](../minimal/README.md) and [ReolinkCreds Light](../reolinkcredslight/README.md) examples.

## Introduction

This simple plugin parses authentication requests made to a Reolink network camera.
Traffic is sent in clear form, over HTTP on port 80.
An example pcap can be found [here](./reolink_sample.pcapng).

This plugin extracts credentials passed to the camera and uses the response to detect wether those were valid or not.
Credentials and response are transmitted using simple JSON structures over HTTP.

In order to provide an interesting example, we want to display the credentials validity on the request packet itself. Since this information will be known once the response has been seen, we need to disable the results cache:

  - during first pass, we have no idea yet if the request credentials are valid
  - once we seen the response, we can update our own cache with the request result
  - during the second pass, we are now able to display on the request pass if the provided credentials are valid

![screenshot](./screenshot.png)

## Detection strategy & Wireshark limitations

Our traffic is seen over HTTP, port 80.

In an ideal world, we would simply register an heuristic function on top of "http" as follow:

```golang
    func (WiregoReolinkCreds) GetDetectionHeuristicsParents() []string {
      return []string{"http"}
    }

    func (WiregoReolinkCreds) DetectionHeuristic(packetNumber int, src string, dst string, layer string,  packet []byte) bool {
      if !strings.HasPrefix(req.RequestURI, "/cgi-bin/api.cgi?cmd=Login") {
        return true
      } else {
        return false
      }
    }
```

We would have the opportunity to flag a generic HTTP traffic as something more specific. If our heuristic fails, we eventually let some other plugin take care of this packet.
Sadly this doesn't work, Wireshark http plugin seems to perform an early detection on the HTTP payload and marks it as "json". The registered heuristics are not called because the embeded "protocol" is already known.

So, we could eventually think of registering our heuristic on top of "json", so that once http marks the HTTP payload as JSON we would have a chance to try to parse it and detect if it is ours.
Again this is not possible, the json plugin does not register itself for heuristics so no detection heuristics can be applied on json payloads.

One other option would be to register an heuristic on top of "tcp" and then try to look for port 80, parse HTTP protocol and check the URI.
Again, this still not works since HTTP is detected before we have a chance to apply our heuristic.

The main problem here is that Wireshark does not really act as a modern DPI framework. The **detection methods are quite linear, some are hardcoded and no priorities are handled**.

Our only option here is to register a **filter** on tcp port 80. All HTTP traffic on port 80 will be sent to our plugin, thus disabling the "http" plugin.
The http plugin does the same and uses fields to register on top of tcp port 80. Since that user plugins are loaded after embeded ones, our filter will overwrite the http one.

## Implementation

As previously explained, the cache is disabled: in order to flag the requests as "valid" or "invalid" we need to be able to update the http request result.

```golang
type WiregoReolinkCreds struct {
}

func main() {
	var wge WiregoReolinkCreds

	wg, err := wirego.New("ipc:///tmp/wirego0", false, wge)
	if err != nil {
		fmt.Println(err)
		return
	}
	wg.ResultsCacheEnable(false)

	wg.Listen()
}
```

**GetName** returns the name of our plugin.

**GetFilter** defines the string that we will use to filter the packets matching our protocol in Wireshark.

```golang
// This function shall return the plugin name
func (WiregoReolinkCreds) GetName() string {
	return "Wirego Reolink Credentials"
}

// This function shall return the wireshark filter
func (WiregoReolinkCreds) GetFilter() string {
	return "reolink"
}
```


The **GetFields** function is used to declare tree distinct custom fields pointing to the user, password and authentication result code. We define first associated "enums" and then for each field how we want it to be displayed and called inside Wireshark.

```golang

// Define here enum identifiers, used to refer to a specific field
const (
	FieldIdUser       wirego.FieldId = 1
	FieldIdPassword   wirego.FieldId = 2
	FieldIdAuthResult wirego.FieldId = 3
)

// GetFields returns the list of fields descriptor that we may eventually return
// when dissecting a packet payload
func (WiregoReolinkCreds) GetFields() []wirego.WiresharkField {
	var fields []wirego.WiresharkField

	//Setup our wireshark custom fields
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldIdUser, Name: "User", Filter: "reolink.user", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldIdPassword, Name: "Password", Filter: "reolink.password", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldIdAuthResult, Name: "Authentication result", Filter: "reolink.authresult", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})

	return fields
}
```

As previously explained, detection will be performed using a filter on TCP port 80. This filter is defined in **GetDetectionFilters**.

```golang
// GetDetectionFilters returns a wireshark filter that will select which packets
// will be sent to your dissector for parsing.
// Two types of filters can be defined: Integers or Strings
func (WiregoReolinkCreds) GetDetectionFilters() []wirego.DetectionFilter {
	var filters []wirego.DetectionFilter
	filters = append(filters, wirego.DetectionFilter{FilterType: wirego.DetectionFilterTypeInt, Name: "tcp.port", ValueInt: 80})

	return filters
}
```


Since we can't use heuristics, **GetDetectionHeuristicsParents** and **DetectionHeuristic** are left empty.

```golang
// GetDissectorFilterHeuristics returns a list of protocols on top of which detection heuristic
// should be called.
func (WiregoReolinkCreds) GetDetectionHeuristicsParents() []string {
	return []string{}
}

func (WiregoReolinkCreds) DetectionHeuristic(packetNumber int, src string, dst string, layer string, packet []byte) bool {
	return false
}
```

The protocol dissection occurs in **DissectPacket**:

  - we first try to parse the TCP payload as an HTTP request
  - if this fails, we try to parse it as an http response

```golang
// DissectPacket provides the packet payload to be parsed.
func (w WiregoReolinkCreds) DissectPacket(packetNumber int, src string, dst string, layer string, packet []byte) *wirego.DissectResult {
	var res wirego.DissectResult

	//Create a bufio.Reader from the packet slice
	r := bytes.NewReader(packet)
	buf := bufio.NewReader(r)

	//Try to parse as an http request
	req, err := http.ReadRequest(buf)
	if err == nil {
		//Success? Call the dissect request function
		return w.DissectRequest(packetNumber, src, dst, layer, req, packet)
	}

	//This failed, rewing the buffer and retry as a Response
	r.Seek(0, io.SeekStart)
	buf.Reset(r)

	//Look for associated http request
	closestRequestIdx := -1
	for i := 0; i < len(requestsCache); i++ {
		if requestsCache[i].packetNumber >= packetNumber {
			break
		}
		closestRequestIdx = i
	}
	//No previous request found, abort
	if closestRequestIdx == -1 {
		return &res
	}

	//Parse as an http response
	resp, err := http.ReadResponse(buf, requestsCache[closestRequestIdx].req)
	if err == nil {
		//Success? Call the dissect response function
		return w.DissectResponse(packetNumber, src, dst, layer, resp, closestRequestIdx, packet)
	}
	return &res
}
```

I won't copy paste the code for the two last functions since this is generic code not really related to Wirego.


The **request dissector** parses the TCP payload using the golang "http" package and then applies what could have been our detection heuristic: check if the URI is *"/cgi-bin/api.cgi?cmd=Login"*.
If this late detection succeeds, the HTTP payload is parsed using the golang "json" package and credentials are extracted.

In order to parse an http response, the golang "http" package requires the associated request. We update a cache containing all requests and their packet number.

The **response dissector** will look into the requests cache for a matching request (the closest lower packet number). The http payload is parsed using the golang "json" package and the authentication result is retrieved. The requests cache is updated with the authentication result.



## Multiple pass management

Wireshark uses a multiple pass strategy.
When a pcap is loaded, all packets are passed to the dissectors following the capture order.

Atfter this first pass, dissectors are called again depending on the Wireshark's window focus.
At this point, there's no guarantee that the passed packets follows any order, this totally depends on what is displayed.

In our plugin, after the first pass the requests dissector will not be able to tell if the request was successfull or not. During later passes, the cache has been updated by the results dissector.

