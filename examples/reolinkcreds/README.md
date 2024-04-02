# Reolink Credentials example plugin

## Introduction

This simple plugin parses authentication requests made to a Reolink network camera.
Traffic occurs in clear form, over HTTP on port 80.
An example pcap can be found [here](./reolink_sample.pcapng).

This plugin extracts credentials passed to the camera and uses the response to detect wether those were valid or not.
Credentials and response are transmitted using simple JSON structures over HTTP.

In order to provide an interesting example, we want to display the credentials validity on the request packet itself. Since this information will be known once the response has been seen, we need to disable the results cache:

  - during first pass, we have no idea yet if the request credentials are valid
  - once we seen the response, we can update our own cache with the request result
  - during the second pass, we are now able to display on the request pass if the provided credentials are valid

## Detection strategy & Wireshark limitations

Our traffic is seen over HTTP, port 80.

In an ideal world, we would simply register an heuristic function on top of "http" as follow:

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



During **init**, which is called at package initialization (hence when the plugin is loaded), we register to the Wirego package. As previously explained, the cache is disabled: in order to flag the requests as "valid" or "invalid" we need to be able to update the http request result.

The **Setup** is not used here, we don't have anything to initialize.

**GetName** returns the name of our plugin.

**GetFilter** defines the string that we will use to filter the packets matching our protocol in Wireshark.


The **GetFields** function is used to declare two distinct custom fields pointing to thje user and password on the authentication request.

As previously explained, detection will be performed using a filter on TCP port 80. This filter is defined in **GetDetectionFilters**.

Since we can't use heuristics, **GetDetectionHeuristicsParents** and **DetectionHeuristic** are left empty.

The protocol dissection occurs in **DissectPacket**:

  - we first try to parse the TCP payload as an HTTP request
  - if this fails, we try to parse it as an http response

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

