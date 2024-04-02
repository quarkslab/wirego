package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/quarkslab/wirego/wirego/wirego"
)

type AuthStatus int

const (
	AuthStatusValid   AuthStatus = iota
	AuthStatusInvalid AuthStatus = iota
	AuthStatusUnknown AuthStatus = iota
)

/*
	Requests have the following format:

	[
		{
			"cmd":"Login",
			"action":0,
			"param":{
				"User":{
					"userName":"admin","password":"myp4ssw0rd!"
				}
			}
		}
	]
*/

type ReolinkAuthUser struct {
	UserName string `json:"userName"`
	Password string `json:"password"`
}

type ReolinkAuthParam struct {
	User ReolinkAuthUser `json:"User"`
}

type ReolinkAuthRequest struct {
	Cmd    string           `json:"cmd"`
	Action int              `json:"action"`
	Param  ReolinkAuthParam `json:"param"`
}

// Define here enum identifiers, used to refer to a specific field
const (
	FieldIdUser       wirego.FieldId = 1
	FieldIdPassword   wirego.FieldId = 2
	FieldIdAuthResult wirego.FieldId = 3
)

/*
Responses have the following format:
[
   {
      "cmd" : "Login",
      "code" : 1,
      "error" : {
         "detail" : "login failed",
         "rspCode" : -7
      }
   }
]
*/

type ReolinkAuthResponseError struct {
	Detail  string `json:"detail"`
	RspCode int    `json:"rspCode"`
}

type ReolinkAuthResponse struct {
	Cmd   string                   `json:"cmd"`
	Code  int                      `json:"code"`
	Error ReolinkAuthResponseError `json:"error"`
}

// Since we implement the wirego.WiregoInterface we need some structure to hold it.
type WiregoReolinkCreds struct {
}

var lastSeenRequest *http.Request

// Unused (but mandatory)
func main() {}

// Called at golang environment initialization (you should probably not touch this)
func init() {
	var wge WiregoReolinkCreds

	//Register to the wirego package
	wirego.Register(wge)
	wirego.ResultsCacheEnable(true)
}

// This function is called when the plugin is loaded.
func (WiregoReolinkCreds) Setup() error {
	lastSeenRequest = nil
	return nil
}

// This function shall return the plugin name
func (WiregoReolinkCreds) GetName() string {
	return "Wirego Reolink Credentials"
}

// This function shall return the wireshark filter
func (WiregoReolinkCreds) GetFilter() string {
	return "reolink"
}

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

// GetDetectionFilters returns a wireshark filter that will select which packets
// will be sent to your dissector for parsing.
// Two types of filters can be defined: Integers or Strings
func (WiregoReolinkCreds) GetDetectionFilters() []wirego.DetectionFilter {
	var filters []wirego.DetectionFilter
	filters = append(filters, wirego.DetectionFilter{FilterType: wirego.DetectionFilterTypeInt, Name: "tcp.port", ValueInt: 80})

	return filters
}

// GetDissectorFilterHeuristics returns a list of protocols on top of which detection heuristic
// should be called.
func (WiregoReolinkCreds) GetDetectionHeuristicsParents() []string {
	return []string{}
}

func (WiregoReolinkCreds) DetectionHeuristic(packetNumber int, src string, dst string, layer string, packet []byte) bool {
	return false
}

func (WiregoReolinkCreds) DissectRequest(packetNumber int, src string, dst string, layer string, req *http.Request, packet []byte) *wirego.DissectResult {
	var res wirego.DissectResult
	var authRequest []ReolinkAuthRequest

	res.Protocol = "Reolink Creds Light"

	//Late detection heuristic
	if !strings.HasPrefix(req.RequestURI, "/cgi-bin/api.cgi?cmd=Login") {
		return &res
	}

	//Parse http body as a json payload
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return &res
	}
	err = json.Unmarshal(body, &authRequest)
	if err != nil {
		return &res
	}

	//Make sure we've parsed something that looks like a Reolink authentication request
	if len(authRequest) == 0 {
		return &res
	}
	if (authRequest[0].Cmd != "Login") || (len(authRequest[0].Param.User.UserName) == 0) || (len(authRequest[0].Param.User.Password) == 0) {
		return &res
	}

	//Set Protocol and info fields
	res.Protocol = "Reolink Creds"
	res.Info = fmt.Sprintf("Authentication request %s:%s", authRequest[0].Param.User.UserName, authRequest[0].Param.User.Password)

	//Offsets sent to Wireshark must refer to the "packet" data sent to the dissector
	//Since we've registered on top of TCP port 80, it's quite hard to predict where the user and passwords fields
	//are located. We use a simple strategy here (this will obviously fail if the password is, for example "cgi-bin")
	userOffset := bytes.Index(packet, []byte(authRequest[0].Param.User.UserName))
	if userOffset != -1 {
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldIdUser, Offset: userOffset, Length: len(authRequest[0].Param.User.UserName)})
	}

	passwordOffset := bytes.Index(packet, []byte(authRequest[0].Param.User.Password))
	if passwordOffset != -1 {
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldIdPassword, Offset: passwordOffset, Length: len(authRequest[0].Param.User.Password)})
	}

	lastSeenRequest = req

	return &res
}

func (WiregoReolinkCreds) DissectResponse(packetNumber int, src string, dst string, layer string, resp *http.Response, packet []byte) *wirego.DissectResult {
	var res wirego.DissectResult
	var authResponse []ReolinkAuthResponse

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &res
	}

	err = json.Unmarshal(body, &authResponse)
	if err != nil {
		return &res
	}

	if len(authResponse) == 0 {
		return &res
	}

	if authResponse[0].Cmd != "Login" {
		return &res
	}

	//Update Protocol and Info fields
	res.Protocol = "Reolink Creds"
	if authResponse[0].Code == 1 {
		res.Info = "Invalid auth"
	} else if authResponse[0].Code == 0 {
		res.Info = "Valid auth"
	} else {
		res.Info = "Unknown result"
	}

	//Point to the authentication result
	detectString := "\"code\" : "
	resultOffset := bytes.Index(packet, []byte(detectString))
	if resultOffset != -1 {
		resultOffset += len(detectString)
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldIdAuthResult, Offset: resultOffset, Length: 1})
	}

	return &res
}

// DissectPacket provides the packet payload to be parsed.
func (w WiregoReolinkCreds) DissectPacket(packetNumber int, src string, dst string, layer string, packet []byte) *wirego.DissectResult {
	var res wirego.DissectResult

	r := bytes.NewReader(packet)
	buf := bufio.NewReader(r)

	//Try to parse as a request
	req, err := http.ReadRequest(buf)
	if err == nil {
		return w.DissectRequest(packetNumber, src, dst, layer, req, packet)
	}

	r.Seek(0, io.SeekStart)
	buf.Reset(r)

	//Maybe a response

	//No previous request seen
	if lastSeenRequest == nil {
		return &res
	}

	resp, err := http.ReadResponse(buf, lastSeenRequest)
	if err == nil {
		return w.DissectResponse(packetNumber, src, dst, layer, resp, packet)
	}
	return &res
}
