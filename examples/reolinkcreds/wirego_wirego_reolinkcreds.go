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

//[{"cmd":"Login","action":0,"param":{"User":{"userName":"admin","password":"myp4ssw0rd!"}}}]

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
	FieldIdCustom1             wirego.FieldId = 1
	FieldIdCustom2             wirego.FieldId = 2
	FieldIdCustomWithSubFields wirego.FieldId = 3
)

/*
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

// Unused (but mandatory)
func main() {}

// Called at golang environment initialization (you should probably not touch this)
func init() {
	var wge WiregoReolinkCreds

	//Register to the wirego package
	wirego.Register(wge)
	wirego.ResultsCacheEnable(false)
}

// This function is called when the plugin is loaded.
func (WiregoReolinkCreds) Setup() error {

	return nil
}

// This function shall return the plugin name
func (WiregoReolinkCreds) GetName() string {
	return "Wirego Reolink Credentials"
}

// This function shall return the wireshark filter
func (WiregoReolinkCreds) GetFilter() string {
	return "wgreolinkcreds"
}

// GetFields returns the list of fields descriptor that we may eventually return
// when dissecting a packet payload
func (WiregoReolinkCreds) GetFields() []wirego.WiresharkField {
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

var lastReq *http.Request

func (WiregoReolinkCreds) DissectRequest(packetNumber int, src string, dst string, layer string, req *http.Request, packet []byte) *wirego.DissectResult {
	var res wirego.DissectResult
	var authRequest []ReolinkAuthRequest

	if !strings.HasPrefix(req.RequestURI, "/cgi-bin/api.cgi?cmd=Login") {
		return &res
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return &res
	}

	err = json.Unmarshal(body, &authRequest)
	if err != nil {
		return &res
	}

	if len(authRequest) == 0 {
		return &res
	}

	if (authRequest[0].Cmd != "Login") || (len(authRequest[0].Param.User.UserName) == 0) || (len(authRequest[0].Param.User.Password) == 0) {
		return &res
	}

	//This string will appear on the packet being parsed
	res.Protocol = "Reolink Creds"

	//This (optional) string will appear in the info section
	res.Info = fmt.Sprintf("Authentication request %s:%s", authRequest[0].Param.User.UserName, authRequest[0].Param.User.Password)

	lastReq = req
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

	//This string will appear on the packet being parsed
	res.Protocol = "Reolink Creds"

	if authResponse[0].Code == 1 {
		res.Info = "Invalid auth"
	} else if authResponse[0].Code == 0 {
		res.Info = "Valid auth"
	} else {
		res.Info = "Unknown result"
	}

	lastReq = nil

	return &res
}

// DissectPacket provides the packet payload to be parsed.
func (w WiregoReolinkCreds) DissectPacket(packetNumber int, src string, dst string, layer string, packet []byte) *wirego.DissectResult {
	var res wirego.DissectResult

	r := bytes.NewReader(packet)
	buf := bufio.NewReader(r)
	req, err := http.ReadRequest(buf)
	if err == nil {
		return w.DissectRequest(packetNumber, src, dst, layer, req, packet)
	}

	r.Seek(0, io.SeekStart)
	buf.Reset(r)
	resp, err := http.ReadResponse(buf, lastReq)
	if err == nil {
		return w.DissectResponse(packetNumber, src, dst, layer, resp, packet)
	}
	return &res
}
