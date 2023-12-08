# Wirego

A Wireshark plugin wrapper for golang


![Wirego Logo](./img/wirego_logo_small.png)

## Introduction

Writing plugins for Wireshark in C/C++ can be opaque: the APIs are quite powerfull, but not really obvious to use. If you just want to develop a quick and dirty plugin you will spend more time trying to understand how things work instead of actually writing the core of your plugin.

Another alternative is to use LUA, but first of all you need to know this language. So again, you'll spend more time trying to learn that new language than actually writing this quick and dirty plugin.


Wirego is a plugin for Wireshark, written in C that actually loads a plugin written in Go language.

You basically don't have to touch the Wirego plugin and you will be given a dummy empty golang plugin to start with.

Now how does the Wirego plugin where to find your wonderfull quick and dirty Golang plugin?
Well, you just edit a $HOME/.wirego configuration file containing the full path to your plugin and that's it.

## Overview

In order to use Wirego, you will need to build the Wirego plugin for Wireshark (or download a prebuild version).

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

// GetDissectorFilter returns a wireshark filter that will select which packets
// will be sent to your dissector for parsing.
// Two types of filters can be defined: Integers or Strings
func (WiregoExample) GetDissectorFilter() []wirego.DissectorFilter {
	var filters []wirego.DissectorFilter

	filters = append(filters, wirego.DissectorFilter{FilterType: wirego.DissectorFilterTypeInt, Name: "udp.port", ValueInt: 137})
	filters = append(filters, wirego.DissectorFilter{FilterType: wirego.DissectorFilterTypeString, Name: "bluetooth.uuid", ValueString: "1234"})

	return filters
}

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
	return &res
}
```

The last step is to build your plugin using:

    	go build -o mywonderfullplugin.so -buildmode=c-shared

And... that's all!

Run Wireshark, to go Preferences -> Wirego and point to your freshly built golang plugin.


A fully working example can be found [Here](./wirego/example/wirego_example.go)

## Building the Wirego plugin

**Note:** If you're running on Linux, you may just want to download the prebuild plugin here: [https://gitlab.qb/bgirard/wirego/-/artifacts](https://gitlab.qb/bgirard/wirego/-/artifacts)

Clone Wireshark:

    git clone https://github.com/wireshark/wireshark.git

Create a symlink from the Wireshark plugins folder to the "wirego_plugin"

    ln -s <path_to>/wirego_plugin wireshark/plugins/epan/wirego

Edit Wireshark's main CMakelists.txt and add the following to PLUGIN_SRC_DIRS:

    plugins/epan/wirego

Now build Wireshark (see README.xxx), but basically it's just:

    mkdir build && cd build
    cmake ../
    make -j


## Building the Golang plugin example

Before going any further, you should build the example and try to load it with the wirego Wireshark plugin.

    cd wirego/example/
    make

The example plugin is a dummy plugin to help you getting started.

## Running Wireshark

Now that Wireshark has been built, you can see that the "epan" directory now contains a plugin called "wirego.so" (see Wireshark documentation for the exact location).

Edit a file located at $HOME/.wirego and type the full path to your plugin.
Start Wireshark.

  echo "/home/bob/myplugin/myplugin.so" > $HOME/.wirego
  ./wireshark

To make sure your plugin has been properly loaded, open Analyze>Enabled Protocols and search for "wirego".

If your golang plugin fails to load for any reason, the plugin will not appear on that list.

You may also open Wireshark preferences, select "Protocols" on the left menu and then locate "Wirego". The preferences page for Wirego will actually show the path loaded from your configuration file (if any).


## Developping a Golang plugin

Now that you've built the "example" plugin, it's probably time to update it with your own code.

Everything you need to update is found in "wirego/example/wirego_example.go" (feel free to rename this file).

In order to create a plugin, you need to import "wirego" and implement the **wirego.WiregoInterface** interface (defined in wirego/wirego.go).


The GetName() and GetFilter() defines how your plugin will appear in Wireshark and how you will be able to filter it using Wireshark.

The **Setup()** function is called when the plugin is loaded. Feel free to setup everything you need here.
That's also a nice place to setup the complete detailed list of your custom fields.
A "field" is defined by the **wirego.WiresharkField** structure and contains:

  - The field enum (InternalId), as defined previously
  - The field name
  - A Wireshark filter that can be used to filter matching packets
  - The type of value for this field
  - How this field should be displayed (**DisplayMode**)

The **GetFields()** returns the list of fields description (see **Setup()**).
Those fields are the results of your parsing code.
During the plugin initialization, behind the hood, we list all the different fields that we may eventually provide, when analyzing packets.
Each field will then be referred with a simple "enum" value, pointing to the full description of the field previously defined.


The function **GetDissectorFilterInteger()** is used to filter the packets that should be sent to your disector. If your protocol happens on TCP port 7122, that's where you define it.



**DissectPacket(packet []byte)** is where the magic happens. You receive a packet payload and return a **wirego.DissectResult** structure.


## Next steps

That project is still under development, many things needs to be improved.
Here's a partial list:

  - The fields type list is incomplete
  - The current API only allows one and only one node to be created for a given packet
  - Support payload split into several packets

## Additional notes

Wirego preferences uses a dedicated config file to locate the golang plugin path, hence when modifying you will need to restart Wireshark.

Here's why:

  - we need to setup everything (plugin name, fields..) during the proto_register_wirego call
  - preferences values are only loaded during the proto_reg_handoff_wirego call, which is too late for us