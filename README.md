# Wirego

A Wireshark plugin wrapper for golang

## Introduction

Writing plugins for Wireshark in C/C++ can be opaque: the APIs are quite powerfull, but not really obvious to use. If you just want to develop a quick and dirty plugin you will spend more time trying to understand how things work instead of actually writing the core of your plugin.

Another alternative is to use LUA, but first of all you need to know this language. So again, you'll spend more time trying to learn that new language than actually writing this quick and dirty plugin.


Wirego is a plugin for Wireshark, written in C that actually loads a plugin written in Go language.

You basically don't have to touch the Wirego plugin and you will be given a dummy empty golang plugin to start with.

Now how does the Wirego plugin where to find your wonderfull quick and dirty Golang plugin?
Well, you just set the WIREGO_PLUGIN environment variable, pointing your plugin and that's it.


## Building the Wirego plugin

Clone Wireshark:

    git clone https://github.com/wireshark/wireshark.git

Create a link from the Wireshark plugins folder to the "wirego_plugin"

    ln -s <path_to>/wirego_plugin wireshark/plugins/epan/wirego

Edit Wireshark's main CMakelists.txt and add the following to PLUGIN_SRC_DIRS:

    plugins/epan/wirego

Now build Wireshark (see README.xxx), but basically it's just:

    mkdir build && cd build
    cmake ../
    make -j


## Building the Golang plugin template

Before going any further, you should build this template and try to load it with the wirego Wireshark plugin.

    cd wirego_template
    go build

The template plugin is a dummy plugin to help you getting started.

## Running Wireshark

Now that Wireshark has been built, you can see that the "epan" directory now contains a plugin called "wirego.so" (see Wireshark documentation for the exact location).

You simply need to set the WIREGO_PLUGIN environment variable to your golang plugin path and then start Wireshark:

  export WIREGO_PLUGIN=/path-to-your-golang-plugin/wirego_template/wirego_template.so
  ./wireshark

To make sure your plugin has been properly loaded, open Analyze>Enabled Protocols and search for "wirego".

If your golang plugin fails to load for any reason, the plugin will not appear on that list.

## Developping a Golang plugin

Now that you've built the "template" plugin, it's probably time to update it with your own code.

Everything you need to update is found in "wirego_template.go" (feel free to rename this file).

The WIREGO_PLUGIN_NAME and WIREGO_PLUGIN_FILTER consts define how your plugin will appear in Wireshark.

You will then have to define "fields", wich are the results of your parsing code.
During the plugin initialization, behind the hood, we list all the different fields that we may eventually provide, when analyzing packets.
Each field will then be referred with a simple "enum" value, pointing to the full description of the field previously defined.

So, we first define the list of enum that we will use with the type "FieldId".

The **setup()** function is called when the plugin is loaded. Feel free to setup everything you need here.
That's also a nice place to setup the complete detailed list of your custom fields.
A "field" is defined by the **WiresharkField** structure and contains:

  - The field enum (InternalId), as defined previously
  - The field name
  - A Wireshark filter that can be used to filter matching packets
  - The type of value for this field
  - How this field should be displayed (**DisplayMode**)

The function **getDetectFilterInteger()** is used to filter the packets that should be sent to your disector. If your protocol happens on TCP port 7122, that's where you define it.

The **getFields()** returns the list of fields description (see **setup()**).

**dissectPacket(packet []byte)** is where the magic happens. You receive a packet payload and return a **DissectResult** structure.


## Next steps

That project is still under development, many things needs to be improved.
Here's a partial list:

  - The fields type list is incomplete
  - The current API only allows one and only one node to be created for a given packet
  - Support payload split into several packets
  - A simple GUI allowing to select the golang plugin to be loaded by wirego would be nice (instead of this environment variable)

