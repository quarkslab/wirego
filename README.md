# Wirego

A Wireshark plugin wrapper for golang


![Wirego Logo](./img/wirego_logo_small.png)

## Introduction

Writing plugins for Wireshark in C/C++ can be opaque: the APIs are quite powerfull, but not really obvious to use. If you just want to develop a quick and dirty plugin you will spend more time trying to understand how things work instead of actually writing the core of your plugin.

Another alternative is to use LUA, but first of all you need to know this language. So again, you'll spend more time trying to learn that new language than actually writing this quick and dirty plugin.

Wirego is a composed of:

  - a Wireshark plugin (wirego_bridge), written in C that will transmit all calls from Wireshark to a remote ZMQ endpoint
  - A set of package for several languages receiving those ZMQ calls and converting them to a simple API

As a starter, a **golang** package is provided and more languages will come later.

You basically don't have to touch the Wirego plugin and you will be given a dummy empty golang plugin to start with.

![screenshot](./examples/minimal/screenshot.png)

## Overview

In order to setup Wirego, you will need follow 3 steps:

  1. Install or build the Wirego bridge plugin for Wireshark
  2. Develop your own plugin, using the "wirego" Go package
  3. Start Wireshark and tell the Wirego bridge where your ZMQ endpoint is

You may use prebuilt binaries for **step 1**, those can be downloaded [here](https://github.com/quarkslab/wirego/releases).
If prefer building the plugin (or if prebuilt binaries fails), refer to the following documentation [here](BUILD_WIREGO.md)


For **step 2**, you will basically just have to __import "wirego"__ and implement the following interface:

```golang
    // WiregoInterface is implemented by the actual wirego plugin
    type WiregoInterface interface {
      GetName() string
      GetFilter() string
      GetFields() []WiresharkField
      GetDetectionFilters() []DetectionFilterType
      GetDetectionHeuristicsParent() []string
      DetectionHeuristic(packetNumber int, src string, dst string, stack string, packet []byte) bool
      DissectPacket(packetNumber int, src string, dst string, stack string, packet []byte) *DissectResult
    }
```

Now it's time for **step 3**: [install the Wirego plugin and start Wireshark](RUNNING.md)!

## Examples

A few plugin examples are available :

  - [Minimal](./examples/minimal/) ; a minimalistic example showing the basic usage of Wirego
  - [Reolink Credentials light](./examples/reolinkcredslight/) : a lightweight version of a Reolink camera credentials parser
  - [Reolink Credentials](./examples/reolinkcreds/) : a advanced version of a Reolink camera credentials parser


## Next steps

That project is still under development, many things needs to be improved.
Here's a partial list:

  - The fields type list is incomplete
  - Support payload split into several packets

## Additional notes

When the path to your plugin in Go is modified, you will be required to restart Wireshark, here's why:

  - we need to setup everything (plugin name, fields..) during the proto_register_wirego call
  - preferences values, hence the ZMQ endpoint, are only loaded during the proto_reg_handoff_wirego call, which is too late for us