# Wirego

A Wireshark plugin framework based on ZMQ, supporting Golang and hopefully more languages soon.


![Wirego Logo](./doc/img/wirego_logo_small.png)

## Introduction

Writing plugins for Wireshark in C/C++ can be opaque: the APIs are quite powerfull, but not really obvious to use. If you just want to develop a quick and dirty plugin you will spend more time trying to understand how things work instead of actually writing the core of your plugin.

Another alternative is to use LUA, but first of all you need to know this language. So again, you'll spend more time trying to learn that new language than actually writing this quick and dirty plugin.

Wirego is a composed of:

  - a Wireshark plugin (wirego_bridge), written in C that will transmit all calls from Wireshark to a remote ZMQ endpoint
  - A set of packages for several languages receiving those ZMQ calls and converting them to a simple API that you can use

![screenshot](./doc/img/schema.png)


As a starter, a **golang** package is provided and more languages will come later.

![screenshot](./examples/minimal/screenshot.png)

In all Wirego's code and documentations we will refer to:

  - **Wirego bridge** : the Wireshark plugin, written in C (you won't have to touch this one)
  - **Wirego package** : a package/class/bundle/sdk for a given language, used to make things easier on your side
  - **Wirego remote** : the application that you will develop using the **Wirego package**

## Overview (in Go)

In order to setup Wirego, you will need follow 3 steps:

  1. Install or build the **Wirego bridge plugin** for Wireshark
  2. Develop your own plugin, using a **Wirego package**
  3. Start Wireshark and tell the Wirego bridge where your ZMQ endpoint is

You may use prebuilt binaries for **step 1**, those can be downloaded [here](https://github.com/quarkslab/wirego/releases).
If prefer building the plugin (or if prebuilt binaries fails), refer to the following documentation [here](./doc/BUILD_WIREGO.md)


The **step 2** will obviously depend on the language you're using. For Go you will basically just have to copy/paste the **main()** function from one of our examples and implement the following interface:

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

Now it's time for **step 3**: [install the Wirego plugin and start Wireshark](./doc/RUNNING.md)!

## Examples

A few plugin examples are available :

  - [Minimal](./examples/minimal/) : a minimalistic example showing the basic usage of Wirego
  - [Reolink Credentials light](./examples/reolinkcredslight/) : a lightweight version of a Reolink camera credentials parser
  - [Reolink Credentials](./examples/reolinkcreds/) : an advanced version of a Reolink camera credentials parser

## Implementing a new language

If you plan to implement a package for a currently unsupported language, please take a look at the [Wirego ZMQ specifications](./doc/PROTOCOL.md).

## Additional notes

When the ZMQ endpoint used by your **Wirego remote plugin** is modified, you will be required to restart Wireshark, here's why:

  - we need to setup everything (plugin name, fields..) during the proto_register_wirego call
  - preferences values, hence the ZMQ endpoint, are only loaded afterwards during the proto_reg_handoff_wirego call
