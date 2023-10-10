# Wirego

A Wireshark plugin wrapper for golang

## Introduction

Writing plugins for Wireshark in C/C++ can be opaque: the APIs are quite powerfull, but not really easy to use. If you just want to develop a quick and dirty plugin you will spend more time trying to understand how things work instead of actually writing the core of your plugin.

Another alternative is to use LUA, but first of all you need to know this language. So again, you'll spend more time trying to learn that new language than actually writing this quick and dirty plugin.


Wirego is a plugin for Wireshark, written in C that actually loads a plugin written in Go language.

You basically don't have to touch the Wirego plugin and you will be provided a dummy empty golang plugin to start with.

Now how does the Wirego plugin where to find your wonderfull quick and dirty Goland plugin?
Well, you just set the WIREGO_PLUGIN environment variable, pointing your plugin and that's it.


## Building the Wirego plugin

Clone wireshark:

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

    cd wirego_template
    go build

The template plugin is a dummy plugin to help you getting started.
Before going further, you should build this template and try to load it with the wirego Wireshark plugin.

## Running Wireshark

Now that Wireshark has been built, you can see that the "epan" directory now contains a plugin called "wirego.so" (see Wireshark documentation for the exact location).

You simply need to set the WIREGO_PLUGIN environment variable to your golang plugin path and then start Wireshark:

  export WIREGO_PLUGIN=/path-to-your-golang-plugin/wirego_template/wirego_template.so
  ./wireshark

To make sure your plugin has been properly loaded, open Analyze>Enabled Protols and search for "wirego".

If your golang plugin fails to load for any reason, the plugin will not appear on that list.

