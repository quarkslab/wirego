# Wirego plugin

This is the actual Wireshark plugin in charge of loading your Golang plugin.
Calls made by Wireshark using the plugin API are teansferred to the actual golang plugin using cgo.

## proto_register_wirego

__Prototype__ void proto_register_wirego(void)

This function is called when plugin dynamic library is loaded.
This must be used to register the plugin to Wireshark.
In our case:

  - locate the golang plugin
  - setup all function callbacks
  - request the plugin name and protocol filter
  - request custom fields from the plugin
  - register custom fields

We also declare a "preference menu entry" for Wirego.
this is just a dummy panel showing where is the golang plugin located.

## proto_reg_handoff_wirego

__Prototype__ void proto_reg_handoff_wirego(void)

This function is called once all plugins did register, it is mainly used to register the dissector handle and on which protocol it should be applied.

In our case, we support two types of protocols filters: integer and string.

Example: 'tcp.port == 25' or 'ip.addr == "1.1.1.1"'

## dissect_wirego

__Prototype__ static int dissect_wirego(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)

This is where the magic happens.
Received structures are converted to a more simple data type in order to be passed to the golang environment.
There are three reasons for this:

  1. complex data management with cgo can be tricky
  2. Wireshark is never really clear about data types: what has been allocated, what is on the stack, concurrency, etc.
  3. the main goal of Wirego is to make things simpler, so let's simplify.

The Wirego dissect call will return an "handler" which can be used later to access all subtelties of the result using dedicated accessors. Again, we don't want Wirego to return complex data structures from the go environment to the Wireshark one.

__Note:__ Converting data structures from Wireshark to simpler ones, passing them to Wirego, then converting back has a cost in terms of memory and CPU. At this point of the project, this seems to be a safer method.


## Garbage collection

https://pkg.go.dev/cmd/cgo#hdr-Passing_pointers

