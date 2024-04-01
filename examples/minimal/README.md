# Wirego minimal example

This very minimal example is a good starting point to develop your own parser.
Just copy-paste this folder, and start customizing to your own needs.


During **init**, which is called at package initialization (hence when the plugin is loaded), we register to the Wirego package. Since we want to be called everytime Wiresharks decides to parse a packet (and eventually multiple times for the same packet), the cache is disabled.

The **Setup** is not used here, it's a very basic example and we don't have anything to initialize.

**GetName** returns thje name of our dummy example plugin and **GetFilter** defines the string that we will use to filter the packets matching our protocol in Wireshark.


The **GetFields** function is used to declare three distinct custom fields that may be returned to Wireshark after the dissect operation.

In order to route traffic to our dissector, we must first detect it. In this example, we use both strategies:

  - use filters through **GetDetectionFilters** to route all packets on udp port 137 or bluetooth UUID 1234
  - register to parent protocol "udp" and detect all packets starting with 0x00


Our dissect packet doesn't dissect much: 

  - we flag all traffic with our protocol name
  - we set the Info field with the packet number
  - we add two fields pointing to the payload
  - and a third one with a sub-field

