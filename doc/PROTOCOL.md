# Wirego ZMQ Protocol specifications

In this specification, the following terms will be used:

  - **"Wirego bridge plugin"**: the Wirego's Wireshark plugin, written in C
  - **"Wirego remote plugin"**: the plugin developed by the end user (hopefully using an available Wirego package for the language)

The Wirego bridge plugin and remote Wirego plugin communicates through a ZMQ REQ/REP scheme.
Through the Wireshark settings, the endpoint shared by the bridge and remote plugin can be defined.

In the REQ/REP protocol, the following roles are defined:

  - Wirego bridge plugin: Acts as a client, sends REQ commands
  - Wirego remote plugin: Acts as a server, receives REQ and sends REP
  
General considerations:

  - All transmitted strings are nul terminated C-style strings
  - All transmitted numerical values are 32 bits little endian integers
  - All transmitted bytes values are pretty standard 8 bits values
  - The first frame of all REQ commands is the command name (as a string)
  - The first frame of all REP is the result status (as a 1 byte boolean)


The following tables describes each command and expected response.

## Ping command

| Command | Type  | Frame Num | Type   | Value      | Description                            |
| ------- | ----- | --------- | ------ | ---------- | -------------------------------------- |
| ping    | REQ   | 0         | string | "ping\0"   | Send a ping to the remote ZMQ endpoint |
| ping    | REP   | 0         | byte   | 0/1        | Reply to the ping request              |

When receiving a ping request from the Wirego bridge, the Wirego remote plugin shall return "1".
