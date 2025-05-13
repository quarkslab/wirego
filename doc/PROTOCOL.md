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
  - All requests use simple data types. When a structure (or an array of structures) might be needed, simple accessors are defined


The following tables describes each command and expected response.
Every response from the **Wirego remote plugin** starts with a 1 byte "Command status": 1 success / 0 failure.
If, for any reason, the remote plugin fails to process a request it MUST act as follows:

  - return a command status with value 0
  - ignore all other return parameters defined in this specification

This current document defines API version: **2.0**


## utility_ping

The utility_ping command is automatically triggered when the **Wirego bridge** plugin is loaded.
If this command doesn't receive a reply within 2s, the Wirego plugin will be disabled.

| Type  | Frame Num | Type   | Value              | Description                            |
| ----- | --------- | ------ | ------------------ | -------------------------------------- |
| REQ   | 0         | string | "utility_ping\0"   | Send a ping to the remote ZMQ endpoint |
| REP   | 0         | byte   | 0/1                | Status (0 failure / 1 success)         |

When receiving a utility_ping request from the Wirego bridge, the Wirego remote plugin shall return "1".

**Note:** Since this call is an utility feature, it should be implemented by the "package" for the given language and not transmitted to the end user.

## utility_get_version

Once the ping is successful, the **Wirego bridge** requests the Wirego's API version from the **Wirego remote plugin** in order to make sure they're compatible.


| Type  | Frame Num | Type   | Value                   | Description                            |
| ----- | --------- | ------ | ----------------------- | -------------------------------------- |
| REQ   | 0         | string | "utility_get_version\0" | Request the remote Wirego API version  |
| REP   | 0         | byte   | 0/1                     | Command status (0 failure / 1 success) |
| REP   | 1         | byte   | Major ver.              | Wirego API major version               |
| REP   | 2         | byte   | Minor ver.              | Wirego API minor version               |

If the version differs (eg. the bridge uses v1.99 and the remote v2.0), the Wirego plugin will not be loaded.

**Note:** Since this call is an utility feature, it should be implemented by the "package" for the given language and not transmitted to the end user.


## setup_get_plugin_name

This call requests the name of the **Wirego remote plugin**.

| Type  | Frame Num | Type   | Value                     | Description                             |
| ----- | --------- | ------ | ------------------------- | --------------------------------------- |
| REQ   | 0         | string | "setup_get_plugin_name\0" | Request the remote plugin name          |
| REP   | 0         | byte   | 0/1                       | status (0 failure / 1 success)          |
| REP   | 1         | string | *                         |  Remote name                            |


## setup_get_plugin_filter

The plugin **filter** can be used to filter traffic on the Wireshark listing, matching the end user protocol.


| Type  | Frame Num | Type   | Value                        | Description                             |
| ----- | --------- | ------ | ---------------------------- | --------------------------------------- |
| REQ   | 0         | string | "setup_get_plugin_filter\0"  | Request the remote plugin filter        |
| REP   | 0         | byte   | 0/1                          | Command status (0 failure / 1 success)  |
| REP   | 1         | string | *                            | Filter name                             |

## setup_get_fields_count

During startup, Wireshark asks every plugin for their "custom fields".
Each plugin has its own fields that it may eventually return.

The **setup_get_fields_count** is used to retrieve the number of fields that will be declared.


| Type  | Frame Num | Type   | Value                        | Description                             |
| ----- | --------- | ------ | ---------------------------- | --------------------------------------- |
| REQ   | 0         | string | "setup_get_fields_count\0"   | Request the remote plugin filter        |
| REP   | 0         | byte   | 0/1                          | Command status (0 failure / 1 success)  |
| REP   | 1         | int    | *                            | Number of fields                        |



## setup_get_field

Once the number of fields is known (see **setup_get_fields_count**), the bridge plugin will iterate through all fields by incrementing the **index** value on the setup_get_fields_count command.

For each field, the remote plugin will provide:

  - the "wirego field id": a unique id generated by the **Wirego remote plugin** to refer to this field (see this as an enum)
  - the "field name": that will be shown on the packet details
  - the "field filter": that can be used to filter packets matching with this value
  - the "value type": that will help Wireshark to properly handle the value (string, int, byte...)
  - the "display mode": that will help Wireshark to properly display the value (decimal, hex...)

| Type  | Frame Num | Type   | Value                  | Description                             |
| ----- | --------- | ------ | ---------------------- | --------------------------------------- |
| REQ   | 0         | string | "setup_get_field\0"    | Request the remote plugin filter        |
| REQ   | 1         | int    | index                  | Field index on the fields array         |
| REP   | 0         | byte   | 0/1                    | Command status (0 failure / 1 success)  |
| REP   | 1         | int    | *                      | Wirego field id                         |
| REP   | 2         | string | *                      | Field name                              |
| REP   | 3         | string | *                      | Field filter                            |
| REP   | 4         | int    | *                      | Field value type                        |
| REP   | 5         | int    | *                      | Field display mode                      |


## setup_detect_int

The end-user protocol dissect function will be called for each packet matching a detection feature.
Detection features can be of type "int", "string" or be based on "heuristics".

The **setup_detect_int** command requests all filters of type "int" that can be used to detect the end-user protocol.
This command will be called incrementally by increasing the index field.
Once the last integer detection filter is reached, the remote plugin MUST return an error by setting the command status to 0.

| Type  | Frame Num | Type   | Value                  | Description                                                 |
| ----- | --------- | ------ | ---------------------- | ----------------------------------------------------------- |
| REQ   | 0         | string | "setup_detect_int\0"   | Request the remote plugin detection integer for given index |
| REQ   | 1         | int    | index                  | Filter index on the detect int array                        |
| REP   | 0         | byte   | 0/1                    | Command status (0 failure / 1 success)                      |
| REP   | 1         | string | *                      | The filter string                                           |
| REP   | 2         | int    | *                      | The filter value                                            |

## setup_detect_string

This command is similar to the "setup_detect_int" one but applies to string filters.

The **setup_detect_string** command requests all filters of type "string" that can be used to detect the end-user protocol.
This command will be called incrementally by increasing the index field.
Once the last string detection filter is reached, the remote plugin MUST return an error by setting the command status to 0.

| Type  | Frame Num | Type   | Value                   | Description                                                |
| ----- | --------- | ------ | ----------------------- | ---------------------------------------------------------- |
| REQ   | 0         | string | "setup_detect_string\0" | Request the remote plugin detection string for given index |
| REQ   | 1         | int    | index                   | Filter index on the detect int array                       |
| REP   | 0         | byte   | 0/1                     | Command status (0 failure / 1 success)                     |
| REP   | 1         | string | *                       | The filter string                                          |
| REP   | 2         | string | *                       | The filter value                                           |


## setup_detect_heuristic_parent

Sometimes, it is not possible to detect a protocol based on an existing Wireshark filter (pointing to an upper layer or a port for example).
It is then required to pass the packet to a detection function which will decide if this packet matches the protocol.
Since Wireshark will not pass every packet to every protocol implementing this feature, plugins must declare their "parent" protocol string.

This command will be called incrementally by increasing the index field.
Once the last heuristic parent filter is reached, the remote plugin MUST return an error by setting the command status to 0.

| Type  | Frame Num | Type   | Value                             | Description                                                |
| ----- | --------- | ------ | --------------------------------- | ---------------------------------------------------------- |
| REQ   | 0         | string | "setup_detect_heuristic_parent\0" | Request the remote plugin heuristic parent for given index |
| REQ   | 1         | int    | index                             | Index on the heuristic parent array                        |
| REP   | 0         | byte   | 0/1                               | Command status (0 failure / 1 success)                     |
| REP   | 1         | string | *                                 | Heuristic parent protocol string                           |

## process_heuristic

When **setup_detect_heuristic_parent** is declared and matches a packet, the packet child is sent to an heuristic function for detection.

| Type  | Frame Num | Type   | Value                   | Description                                                |
| ----- | --------- | ------ | ------------------------| ---------------------------------------------------------- |
| REQ   | 0         | string | "process_heuristic\0"   | Request the remote plugin heuristic parent for given index |
| REQ   | 1         | int    | packet_number           | The packet number on the current capture                   |
| REQ   | 2         | string | src                     | The packet source string                                   |
| REQ   | 3         | string | dst                     | The packet destination string                              |
| REQ   | 4         | string | layer                   | The packet layer stack string                              |
| REQ   | 5         | bytes  | data                    | The packet data                                            |
| REP   | 0         | byte   | 0/1                     | Command status (0 failure / 1 success)                     |
| REP   | 1         | byte   | 0/1                     | Detection result (0 failure / 1 success)                   |

If detection succeeds, the same packet will be sent to the **process_dissect_packet** command.

## process_dissect_packet

Everytime a packet matches:

  - An integer filter defined using **detect_int**
  - A string filter defined using **detect_string**
  - A heuristic detection **detection_heuristic**

the packet payload is sent to the dissector function through **process_dissect_packet**.


| Type  | Frame Num | Type   | Value                      | Description                                                |
| ----- | --------- | ------ | -------------------------- | ---------------------------------------------------------- |
| REQ   | 0         | string | "process_dissect_packet\0" | Request the remote plugin to dissect the packet            |
| REQ   | 1         | int    | packet_number              | The packet number on the current capture                   |
| REQ   | 2         | string | src                        | The packet source string                                   |
| REQ   | 3         | string | dst                        | The packet destination string                              |
| REQ   | 4         | string | layer                      | The packet layer stack string                              |
| REQ   | 5         | bytes  | data                       | The packet data                                            |
| REP   | 0         | byte   | 0/1                        | Command status (0 failure / 1 success)                     |
| REP   | 1         | int    | *                          | Dissect handler                                            |

The dissection result can be a quite complex structure, containing multiple data types and eventually trees.
In order to avoid imposing a specific serialization method that might not be easily available in any language, the following scheme is used:

  - The dissect command returns an handler (integer)
  - The **Wirego bridge** plugin will perform subsequent calls using this handler to retrieve all results

The **dissect_packet** command only returns the handler to be used with the commands defined later in this specification.

**Note:** The **Wirego remote** package should make things easier to the end user, by allowing it to return a complete structure/class/whatever. The package should implement a map, using the handler as a key poiting to the returned structure (see **resultsCache       map[int]*DissectResultFlattenEntry** in "wirego.go").

## result_get_protocol

As stated in the **dissect_packet** command description, the dissection handler can be used to access every part of a dissection result.
The **result_get_protocol** can be used to retreieve the "protocol" value, shown on the **Protocol** column in Wireshark.


| Type  | Frame Num | Type   | Value                   | Description                                                |
| ----- | --------- | ------ | ------------------------| ---------------------------------------------------------- |
| REQ   | 0         | string | "result_get_protocol\0" | Request the protocol result for the given dissect handler  |
| REQ   | 1         | int    | dissect_handler         | The dissection handler returned by dissect_packet          |
| REP   | 0         | byte   | 0/1                     | Command status (0 failure / 1 success)                     |
| REP   | 1         | string | protocol                | The protocol name                                          |


## result_get_info

As stated in the **dissect_packet** command description, the dissection handler can be used to access every part of a dissection result.
The **result_get_info** can be used to retreieve the "info" value, shown on the **Info** column in Wireshark.


| Type  | Frame Num | Type   | Value                   | Description                                                |
| ----- | --------- | ------ | ------------------------| ---------------------------------------------------------- |
| REQ   | 0         | string | "result_get_info\0"     | Request the info result for the given dissect handler      |
| REQ   | 1         | int    | dissect_handler         | The dissection handler returned by dissect_packet          |
| REP   | 0         | byte   | 0/1                     | Command status (0 failure / 1 success)                     |
| REP   | 1         | string | info                    | The info value                                             |


## result_get_fields_count

As stated in the **dissect_packet** command description, the dissection handler can be used to access every part of a dissection result.
A dissection may return a long list of extracted fields.
The **result_get_fields_count** is used to retrieve the number of fields available.

| Type  | Frame Num | Type   | Value                       | Description                                                |
| ----- | --------- | ------ | --------------------------- | ---------------------------------------------------------- |
| REQ   | 0         | string | "result_get_fields_count\0" | Request the number of results fields                       |
| REQ   | 1         | int    | dissect_handler             | The dissection handler returned by dissect_packet          |
| REP   | 0         | byte   | 0/1                         | Command status (0 failure / 1 success)                     |
| REP   | 1         | int    | fields count                | Number of fields available                                 |

## result_get_field

As stated in the **dissect_packet** command description, the dissection handler can be used to access every part of a dissection result.
The command **result_get_fields_count** gave us the number of results fields available.
The **wirego bridge plugin** will iterate by increasing the index value in or order to collect all those fields.

| Type  | Frame Num | Type   | Value                       | Description                                                   |
| ----- | --------- | ------ | --------------------------- | ------------------------------------------------------------- |
| REQ   | 0         | string | "result_get_field\0"        | Request fields values for given index                         |
| REQ   | 1         | int    | dissect_handler             | The dissection handler returned by dissect_packet             |
| REQ   | 2         | int    | index                       | The index on the fields list fore this packet result          |
| REP   | 0         | byte   | 0/1                         | Command status (0 failure / 1 success)                        |
| REP   | 1         | int    | parent_idx                  | When a tree is defined, point to the parent index (-1 if not) |
| REP   | 2         | int    | wirego_field_id             | Refers to the field type, as defined with **get_field**       |
| REP   | 3         | int    | offset                      | The field offset in the packet payload                        |
| REP   | 4         | int    | length                      | The field size in the packet payload                          |

## result_release

As stated previously, the **Wirego remote plugin** package/class+/whatever must implement a results cache, using the dissect_handler as a key, poiting to the actual results.
The **result_release** command is called once all data for the given result have been collected.

You may want to:

  - Free this map entry
  - Keep this entry to reuse it later and avoid re-dissecting a packet multiple times
  - Setup a customizable cache, where the end-use may decide to enable it or not


| Type  | Frame Num | Type   | Value                       | Description                                                |
| ----- | --------- | ------ | --------------------------- | ---------------------------------------------------------- |
| REQ   | 0         | string | "result_release\0"          | Request the number of results fields                       |
| REQ   | 1         | int    | dissect_handler             | The dissection handler returned by dissect_packet          |
| REP   | 0         | byte   | 0/1                         | Command status (0 failure / 1 success)                     |
