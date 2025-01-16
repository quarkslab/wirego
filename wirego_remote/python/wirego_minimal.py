import wirego
from typing import List
from enum import IntEnum

class FieldEnum(IntEnum):
	FieldIdCustom1  = 0x01
	FieldIdCustom2  = 0x02
	FieldIdCustomWithSubFields  = 0x03
    
class WiregoMinimal(wirego.WiregoListener):

    # This function shall return the plugin name
    def get_name(self):
        return "Wirego Minimal Example"

    # This function shall return the wireshark filter
    def get_filter(self):
        return "wgminexample"

    # GetFields returns the list of fields descriptor that we may eventually return
    # when dissecting a packet payload
    def get_fields(self):
      return [
        wirego.WiregoField(FieldEnum.FieldIdCustom1, "Custom1", "wirego.custom01", wirego.ValueType.ValueTypeUInt8, wirego.DisplayMode.DisplayModeHexadecimal),
        wirego.WiregoField(FieldEnum.FieldIdCustom1, "Custom2", "wirego.custom02", wirego.ValueType.ValueTypeUInt16, wirego.DisplayMode.DisplayModeDecimal),
        wirego.WiregoField(FieldEnum.FieldIdCustomWithSubFields, "Custom With Subs", "wirego.custom_subs", wirego.ValueType.ValueTypeUInt32, wirego.DisplayMode.DisplayModeHexadecimal),
      ]

    # get_detection_filters returns a wireshark filter that will select which packets
    # will be sent to your dissector for parsing.
    # Two types of filters can be defined: Integers or Strings
    def get_detection_filters(self):
      return [
        wirego.DetectionFilter(wirego.DetectionFilterType.DetectionFilterTypeInt, "udp.port", 137, ""),
        wirego.DetectionFilter(wirego.DetectionFilterType.DetectionFilterTypeStr, "bluetooth.uuid", 0, "1234"),
      ]

    # get_detection_heuristics_parents returns a list of protocols on top of which detection heuristic
    # should be called.
    def get_detection_heuristics_parents(self):
      return [
        "udp", 
        "http",
      ]

    # detection_heuristic applies an heuristic to identify the protocol.
    def detection_heuristic(self, packet_number: int, src: str, dst: str, stack: str, packet: bytes) -> bool:
      #All packets starting with 0x00 should be passed to our dissector (super advanced heuristic)
      if (len(packet) != 0) and (packet[0] == 0x00):
        return True
      return False

    #dissect_packet provides the packet payload to be parsed.
    def dissect_packet(self, packet_number: int, src: str, dst: str, stack: str, packet: bytes) -> wirego.DissectResult:
      #This string will appear on the packet being parsed
      protocol = "Protocol name example"

      #This (optional) string will appear in the info section
      info = "Info example pkt " + str(packet_number)

      fields = []

      #Add a few fields and refer to them using our own "internalId"
      if len(packet) > 6:
        fields.append(wirego.DissectField(FieldEnum.FieldIdCustom1, 0, 2, []))
        fields.append(wirego.DissectField(FieldEnum.FieldIdCustom2, 2, 4, []))
    
    	#Add a field with two sub field
      if len(packet) > 10:
        subField1 = wirego.DissectField(FieldEnum.FieldIdCustom1, 6, 2, [])
        subField2 = wirego.DissectField(FieldEnum.FieldIdCustom1, 8, 2, [])
        field = wirego.DissectField(FieldEnum.FieldIdCustomWithSubFields, 6, 4, [subField1, subField2])
        fields.append(field)
      
      return wirego.DissectResult(protocol, info, fields)

print("Wirego remote Python example")

# Create our listener
tl = WiregoMinimal()

# Instanciate wirego
wg = wirego.Wirego("ipc:///tmp/wirego0", False, tl)
wg.results_cache_enable(True)

wg.listen()
