#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import IntEnum
from typing import NewType
from typing import List
from typing import Optional
import zmq
import logging

__title__       = "Wirego Remote"
__description__ = "Python class for Wirego remote"
__author__      = "Benoit Girard"
__email__       = "bgirard@quarkslab.com"
__license__     = 'GPL-2.0-or-later'
__copyright__   = 'Copyright (c) 2024 Benoit Girard'

# FieldId type (just overloading int type)
FieldId = NewType('FieldId', int)

#ValueType defines a type of data supported by Wireshark
class ValueType(IntEnum):
	ValueTypeNone  = 0x01
	ValueTypeBool  = 0x02
	ValueTypeUInt8  = 0x03
	ValueTypeInt8   = 0x04
	ValueTypeUInt16  = 0x05
	ValueTypeInt16   = 0x06
	ValueTypeUInt32  = 0x07
	ValueTypeInt32   = 0x08
	ValueTypeCString  = 0x09
	ValueTypeString   = 0x10

#DisplayMode tells Wireshark how to display a field
class DisplayMode(IntEnum):
	DisplayModeNone         = 0x01
	DisplayModeDecimal      = 0x02
	DisplayModeHexadecimal  = 0x03

#DetectionFilterType defines the type of a declared detection filter
class DetectionFilterType(IntEnum):
	DetectionFilterTypeInt = 0x01
	DetectionFilterTypeStr = 0x02

@dataclass
class WiregoField:
    wirego_field_id: FieldId
    name: str
    filter: str
    value_type: ValueType
    display_mode: DisplayMode


@dataclass
class DetectionFilter:
	filter_type: DetectionFilterType
	name: str
	value_int: int
	value_str: str

@dataclass
class DissectField:
    wirego_field_id: FieldId
    offset: int
    length: int
    sub_fields: List['DissectField']

@dataclass
class DissectResult:
  protocol: str
  info: str
  fields: List[DissectField]


# Stores a given field from a dissection result
@dataclass
class DissectResultFieldFlatten:
  parent_idx: int #Index of parent field (for nested fields)
  wirego_field_id: FieldId # Field id (Wirego)
  offset: int # Field Offset in packet
  length: int # Field length


@dataclass
class DissectResultFlattenEntry:
  protocol: str  # Protocol column for Wireshark
  info: str # Info column for Wireshark
  fields: List[DissectResultFieldFlatten] # List of fields for Wireshark


class WiregoListener(ABC):

    @abstractmethod
    def get_name(self) -> str:
        pass

    @abstractmethod
    def get_filter(self) -> str:
        pass

    @abstractmethod
    def get_fields(self) -> List[WiregoField]:
        pass

    @abstractmethod
    def get_detection_filters(self) -> List[DetectionFilter]:
        pass

    @abstractmethod
    def get_detection_heuristics_parents(self) -> List[str]:
        pass

    @abstractmethod
    def detection_heuristic(self, packet_number: int, src: str, dst: str, stack: str, packet: bytes) -> bool:
        pass

    @abstractmethod
    def dissect_packet(self, packet_number: int, src: str, dst: str, stack: str, packet: bytes) -> DissectResult:
        pass


class Wirego:
    
    def __init__(self, zmq_endpoint: str, verbose: bool, wglistener: WiregoListener):
        self.zmq_endpoint = zmq_endpoint
        self.verbose = verbose
        self.wglistener = wglistener
        self.cache_enable = False
        self.cache = {}
        if self.verbose:
          logging.basicConfig(level=logging.DEBUG)
        else:
          logging.basicConfig(level=logging.WARNING)

    def results_cache_enable(self, enable: bool):
        self.cache_enable = enable
  
    def listen(self):
        logging.warning("Waiting for Wirego bridge commands...")
        self.fields = self.wglistener.get_fields()
        self.heuristics_parents = self.wglistener.get_detection_heuristics_parents()
        self.detection_filters = self.wglistener.get_detection_filters()

        context = zmq.Context()
        socket = context.socket(zmq.REP)
        socket.bind(self.zmq_endpoint)
        while True:
          #  Wait for next request from client
          messageFrames = socket.recv_multipart(0, False, False)
          if len(messageFrames) < 1:
             logging.error("Received empty request from Wirego bridge.")
             return

          logging.debug("Received request: %s" % messageFrames)
          msg_type = messageFrames[0].bytes.decode('utf-8')
          logging.debug("-> Message type: "+msg_type)
          match msg_type:
              case "utility_ping\x00":
                  logging.warning("Received ping request from Wirego Bridge.")
                  socket.send(b"\x01")
              case "utility_get_version\x00":
                self._utility_get_version(socket, messageFrames)
              case "setup_get_plugin_name\x00":
                self._setup_get_plugin_name(socket, messageFrames)
              case "setup_get_plugin_filter\x00":
                self._setup_get_plugin_filter(socket, messageFrames)
              case "setup_detect_string\x00":
                self._setup_detect_string(socket, messageFrames)
              case "setup_detect_int\x00":
                self._setup_detect_int(socket, messageFrames)
              case "setup_get_fields_count\x00":
                self._setup_get_fields_count(socket, messageFrames)
              case "setup_get_field\x00":
                self._setup_get_field(socket, messageFrames)
              case "setup_detect_heuristic_parent\x00":
                self._setup_detect_heuristic_parent(socket, messageFrames)
              case "process_heuristic\x00":
                self._process_heuristic(socket, messageFrames)
              case "process_dissect_packet\x00":
                self._process_dissect_packet(socket, messageFrames)
              case "result_get_protocol\x00":
                self._result_get_protocol(socket, messageFrames)
              case "result_get_info\x00":
                self._result_get_info(socket, messageFrames)
              case "result_get_fields_count\x00":
                self._result_get_fields_count(socket, messageFrames)
              case "result_get_field\x00":
                self._result_get_field(socket, messageFrames)
              case "result_release\x00":
                self._result_release(socket, messageFrames)          
              case _:
                logging.warning("!!!!! Unknown message type: ", msg_type)
                socket.send(b"\x00")
        return

    def _utility_get_version(self, socket, messageFrames):
      socket.send(b"\x01", zmq.SNDMORE)
      socket.send(b"\x02", zmq.SNDMORE)
      socket.send(b"\x00")

    def _setup_get_plugin_filter(self, socket, messageFrames):
      socket.send(b"\x01", zmq.SNDMORE)
      socket.send(self.wglistener.get_filter().encode()  + b'\x00')
  
    def _setup_get_plugin_name(self, socket, messageFrames):
      socket.send(b"\x01", zmq.SNDMORE)
      socket.send(self.wglistener.get_name().encode()  + b'\x00')

    def _setup_get_field(self, socket, messageFrames):
      if len(messageFrames) != 2:
        socket.send(b"\x00")
        return
      idx = int.from_bytes(messageFrames[1], 'little')
      if idx >= len(self.fields):
          socket.send(b"\x00")
          return
      socket.send(b"\x01", zmq.SNDMORE)
      socket.send(self.fields[idx].wirego_field_id.to_bytes(4, 'little'), zmq.SNDMORE)
      socket.send(self.fields[idx].name.encode()  + b'\x00', zmq.SNDMORE)
      socket.send(self.fields[idx].filter.encode()  + b'\x00', zmq.SNDMORE)
      socket.send(self.fields[idx].value_type.to_bytes(4, 'little'), zmq.SNDMORE)
      socket.send(self.fields[idx].display_mode.to_bytes(4, 'little'))

    def _setup_detect_heuristic_parent(self, socket, messageFrames):
      if len(messageFrames) != 2:
        socket.send(b"\x00")
        return
      idx = int.from_bytes(messageFrames[1], 'little')
      if idx >= len(self.heuristics_parents):
        socket.send(b"\x00")
        return
      socket.send(b"\x01", zmq.SNDMORE)
      socket.send(self.heuristics_parents[idx].encode()  + b'\x00')


    def _setup_get_fields_count(self, socket, messageFrames):
        socket.send(b"\x01", zmq.SNDMORE)
        socket.send(len(self.fields).to_bytes(4, 'little'))

    def _setup_detect_string(self, socket, messageFrames):
        if len(messageFrames) != 2:
          socket.send(b"\x00")
          return
        idx = int.from_bytes(messageFrames[1], 'little')
        if idx >= len(self.fields):
            socket.send(b"\x00")
            return
        cnt = 0
        for f in self.detection_filters:
            if f.filter_type == DetectionFilterType.DetectionFilterTypeStr:
                if cnt == idx:
                    socket.send(b"\x01", zmq.SNDMORE)
                    socket.send(f.name.encode()  + b'\x00', zmq.SNDMORE)
                    socket.send(f.value_str.encode()  + b'\x00')
                    return
                else:
                    cnt = cnt + 1
        #gone too far, no more strings
        socket.send(b"\x00")

    def _setup_detect_int(self, socket, messageFrames):
      if len(messageFrames) != 2:
          socket.send(b"\x00")
          return
      idx = int.from_bytes(messageFrames[1], 'little')
      if idx >= len(self.fields):
          socket.send(b"\x00")
          return
      cnt = 0
      for f in self.detection_filters:
          if f.filter_type == DetectionFilterType.DetectionFilterTypeInt:
              if cnt == idx:
                  socket.send(b"\x01", zmq.SNDMORE)
                  socket.send(f.name.encode()  + b'\x00', zmq.SNDMORE)
                  socket.send(f.value_int.to_bytes(4, 'little'))
                  return
              else:
                  cnt = cnt + 1
      #gone too far, no more int
      socket.send(b"\x00")

    def _process_heuristic(self, socket, messageFrames):
      if len(messageFrames) != 6:
        socket.send(b"\x00")
        return
      packet_number = messageFrames[1]
      src = messageFrames[2]
      dst = messageFrames[3]
      layer = messageFrames[4]
      packet_data = messageFrames[5]
      result = self.wglistener.detection_heuristic(packet_number, src, dst, layer, packet_data)
      socket.send(b"\x01", zmq.SNDMORE)
      if result:
        socket.send(b"\x01", zmq.SNDMORE)
      else:
        socket.send(b"\x00")

    def _process_dissect_packet(self, socket, messageFrames):
      if len(messageFrames) != 6:
        socket.send(b"\x00")
        return
      pktnum = int.from_bytes(messageFrames[1], 'little')
      src = messageFrames[2].bytes.decode('utf-8')
      dst = messageFrames[3].bytes.decode('utf-8')
      layer = messageFrames[4].bytes.decode('utf-8')
      packet_data = messageFrames[5]
      
      # Not in cache, dissect packet
      if not pktnum in self.cache:
        result = self.wglistener.dissect_packet(pktnum, src, dst, layer, packet_data)
        self._add_result_to_cache(result, pktnum)

      socket.send(b"\x01", zmq.SNDMORE)
      socket.send(pktnum.to_bytes(4, 'little')) # use pkt number as dissect handler 

    def _result_get_protocol(self, socket, messageFrames):
      if len(messageFrames) != 2:
        socket.send(b"\x00")
        return
      packet_number = int.from_bytes(messageFrames[1], 'little')
      if not packet_number in self.cache:
        socket.send(b"\x00")
        return
      socket.send(b"\x01", zmq.SNDMORE)
      socket.send(self.cache[packet_number].protocol.encode()  + b'\x00')

    def _result_get_info(self, socket, messageFrames):
        if len(messageFrames) != 2:
          socket.send(b"\x00")
          return
        packet_number = int.from_bytes(messageFrames[1], 'little')
        if not packet_number in self.cache:
          socket.send(b"\x00")
          return
        socket.send(b"\x01", zmq.SNDMORE)
        socket.send(self.cache[packet_number].info.encode()  + b'\x00')  
 
    
    def _result_get_fields_count(self, socket, messageFrames):
      if len(messageFrames) != 2:
        socket.send(b"\x00")
        return
      packet_number = int.from_bytes(messageFrames[1], 'little')
      if not packet_number in self.cache:
        socket.send(b"\x00")
        return
      count = len(self.cache[packet_number].fields)
      socket.send(b"\x01", zmq.SNDMORE)
      socket.send(int.to_bytes(count, 4, 'little'))  
 
    def _result_get_field(self, socket, messageFrames):
      if len(messageFrames) != 3:
        socket.send(b"\x00")
        return
      packet_number = int.from_bytes(messageFrames[1], 'little')
      idx = int.from_bytes(messageFrames[2], 'little')
  
      if not packet_number in self.cache:
        socket.send(b"\x00")
        return
      result = self.cache[packet_number]
      if idx >= len(result.fields):
        socket.send(b"\x00")
        return
      socket.send(b"\x01", zmq.SNDMORE)
      socket.send(result.fields[idx].parent_idx.to_bytes(4, byteorder='little', signed=True), zmq.SNDMORE)
      socket.send(result.fields[idx].wirego_field_id.to_bytes(4, 'little'), zmq.SNDMORE)
      socket.send(result.fields[idx].offset.to_bytes(4, 'little'), zmq.SNDMORE) 
      socket.send(result.fields[idx].length.to_bytes(4, 'little'))


    def _result_release(self, socket, messageFrames):
      if len(messageFrames) != 2:
        socket.send(b"\x00")
        return

      packet_number = int.from_bytes(messageFrames[1], 'little')
      if not self.cache_enable:
        # Remove from cache
        self.cache.pop(packet_number)

      socket.send(b"\x01")
      return

    def _add_result_to_cache(self, result, pktnum):
      # Flatten results to a simple list with parenIdx pointing to parent's entry
      flatten = DissectResultFlattenEntry(result.info, result.info, [])
      for r in result.fields:
        self._add_fields_recursive(flatten, -1, r)
      self.cache[pktnum] = flatten # Since we have one result per packet number, use pktnum as key

    def _add_fields_recursive(self, flatten: DissectResultFlattenEntry, parent_idx: int, field: DissectField):
      new_parent_idx: int
      field_flatten = DissectResultFieldFlatten(parent_idx, field.wirego_field_id, field.offset, field.length)
      flatten.fields.append(field_flatten)

      new_parent_idx = len(flatten.fields) - 1
      for sub in field.sub_fields:
        self._add_fields_recursive(flatten, new_parent_idx, sub)
