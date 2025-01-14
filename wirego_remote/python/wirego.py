#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import IntEnum
from typing import NewType
from typing import List
from typing import Optional

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
    def detection_heuristic(packetNumber: int, src: str, dst: str, stack: str, packet: bytes) -> bool:
        pass

    @abstractmethod
    def dissect_packet(packetNumber: int, src: str, dst: str, stack: str, packet: bytes) -> DissectResult:
        pass


class Wirego:
    
    def __init__(self, zmq_endpoint: str, verbose: bool, wglistener: WiregoListener):
        self.zmq_endpoint = zmq_endpoint
        self.verbose = verbose
        self.wglistener = wglistener
        self.cache_enable = False

        print(wglistener.get_fields())
        print(wglistener.get_detection_filters())

    def results_cache_enable(self, enable: bool):
        self.cache_enable = enable
  
    def listen(self):
         return