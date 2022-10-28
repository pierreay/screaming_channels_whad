# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: protocol/whad.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from whad.protocol import device_pb2 as protocol_dot_device__pb2
from whad.protocol import generic_pb2 as protocol_dot_generic__pb2
from whad.protocol.ble import ble_pb2 as protocol_dot_ble_dot_ble__pb2
from whad.protocol.zigbee import zigbee_pb2 as protocol_dot_zigbee_dot_zigbee__pb2
from whad.protocol.esb import esb_pb2 as protocol_dot_esb_dot_esb__pb2
from whad.protocol.unifying import unifying_pb2 as protocol_dot_unifying_dot_unifying__pb2
from whad.protocol.phy import phy_pb2 as protocol_dot_phy_dot_phy__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13protocol/whad.proto\x1a\x15protocol/device.proto\x1a\x16protocol/generic.proto\x1a\x16protocol/ble/ble.proto\x1a\x1cprotocol/zigbee/zigbee.proto\x1a\x16protocol/esb/esb.proto\x1a protocol/unifying/unifying.proto\x1a\x16protocol/phy/phy.proto\"\xff\x01\n\x07Message\x12#\n\x07generic\x18\x01 \x01(\x0b\x32\x10.generic.MessageH\x00\x12\'\n\tdiscovery\x18\x02 \x01(\x0b\x32\x12.discovery.MessageH\x00\x12\x1b\n\x03\x62le\x18\x03 \x01(\x0b\x32\x0c.ble.MessageH\x00\x12!\n\x06zigbee\x18\x04 \x01(\x0b\x32\x0f.zigbee.MessageH\x00\x12\x1b\n\x03\x65sb\x18\x05 \x01(\x0b\x32\x0c.esb.MessageH\x00\x12%\n\x08unifying\x18\x06 \x01(\x0b\x32\x11.unifying.MessageH\x00\x12\x1b\n\x03phy\x18\x07 \x01(\x0b\x32\x0c.phy.MessageH\x00\x42\x05\n\x03msgb\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'protocol.whad_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _MESSAGE._serialized_start=207
  _MESSAGE._serialized_end=462
# @@protoc_insertion_point(module_scope)
