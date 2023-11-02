# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: protocol/device.proto

from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='protocol/device.proto',
  package='discovery',
  syntax='proto3',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x15protocol/device.proto\x12\tdiscovery\"\x12\n\x10\x44\x65viceResetQuery\"\x11\n\x0f\x44\x65viceReadyResp\"\"\n\x11SetTransportSpeed\x12\r\n\x05speed\x18\x01 \x01(\r\"\xe0\x01\n\x0e\x44\x65viceInfoResp\x12\x0c\n\x04type\x18\x01 \x01(\r\x12\r\n\x05\x64\x65vid\x18\x02 \x01(\x0c\x12\x15\n\rproto_min_ver\x18\x03 \x01(\r\x12\x11\n\tmax_speed\x18\x04 \x01(\r\x12\x11\n\tfw_author\x18\x05 \x01(\x0c\x12\x0e\n\x06\x66w_url\x18\x06 \x01(\x0c\x12\x18\n\x10\x66w_version_major\x18\x07 \x01(\r\x12\x18\n\x10\x66w_version_minor\x18\x08 \x01(\r\x12\x16\n\x0e\x66w_version_rev\x18\t \x01(\r\x12\x18\n\x0c\x63\x61pabilities\x18\n \x03(\rB\x02\x10\x01\"B\n\x14\x44\x65viceDomainInfoResp\x12\x0e\n\x06\x64omain\x18\x01 \x01(\r\x12\x1a\n\x12supported_commands\x18\x02 \x01(\x04\"$\n\x0f\x44\x65viceInfoQuery\x12\x11\n\tproto_ver\x18\x01 \x01(\r\"\'\n\x15\x44\x65viceDomainInfoQuery\x12\x0e\n\x06\x64omain\x18\x01 \x01(\r\"\xfd\x02\n\x07Message\x12\x32\n\x0breset_query\x18\x01 \x01(\x0b\x32\x1b.discovery.DeviceResetQueryH\x00\x12\x30\n\nready_resp\x18\x02 \x01(\x0b\x32\x1a.discovery.DeviceReadyRespH\x00\x12\x30\n\ninfo_query\x18\x03 \x01(\x0b\x32\x1a.discovery.DeviceInfoQueryH\x00\x12.\n\tinfo_resp\x18\x04 \x01(\x0b\x32\x19.discovery.DeviceInfoRespH\x00\x12\x38\n\x0c\x64omain_query\x18\x05 \x01(\x0b\x32 .discovery.DeviceDomainInfoQueryH\x00\x12\x36\n\x0b\x64omain_resp\x18\x06 \x01(\x0b\x32\x1f.discovery.DeviceDomainInfoRespH\x00\x12\x31\n\tset_speed\x18\x07 \x01(\x0b\x32\x1c.discovery.SetTransportSpeedH\x00\x42\x05\n\x03msg*\xc5\x01\n\x06\x44omain\x12\x0f\n\x0b_DomainNone\x10\x00\x12\n\n\x03Phy\x10\x80\x80\x80\x08\x12\x10\n\tBtClassic\x10\x80\x80\x80\x10\x12\x0b\n\x04\x42tLE\x10\x80\x80\x80\x18\x12\r\n\x06Zigbee\x10\x80\x80\x80 \x12\x10\n\tSixLowPan\x10\x80\x80\x80(\x12\n\n\x03\x45sb\x10\x80\x80\x80\x30\x12\x17\n\x10LogitechUnifying\x10\x80\x80\x80\x38\x12\r\n\x06Mosart\x10\x80\x80\x80@\x12\n\n\x03\x41NT\x10\x80\x80\x80H\x12\x0f\n\x08\x41NT_Plus\x10\x80\x80\x80P\x12\r\n\x06\x41NT_FS\x10\x80\x80\x80X*P\n\nDeviceType\x12\x12\n\x0e\x45sp32BleFuzzer\x10\x00\x12\r\n\tButterfly\x10\x01\x12\x0c\n\x08\x42tleJack\x10\x02\x12\x11\n\rVirtualDevice\x10\x04*|\n\nCapability\x12\x0c\n\x08_CapNone\x10\x00\x12\x08\n\x04Scan\x10\x01\x12\t\n\x05Sniff\x10\x02\x12\n\n\x06Inject\x10\x04\x12\x07\n\x03Jam\x10\x08\x12\n\n\x06Hijack\x10\x10\x12\x08\n\x04Hook\x10 \x12\x10\n\x0cSimulateRole\x10@\x12\x0e\n\tNoRawData\x10\x80\x01\x62\x06proto3'
)

_DOMAIN = _descriptor.EnumDescriptor(
  name='Domain',
  full_name='discovery.Domain',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='_DomainNone', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Phy', index=1, number=16777216,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='BtClassic', index=2, number=33554432,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='BtLE', index=3, number=50331648,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Zigbee', index=4, number=67108864,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='SixLowPan', index=5, number=83886080,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Esb', index=6, number=100663296,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='LogitechUnifying', index=7, number=117440512,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Mosart', index=8, number=134217728,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='ANT', index=9, number=150994944,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='ANT_Plus', index=10, number=167772160,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='ANT_FS', index=11, number=184549376,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=870,
  serialized_end=1067,
)
_sym_db.RegisterEnumDescriptor(_DOMAIN)

Domain = enum_type_wrapper.EnumTypeWrapper(_DOMAIN)
_DEVICETYPE = _descriptor.EnumDescriptor(
  name='DeviceType',
  full_name='discovery.DeviceType',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='Esp32BleFuzzer', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Butterfly', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='BtleJack', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='VirtualDevice', index=3, number=4,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=1069,
  serialized_end=1149,
)
_sym_db.RegisterEnumDescriptor(_DEVICETYPE)

DeviceType = enum_type_wrapper.EnumTypeWrapper(_DEVICETYPE)
_CAPABILITY = _descriptor.EnumDescriptor(
  name='Capability',
  full_name='discovery.Capability',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='_CapNone', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Scan', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Sniff', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Inject', index=3, number=4,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Jam', index=4, number=8,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Hijack', index=5, number=16,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Hook', index=6, number=32,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='SimulateRole', index=7, number=64,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='NoRawData', index=8, number=128,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=1151,
  serialized_end=1275,
)
_sym_db.RegisterEnumDescriptor(_CAPABILITY)

Capability = enum_type_wrapper.EnumTypeWrapper(_CAPABILITY)
_DomainNone = 0
Phy = 16777216
BtClassic = 33554432
BtLE = 50331648
Zigbee = 67108864
SixLowPan = 83886080
Esb = 100663296
LogitechUnifying = 117440512
Mosart = 134217728
ANT = 150994944
ANT_Plus = 167772160
ANT_FS = 184549376
Esp32BleFuzzer = 0
Butterfly = 1
BtleJack = 2
VirtualDevice = 4
_CapNone = 0
Scan = 1
Sniff = 2
Inject = 4
Jam = 8
Hijack = 16
Hook = 32
SimulateRole = 64
NoRawData = 128



_DEVICERESETQUERY = _descriptor.Descriptor(
  name='DeviceResetQuery',
  full_name='discovery.DeviceResetQuery',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=36,
  serialized_end=54,
)


_DEVICEREADYRESP = _descriptor.Descriptor(
  name='DeviceReadyResp',
  full_name='discovery.DeviceReadyResp',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=56,
  serialized_end=73,
)


_SETTRANSPORTSPEED = _descriptor.Descriptor(
  name='SetTransportSpeed',
  full_name='discovery.SetTransportSpeed',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='speed', full_name='discovery.SetTransportSpeed.speed', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=75,
  serialized_end=109,
)


_DEVICEINFORESP = _descriptor.Descriptor(
  name='DeviceInfoResp',
  full_name='discovery.DeviceInfoResp',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='type', full_name='discovery.DeviceInfoResp.type', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='devid', full_name='discovery.DeviceInfoResp.devid', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='proto_min_ver', full_name='discovery.DeviceInfoResp.proto_min_ver', index=2,
      number=3, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='max_speed', full_name='discovery.DeviceInfoResp.max_speed', index=3,
      number=4, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='fw_author', full_name='discovery.DeviceInfoResp.fw_author', index=4,
      number=5, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='fw_url', full_name='discovery.DeviceInfoResp.fw_url', index=5,
      number=6, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='fw_version_major', full_name='discovery.DeviceInfoResp.fw_version_major', index=6,
      number=7, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='fw_version_minor', full_name='discovery.DeviceInfoResp.fw_version_minor', index=7,
      number=8, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='fw_version_rev', full_name='discovery.DeviceInfoResp.fw_version_rev', index=8,
      number=9, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='capabilities', full_name='discovery.DeviceInfoResp.capabilities', index=9,
      number=10, type=13, cpp_type=3, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=b'\020\001', file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=112,
  serialized_end=336,
)


_DEVICEDOMAININFORESP = _descriptor.Descriptor(
  name='DeviceDomainInfoResp',
  full_name='discovery.DeviceDomainInfoResp',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='domain', full_name='discovery.DeviceDomainInfoResp.domain', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='supported_commands', full_name='discovery.DeviceDomainInfoResp.supported_commands', index=1,
      number=2, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=338,
  serialized_end=404,
)


_DEVICEINFOQUERY = _descriptor.Descriptor(
  name='DeviceInfoQuery',
  full_name='discovery.DeviceInfoQuery',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='proto_ver', full_name='discovery.DeviceInfoQuery.proto_ver', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=406,
  serialized_end=442,
)


_DEVICEDOMAININFOQUERY = _descriptor.Descriptor(
  name='DeviceDomainInfoQuery',
  full_name='discovery.DeviceDomainInfoQuery',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='domain', full_name='discovery.DeviceDomainInfoQuery.domain', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=444,
  serialized_end=483,
)


_MESSAGE = _descriptor.Descriptor(
  name='Message',
  full_name='discovery.Message',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='reset_query', full_name='discovery.Message.reset_query', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='ready_resp', full_name='discovery.Message.ready_resp', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='info_query', full_name='discovery.Message.info_query', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='info_resp', full_name='discovery.Message.info_resp', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='domain_query', full_name='discovery.Message.domain_query', index=4,
      number=5, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='domain_resp', full_name='discovery.Message.domain_resp', index=5,
      number=6, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='set_speed', full_name='discovery.Message.set_speed', index=6,
      number=7, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='msg', full_name='discovery.Message.msg',
      index=0, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
  ],
  serialized_start=486,
  serialized_end=867,
)

_MESSAGE.fields_by_name['reset_query'].message_type = _DEVICERESETQUERY
_MESSAGE.fields_by_name['ready_resp'].message_type = _DEVICEREADYRESP
_MESSAGE.fields_by_name['info_query'].message_type = _DEVICEINFOQUERY
_MESSAGE.fields_by_name['info_resp'].message_type = _DEVICEINFORESP
_MESSAGE.fields_by_name['domain_query'].message_type = _DEVICEDOMAININFOQUERY
_MESSAGE.fields_by_name['domain_resp'].message_type = _DEVICEDOMAININFORESP
_MESSAGE.fields_by_name['set_speed'].message_type = _SETTRANSPORTSPEED
_MESSAGE.oneofs_by_name['msg'].fields.append(
  _MESSAGE.fields_by_name['reset_query'])
_MESSAGE.fields_by_name['reset_query'].containing_oneof = _MESSAGE.oneofs_by_name['msg']
_MESSAGE.oneofs_by_name['msg'].fields.append(
  _MESSAGE.fields_by_name['ready_resp'])
_MESSAGE.fields_by_name['ready_resp'].containing_oneof = _MESSAGE.oneofs_by_name['msg']
_MESSAGE.oneofs_by_name['msg'].fields.append(
  _MESSAGE.fields_by_name['info_query'])
_MESSAGE.fields_by_name['info_query'].containing_oneof = _MESSAGE.oneofs_by_name['msg']
_MESSAGE.oneofs_by_name['msg'].fields.append(
  _MESSAGE.fields_by_name['info_resp'])
_MESSAGE.fields_by_name['info_resp'].containing_oneof = _MESSAGE.oneofs_by_name['msg']
_MESSAGE.oneofs_by_name['msg'].fields.append(
  _MESSAGE.fields_by_name['domain_query'])
_MESSAGE.fields_by_name['domain_query'].containing_oneof = _MESSAGE.oneofs_by_name['msg']
_MESSAGE.oneofs_by_name['msg'].fields.append(
  _MESSAGE.fields_by_name['domain_resp'])
_MESSAGE.fields_by_name['domain_resp'].containing_oneof = _MESSAGE.oneofs_by_name['msg']
_MESSAGE.oneofs_by_name['msg'].fields.append(
  _MESSAGE.fields_by_name['set_speed'])
_MESSAGE.fields_by_name['set_speed'].containing_oneof = _MESSAGE.oneofs_by_name['msg']
DESCRIPTOR.message_types_by_name['DeviceResetQuery'] = _DEVICERESETQUERY
DESCRIPTOR.message_types_by_name['DeviceReadyResp'] = _DEVICEREADYRESP
DESCRIPTOR.message_types_by_name['SetTransportSpeed'] = _SETTRANSPORTSPEED
DESCRIPTOR.message_types_by_name['DeviceInfoResp'] = _DEVICEINFORESP
DESCRIPTOR.message_types_by_name['DeviceDomainInfoResp'] = _DEVICEDOMAININFORESP
DESCRIPTOR.message_types_by_name['DeviceInfoQuery'] = _DEVICEINFOQUERY
DESCRIPTOR.message_types_by_name['DeviceDomainInfoQuery'] = _DEVICEDOMAININFOQUERY
DESCRIPTOR.message_types_by_name['Message'] = _MESSAGE
DESCRIPTOR.enum_types_by_name['Domain'] = _DOMAIN
DESCRIPTOR.enum_types_by_name['DeviceType'] = _DEVICETYPE
DESCRIPTOR.enum_types_by_name['Capability'] = _CAPABILITY
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

DeviceResetQuery = _reflection.GeneratedProtocolMessageType('DeviceResetQuery', (_message.Message,), {
  'DESCRIPTOR' : _DEVICERESETQUERY,
  '__module__' : 'protocol.device_pb2'
  # @@protoc_insertion_point(class_scope:discovery.DeviceResetQuery)
  })
_sym_db.RegisterMessage(DeviceResetQuery)

DeviceReadyResp = _reflection.GeneratedProtocolMessageType('DeviceReadyResp', (_message.Message,), {
  'DESCRIPTOR' : _DEVICEREADYRESP,
  '__module__' : 'protocol.device_pb2'
  # @@protoc_insertion_point(class_scope:discovery.DeviceReadyResp)
  })
_sym_db.RegisterMessage(DeviceReadyResp)

SetTransportSpeed = _reflection.GeneratedProtocolMessageType('SetTransportSpeed', (_message.Message,), {
  'DESCRIPTOR' : _SETTRANSPORTSPEED,
  '__module__' : 'protocol.device_pb2'
  # @@protoc_insertion_point(class_scope:discovery.SetTransportSpeed)
  })
_sym_db.RegisterMessage(SetTransportSpeed)

DeviceInfoResp = _reflection.GeneratedProtocolMessageType('DeviceInfoResp', (_message.Message,), {
  'DESCRIPTOR' : _DEVICEINFORESP,
  '__module__' : 'protocol.device_pb2'
  # @@protoc_insertion_point(class_scope:discovery.DeviceInfoResp)
  })
_sym_db.RegisterMessage(DeviceInfoResp)

DeviceDomainInfoResp = _reflection.GeneratedProtocolMessageType('DeviceDomainInfoResp', (_message.Message,), {
  'DESCRIPTOR' : _DEVICEDOMAININFORESP,
  '__module__' : 'protocol.device_pb2'
  # @@protoc_insertion_point(class_scope:discovery.DeviceDomainInfoResp)
  })
_sym_db.RegisterMessage(DeviceDomainInfoResp)

DeviceInfoQuery = _reflection.GeneratedProtocolMessageType('DeviceInfoQuery', (_message.Message,), {
  'DESCRIPTOR' : _DEVICEINFOQUERY,
  '__module__' : 'protocol.device_pb2'
  # @@protoc_insertion_point(class_scope:discovery.DeviceInfoQuery)
  })
_sym_db.RegisterMessage(DeviceInfoQuery)

DeviceDomainInfoQuery = _reflection.GeneratedProtocolMessageType('DeviceDomainInfoQuery', (_message.Message,), {
  'DESCRIPTOR' : _DEVICEDOMAININFOQUERY,
  '__module__' : 'protocol.device_pb2'
  # @@protoc_insertion_point(class_scope:discovery.DeviceDomainInfoQuery)
  })
_sym_db.RegisterMessage(DeviceDomainInfoQuery)

Message = _reflection.GeneratedProtocolMessageType('Message', (_message.Message,), {
  'DESCRIPTOR' : _MESSAGE,
  '__module__' : 'protocol.device_pb2'
  # @@protoc_insertion_point(class_scope:discovery.Message)
  })
_sym_db.RegisterMessage(Message)


_DEVICEINFORESP.fields_by_name['capabilities']._options = None
# @@protoc_insertion_point(module_scope)
