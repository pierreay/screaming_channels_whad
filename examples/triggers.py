'''
trigger1 = ManualTrigger()
central.prepare(
    BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Read_Request(gatt_handle=9),
    BTLE_DATA(MD=1)/BTLE_CTRL()/LL_ENC_REQ(rand=0xdb99523e208507f, ediv=0xc4f1, skdm=0x12b8538c67e062eb, ivm=0x268edbb8),
    trigger=trigger1)

prepared_packets = [
    BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=2, data=b"ABCDABCDABCD"),
    BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Read_Request(gatt_handle=42)
]


prepared_packets2 = [
    BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=1, data=b"AfterReception"),
    BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=2, data=b"AfterReception"),
    BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=3, data=b"AfterReception"),
    BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=4, data=b"AfterReception"),
]

trigger1 = ManualTrigger()
central.prepare(*prepared_packets, trigger=trigger1)

trigger = ManualTrigger()
central.prepare(*prepared_packets2, trigger=trigger)
input()
#trigger1.trigger()
central.trigger(trigger1)
input()
central.trigger(trigger)
while True:
    print(trigger1.triggered, trigger2.triggered)
    input()
    trigger1.trigger()
    input()
    trigger2.trigger()
'''

'''
trigger = ReceptionTrigger(packet=BTLE_DATA()/BTLE_CTRL()/LL_ENC_REQ(), selected_fields=("opcode", "len"))
sniffer.prepare(BTLE_DATA()/BTLE_CTRL()/LL_REJECT_IND(code=0x06), trigger=trigger, direction=BleDirection.INJECTION_TO_MASTER)

trigger1 = ManualTrigger()
sniffer.prepare(
BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=0x21, data=b"\x55\x10\x01\x0d\x0a"),
trigger=trigger1, direction=BleDirection.INJECTION_TO_SLAVE)

trigger2 = ManualTrigger()
sniffer.prepare(
BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=0x21, data=b"\x55\x10\x00\x0d\x0a"),
trigger=trigger2, direction=BleDirection.INJECTION_TO_SLAVE)

trigger1 = ConnectionEventTrigger(130)
sniffer.prepare(
BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=0x21, data=b"\x55\x10\x00\x0d\x0a"),
BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=0x21, data=b"\x55\x10\x01\x0d\x0a"),
BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=0x21, data=b"\x55\x10\x00\x0d\x0a"),
BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=0x21, data=b"\x55\x10\x01\x0d\x0a"),
trigger=trigger1, direction=BleDirection.INJECTION_TO_SLAVE)

trigger2 = ReceptionTrigger(packet=BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Read_Request(gatt_handle=0x3), selected_fields=("opcode", "gatt_handle"))
sniffer.prepare(
BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Read_Response(value=b"Hacked :D"),
trigger=trigger2, direction=BleDirection.INJECTION_TO_MASTER)
'''

from whad.ble import Central, ConnectionEventTrigger, ReceptionTrigger, ManualTrigger
from whad.ble.profile import UUID
from whad.device import WhadDevice
from time import sleep
from scapy.all import BTLE_DATA, ATT_Hdr, L2CAP_Hdr, ATT_Read_Request, ATT_Write_Request, ATT_Error_Response, ATT_Read_Response

def show(packet):
    print(packet.metadata, repr(packet))

central = Central(WhadDevice.create('uart0'))
central.attach_callback(show)

while True:
    trigger2 = ReceptionTrigger(
        packet=BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Read_Response(),
        selected_fields=("opcode")
    )
    central.prepare(
        BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=0x21, data=bytes.fromhex("5510000d0a")),
        trigger=trigger2
    )
    print("New connection")
    #print('Using device: %s' % central.device.device_id)
    device = central.connect('74:da:ea:91:47:e3' ,random=False)
    input()
    # Discover
    device.discover()
    for service in device.services():
        print('-- Service %s' % service.uuid)
        for charac in service.characteristics():
            print(' + Characteristic %s' % charac.uuid)

    # Read Device Name characteristic (Generic Access Service)
    c = device.get_characteristic(UUID('1800'), UUID('2A00'))
    print(c.value)
    input()

    # Disconnect
    print("Stop connection")
    device.disconnect()
central.stop()
central.close()
>>>>>>> eda79fc (Add a reception trigger in examples (from Romain))
