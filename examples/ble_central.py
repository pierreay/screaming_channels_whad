from whad.ble import Central, ConnectionEventTrigger, ReceptionTrigger, ManualTrigger
from whad.ble.profile import UUID
from whad.device import WhadDevice
from time import sleep
from scapy.all import BTLE_DATA, ATT_Hdr, L2CAP_Hdr, ATT_Read_Request, ATT_Write_Request, ATT_Error_Response, BTLE_EMPTY_PDU, BTLE_CTRL, LL_ENC_REQ

def show(packet):
    print(packet.metadata, repr(packet))

# Create central device.
print("Create central from uart0")
central = Central(WhadDevice.create('uart0'))
central.attach_callback(show)

# Make 3 connection that simulate multiple traces collection.
for i in list(range(3)):
    # Create triggers.
    trigger_radio = ConnectionEventTrigger(10)
    central.prepare(
        # Send an empty packet, the goal here is just to inform the radio thread
        # that it has to turn ON the recording at a precise connection event.
        BTLE_DATA()/BTLE_EMPTY_PDU(),
        trigger=trigger_radio
    )
    trigger_read_enc = ConnectionEventTrigger(20)
    central.prepare(
        BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Read_Request(gatt_handle=3),
        # RAND and EDIV are obtained after pairing with the `run_pairing.sh` script.
        # TODO Why MD=1 is set for LL_ENC_REQ but not for ATT_Read_Request?
        BTLE_DATA(MD=1)/BTLE_CTRL()/LL_ENC_REQ(rand=0x26e9429fd727c6f3, ediv=0x6c51, skdm=0xf3681496c43831bb, ivm=0x99e664e3),
        trigger=trigger_read_enc
    )

    # Connect to the peripheral.
    # 1. Use increased Hop Interval. Decreasing it speed-up the connection, and
    # doesn't seems to make ATT_Read_Response and LL_ENC_RSP on different channel
    # (hence, different connection event). Would it be better to do so?
    # 2. Set channel map to 0x300 which corresponds to channel 8-9.
    device = central.connect('F4:9E:F2:6D:37:85', random=False, hop_interval=56, channel_map=0x00000300)

    # Wait for radio trigger.
    while not trigger_radio.triggered:
        pass
    print("[RADIO ON]")

    # Wait for encryption trigger.
    while not trigger_read_enc.triggered:
        pass
    print("[ENC_REQ SEND]")

    # Wait for ENC_REQ.
    sleep(1)
    print("[RADIO OFF]")

    # Disconnect.
    device.disconnect()
    sleep(1)

# Clean.
central.stop()
central.close()
