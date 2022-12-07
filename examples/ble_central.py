from whad.ble import Central, ConnectionEventTrigger, ReceptionTrigger, ManualTrigger
from whad.ble.profile import UUID
from whad.ble.stack.llm import ENC_RSP
from whad.device import WhadDevice
from time import sleep, time
from scapy.all import BTLE_DATA, BTLE_ADV, ATT_Hdr, L2CAP_Hdr, ATT_Read_Request, ATT_Write_Request, ATT_Error_Response, BTLE_EMPTY_PDU, BTLE_CTRL, LL_ENC_REQ

TIME_START                  = 0
TIME_END                    = 0
HCI_CREATE_CONNECTION_COUNT = 0
LL_ENC_REQ_COUNT            = 0
LL_ENC_RSP_COUNT            = 0

def count_ll_enc_rsp(packet):
    global LL_ENC_RSP_COUNT
    if packet.haslayer(BTLE_DATA):
        btle_data = packet.getlayer(BTLE_DATA)
        if btle_data.haslayer(BTLE_CTRL):
            btle_ctrl = btle_data.getlayer(BTLE_CTRL)
            if btle_ctrl.opcode == ENC_RSP:
                LL_ENC_RSP_COUNT += 1

# Create central device.
TIME_START = time()
print("Create central from uart0")
central = Central(WhadDevice.create('uart0'))
central.attach_callback(count_ll_enc_rsp, on_reception=True, filter=lambda pkt:True)
# Show received packets that are not advertising or empty. */
central.attach_callback(lambda pkt:pkt.show(), on_reception=True, filter=lambda pkt:pkt.haslayer(BTLE_ADV) == 0 and pkt.getlayer(BTLE_DATA).len)

# Require a defined number of encryption response that simulate multiple traces collection.
while LL_ENC_RSP_COUNT < 10:
    # Create triggers.
    radio_trigger = ConnectionEventTrigger(10)
    radio_state = False
    # Send an empty packet, the goal here is just to inform the radio thread
    # that it has to turn ON the recording at a precise connection event.
    central.prepare(
        BTLE_DATA()/BTLE_EMPTY_PDU(),
        trigger=radio_trigger
    )
    read_enc_trigger = ConnectionEventTrigger(20)
    read_enc_state = False
    # 1. RAND and EDIV are obtained after pairing with the `run_pairing.sh` script.
    # 2. SKDM and IVM are obtained after sniffing during pairing with the `whadsniff` utility.
    # 3. Theoretically, only EDIV is necessary to identify the LTK on the
    # peripheral and start an AES encryption with the LTK as a key.
    # 4. Set MD=1 here to force READ_RSP on the same connection event as
    # ENC_RSP, excepting READ_RSP during AES processing. Do not set MD=1
    # before, otherwise connection event will be separated.
    central.prepare(
        BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Read_Request(gatt_handle=3),
        BTLE_DATA(MD=1)/BTLE_CTRL()/LL_ENC_REQ(rand=0xb84dc0a56a56e366, ediv=0xd117, skdm=0xf3681496c43831bb, ivm=0x99e664e3),
        trigger=read_enc_trigger
    )

    # Connect to the peripheral.
    # 1. Use increased Hop Interval. Decreasing it speed-up the connection, and
    # doesn't seems to make ATT_Read_Response and LL_ENC_RSP on different channel
    # (hence, different connection event). Would it be better to do so?
    # 2. Set channel map to 0x300 which corresponds to channel 8-9.
    device = central.connect('F4:9E:F2:6D:37:85', random=False, hop_interval=56, channel_map=0x00000300)
    HCI_CREATE_CONNECTION_COUNT += 1
    # Connection can be lost because of firmware bugs, interferances, or because
    # our packets are not legitimate. If so, just retry a connect.
    while central.is_connected():
        # Step 1: Turn the radio ON.
        if radio_trigger.triggered and not radio_state:
            radio_state = True
            print("[RADIO ON]")
        # Step 2: Send READ_REQ and ENC_REQ.
        if radio_state and read_enc_trigger.triggered and not read_enc_state:
            read_enc_state = True
            LL_ENC_REQ_COUNT += 1
            print("[ENC_REQ SEND]")
        # Step 3: Disconnect.
        if radio_state and read_enc_state:
            sleep(0.2) # Wait for ENC_RSP.
            device.disconnect()
            print("[RADIO OFF]")
            break    # Either: 1) Wait for disconnect ; 2) Break out of the
                     # loop ; Otherwise we send two disconnect.

# Clean.
central.stop()
central.close()
TIME_END = time()

# Display informations.
print("HCI_CREATE_CONNECTION_COUNT={}".format(HCI_CREATE_CONNECTION_COUNT))
print("LL_ENC_REQ_COUNT={}".format(LL_ENC_REQ_COUNT))
print("LL_ENC_RSP_COUNT={}".format(LL_ENC_RSP_COUNT))
print("TIME={:.2f}s".format(TIME_END - TIME_START))
