from whad.phy import Phy, Endianness
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from time import time,sleep
import sys

if __name__ == '__main__':
    # Connect to target device and performs discovery
    try:
        def show_packet(pkt):
            pkt.show()

        dev = WhadDevice.create("uart0")
        sniffer1 = Phy(dev)
        sniffer1.attach_callback(show_packet)
        sniffer1.set_frequency(2418)
        sniffer1.set_datarate(1000000)
        sniffer1.configure_gfsk(deviation=250000)
        sniffer1.set_endianness(Endianness.BIG)
        sniffer1.set_sync_word(bytes.fromhex("41424344"))
        sniffer1.sniff_phy()
        sniffer1.start()


        while True:
            input()



    except (KeyboardInterrupt, SystemExit):
        dev.close()

    except WhadDeviceNotFound:
        print('[e] Device not found')
        exit(1)