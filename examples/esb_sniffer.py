from whad.esb import ESB, PRX, PTX
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.scapy.layers.esb import ESB_Hdr
from scapy.compat import raw
import sys

def show(pkt):
    if hasattr(pkt, "metadata"):
        print(pkt.metadata)
    print(bytes(pkt).hex(), repr(pkt))

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = WhadDevice.create(interface)
            connector = PRX(dev)
            connector.address = "ca:e9:06:ec:a4"
            connector.channel = 8
            connector.attach_callback(show, on_reception = True)
            connector.start()

            #print("sync:", connector.stack.ll.synchronize())
            while True:
                input()
                print("send:", connector.stack.ll.prepare_acknowledgment(bytes.fromhex("4142434445464748")))

            #connector.set_node_address("ca:e9:06:ec:a4")
            #connector.enable_prx_mode(channel=8)
            #connector.sniff_esb(channel=None, address="ca:e9:06:ec:a4")
            while True:
                input()
                connector.send(ESB_Hdr(bytes.fromhex("cae906eca42a0061010000000000001e5c2980")))

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
