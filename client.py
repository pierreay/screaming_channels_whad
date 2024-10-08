from whad.ble import Central
from whad.ble.profile import UUID
from whad.device.uart import UartDevice
from time import time,sleep
from whad.common.monitors import WiresharkMonitor

import logging
logging.basicConfig(level=logging.WARNING)
logging.getLogger('whad.ble.stack.llm').setLevel(logging.INFO)

"""
scanner = Scanner(UartDevice('/dev/ttyUSB0', 115200))
scanner.start()
while True:
    try:
        for rssi, device in scanner.discover_devices():
            print('%d - %s' % (rssi, device.AdvA))
    except KeyboardInterrupt as exc:
        scanner.stop()
        scanner.device.close()
        break

class MyAsyncScanner(Scanner):
    def __init__(self, device):
        super().__init__(device)

    def on_adv_pdu(self, rssi, packet):
        print('%d - %s' %(
            rssi,
            packet.AdvA
        ))
        
class AsyncScan(Thread):
    def __init__(self, device):
        super().__init__()
        self.scan = MyAsyncScanner(device)

    def run(self):
        self.scan.start()
        while True:
            self.scan.process()
"""

""" Asynchronous scanner 
scanner = AsyncScan(UartDevice('/dev/ttyUSB0', 115200))
scanner.start()
scanner.join()
"""

""" Synchronous scanner 
scanner = Scanner(UartDevice('/dev/ttyUSB0', 115200))
scanner.start()
while True:
    try:
        for rssi, device in scanner.discover_devices():
            if (rssi >= -65):
                print('%d - %s' % (rssi, device.AdvA))
    except KeyboardInterrupt as exc:
        scanner.stop()
        break
"""


def test_cb(characteristic, value, indicate=False):
    print('> charac %s updated with value: %s' % (characteristic.uuid(), value))

central = Central(UartDevice('/dev/ttyUSB0', 115200))
print(central.device.device_id)
#device = central.connect('84:CC:A8:7E:D5:A2')
#device = central.connect('EC:8C:47:10:66:F0')
#device = central.connect('D6:F3:6E:89:DA:F5')
#device = central.connect('d4:3b:04:2c:ad:16')
#device = central.connect('0c:b8:15:c2:35:16')
#device = central.connect('0C:B8:15:C4:88:8E')
device = central.connect('C1:7C:2F:90:37:E1')

monitor_pcap = WiresharkMonitor()
monitor_pcap.attach(central)
monitor_pcap.start()
device.discover()
for service in device.services():
    print('-- Service %s' % service.uuid)
    for charac in service.characteristics():
        print(' + Characteristic %s' % charac.uuid)

#c = device.get_characteristic(UUID('b112f5e6-2679-30da-a26e-0273b6043849'), UUID('b112f5e6-2679-30da-a26e-0273b6043849'))
print(central.export_profile())

#print('sub=%s' % c.subscribe(notification=True, callback=test_cb))
c = device.get_characteristic(UUID('1800'), UUID('2A00'))
print(c.value)
#print(central.stop())
monitor_pcap.close()
device.disconnect()
central.stop()
central.close()



