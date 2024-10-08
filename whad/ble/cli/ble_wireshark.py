"""Bluetooth Low Energy wireshark monitoring tool

This utility must be chained between two command-line tools to
monitor BLE packets going back and forth.
"""
import logging
import struct
from time import sleep
from threading import Thread
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_DATA, BTLE_ADV_IND, \
    BTLE_ADV_NONCONN_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_SCAN_IND, BTLE_SCAN_RSP, \
    BTLE_RF, BTLE_CTRL

from whad.protocol.ble.ble_pb2 import BleDirection, CentralMode, SetEncryptionCmd, StartCmd, StopCmd, \
    ScanMode, Start, Stop, BleAdvType, ConnectTo, CentralModeCmd, PeripheralMode, \
    PeripheralModeCmd, SetBdAddress, SendPDU, SniffAdv, SniffConnReq, HijackMaster, \
    HijackSlave, HijackBoth, SendRawPDU, AdvModeCmd, BleAdvType, SniffAccessAddress, \
    SniffAccessAddressCmd, SniffActiveConn, SniffActiveConnCmd, BleAddrType, ReactiveJam, \
    JamAdvOnChannel, PrepareSequence, PrepareSequenceCmd, TriggerSequence, DeleteSequence
from whad.cli.app import CommandLineApp
from whad.ble.connector import Central
from whad.common.monitors import WiresharkMonitor
from whad.device.unix import UnixSocketProxy, UnixSocketConnector
from whad.ble.metadata import generate_ble_metadata, BLEMetadata

from whad.ble.connector.translator import BleMessageTranslator

logger = logging.getLogger(__name__)


class BleUnixSocketConnector(UnixSocketConnector):
    """
    Specific connector for BLE protocol over UnixSocket.
    """

    def __init__(self, device, path=None):
        """Initialize our Unix Socket connector
        """
        super().__init__(device, path)
        self.__translator = BleMessageTranslator()


    def on_msg_sent(self, message):
        if message.WhichOneof('msg') == 'discovery':
            return
        elif message.WhichOneof('msg') == 'generic':
            return
        else:
            """Sent a domain message, process only BLE messages.
            """
            domain = message.WhichOneof('msg')
            if domain is not None:
                logger.info('message concerns domain `%s`, forward to domain-specific handler' % domain)
                if domain == 'ble':
                    # Convert message to packet, if any
                    message = getattr(message,domain)
                    msg_type = message.WhichOneof('msg')
                    if msg_type == 'send_pdu':
                        packet = self.__translator.from_message(message, msg_type)
                    elif msg_type == 'send_raw_pdu':
                        packet = self.__translator.from_message(message, msg_type)

                    if packet is not None:
                        self.monitor_packet_tx(packet)


    def on_domain_msg(self, domain, message):
        """Received a domain message, process only BLE messages.
        """
        packet = None
        if domain == 'ble':
            msg_type = message.WhichOneof('msg')
            if msg_type == 'adv_pdu':
                packet = self.__translator.from_message(message, msg_type)
            elif msg_type == 'pdu':
                packet = self.__translator.from_message(message, msg_type)
            elif msg_type == 'raw_pdu':
                packet = self.__translator.from_message(message, msg_type)

            if packet is not None:
                self.monitor_packet_rx(packet)

            
    def format(self, packet):
        """
        Converts a scapy packet with its metadata to a tuple containing a scapy packet with
        the appropriate header and the timestamp in microseconds.
        """
        return self.__translator.format(packet)


class BleWiresharkApp(CommandLineApp):

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD Bluetooth Low Energy wireshark monitoring',
            interface=True,
            commands=False
        )
        self.proxy = None


    def run(self):
        """Override App's run() method to handle scripting feature.
        """
        try:
            # Launch pre-run tasks
            self.pre_run()

            # We need to have an interface specified
            if self.input_interface is not None:
                # Make sure we are placed between two piped tools
                if self.is_stdout_piped() and self.is_stdin_piped():
                    # Start wireshark monitoring
                    self.monitor()
                else:
                    self.error('Tool must be piped to another WHAD tool.')
            else:
                self.error('<i>ble-wireshark</i> must be placed between two WHAD CLI tools to monitor traffic.')

        except KeyboardInterrupt as keybd:
            self.warning('ble-wireshark stopped (CTL-C)')
            if self.proxy is not None:
                self.proxy.stop()

        # Launch post-run tasks
        self.post_run()

    def monitor(self):
        """Start a new Unix socket server and forward all messages
        """
        # Create our proxy
        self.proxy = UnixSocketProxy(self.input_interface, self.args.__dict__, BleUnixSocketConnector)

        # Attach a wireshark monitor to our proxy
        monitor = WiresharkMonitor()
        monitor.attach(self.proxy.connector)
        monitor.start()
        self.proxy.start()
        self.proxy.join()
        

def ble_wireshark_main():
    app = BleWiresharkApp()
    app.run()
