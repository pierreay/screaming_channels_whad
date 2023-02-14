"""
BLE Scanning device database
============================

This module provides a database that keeps track of discovered devices,
:class:`whad.ble.scanning.AdvertisingDevicesDB`. Discovered devices information
are handled in :class:`whad.ble.scanning.AdvertisingDevice`.
"""

from whad.ble import BDAddress, AdvDataFieldList, \
    AdvCompleteLocalName, AdvDataError, AdvDataFieldListOverflow, \
    AdvShortenedLocalName

from scapy.layers.bluetooth4LE import BTLE_ADV_IND, BTLE_ADV_NONCONN_IND, \
    BTLE_ADV_DIRECT_IND, BTLE_SCAN_RSP, BTLE_ADV

class AdvertisingDevice(object):
    """Store information about a device:

    * Received Signal Strength Indicator (RSSI)
    * Address type (public or random)
    * Advertising data
    * Scan response data
    * Type of advertising PDU
    * Connectable information
    """

    def __init__(self, rssi, address_type, bd_address, adv_data, rsp_data=None, undirected=True, connectable=True):
        """Instantiate an AdvertisingDevice.

        :param  rssi:           Received Signal Strength Indicator
        :type   rssi:           float
        :param  address_type:   Address type
        :type   address_type:   int
        :param  bd_address:     Bluetooth device address
        :type   bd_address:     str
        :param  adv_data:       Advertising data
        :type   adv_data:       bytes
        :param  rsp_data:       Scan response data
        :type   rsp_data:       bytes, optional
        :param  undirected:     ``True`` if advertising PDUs are undirected, `False` otherwise
        :type   undirected:     bool, optional
        :param  connectable:    ``True`` if device accepts connection, `False` otherwise
        :type   connectable:    bool, optional
        """
        self.__address_type = address_type
        self.__bd_address = bd_address
        self.__adv_data = adv_data
        self.__rsp_data = rsp_data
        self.__rssi = rssi
        self.__got_scan_rsp = False
        self.__undirected = undirected
        self.__connectable = connectable

    @property
    def address(self) -> str:
        """Device BD address.
        """
        return str(self.__bd_address)

    @property
    def address_type(self) -> int:
        """Device address type.
        """
        return self.__address_type

    @property
    def rssi(self) -> float:
        """Device RSSI.
        """
        return self.__rssi

    @property
    def adv_records(self) -> bytes:
        """Advertising records.
        """
        return self.__adv_data

    @property
    def scan_rsp_records(self) -> bytes:
        """Scan response records.
        """
        return self.__rsp_data

    @property
    def ad_records(self) -> AdvDataFieldList:
        """Combined advertising and scan response records.
        """
        out = AdvDataFieldList()
        for record in self.__adv_data:
            out.add(record)
        if self.__rsp_data is not None:
            for record in self.__rsp_data:
                out.add(record)
        return out

    @property
    def got_scan_rsp(self) -> bool:
        """Received a scan response from device.
        """
        return self.__got_scan_rsp

    @property
    def name(self) -> str:
        """Device complete or short name.
        """
        # Do we have a name ?
        complete_name = None
        short_name = None
        for record in self.ad_records:
            if isinstance(record, AdvShortenedLocalName):
                short_name = record.name.decode('utf-8')
            elif isinstance(record, AdvCompleteLocalName):
                complete_name = record.name.decode('utf-8')
        
        # Return discovered name (if any)
        if complete_name is not None:
            return complete_name
        elif short_name is not None:
            return short_name
        else:
            return None


    def __repr__(self):
        """Show device information.
        """
        # Do we have a name ?
        complete_name = None
        short_name = None
        for record in self.ad_records:
            if isinstance(record, AdvShortenedLocalName):
                short_name = record.name.decode('utf-8')
            elif isinstance(record, AdvCompleteLocalName):
                complete_name = record.name.decode('utf-8')

        # Pick the best name
        if complete_name:
            name = 'name:"%s"' % complete_name
        elif short_name:
            name = 'name:"%s"' % short_name
        else:
            name = ''

        # Display address type
        if self.__address_type == 0:
            addrtype = '[PUB]'
        else:
            addrtype = '[RND]'

        # Generate device summary
        return '[%4d dBm] %s %s %s' % (
            self.__rssi,
            addrtype,
            self.__bd_address,
            name
        )


    def update_rssi(self, rssi=0):
        """Update device RSSI.

        :param  rssi: New RSSI value.
        :type   rssi: float
        """
        self.__rssi = rssi

    def set_scan_rsp(self, scan_rsp):
        """Update device advertisement data.

        :param  scan_rsp:   Raw scan response.
        :type   scan_rsp:   bytes
        """
        if not self.__got_scan_rsp:
            self.__rsp_data = scan_rsp
            self.__got_scan_rsp = True


class AdvertisingDevicesDB(object):
    """Bluetooth Low Energy devices database.

    This class stores information about discovered devices.
    """

    def __init__(self):
        self.reset()


    def reset(self):
        """Remove database content.
        """
        self.__db = {}


    def find_device(self, address) -> AdvertisingDevice:
        """Find a device based on its BD address.

        :param      address: Device BD address
        :type       address: str
        :return:    Device if found, `None` otherwise.
        :rtype:     :class:`whad.ble.scanning.AdvertisingDevice`
        """
        if address in self.__db:
            return self.__db[address]
        else:
            return None


    def register_device(self, device):
        """Register or update a device.

        :param  device: Device to register.
        :type   device: :class:`whad.ble.scanning.AdvertisingDevice`
        """
        self.__db[device.address] = device


    def on_device_found(self, rssi, adv_packet, filter_addr=None):
        """Device advertising packet or scan response received.

        Parse the incoming packet and handle device appropriately.

        :param  rssi:           Received Signal Strength Indicator
        :type   rssi:           float
        :param  adv_packet:     Advertising packet
        :type   adv_packet:     :class:`scapy.packet.Packet`
        :param  filter_addr:    BD address to filter
        :type   filter_addr:    str
        """
        addr_type = adv_packet.getlayer(BTLE_ADV).TxAdd

        if adv_packet.haslayer(BTLE_ADV_IND):
            bd_address = BDAddress(adv_packet[BTLE_ADV_IND].AdvA)
            try:
                adv_data = b''.join([ bytes(record) for record in adv_packet[BTLE_ADV_IND].data])
                adv_list = AdvDataFieldList.from_bytes(adv_data)
                device = AdvertisingDevice(
                    rssi,
                    addr_type,
                    bd_address,
                    adv_list
                )

                # If bd address does not match, don't report it
                if filter_addr is not None and filter_addr.lower() != str(bd_address).lower():
                    return

                if str(bd_address) not in self.__db:
                    self.__db[str(bd_address)] = device
                    return device
            except AdvDataError as ad_error:
                pass
            except AdvDataFieldListOverflow as ad_ovf:
                pass

        elif adv_packet.haslayer(BTLE_ADV_NONCONN_IND):
            try:
                bd_address = BDAddress(adv_packet[BTLE_ADV_NONCONN_IND].AdvA)
                adv_data = b''.join([ bytes(record) for record in adv_packet[BTLE_ADV_NONCONN_IND].data])
                adv_list = AdvDataFieldList.from_bytes(adv_data)
                device = AdvertisingDevice(
                    rssi,
                    addr_type,
                    bd_address,
                    adv_list,
                    connectable=False
                )

                # If bd address does not match, don't report it
                if filter_addr is not None and filter_addr.lower() != str(bd_address).lower():
                    return

                if str(bd_address) not in self.__db:
                    self.__db[str(bd_address)] = device
                    return device
            except AdvDataError as ad_error:
                pass
            except AdvDataFieldListOverflow as ad_ovf:
                pass

        elif adv_packet.haslayer(BTLE_SCAN_RSP):
            try:
                bd_address = BDAddress(adv_packet[BTLE_SCAN_RSP].AdvA)
                adv_data = b''.join([ bytes(record) for record in adv_packet[BTLE_SCAN_RSP].data])
                adv_list = AdvDataFieldList.from_bytes(adv_data)
                if str(bd_address) in self.__db:
                    device = self.__db[str(bd_address)]
                    if not device.got_scan_rsp:
                        device.set_scan_rsp(adv_list)
                        return device
            except AdvDataError as ad_error:
                pass
            except AdvDataFieldListOverflow as ad_ovf:
                pass
