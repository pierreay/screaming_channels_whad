from whad.zigbee.stack.apl.zcl import ZCLCluster, ZCLClientCluster, ZCLServerCluster, ZCLClusterConfiguration
from whad.zigbee.stack.mac.constants import MACAddressMode
from whad.scapy.layers.zll import ZigbeeZLLCommissioningCluster, ZLLScanRequest, ZLLIdentifyRequest, \
    ZLLDeviceInformationRequest, ZLLResetToFactoryNewRequest, ZLLNetworkJoinRouterRequest
from whad.zigbee.crypto import TouchlinkKeyManager
from random import randint


class ZCLTouchLinkClient(ZCLClientCluster):

    def __init__(self):
        self.transaction_id = None
        super().__init__(cluster_id=0x1000, default_configuration=ZCLClusterConfiguration(destination_address=0xFFFF,destination_pan_id =0xFFFF, interpan=True, disable_default_response=True))

    @ZCLCluster.command_generate(0x00, "ScanRequest")
    def scan_request(self, transaction_id=None, link_initiator=True, address_assignment=True, factory_new=True):
        if transaction_id is None:
            transaction_id = randint(0, 0xFFFFFFFF)
            self.transaction_id = transaction_id
        node_descriptor = self.application.manager.get_application_by_name("zdo").configuration.get("configNodeDescriptor")
        command = ZLLScanRequest(
            inter_pan_transaction_id=transaction_id,
            rx_on_when_idle=int(node_descriptor.receiver_on_when_idle),
            logical_type=int(node_descriptor.logical_type),
            link_initiator=link_initiator,
            address_assignment=address_assignment,
            factory_new=factory_new
        )

        self.send_command(command)


    @ZCLCluster.command_receive(0x01, "ScanResponse")
    def on_scan_response(self, command, source_address):
        if command.inter_pan_transaction_id == self.transaction_id:
            command.show()
            self.network_join_router_request(
                transaction_id=self.transaction_id,
                response_id=command.response_id,
                destination_address=source_address,
                extended_pan_id=0x1122334455667788,
                network_address=0x0024,
                key_index=4,
            )
            self.network_join_router_request(transaction_id=self.transaction_id, destination_address=source_address)
            #self.identify_request(transaction_id=self.transaction_id, identify_duration=5, destination_address=source_address)

            '''
            self.reset_to_factory_new(
            transaction_id=self.transaction_id,
            destination_address=source_address
            )
            '''
            #self.device_information_request(transaction_id=self.transaction_id, start_index=0, destination_address=source_address)
        #status = self.wait_response()
        #return status == 0



    @ZCLCluster.command_generate(0x02, "DeviceInformationRequest")
    def device_information_request(self,transaction_id=None, start_index=0, destination_address=None):
        if transaction_id is None:
            transaction_id = randint(0, 0xFFFFFFFF)
            self.transaction_id = transaction_id

        self.configure(
            destination_address=destination_address,
            destination_address_mode=MACAddressMode.EXTENDED,
            interpan=True,
            acknowledged_transmission=True,
            disable_default_response=True
        )

        command = ZLLDeviceInformationRequest(inter_pan_transaction_id=transaction_id, start_index=start_index)
        self.send_command(command)

    @ZCLCluster.command_generate(0x06, "IdentifyRequest")
    def identify_request(self,transaction_id=None, identify_duration=1, destination_address=None):
        if transaction_id is None:
            transaction_id = randint(0, 0xFFFFFFFF)
            self.transaction_id = transaction_id

        self.configure(
            destination_address=destination_address,
            destination_address_mode=MACAddressMode.EXTENDED,
            interpan=True,
            acknowledged_transmission=True,
            disable_default_response=True
        )

        command = ZLLIdentifyRequest(inter_pan_transaction_id=transaction_id, identify_duration=identify_duration)
        self.send_command(command)

    @ZCLCluster.command_generate(0x07, "ResetToFactoryNew")
    def reset_to_factory_new(self,transaction_id=None, destination_address=None):
        if transaction_id is None:
            transaction_id = randint(0, 0xFFFFFFFF)
            self.transaction_id = transaction_id

        self.configure(
            destination_address=destination_address,
            destination_address_mode=MACAddressMode.EXTENDED,
            interpan=True,
            acknowledged_transmission=True,
            disable_default_response=True
        )
        command = ZLLResetToFactoryNewRequest(inter_pan_transaction_id=transaction_id)
        self.send_command(command)

    @ZCLCluster.command_generate(0x12, "NetworkJoinRouterRequest")
    def network_join_router_request(self,transaction_id=None, response_id=None, destination_address=None, key_index=4, network_update_id=0, key=bytes.fromhex("11223344556677881122334455667788"), logical_channel=25, pan_id=0x1234, extended_pan_id=0x0102030405060708, network_address=0x0001):
        if transaction_id is None:
            transaction_id = randint(0, 0xFFFFFFFF)
            self.transaction_id = transaction_id

        self.configure(
            destination_address=destination_address,
            destination_address_mode=MACAddressMode.EXTENDED,
            interpan=True,
            acknowledged_transmission=True,
            disable_default_response=True
        )

        encrypted_key = TouchlinkKeyManager(
            unencrypted_key=key,
            response_id=response_id,
            transaction_id=transaction_id,
            key_index=key_index
        ).encrypted_key

        command = ZLLNetworkJoinRouterRequest(
            inter_pan_transaction_id=transaction_id,
            pan_id_ext=extended_pan_id,
            key_index=key_index,
            encrypted_network_key=encrypted_key,
            network_update_id=network_update_id,
            channel=logical_channel,
            pan_id=pan_id,
            network_address=network_address
        )
        command.show()
        self.send_command(command)


    @ZCLCluster.command_receive(0x13, "NetworkJoinRouterResponse")
    def on_network_join_router_response(self, command, source_address):
        command.show()
        if command.inter_pan_transaction_id == self.transaction_id:
            print("Touchlink provisionning OK !")
            exit()

# TODO: old version, refactoring needed
'''
class ZCLTouchLink(ZCLCluster):
    def __init__(self):
        super().__init__(cluster_id=0x1000)

    def register_commands(self):
        self.commands.add_command(0x00, "ScanRequest", generate_callback=self.scan_request, receive_callback=None)
        self.commands.add_command(0x01, "ScanResponse", generate_callback=None, receive_callback=self.on_scan_response)

    def scan_request(self, transaction_id=randint(0, 0xFFFFFFFF), link_initiator=True, address_assignment=True, factory_new=True):
        node_descriptor = self.application.manager.get_application_by_name("zdo").configuration.get("configNodeDescriptor")

        command = ZLLScanRequest(
            inter_pan_transaction_id=transaction_id,
            rx_on_when_idle=int(node_descriptor.receiver_on_when_idle),
            logical_type=int(node_descriptor.logical_type),
            link_initiator=link_initiator,
            address_assignment=address_assignment,
            factory_new=factory_new
        )

        return self.send_command(0x00, command)

    def on_scan_response(self, payload, transaction=None, no_response=True):
        payload.show()

    def send_command(self, command_identifier, command, transaction=None,  disable_default_response=True):
        if transaction is None:
            transaction = ZCLCluster.zcl_transaction_counter
            ZCLCluster.zcl_transaction_counter += 1

        asdu = ZigbeeZLLCommissioningCluster(
                zcl_frametype=1,
                direction=0,
                command_identifier=command_identifier,
                transaction_sequence=transaction,
                disable_default_response=disable_default_response
        ) / command

        return self.send_interpan_data(asdu, asdu_handle=0, source_address_mode=MACAddressMode.EXTENDED, destination_pan_id=0xFFFF, destination_address=0xFFFF)

    def on_interpan_data(self, asdu,destination_pan_id, destination_address, source_pan_id, source_address, link_quality):
        command_identifier = asdu.command_identifier

        try:
            command = self.commands.get_command(command_identifier)
            command.receive_callback(asdu[ZigbeeZLLCommissioningCluster].payload, transaction=asdu.transaction_sequence, no_response=asdu.disable_default_response)

        except ZCLCommandNotFound:
            logger.info("[zcl] command not found (command_identifier = 0x{:02x})".format(command_identifier))
'''
