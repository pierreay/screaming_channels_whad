from whad.zigbee.stack.mac.constants import MACAddressMode

class ApplicationObject:
    def __init__(self, name, profile_id, device_id, device_version=0, input_clusters=[], output_clusters=[]):
        self.manager = None
        self.name = name
        self.profile_id = profile_id
        self.device_id = device_id
        self.device_version = device_version
        self.input_clusters = input_clusters
        self.output_clusters = output_clusters
        for cluster in self.input_clusters + self.output_clusters:
            cluster.application = self

    def initialize(self):
        pass

    def start(self):
        pass

    def add_input_cluster(self, cluster):
        self.input_clusters.append(cluster)
        cluster.application = self

    def add_output_cluster(self, cluster):
        self.output_clusters.append(cluster)
        cluster.application = self


    def send_data(self, asdu, destination_address_mode, destination_address, destination_endpoint, alias_address=None, alias_sequence_number=0, radius=30, security_enabled_transmission=False, use_network_key=False, acknowledged_transmission=False, fragmentation_permitted=False, include_extended_nonce=False, cluster_id=None):
        return self.manager.send_data(
            asdu,
            destination_address_mode,
            destination_address,
            destination_endpoint,
            alias_address=alias_address,
            alias_sequence_number=alias_sequence_number,
            radius=radius,
            security_enabled_transmission=security_enabled_transmission,
            use_network_key=use_network_key,
            acknowledged_transmission=acknowledged_transmission,
            fragmentation_permitted=fragmentation_permitted,
            include_extended_nonce=include_extended_nonce,
            cluster_id=cluster_id,
            profile_id=self.profile_id,
            application=self
        )

    def send_interpan_data(self, asdu, asdu_handle=0, source_address_mode=MACAddressMode.SHORT, destination_pan_id=0xFFFF, destination_address=0xFFFF,destination_address_mode=MACAddressMode.SHORT, cluster_id=0, acknowledged_transmission=False):
        print(acknowledged_transmission)
        return self.manager.send_interpan_data(asdu, asdu_handle=asdu_handle, source_address_mode=source_address_mode, destination_pan_id=destination_pan_id, destination_address=destination_address, destination_address_mode=destination_address_mode, profile_id=self.profile_id, cluster_id=cluster_id, acknowledged_transmission=acknowledged_transmission)

    def on_interpan_data(self, asdu, cluster_id=0, destination_pan_id=0xFFFF, destination_address=0xFFFF, source_pan_id=0xFFFF, source_address=0xFFFF, link_quality=255):
        for cluster in self.input_clusters + self.output_clusters:
            if cluster.cluster_id == cluster_id:
                cluster.on_interpan_data(asdu,  destination_pan_id=destination_pan_id, destination_address=destination_address, source_pan_id=source_pan_id, source_address=source_address, link_quality=link_quality)
                return True
        return False

    def on_data(self, asdu, source_address, source_address_mode, cluster_id, security_status, link_quality):
        # Checks if the application exposes a cluster matching the cluster id
        for cluster in self.input_clusters + self.output_clusters:
            if cluster.cluster_id == cluster_id:
                cluster.on_data(asdu, source_address, source_address_mode, security_status, link_quality)
                return True
        return False
