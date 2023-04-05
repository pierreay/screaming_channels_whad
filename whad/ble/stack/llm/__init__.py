"""
Bluetooth LE Stack Link-layer Manager
"""
from binascii import hexlify
from struct import pack
from random import randint

from time import sleep

from scapy.layers.bluetooth4LE import *

from whad.ble.stack.l2cap import BleL2CAP
from whad.ble.crypto import LinkLayerCryptoManager, generate_random_value, e

import logging
logger = logging.getLogger(__name__)

CONNECTION_UPDATE_REQ = 0x00
CHANNEL_MAP_REQ = 0x01
TERMINATE_IND = 0x02
ENC_REQ = 0x03
ENC_RSP = 0x04
START_ENC_REQ = 0x05
START_ENC_RSP = 0x06
UNKNOWN_RSP = 0x07
FEATURE_REQ = 0x08
FEATURE_RSP = 0x09
PAUSE_ENC_REQ = 0x0A
PAUSE_ENC_RSP = 0x0B
VERSION_IND = 0x0C
REJECT_IND = 0x0D
SLAVE_FEATURE_REQ = 0x0E
CONNECTION_PARAM_REQ = 0x0F
CONNECTION_PARAM_RSP = 0x10
REJECT_IND_EXT = 0x11
PING_REQ = 0x12
PING_RSP = 0x13
LENGTH_REQ = 0x14
LENGTH_RSP = 0x15

class BleConnection(object):

    def __init__(self, llm, conn_handle, local_peer_addr, remote_peer_addr):
        self.__llm = llm
        self.__conn_handle = conn_handle
        self.__local_peer = local_peer_addr
        self.__remote_peer = remote_peer_addr
        self.__l2cap = BleL2CAP(self)
        self.__encrypted = False
        self.__llcm = None

        self.__handlers = {
            CONNECTION_UPDATE_REQ: self.on_connection_update_req,
            CHANNEL_MAP_REQ: self.on_channel_map_req,
            TERMINATE_IND: self.on_terminate_ind,
            ENC_REQ: self.on_enc_req,
            ENC_RSP: self.on_enc_rsp,
            START_ENC_REQ: self.on_start_enc_req,
            START_ENC_RSP: self.on_start_enc_rsp,
            UNKNOWN_RSP: self.on_unknown_rsp,
            FEATURE_REQ: self.on_feature_req,
            FEATURE_RSP: self.on_feature_rsp,
            PAUSE_ENC_REQ: self.on_pause_enc_req,
            PAUSE_ENC_RSP: self.on_pause_enc_rsp,
            VERSION_IND: self.on_version_ind,
            REJECT_IND: self.on_reject_ind,
            SLAVE_FEATURE_REQ: self.on_slave_feature_req,
            CONNECTION_PARAM_REQ: self.on_connection_param_req,
            CONNECTION_PARAM_RSP: self.on_connection_param_rsp,
            REJECT_IND_EXT: self.on_reject_ind_ext,
            PING_REQ: self.on_ping_req,
            PING_RSP: self.on_ping_rsp,
            LENGTH_REQ: self.on_length_req,
            LENGTH_RSP: self.on_length_rsp
        }

    @property
    def remote_peer(self):
        return self.__remote_peer

    @property
    def local_peer(self):
        return self.__local_peer

    def on_disconnect(self):
        """Connection has been closed.
        """
        # Notify GATT layer that the connection has been terminated.
        if self.__l2cap.gatt is not None:
            self.__l2cap.gatt.on_terminated()
            #self.__llm.on_disconnected()

    def on_ctrl_pdu(self, control):
        """Handle Control PDU at connection-level"""
        ctrl = control.getlayer(BTLE_CTRL)
        if ctrl.opcode in self.__handlers:
            self.__handlers[int(ctrl.opcode)](ctrl.getlayer(1))


    def on_l2cap_data(self, data, fragment=False):
        """Forward L2CAP data to L2CAP layer"""
        self.__l2cap.on_data_received(data, fragment)

    def send_l2cap_data(self, data, fragment=False, encrypt=None):
        """Sends data back
        """
        self.__llm.send_data(self.__conn_handle, data, fragment, encrypt=encrypt)

    def send_control(self, pdu, encrypt=None):
        """Sends back a control PDU
        """
        self.__llm.send_control(self.__conn_handle, pdu, encrypt=encrypt)

    @property
    def gatt_class(self):
        return self.__llm.gatt_class

    @property
    def gatt(self):
        return self.__l2cap.att.gatt

    @property
    def conn_handle(self):
        return self.__conn_handle

    def set_stk(self, stk):
        self.__encrypted = True
        self.__stk = stk

    def set_ltk(self, ltk):
        self.__ltk = ltk

    ### Link-layer control PDU callbacks

    def on_unsupported_opcode(self, opcode):
        self.send_control(
            BTLE_CTRL() / LL_UNKNOWN_RSP(code=opcode)
        )

    def on_connection_update_req(self, conn_update):
        """Connection update is not supported yet
        """
        self.on_unsupported_opcode(CONNECTION_UPDATE_REQ)

    def on_channel_map_req(self, channel_map):
        """Channel map update is not supported yet
        """
        self.on_unsupported_opcode(CHANNEL_MAP_REQ)

    def on_terminate_ind(self, terminate):
        """Terminate this connection
        """
        # Notify Link-layer manager that our connection has been terminated
        self.__llm.on_disconnect(self.__conn_handle)

    def on_enc_req(self, enc_req):
        """Encryption request handler
        """
        # Allowed if we have already negociated an STK
        if self.__stk is not None:

            # Generate our SKD and IV
            self.__skd = randint(0, 0x10000000000000000)
            self.__iv = randint(0, 0x100000000)

            logger.info('[llm] Received LL_ENC_REQ: rand=%s ediv=%s skd=%s iv=%s' % (
                hexlify(pack('<Q', enc_req.rand)),
                hexlify(pack('<H', enc_req.ediv)),
                hexlify(pack('<Q', enc_req.skdm)),
                hexlify(pack('<I', enc_req.ivm)),
            ))

            logger.info('[llm] Initiate connection LinkLayerCryptoManager')

            # Save master rand/iv
            self.__randm = enc_req.rand
            self.__ediv = enc_req.ediv

            # Initiate LLCM
            self.__llcm = LinkLayerCryptoManager(
                self.__stk,
                enc_req.skdm,
                enc_req.ivm,
                self.__skd,
                self.__iv
            )

            # Compute session key
            master_skd = pack(">Q", enc_req.skdm)
            master_iv = pack("<L", enc_req.ivm)
            slave_skd = pack(">Q", self.__skd)
            slave_iv = pack("<L", self.__iv)

            # Generate session key diversifier
            skd = slave_skd + master_skd

            # Generate initialization vector
            iv = master_iv + slave_iv

            # Generate session key
            session_key = e(self.__stk, skd)

            logger.info('[llm] master  skd: %s' % hexlify(master_skd))
            logger.info('[llm] master   iv: %s' % hexlify(master_iv))
            logger.info('[llm] slave   skd: %s' % hexlify(slave_skd))
            logger.info('[llm] slave    iv: %s' % hexlify(slave_iv))
            logger.info('[llm] Session  TK: %s' % hexlify(self.__stk))
            logger.info('[llm] Session  iv: %s' % hexlify(iv))
            logger.info('[llm] Exp. Ses iv: %s' % hexlify(self.__llcm.iv))
            logger.info('[llm] Session key: %s' % hexlify(session_key))

            logger.info('[llm] Send LL_ENC_RSP: skd=%s iv=%s' % (
                hexlify(pack('<Q', self.__skd)),
                hexlify(pack('<I', self.__iv))
            ))

            # Send back our parameters
            self.send_control(
                BTLE_CTRL() / LL_ENC_RSP(
                    skds = self.__skd,
                    ivs = self.__iv
                )
            )

            # Notify encryption enabled
            if not self.__llm.set_encryption(
                self.conn_handle,
                enabled = True,
                key=session_key,
                iv=iv
            ):
                logger.info('[llm] Cannot enable encryption')
            else:
                logger.info('[llm] Encryption enabled in hardware')

            # Start encryption (STK as LTK)
            self.send_control(
                BTLE_CTRL() / LL_START_ENC_REQ(),
                encrypt=False
            )

        else:
            self.send_control(


                BTLE_CTRL() / LL_REJECT_IND(
                    code=0x1A # Unsupported Remote Feature
                )
            )

    def on_enc_rsp(self, enc_rsp):
        """Encryption not supported yet"""
        skds_path = "/tmp/whad_skds"
        # print("[WHAD] [ble/stack/llm/__init__.py] Received SKD_S on LL_ENC_RSP: enc_rsp.skds: raw={} hexlify_pack_<Q={}".format(enc_rsp.skds, hexlify(pack('<Q', enc_rsp.skds))))
        # print("[WHAD] [ble/stack/llm/__init__.py] Write {}".format(skds_path))
        with open(skds_path, mode="w") as f:
            f.write("{}\n".format(enc_rsp.skds))
        pass

    def on_start_enc_req(self, start_enc_req):
        """Encryption not supported yet
        """
        self.on_unsupported_opcode(START_ENC_REQ)

    def on_start_enc_rsp(self, start_enc_rsp):
        """Encryption start response handler

        Normally, we get this packet when a link has successfully
        been encrypted (with STK or LTK). So we need to notify the
        SMP that encryption has been acknowledged by the remote peer.


        """
        # Check if we are the encryption initiator,
        # if yes then we need to answer to this encrypted LL_START_ENC_RSP
        # with another encrypted LL_START_ENC_RSP
        if not self.__l2cap.smp.is_initiator():
            self.send_control(
                BTLE_CTRL() / LL_START_ENC_RSP()
            )

        # Notify SMP channel is now encrypted
        self.__l2cap.smp.on_channel_encrypted()

    def on_unknown_rsp(self, unk_rsp):
        pass

    def on_feature_req(self, feature_req):
        """Features not supported yet
        """
        self.on_unsupported_opcode(FEATURE_REQ)

    def on_feature_rsp(self, feature_rsp):
        """Features not supported yet
        """
        self.on_unsupported_opcode(FEATURE_RSP)

    def on_pause_enc_req(self, pause_enc_req):
        """Encryption not supported yet
        """
        self.on_unsupported_opcode(PAUSE_ENC_REQ)

    def on_pause_enc_rsp(self, pause_enc_rsp):
        """Encryption not supported yet
        """
        self.on_unsupported_opcode(PAUSE_ENC_RSP)

    def on_version_ind(self, version):
        """Send back our version info
        """
        self.send_control(
            BTLE_CTRL() / LL_VERSION_IND(
                version=self.__llm.stack.bt_version,
                company=self.__llm.stack.manufacturer_id,
                subversion=self.__llm.stack.bt_sub_version
            )
        )

    def on_reject_ind(self, reject):
        pass

    def on_slave_feature_req(self, feature_req):
        self.on_unsupported_opcode(FEATURE_REQ)

    def on_connection_param_req(self, conn_param_req):
        self.on_unsupported_opcode(CONNECTION_PARAM_REQ)

    def on_connection_param_rsp(self, conn_param_rsp):
        pass

    def on_reject_ind_ext(self, reject_ext):
        pass

    def on_ping_req(self, ping_req):
        pass

    def on_ping_rsp(self, ping_rsp):
        pass

    def on_length_req(self, length_req):
        pass

    def on_length_rsp(self, length_rsp):
        pass


    ##################################
    # Control PDU callbacks
    ##################################

class BleLinkLayerManager(object):

    def __init__(self, stack, gatt_class):
        self.__stack = stack
        self.__connections = {}
        self.__gatt_class = gatt_class

    @property
    def gatt_class(self):
        return self.__gatt_class

    @property
    def stack(self):
        return self.__stack

    def on_connect(self, conn_handle, local_peer_addr, remote_peer_addr):
        """Handles BLE connection
        """
        if conn_handle not in self.__connections:
            logger.info('[llm] registers new connection %d with %s' % (conn_handle, remote_peer_addr))
            self.__connections[conn_handle] = BleConnection(
                self,
                conn_handle,
                local_peer_addr,
                remote_peer_addr
            )
            return self.__connections[conn_handle]
        else:
            logger.error('[!] Connection already exists')
            self.__connections[conn_handle] = BleConnection(
                self,
                conn_handle,
                local_peer_addr,
                remote_peer_addr
            )
            return self.__connections[conn_handle]

    def on_disconnect(self, conn_handle):
        if conn_handle in self.__connections:
            logger.info('[llm] connection %d has just terminated' % conn_handle)
            self.__connections[conn_handle].on_disconnect()
            del self.__connections[conn_handle]

    def on_ctl_pdu(self, conn_handle, control):
        """Handles Control PDU
        """
        if conn_handle in self.__connections:
            conn = self.__connections[conn_handle]
            conn.on_ctrl_pdu(control)
        else:
            logger.error('[!] Wrong connection handle: %d', conn_handle)

    def on_data_pdu(self, conn_handle, data):
        """Manages Data PDU.
        """
        if conn_handle in self.__connections:
            conn = self.__connections[conn_handle]
            conn.on_l2cap_data(bytes(data.payload), data.LLID == 0x1)

    def send_data(self, conn_handle, data, fragment=False, encrypt=None):
        """Pack data into a Data PDU and transfer it to the device.
        """
        llid = 0x01 if fragment else 0x02
        self.__stack.send_data(
            conn_handle,
            BTLE_DATA(
                LLID=llid,
                len=len(data)
            )/data,
            encrypt=encrypt
        )

    def send_control(self, conn_handle, control_pdu, encrypt=None):
        """Send a control PDU
        """
        self.__stack.send_control(
            conn_handle,
            BTLE_DATA(
                LLID=0x03,
                len=len(control_pdu)
            )/control_pdu,
            encrypt=encrypt
        )

    def set_encryption(self, conn_handle, enabled=False, key=None, iv=None):
        """Notify connector encryption has been enabled or disabled.
        """
        return self.__stack.set_encryption(
            conn_handle,
            enabled,
            key,
            iv
        )
