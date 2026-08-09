#!/usr/bin/env python3

import mmap
import os
import socket
import struct
import time
import unittest

from asfframework import VppAsfTestCase, VppTestRunner

from vpp_vhost_interface import VppVhostInterface
from vpp_papi_exceptions import CliFailedCommandError
from config import config


class VhostUserGuest:
    """Minimal vhost-user guest peer with one real memory-backed queue pair."""

    _VERSION = 1
    _NOFD = 0x100
    _SET_OWNER = 3
    _SET_FEATURES = 2
    _SET_MEM_TABLE = 5
    _SET_VRING_NUM = 8
    _SET_VRING_ADDR = 9
    _SET_VRING_BASE = 10
    _SET_VRING_KICK = 12
    _GUEST_CSUM = 1 << 1
    _RING_PACKED = 1 << 34
    _RING_SIZE = 8
    _GUEST_BASE = 0x100000
    _MEMORY_SIZE = 0x10000
    _DESC_SIZE = 16

    def __init__(self, socket_path, packed):
        self.socket_path = socket_path
        self.packed = packed
        self.fd = os.memfd_create("vhost-shinfo-guest", os.MFD_CLOEXEC)
        os.ftruncate(self.fd, self._MEMORY_SIZE)
        self.memory = mmap.mmap(self.fd, self._MEMORY_SIZE)
        self.socket = None
        self._desc_offsets = (0x0000, 0x4000)
        self._avail_offsets = (0x1000, 0x5000)
        self._used_offsets = (0x2000, 0x6000)
        self._packet_offset = 0x3000

    def close(self):
        if self.socket:
            self.socket.close()
            self.socket = None
        self.memory.close()
        os.close(self.fd)

    def _send(self, request, payload=b"", fds=()):
        header = struct.pack("<III", request, self._VERSION, len(payload))
        ancillary = []
        if fds:
            ancillary.append((socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("%di" % len(fds), *fds)))
        sent = self.socket.sendmsg([header + payload], ancillary)
        self.assert_sent(sent, len(header) + len(payload))

    @staticmethod
    def assert_sent(sent, expected):
        if sent != expected:
            raise RuntimeError("short vhost-user message")

    def _guest_address(self, offset):
        return self._GUEST_BASE + offset

    def _write(self, offset, data):
        self.memory.seek(offset)
        self.memory.write(data)

    def _read(self, offset, size):
        self.memory.seek(offset)
        return self.memory.read(size)

    def _setup_ring(self, queue):
        desc_offset = self._desc_offsets[queue]
        avail_offset = self._avail_offsets[queue]
        used_offset = self._used_offsets[queue]
        packet_offset = self._packet_offset + queue * 0x1000
        if self.packed:
            self._write(
                desc_offset,
                struct.pack(
                    "<QIHH",
                    self._guest_address(packet_offset),
                    2048,
                    queue,
                    0,
                ),
            )
            self._write(avail_offset, b"\0" * 4)
            self._write(used_offset, b"\0" * 4)
        else:
            self._write(
                desc_offset,
                struct.pack("<QIHH", self._guest_address(packet_offset), 2048, 0, 0),
            )
            self._write(avail_offset, struct.pack("<HHH", 0, 1 if queue == 0 else 0, 0))
            self._write(used_offset, b"\0" * 8)

        self._send(self._SET_VRING_NUM, struct.pack("<II", queue, self._RING_SIZE))
        self._send(
            self._SET_VRING_ADDR,
            struct.pack(
                "<IIQQQQ",
                queue,
                0,
                self._guest_address(desc_offset),
                self._guest_address(used_offset),
                self._guest_address(avail_offset),
                0,
            ),
        )
        self._send(self._SET_VRING_BASE, struct.pack("<II", queue, 0))
        self._send(self._SET_VRING_KICK, struct.pack("<Q", queue | self._NOFD))

    def connect(self):
        deadline = time.monotonic() + 5
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        while True:
            try:
                self.socket.connect(self.socket_path)
                break
            except FileNotFoundError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)
            except ConnectionRefusedError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)

        features = self._GUEST_CSUM | (self._RING_PACKED if self.packed else 0)
        self._send(self._SET_OWNER)
        self._send(self._SET_FEATURES, struct.pack("<Q", features))
        regions = struct.pack(
            "<QQQQ",
            self._GUEST_BASE,
            self._MEMORY_SIZE,
            self._GUEST_BASE,
            0,
        )
        memory = struct.pack("<II", 1, 0) + regions + b"\0" * (7 * len(regions))
        self._send(self._SET_MEM_TABLE, memory, (self.fd,))
        self._setup_ring(0)
        self._setup_ring(1)

    def packet(self):
        return self._read(self._packet_offset, 128)

    def published(self):
        if self.packed:
            return struct.unpack("<QIHH", self._read(self._desc_offsets[0], self._DESC_SIZE))[1] != 2048
        return struct.unpack("<H", self._read(self._used_offsets[0] + 2, 2))[0] == 1

    def prepare_fault_descriptor(self):
        packet_offset = self._packet_offset
        if self.packed:
            self._write(
                self._desc_offsets[0] + self._DESC_SIZE,
                struct.pack("<QIHH", self._guest_address(packet_offset), 2048, 1, 0),
            )
        else:
            self._write(
                self._desc_offsets[0] + self._DESC_SIZE,
                struct.pack("<QIHH", self._guest_address(packet_offset), 2048, 0, 0),
            )
            self._write(self._avail_offsets[0] + 4 + 2, struct.pack("<H", 1))
            self._write(self._avail_offsets[0] + 2, struct.pack("<H", 2))

    def fault_published(self):
        if self.packed:
            return struct.unpack(
                "<QIHH", self._read(self._desc_offsets[0] + self._DESC_SIZE, self._DESC_SIZE)
            )[1] != 2048
        return struct.unpack("<H", self._read(self._used_offsets[0] + 2, 2))[0] != 1


@unittest.skipIf("vhost" in config.excluded_plugins, "Exclude Vhost plugin tests")
class TesVhostInterface(VppAsfTestCase):
    """Vhost User Test Case"""

    @classmethod
    def setUpClass(cls):
        super(TesVhostInterface, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TesVhostInterface, cls).tearDownClass()

    def tearDown(self):
        super(TesVhostInterface, self).tearDown()
        if not self.vpp_dead:
            if_dump = self.vapi.sw_interface_vhost_user_dump()
            for ifc in if_dump:
                self.vapi.delete_vhost_user_if(ifc.sw_if_index)

    def test_vhost(self):
        """Vhost User add/delete interface test"""
        self.logger.info("Vhost User add interfaces")

        # create interface 1 (VirtualEthernet0/0/0)
        vhost_if1 = VppVhostInterface(self, sock_filename="/tmp/sock1")
        vhost_if1.add_vpp_config()
        vhost_if1.admin_up()

        # create interface 2 (VirtualEthernet0/0/1)
        vhost_if2 = VppVhostInterface(self, sock_filename="/tmp/sock2")
        vhost_if2.add_vpp_config()
        vhost_if2.admin_up()

        # verify both interfaces in the show
        ifs = self.vapi.cli("show interface")
        self.assertIn("VirtualEthernet0/0/0", ifs)
        self.assertIn("VirtualEthernet0/0/1", ifs)

        # verify they are in the dump also
        if_dump = self.vapi.sw_interface_vhost_user_dump()
        self.assertTrue(vhost_if1.is_interface_config_in_dump(if_dump))
        self.assertTrue(vhost_if2.is_interface_config_in_dump(if_dump))

        # delete VirtualEthernet0/0/1
        self.logger.info("Deleting VirtualEthernet0/0/1")
        vhost_if2.remove_vpp_config()

        self.logger.info("Verifying VirtualEthernet0/0/1 is deleted")

        ifs = self.vapi.cli("show interface")
        # verify VirtualEthernet0/0/0 still in the show
        self.assertIn("VirtualEthernet0/0/0", ifs)

        # verify VirtualEthernet0/0/1 not in the show
        self.assertNotIn("VirtualEthernet0/0/1", ifs)

        # verify VirtualEthernet0/0/1 is not in the dump
        if_dump = self.vapi.sw_interface_vhost_user_dump()
        self.assertFalse(vhost_if2.is_interface_config_in_dump(if_dump))

        # verify VirtualEthernet0/0/0 is still in the dump
        self.assertTrue(vhost_if1.is_interface_config_in_dump(if_dump))

        # delete VirtualEthernet0/0/0
        self.logger.info("Deleting VirtualEthernet0/0/0")
        vhost_if1.remove_vpp_config()

        self.logger.info("Verifying VirtualEthernet0/0/0 is deleted")

        # verify VirtualEthernet0/0/0 not in the show
        ifs = self.vapi.cli("show interface")
        self.assertNotIn("VirtualEthernet0/0/0", ifs)

        # verify VirtualEthernet0/0/0 is not in the dump
        if_dump = self.vapi.sw_interface_vhost_user_dump()
        self.assertFalse(vhost_if1.is_interface_config_in_dump(if_dump))

    def test_vhost_interface_state(self):
        """Vhost User interface states and events test"""

        self.vapi.want_interface_events()

        # clear outstanding events
        # (like delete interface events from other tests)
        self.vapi.collect_events()

        vhost_if = VppVhostInterface(self, sock_filename="/tmp/sock1")

        # create vhost interface
        vhost_if.add_vpp_config()
        self.sleep(0.1)
        events = self.vapi.collect_events()
        # creating interface does now create events
        self.assert_equal(len(events), 1, "number of events")

        vhost_if.admin_up()
        vhost_if.assert_interface_state(1, 0, expect_event=True)

        vhost_if.admin_down()
        vhost_if.assert_interface_state(0, 0, expect_event=True)

        # delete vhost interface
        vhost_if.remove_vpp_config()
        event = self.vapi.wait_for_event(timeout=1)
        self.assert_equal(event.sw_if_index, vhost_if.sw_if_index, "sw_if_index")
        self.assert_equal(event.deleted, 1, "deleted flag")

        # verify there are no more events
        events = self.vapi.collect_events()
        self.assert_equal(len(events), 0, "number of events")

    def test_vhost_interface_custom_mac_addr(self):
        """Vhost User interface custom mac address test"""

        mac_addr = "aa:bb:cc:dd:ee:ff"
        vhost_if = VppVhostInterface(
            self, sock_filename="/tmp/sock1", use_custom_mac=1, mac_address=mac_addr
        )

        # create vhost interface
        vhost_if.add_vpp_config()
        self.sleep(0.1)

        # verify mac in the dump
        if_dump_list = self.vapi.sw_interface_dump(sw_if_index=vhost_if.sw_if_index)
        self.assert_equal(len(if_dump_list), 1, "if dump length")

        [if_dump] = if_dump_list
        self.assert_equal(if_dump.l2_address.mac_string, mac_addr, "MAC Address")

        # delete VirtualEthernet
        self.logger.info("Deleting VirtualEthernet")
        vhost_if.remove_vpp_config()

    def test_vhost_shared_view_guest_peer(self):
        """Shared offload views reach real split and packed guest rings."""

        for packed in (False, True):
            suffix = "packed" if packed else "split"
            socket_path = "/tmp/vhost-shinfo-%s-%s" % (os.getpid(), suffix)
            guest = VhostUserGuest(socket_path, packed)
            vhost_if = VppVhostInterface(
                self,
                sock_filename=socket_path,
                is_server=1,
                enable_gso=1,
                enable_packed_ring=int(packed),
            )
            try:
                vhost_if.add_vpp_config()
                guest.connect()
                vhost_if.admin_up()
                self.vapi.cli(
                    "test vhost-shared-view sw_if_index %d" % vhost_if.sw_if_index
                )
                self.assertTrue(guest.published(), "%s guest ring publication" % suffix)
                packet = guest.packet()
                self.assertEqual(packet[0] & 1, 1, "%s guest checksum header" % suffix)
                self.assertNotEqual(
                    struct.unpack("!H", packet[10 + 14 + 20 + 6 : 10 + 14 + 20 + 8])[0],
                    0,
                    "%s guest UDP checksum rewrite" % suffix,
                )
                guest.prepare_fault_descriptor()
                try:
                    self.vapi.cli(
                        "test vhost-shared-view sw_if_index %d fault"
                        % vhost_if.sw_if_index
                    )
                except CliFailedCommandError as error:
                    if "fault injector unavailable" not in str(error):
                        raise
                else:
                    self.assertFalse(
                        guest.fault_published(),
                        "%s failed COW must not publish a guest descriptor" % suffix,
                    )
            finally:
                if not self.vpp_dead:
                    vhost_if.remove_vpp_config()
                guest.close()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
