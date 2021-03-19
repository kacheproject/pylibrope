from dataclasses import dataclass
import time

import asyncio

from zmq import MessageTracker, Frame
from .netdb import Lease, NetDB, RouterInfo, RouterStatus, unix_timestamp_to_tamse
from typing import Any, AsyncIterator, Dict, Generator, Iterator, List, Optional, Sequence, Tuple, TypeVar
from nacl.encoding import URLSafeBase64Encoder
from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey, PublicKey
import zmq
from zmq.asyncio import Context, Socket, Poller
from enum import Enum
from ctypes import c_int64, c_int8
from zmq.utils.monitor import parse_monitor_message


def encode_tansmission_public_key(key: PublicKey):
    return key.encode(encoder=URLSafeBase64Encoder)


def decode_transmission_public_key(data: bytes) -> Optional[PublicKey]:
    try:
        return PublicKey(data, encoder=URLSafeBase64Encoder)
    except:
        return None

T = TypeVar('T')

def itself(o: T) -> T:
    return o


class PhysicalAddressStatus(Enum):
    OFFLINE = 0
    ONLINE = 1
    CONNECTED = 2


@dataclass
class PhysicalAddress(object):
    address: str
    status: PhysicalAddressStatus
    socket: Optional[Socket] = None

    def update_socket(self, socket: Optional[Socket]):
        if socket != None:
            self.socket = socket
            self.status = PhysicalAddressStatus.CONNECTED
        else:
            self.socket = None
            self.status = PhysicalAddressStatus.ONLINE

    @property
    def is_online(self):
        return self.status >= PhysicalAddressStatus.ONLINE

    @property
    def is_connected(self):
        return self.status == PhysicalAddressStatus.CONNECTED


class RopeProtoCmd(object):
    HELO = bytes(0)

@dataclass
class RopeMessage(object):
    identity: bytes
    body: List[bytes]

    @property
    def command(self):
        return self.body[0]
    
    @classmethod
    def from_frames(cls, data: List[bytes]) -> Optional["RopeMessage"]:
        identity = data.pop(0)
        return cls(identity, data)


class RopeRouter(object):
    """The rope router. This class provides functionality to exchange private network infomation and connect to specific remote.

    WARNING: kacheproject/rfc/rfc0 still in incomplete stage, the v1 protocol may be changing across different versions.

    * Messages
    ID (32 bytes) | COMMAND (1 byte integer) | ...

    HELO (0) | USING_PHYSICAL_ADDRESS (string) | MY_VERSION (string) | MY_ISOLATION (1 byte integer)
    BYE (1) | REASON (1 byte integer)
    EXCH_LEASE (2) | LEASE_ID (32 bytes) | ROUTER_ID (32 bytes) | BEFORE (8 bytes integer) | TAGS (string, separated by comma)
    EXCH_ROUTER_INFO (3) | ROUTER_ID (32 bytes) | ISOLATION (1 byte integer) | ...PHYSICAL_ADDRESS (string)
    ASK (4) | TYPE (lease=1, router=2, 1 byte integer) | ID (32 bytes)
    EXCH_ROUTER_STATUS (5) | ROUTER_ID (32 bytes) | STATUS (offline=0, online=1, 1 byte integer)
    EXCH_PHYSICAL_ADDRESS_STATUS (6) | PHYSICAL_ADDRESS (string) | STATUS (offline=0, online=1, connected=2, 1 byte integer)

    CONNECT (-1) | LEASE_ID (32 bytes) | USING_PHYSICAL_ADDRESS (string)
    GO_CONNECT (-2) | LEASE_ID (32 bytes) | PORT (4 byte integer)

    * About "isolation"
    Isolation is a 1 byte integer, which is similar to "netId" in I2P, used to sparate routers to different area for reasons.
    Routers should simply ignore messages from different isolation.
    Currently it's `1`.
    Any value < 0 tell other router this router is for testing purpose.
    """
    __ROPE_PROTO_VERSION__ = "1"

    def __init__(
        self,
        transmission_key: PrivateKey,
        self_identity_signing_key: SigningKey,
        isolation: int = 1,
        *,
        zctx: Context = None
    ) -> None:
        self.netdb = NetDB()
        self.transmission_key = transmission_key
        self.identity_signing_key = self_identity_signing_key
        self.physical_connections: Dict[str, PhysicalAddress] = {}
        self.zctx = zctx if zctx else Context()
        self.server_port = 9525
        self.me = RouterInfo(
            self_identity_signing_key.verify_key.encode(),
            [
                "lo://:{}".format(self.server_port),
            ],
            status=RouterStatus.ONLINE,
            isolation=isolation,
            created_time=c_int64(unix_timestamp_to_tamse(int(time.time()))),
            last_active_time=c_int64(0),
        )
        self.netdb.add_router_info(self.me)
        self.me.active()
        self.futures: List[asyncio.Future] = []

    def _build_message(self, frames: Sequence[bytes]) -> List[bytes]:
        assert self.me.identity
        return [self.me.identity, *frames]
    
    def check_router_connection(self, router_info: RouterInfo) -> bool:
        connected_count = sum(map(lambda _: 1, filter(lambda x: x and x.is_connected, map(self.physical_connections.get,router_info.physical_addresses))))
        result = connected_count > 0
        if not result:
            router_info.status = RouterStatus.OFFLINE
        else:
            router_info.status = RouterStatus.ONLINE
        return result

    async def _cothread_connection_monitor(
        self, physical_addr: PhysicalAddress, connection: Socket
    ):
        monitor_socket: Socket = connection.get_monitor_socket()
        while True:
            messages = await monitor_socket.recv_multipart()
            evd = parse_monitor_message(messages)
            evtype = evd["event"]
            if evtype == zmq.EVENT_DISCONNECTED:
                physical_addr.status = PhysicalAddressStatus.OFFLINE
            elif evtype == zmq.EVENT_CONNECTED:
                physical_addr.status = PhysicalAddressStatus.CONNECTED
            elif evtype == zmq.EVENT_CLOSED:
                physical_addr.status = PhysicalAddressStatus.OFFLINE
                self.physical_connections.pop(physical_addr.address)
                for router_info in self.netdb.search_routers(physical_address=physical_addr.address):
                    list(map(self.check_router_connection, router_info))
                return

    def _gossip_message(self, frames: List[bytes]):
        pass # TODO (rubicon): complete _gossip_message

    def _helo(self, peer_physical_addr: str) -> List[bytes]:
        return self._build_message((RopeProtoCmd.HELO, bytes(peer_physical_addr, "utf-8"), bytes(self.__ROPE_PROTO_VERSION__, 'utf-8'), bytes(self.me.isolation)))

    def create_user_socket(
        self, target_identity: str, entrypoint: str, socktype: int
    ) -> Optional[Socket]:
        pass # TODO (rubicon): complete create_user_socket

    def _connect(self, physical_address: str, zsock_type: int, curve_client_key: Optional[bytes]=None) -> PhysicalAddress:
        if physical_address in self.physical_connections:
            return self.physical_connections[physical_address]
        sock = self.zctx.socket(zsock_type)
        paddr_ins = PhysicalAddress(
            address=physical_address,
            status=PhysicalAddressStatus.OFFLINE,
            socket=sock,
        )
        fut = asyncio.ensure_future(self._cothread_connection_monitor(paddr_ins, sock))
        self.futures.append(fut)
        @fut.add_done_callback
        def monitor_ended_callback(fut: asyncio.Future):
            self.futures.remove(fut)
        sock.connect(paddr_ins.address)
        return paddr_ins
    
    async def helo(self, socket: Socket, peer_physical_address: str) -> Optional[bytes]:
        message = self._helo(peer_physical_address)
        await socket.send_multipart(message)
        recv_msg_data: List[zmq.Frame] = await socket.recv_multipart(copy=False)
        msg = RopeMessage.from_frames(list(map(bytes, recv_msg_data)))
        if msg:
            try:
                cmd, phyaddr, remote_ver, remote_isolation = msg.body
                if cmd == bytes(0):
                    self.me.update_physical_address(phyaddr)
                    router_info = self.netdb.get_router_info(msg.identity)
                    router_info.rope_version = remote_ver.decode('utf-8')
                    router_info.isolation = c_int8(remote_isolation[0])
                    router_info.active()
                    peer_addr = recv_msg_data[0]["Peer-Address"]
                    if isinstance(peer_addr, str):
                        router_info.update_physical_address(peer_addr)
                return msg.identity
            except:
                return None
        return None

    async def try_hello(self, physical_addresses: List[str]) -> AsyncIterator[PhysicalAddress]:
        for paddr in physical_addresses:
            paddr_ins = self._connect(paddr, zmq.REQ)
            assert paddr_ins.socket
            try:
                router_id = await asyncio.wait_for(self.helo(paddr_ins.socket, paddr_ins.address), timeout=1)
                if router_id:
                    yield paddr_ins
            except asyncio.TimeoutError:
                paddr_ins.socket.close(0)

    async def _connect_router(self, router_info: RouterInfo) -> Optional[PhysicalAddress]:
        for paddr in router_info.physical_addresses:
            if paddr in self.physical_connections:
                instance = self.physical_connections[paddr]
                if instance.is_connected:
                    return instance
        # Try connecting if not found any exists connection
        async for paddr_ins in self.try_hello(router_info.physical_addresses):
            return paddr_ins
        return None
    
    async def get_socket_for_lease(self, router_info: RouterInfo, lease: Lease) -> Optional[PhysicalAddress]:
        pass # TODO (rubicon): complete get_socket_for_lease

    async def _cothread_user_socket_proxy(
        self, router_info: RouterInfo, lease: Lease, socket: Socket
    ):
        current_physical_address: Optional[PhysicalAddress] = await self.get_socket_for_lease(router_info, lease)
        if not current_physical_address:
            socket.close()
            return
        poller = Poller()
        poller.register(current_physical_address.socket)
        poller.register(socket, zmq.POLLIN)
        buffer: List[Tuple[Socket, List[Frame]]] = []
        while True:
            if (not current_physical_address) or (not current_physical_address.is_connected):
                if current_physical_address:
                    poller.unregister(current_physical_address.socket)
                current_physical_address = await self.get_socket_for_lease(router_info, lease)
                if not current_physical_address:
                    socket.close()
                    return
                else:
                    poller.register(socket, zmq.POLLIN)
            if not current_physical_address.socket:
                socket.close()
                return
            if buffer:
                buffer_pointer = -1
                for target_socket, frames in buffer:
                    target_socket = current_physical_address.socket if target_socket != socket else socket
                    try:
                        await asyncio.wait_for(target_socket.send_multipart(frames, copy=False, track=True), len(frames) * 5)
                        buffer_pointer += 1
                    except asyncio.TimeoutError:
                        break
                if buffer_pointer != (len(buffer)-1):
                    buffer = buffer[buffer_pointer:]
                else:
                    buffer = []
            else:
                pevents: List[Tuple[Socket, int]] = await poller.poll()
                for sock, ev in pevents:
                    target_sock = current_physical_address.socket if sock == socket else socket
                    if ev & zmq.POLLIN:
                        frames = await sock.recv_multipart(copy=False)
                        try:
                            await asyncio.wait_for(target_sock.send_multipart(frames, copy=False, track=True), len(frames) * 5)
                        except asyncio.TimeoutError:
                            buffer.append((target_sock, frames))

    async def run(self):
        pass
