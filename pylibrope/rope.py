from dataclasses import dataclass
import time
import sys
import math
import json

import asyncio

from zmq import MessageTracker, Frame
from .netdb import Lease, NetDB, RouterInfo, RouterStatus, unix_timestamp_to_tamse
from typing import (
    Any,
    AsyncIterator, Awaitable, Callable,
    Dict,
    Generator, Iterable,
    Iterator,
    List,
    Optional,
    Sequence,
    Tuple,
    TypeVar, Union, cast,
)
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


T = TypeVar("T")


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


class RopeProto(object):
    __PROTO_VERSION__ = "1"
    PING = bytes(0)
    PONG = bytes(1)
    SOTRE = bytes(2)
    ASK = bytes(4)
    ANSWER = bytes(8)
    SEARCH = bytes(16)
    RESULT = bytes(32)
    NEXT_TO = bytes(64)
    BUDDY_SERVICE = bytes(128)
    REJECT_BUDDY_SERVICE = bytes(256)
    BROADCAST_CHANGE = bytes(512)
    ERROR = bytes(1024)

    def __init__(self, identity: bytes, isolation: c_int8) -> None:
        self.identity = identity
        self.isolation = isolation

    def ping(self, peer_physical_addr: str) -> List[bytes]:
        return self.build_message(
            (
                self.PING,
                bytes(peer_physical_addr, "utf-8"),
                bytes(self.__PROTO_VERSION__, "utf-8"),
                bytes(self.isolation.value),
            )
        )

    def pong(self, peer_physical_addr: str) -> List[bytes]:
        return self.build_message(
            (self.PONG, peer_physical_addr.encode('utf-8'), self.__PROTO_VERSION__.encode('utf-8'), bytes(self.isolation.value))
        )

    def store(self, type: int, keywords: List[str], identity: bytes, content: Dict):
        return self.build_message(
            (self.SOTRE, bytes(type), bytes(','.join(keywords), 'utf-8'), identity, json.dumps(content).encode('utf-8'))
        )

    def build_message(self, frames: Sequence[bytes]) -> List[bytes]:
        assert self.identity
        return [self.identity, *frames]


@dataclass
class RopeMessage(object):
    identity: bytes
    body: List[bytes]
    peer_address: Optional[str] = None

    @property
    def command(self):
        return self.body[0]

    @classmethod
    def from_frames(cls, data: Union[List[bytes], List[Frame]]) -> Optional["RopeMessage"]:
        peer_address: Optional[str] = None
        if isinstance(data[0], Frame):
            peer_address = data[0]['Peer-Address']
            data = list(map(bytes, data))
        data = cast(List[bytes], data)
        identity = data.pop(0)
        return cls(identity, data, peer_address=peer_address)

def _limit(limit: int, iter: Iterable[T]) -> Iterator[T]:
    for v, _ in zip(iter, range(0, limit)):
        yield v

class KBucket(object):
    def __init__(self, me: RouterInfo) -> None:
        self.me = me
        self.buckets: List[List[RouterInfo]] = []
        for _ in range(0, 256):
            self.buckets.append([])

    @staticmethod
    def kad_distance(a: bytes, b: bytes) -> int:
        assert len(a) == 32 and len(b) == 32
        return int.from_bytes(a, sys.byteorder) ^ int.from_bytes(b, sys.byteorder)

    def add(self, router_info: RouterInfo):
        d = self.kad_distance(self.me.identity, router_info.identity)
        list_i = int(math.sqrt(d)) - 1
        self.buckets[list_i].remove(router_info)

    async def refresh_by(self, callable: Callable[[RouterInfo], Awaitable[bool]]) -> AsyncIterator[RouterInfo]:
        for bucket in self.buckets:
            for info in list(bucket):
                result = await callable(info)
                bucket.remove(info) # TODO (rubicon): use better structure to speed up removing and inserting
                if result:
                    bucket.append(info)
                    yield info

    def get_nearest_routers(self, identity: bytes, k:int=20) -> Iterator[RouterInfo]:
        """Get nearest `k` routers from `identity`.
        This is a fast implementation, the results are "possible" nearest routers.
        By the nature of the structure used by the KBucket, online time will be the first consideration rather than kad logic distance.
        """
        if not identity:
            identity = self.me.identity
        d = self.kad_distance(identity, self.me.identity)
        yield from _limit(k, self.get_nearest_routers_by_distance(d))

    def get_nearest_routers_by_distance(self, d:int, n:int=256) -> Iterator[RouterInfo]:
        n = abs(n)
        if d >= 0 and d < 256:
            yield from self.buckets[d]
        if n != 0:
            if (d-1) >= 0:
                yield from self.get_nearest_routers_by_distance(d-1, n-1)
            if (d+1) < 256:
                yield from self.get_nearest_routers_by_distance(d+1, n-1)




class RopeRouter(object):
    """The rope router. This class provides functionality to exchange private network infomation and connect to specific remote.

    Rope maintains kad tables across devices. The table stores messages about ROUTERS and LEASES. Lease maintains a entrypoint, which will be same level to router.
    Leases have expired time while routers doesn't. But every router should have at least one lease (can be itself), or it will be considered died.

    Every router should have a lease with tag "rope.router".

    WARNING: kacheproject/rfc/rfc0 still in incomplete stage, the v1 protocol may be changing across different versions.

    * Messages
    ROUTER_ID (32 bytes) | COMMAND (2 byte integer) | ...

    PING (0) | USING_PHYSICAL_ADDRESS (string) | MY_VERSION (string) | MY_ISOLATION (1 byte integer)
    PONG (1) | USING_PHYSICAL_ADDRESS (string) | MY_VERSION (string) | MY_ISOLATION (1 byte integer)
    STORE (2) | TYPE (lease=1, router_info=2, 1 byte integer) | KEYWORDS (string, sparated by comma) | ID (32 bytes) | CONTENT (string)
    ASK (4) | ID (32 bytes)
    ANSWER (8) | ID (32 bytes) | TYPE (lease=1, router_info=2, 1 byte integer) | CONTENT (string) # reply for ASK
    SEARCH (16) | TAGS (string, sparated by comma) | TYPE (all=0, lease=1, router_info=2, 1 byte integer)
    RESULT (32) | ...ID (32 bytes) # reply for SEARCH
    NEXT_TO (64) | ID (32 bytes) | NEAREST_ROUTER_ID (32 bytes) # reply for ASK and SEARCH
    BUDDY_SERVICE (128) | LEASE_ID (32 bytes) | PHYSICAL_ADDRESS (string)
    REJECT_BUDDY_SERVICE (256) | PHYSICAL_ADDRESS (string)
    BROADCAST_CHANGE (512) | TYPE(lease=1, router_info=2, 1 byte integer) | ID (32 bytes) | TTL (1 byte integer)
    ERROR (1024)

    All "CONTENT"s are json document.
    lease {
        physical_addresses: [String],
        router_id: String, // encoded by urlsafe base64
        id: String, // encoded by urlsafe base64, signing by router
        tags: [String],
    }

    router_info {
        id: String, // encoded by urlsafe base64
        isolation: Number, // int8
        rope_version: String,
    }

    * About "isolation"
    Isolation is a 1 byte integer, which is similar to "netId" in I2P, used to sparate routers to different area for reasons.
    Routers should simply ignore messages from different isolation.
    Currently it's `1`.
    Any value < 0 tell other router this router is for testing purpose.

    * Leases
    Leases only could be changed by the router which first publish the lease.

    * Rope "buddy service"
    Like "low id" nodes in typical kad network, there are many devices may need help while being connected from others (at least in some siutation).
    So we need some routers which in public network help others as a bridge. The new physical address should be added to lease after buddy service is accepted.
    """

    __ROPE_PROTO_VERSION__ = "1"

    def __init__(
        self,
        transmission_key: PrivateKey,
        self_identity_key: SigningKey,
        isolation: int = 1,
        *,
        zctx: Context = None
    ) -> None:
        self.netdb = NetDB()
        self.transmission_key = transmission_key
        self.identity_signing_key = self_identity_key
        self.physical_connections: Dict[str, PhysicalAddress] = {} # should be removed
        self.zctx = zctx if zctx else Context()
        self.server_port = 9525
        self.me = RouterInfo(
            identity=self_identity_key.verify_key.encode(),
            isolation=c_int8(isolation),
            rope_version=self.__ROPE_PROTO_VERSION__,
        )
        self.kbucket = KBucket(self.me)
        self.netdb.add_router_info(self.me)
        self.futures: List[asyncio.Future] = []
        self.proto = RopeProto(self.me.identity, self.me.isolation)

    async def _server(self):
        server_socket = self.zctx.socket(zmq.ROUTER)
        try:
            while True:
                data: List[Frame] = await server_socket.recv_multipart(copy=False)
                routing_id = data.pop(0).bytes
                data.pop(0)
                message = RopeMessage.from_frames(data)
                try:
                    reply = await self._server_message_handler(message)
                    if reply:
                        reply.insert(0, bytes())
                        reply.insert(0, routing_id)
                        server_socket.send_multipart(reply)
                except Exception as e:
                    server_socket.send_multipart((routing_id, bytes(), RopeProto.ERROR,))
                    # TODO (rubicon): logging error
        finally:
            server_socket.close()

    async def _server_message_handler(self, message: RopeMessage) -> Optional[List[bytes]]:
        command = message.command
        if command == RopeProto.PING:
            return self.proto.pong(message.peer_address if message.peer_address else "")
        else:
            return None

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
                return

    def _gossip_message(self, frames: List[bytes]):
        pass  # TODO (rubicon): complete _gossip_message

    def create_user_socket(
        self, target_identity: str, entrypoint: str, socktype: int
    ) -> Optional[Socket]:
        pass  # TODO (rubicon): complete create_user_socket

    def _connect(
        self,
        physical_address: str,
        zsock_type: int,
    ) -> PhysicalAddress:
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

        sock.setsockopt(zmq.CURVE_PUBLICKEY, cast(bytes, self.identity_signing_key.public_key.encode()))
        sock.setsockopt(zmq.CURVE_SECRETKEY, cast(bytes, self.identity_signing_key.encode()))
        sock.connect(paddr_ins.address)
        return paddr_ins

    async def get_socket_for_lease(
        self, router_info: RouterInfo, lease: Lease
    ) -> Optional[PhysicalAddress]:
        pass  # TODO (rubicon): complete get_socket_for_lease

    async def _cothread_user_socket_proxy(
        self, router_info: RouterInfo, lease: Lease, socket: Socket
    ):
        current_physical_address: Optional[
            PhysicalAddress
        ] = await self.get_socket_for_lease(router_info, lease)
        if not current_physical_address:
            socket.close()
            return
        poller = Poller()
        poller.register(current_physical_address.socket)
        poller.register(socket, zmq.POLLIN)
        buffer: List[Tuple[Socket, List[Frame]]] = []
        while True:
            if (not current_physical_address) or (
                not current_physical_address.is_connected
            ):
                if current_physical_address:
                    poller.unregister(current_physical_address.socket)
                current_physical_address = await self.get_socket_for_lease(
                    router_info, lease
                )
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
                    target_socket = (
                        current_physical_address.socket
                        if target_socket != socket
                        else socket
                    )
                    try:
                        await asyncio.wait_for(
                            target_socket.send_multipart(
                                frames, copy=False, track=True
                            ),
                            len(frames) * 5,
                        )
                        buffer_pointer += 1
                    except asyncio.TimeoutError:
                        break
                if buffer_pointer != (len(buffer) - 1):
                    buffer = buffer[buffer_pointer:]
                else:
                    buffer = []
            else:
                pevents: List[Tuple[Socket, int]] = await poller.poll()
                for sock, ev in pevents:
                    target_sock = (
                        current_physical_address.socket if sock == socket else socket
                    )
                    if ev & zmq.POLLIN:
                        frames = await sock.recv_multipart(copy=False)
                        try:
                            await asyncio.wait_for(
                                target_sock.send_multipart(
                                    frames, copy=False, track=True
                                ),
                                len(frames) * 5,
                            )
                        except asyncio.TimeoutError:
                            buffer.append((target_sock, frames))

    async def run(self):
        pass
