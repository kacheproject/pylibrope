from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, List, Tuple, Union
from ctypes import c_int, c_int32, c_int64, c_int8, c_uint64
import time
from nacl.signing import SigningKey


class RouterStatus(Enum):
    OFFLINE = 0
    ONLINE = 1


def tamse_timestamp_to_unix(t: Union[int, c_int64]) -> int:
    if isinstance(t, c_int64):
        t = t.value
    return t + 612892800


def unix_timestamp_to_tamse(t: Union[int, c_int64]) -> int:
    if isinstance(t, c_int64):
        t = t.value
    return t - 612892800


@dataclass
class RouterInfo(object):
    identity: bytes  # it's a libsodium verify key
    isolation: c_int8
    rope_version: str


@dataclass
class Lease(object):
    router_id: bytes
    identity: bytes
    tags: List[str] # all tags should only contain a-zA-Z0-9
    physical_addresses: List[str] # TODO (rubicon): use object to track avaliabilities of addresses
    before: c_int64  # TAMSE (Tansport Advanced Managed SEquence) timestamp: unix timestamp - 612892800

    @property
    def before_unix(self) -> c_int64:
        return c_int64(tamse_timestamp_to_unix(self.before))

    @before_unix.setter
    def before_unix(self, value: Union[int, c_int]) -> None:
        if isinstance(value, c_int):
            value = value.value
        self.before = c_int64(unix_timestamp_to_tamse(value))


class NetDB(object):
    __VERSION__ = "1"

    def __init__(self) -> None:
        self.router_info: Dict[bytes, RouterInfo] = {}
        self.leaseset: Dict[bytes, Lease] = {}

    def get_router_info(self, router_id: bytes) -> RouterInfo:
        result = self.router_info.get(router_id, None)
        if not result:
            result = RouterInfo(
                identity=router_id,
                isolation=c_int8(-1),
                rope_version="",
            )
            self.router_info[router_id] = result
        return result

    def add_router_info(self, info: RouterInfo) -> None:
        self.router_info[info.identity] = info

    def router_info_exists(self, router_id: bytes) -> bool:
        return router_id in self.router_info

    def get_lease(self, identity: bytes) -> Optional[Lease]:
        return self.leaseset.get(identity, None)

    def new_lease(
        self, router_id: bytes, tags: List[str], before: int
    ) -> Tuple[Lease, SigningKey]: # TODO (rubicon): use RouterInfo instead router_id in parameters
        new_signing_key = SigningKey.generate()
        new_id = new_signing_key.verify_key.encode()
        assert isinstance(new_id, bytes)
        lease = Lease(
            router_id=router_id,
            identity=new_id, # TODO (rubicon): verifiable lease identity
            tags=tags,
            physical_addresses=[],
            before=c_int64(before),
        )
        self.leaseset[new_id] = lease
        return lease, new_signing_key

    def search_leases(self, *, tag: Optional[str] = None) -> List[Lease]:
        result = []
        if tag:
            for lease in self.leaseset.values():
                if tag in lease.tags:
                    result.append(lease)
        else:
            result.extend(self.leaseset.values())
        return result
