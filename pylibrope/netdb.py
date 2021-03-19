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
    physical_addresses: List[
        str
    ]  # standard URI: tcp://10.0.0.1:5050, ropx+pub://abc/abc
    status: RouterStatus
    isolation: c_int8
    created_time: c_int64
    last_active_time: c_int64
    rope_version: str

    def active(self):
        self.last_active_time = c_int64(unix_timestamp_to_tamse(int(time.time())))

    def update_physical_address(self, addr: str) -> bool:
        if addr not in self.physical_addresses:
            self.physical_addresses.append(addr)
            return True
        else:
            return False


@dataclass
class Lease(object):
    router_id: bytes
    identity: bytes
    tags: List[str]
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
                physical_addresses=[],
                status=RouterStatus.OFFLINE,
                created_time=c_int64(unix_timestamp_to_tamse(int(time.time()))),
                isolation=c_int8(-1),
                last_active_time=c_int64(0),
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
    ) -> Tuple[Lease, SigningKey]:
        new_signing_key = SigningKey.generate()
        new_id = new_signing_key.verify_key.encode()
        assert isinstance(new_id, bytes)
        lease = Lease(
            router_id=router_id,
            identity=new_id,
            tags=tags,
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

    def search_routers(
        self, *, physical_address: Optional[str] = None
    ) -> List[RouterInfo]:
        result = []
        if physical_address:
            for router_info in self.router_info.values():
                if physical_address in router_info.physical_addresses:
                    result.append(router_info)
        else:
            result.extend(self.router_info.values())
        return result
