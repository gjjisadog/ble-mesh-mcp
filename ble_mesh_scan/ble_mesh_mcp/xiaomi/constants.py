"""Constants from the observed Xiaomi FE95 Mesh Auth profile."""

from enum import IntEnum


UUID_FE95 = "0000fe95-0000-1000-8000-00805f9b34fb"
UUID_CTRL = "00000010-0000-1000-8000-00805f9b34fb"
UUID_SECURE = "00000016-0000-1000-8000-00805f9b34fb"


class RxferMode(IntEnum):
    SEG_CMD = 0
    SEG_ACK = 1
    SGL_CMD = 2
    SGL_ACK = 3
    MNG_CMD = 4
    MNG_ACK = 5


class RxferAck(IntEnum):
    A_SUCCESS = 0
    A_READY = 1
    A_BUSY = 2
    A_TIMEOUT = 3
    A_CANCEL = 4
    A_LOST = 5


class RxferManagement(IntEnum):
    M_FEATURE = 0
    M_LENGTH = 1


class RxferType(IntEnum):
    PASS_THROUGH = 0x00
    DEV_CERT = 0x01
    DEV_MANU_CERT = 0x02
    ECC_PUBKEY = 0x03
    DEV_SIGNATURE = 0x04
    DEV_LOGIN_INFO = 0x05
    DEV_SHARE_INFO = 0x06
    SERVER_CERT = 0x07
    SERVER_SIGN = 0x08
    MESH_CONFIG = 0x09
    APP_CONFIRMATION = 0x0A
    APP_RANDOM = 0x0B
    DEV_CONFIRMATION = 0x0C
    DEV_RANDOM = 0x0D
    BIND_KEY = 0x0E
    WIFI_CONFIG = 0x0F


RXFER_MODE_NAMES = {mode.value: mode.name for mode in RxferMode}
RXFER_TYPE_NAMES = {data_type.value: data_type.name for data_type in RxferType}


class MeshAuthOpcode(IntEnum):
    MESH_REG_START = 0x40
    MESH_REG_SUCCESS = 0x41
    MESH_REG_FAILED = 0x42
    MESH_REG_VERIFY_SUCCESS = 0x43
    MESH_ADMIN_LOGIN_START = 0x50
    MESH_ADMIN_LOGIN_SUCCESS = 0x51
    MESH_ADMIN_INVALID_LTMK = 0x52
    MESH_ADMIN_LOGIN_FAILED = 0x53
