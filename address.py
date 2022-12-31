from enum import IntEnum, unique
from typing import Optional, Literal, Tuple

from bip_utils import Base58Decoder


@unique
class ErgoAddressTypes(IntEnum):
    P2PK = 0x01
    P2SH = 0x02
    P2S = 0x03


@unique
class ErgoNetworkTypes(IntEnum):
    MAINNET = 0x00
    TESTNET = 0x10


class ErgoAddrConst:
    # Checksum length in bytes
    CHECKSUM_BYTE_LEN: int = 4


def EncodePrefix(addr_type: ErgoAddressTypes,
                 net_type: ErgoNetworkTypes) -> bytes:
    return ToBytes(addr_type + net_type)  # prefix byte


def validate_and_remove_prefix(addr: bytes, prefix: bytes) -> bytes:
    """
    Validate and remove prefix from an address.
    Args:
        addr (bytes)  : Address string or bytes
        prefix (bytes): Address prefix
    Returns:
        bytes: Address bytes with prefix removed
    Raises:
        ValueError: If the prefix is not valid
    """
    prefix_got = addr[:1]
    if prefix != prefix_got:
        raise ValueError(f"Invalid prefix (expected {prefix!r}, got {prefix_got!r})")
    return addr[1:]


def SplitPartsByChecksum(addr_bytes: bytes,
                         checksum_len: int) -> Tuple[bytes, bytes]:
    """
    Split address in two parts, considering the checksum at the end of it.

    Args:
        addr_bytes (bytes): Address bytes
        checksum_len (int): Checksum length

    Returns:
        tuple[bytes, bytes]: Payload bytes (index 0) and checksum bytes (index 1)
    """
    checksum_bytes = addr_bytes[-1 * checksum_len:]
    payload_bytes = addr_bytes[:-1 * checksum_len]
    return payload_bytes, checksum_bytes


def ToBytes(data_int: int,
            bytes_num: Optional[int] = None,
            endianness: Literal["little", "big"] = "big",
            signed: bool = False) -> bytes:
    """
    Convert integer to bytes.
    Args:
        data_int (int)                          : Data integer
        bytes_num (int, optional)               : Number of bytes, automatic if None
        endianness ("big" or "little", optional): Endianness (default: big)
        signed (bool, optional)                 : True if signed, false otherwise (default: false)
    Returns:
        bytes: Bytes representation
    """

    # In case gmpy is used
    if data_int.__class__.__name__ == "mpz":
        data_int = int(data_int)

    bytes_num = bytes_num or ((data_int.bit_length() if data_int > 0 else 1) + 7) // 8
    return data_int.to_bytes(bytes_num, byteorder=endianness, signed=signed)


def get_prefix(addr) -> bytes:
    addr_dec_bytes = Base58Decoder.Decode(addr)

    addr_with_prefix, checksum_bytes = SplitPartsByChecksum(addr_dec_bytes,
                                                            ErgoAddrConst.CHECKSUM_BYTE_LEN)
    return addr_with_prefix[:1]


def get_prefix_information(prefix: bytes):
    prefix_mapping = {
        b'\x01': (ErgoAddressTypes.P2PK, ErgoNetworkTypes.MAINNET),
        b'\x02': (ErgoAddressTypes.P2SH, ErgoNetworkTypes.MAINNET),
        b'\x03': (ErgoAddressTypes.P2S, ErgoNetworkTypes.MAINNET),
        b'\x11': (ErgoAddressTypes.P2PK, ErgoNetworkTypes.TESTNET),
        b'\x12': (ErgoAddressTypes.P2SH, ErgoNetworkTypes.TESTNET),
        b'\x13': (ErgoAddressTypes.P2S, ErgoNetworkTypes.TESTNET)
    }
    return prefix_mapping.get(prefix, (None, None))


def isP2PK(addr, net_type: ErgoNetworkTypes = ErgoNetworkTypes.MAINNET):
    address_type = ErgoAddressTypes.P2PK
    prefix = EncodePrefix(address_type, net_type)
    if prefix != get_prefix(addr):
        return False
    return True


def isP2SH(addr, net_type: ErgoNetworkTypes = ErgoNetworkTypes.MAINNET):
    address_type = ErgoAddressTypes.P2SH
    prefix = EncodePrefix(address_type, net_type)
    if prefix != get_prefix(addr):
        return False
    return True


def isP2S(addr, net_type: ErgoNetworkTypes = ErgoNetworkTypes.MAINNET):
    address_type = ErgoAddressTypes.P2S
    prefix = EncodePrefix(address_type, net_type)
    if prefix != get_prefix(addr):
        return False
    return True

# Example usage below


addr_list = ["3WvsT2Gm4EpsM9Pg18PdY6XyhNNMqXDsvJTbbf6ihLvAmSb7u5RN",
             "8UmyuJuQ3FS9ts7j72fn3fKChXSGzbL9WC", "8LnSX95GAWdbDZWJZQ73Uth4uE8HqN3emJ",
             "imdaM2NzX",
             "z4hAmfvfSnQJPChMWzfBzJjpB8ei2HoLCZ2RHTaNArMNHFirdJTc7E",
             "9fRAWhdxEsTcdb8PhGNrZfwqa65zfkuYHAMmkQLcic1gdLSV5vA",
             "25qGdVWg2yyYho8uC1pLtc7KxFn4nEEAwD",
             "23NL9a8ngN28ovtLiKLgHexcdTKBbUMLhH",
             "7bwdkU5V8",
             "BxKBaHkvrTvLZrDcZjcsxsF7aSsrN73ijeFZXtbj4CXZHHcvBtqSxQ"]

for addr in addr_list:

    prefix = get_prefix(addr)
    info = get_prefix_information(prefix)

    for x in info:
        print(x.name)

    print("Is P2PK:", isP2PK(addr, info[1]))
    print("Is P2SH:", isP2SH(addr, info[1]))
    print("Is P2S:", isP2S(addr, info[1]))
