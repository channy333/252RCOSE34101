from Crypto.Hash import keccak
from typing import Union


def subblock(data: Union[bytes, bytearray, str], prev_last_bit: int):
    if isinstance(data, str):
        if len(data) != 14:
            raise ValueError()
        b = bytes.fromhex(data)
    else:
        b = bytes(data)
    if len(b) != 7:
        raise ValueError()
    first_bit = (b[0] >> 7) & 1
    xor_bit = prev_last_bit ^ first_bit
    modified_first_byte = (b[0] & 0x7F) | (xor_bit << 7)
    modified_subblock = bytes([modified_first_byte]) + b[1:]
    digest = keccak.new(digest_bits=256)
    digest.update(modified_subblock)
    digest = digest.hexdigest()
    h = digest[:6]
    last_bit = b[-1] & 1
    return h, last_bit


def block(data: Union[bytes, bytearray, str]):
    if isinstance(data, str):
        if len(data) % 56 != 0:
            raise ValueError()
        b = bytes.fromhex(data)
    else:
        b = bytes(data)
    if len(b) % 28 != 0:
        raise ValueError()

    h = ""
    for offset in range(0, len(b), 28):
        block_data = b[offset : offset + 28]
        subs = [block_data[i : i + 7] for i in range(0, 28, 7)]
        prev_last_bit = subs[-1][-1] & 1
        for sub in subs:
            sub_hash, last_bit = subblock(sub, prev_last_bit)
            prev_last_bit = last_bit
            h += sub_hash
    return h


def toyhash(data: str):
    if len(data) % 56 != 0:
        data = data.ljust(((len(data) // 56) + 1) * 56, "0")
    h = ""
    for i in range(0, len(data), 56):
        block_data = data[i : i + 56]
        h += block(block_data)
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(bytes.fromhex(h))
    return keccak_hash.hexdigest()[:32]


if __name__ == "__main__":
    # example
    # deposit tx hash 0x33892db9cb0d863970da1f749a4f2d3c9c82b8b0a8234690580caa44880e4e34
    # withdraw tx hash 0x3e200260026d943a786976f411d88bf11bb7e3748925eea8c394af378015f7a4
    m = (
        "2942164490202799"  # salt
        + "c40ae171869eF802090144Bdc4511C6D2855D3f3"  # address
        + "00038D7EA4C68000"  # amount of eth (in wei) 0.001 ETH (1000000000000000 wei)
    )
    print(f"Hash of {m}: {toyhash(m)}")
