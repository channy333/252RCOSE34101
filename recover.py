from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from binascii import unhexlify
try:
    from tqdm import tqdm
except Exception:
    tqdm = lambda x, **k: x

P_PAIR = b"This is a top secret message. Do not share it with anyone!"
C_PAIR_HEX = (
    "3e40001d1bc6d179551288606d9404914c002383a158dbc45748957"
    "a845b3195eaf9ac3f1e34dc2ef8888c70399ec0acbed366b8e1fcc8"
    "b501f5763fe91862a3"
)
C_PAIR = unhexlify(C_PAIR_HEX)
aP_hex = "a3f19c8d4e6b72f0"
a3_hex = "5e8b41c2d9f07a36"

k_hex  = "e2377ecff7"

BLOCK = 16
PREFIX_LEN = 8

def build_left_table(k_hex: str):
    """
    좌측(M1): 모든 X(3B)에 대해 M = E_{K1}(pad(P)[0]) 계산
      K1 = aP || k || X
    prefix 8바이트로 버킷화하여 메모리 절약.
    """
    aP = bytes.fromhex(aP_hex)
    k  = bytes.fromhex(k_hex)
    P0 = pad(P_PAIR, BLOCK)[:BLOCK]
    table = {}
    for x in tqdm(range(1 << 24), desc=f"[{k_hex}] Build left (X)"):
        X  = x.to_bytes(3, "big")
        K1 = aP + k + X
        mid = AES.new(K1, AES.MODE_ECB).encrypt(P0)
        key = mid[:PREFIX_LEN]
        bucket = table.get(key)
        if bucket is None:
            table[key] = [(mid, X)]
        else:
            bucket.append((mid, X))
    return table

def search_right_and_verify(k_hex: str, table):
    """
    우측(M2): 모든 Y(3B)에 대해 M' = D_{K2}(C0) 계산
      K2 = a3 || k || Y
    버킷으로 후보 매칭 후, 전체 C_PAIR로 재검증하여 진짜 키만 반환.
    """
    a3 = bytes.fromhex(a3_hex)
    k  = bytes.fromhex(k_hex)
    P_pad = pad(P_PAIR, BLOCK)
    C0    = C_PAIR[:BLOCK]

    for y in tqdm(range(1 << 24), desc=f"[{k_hex}] Search right (Y)"):
        Y  = y.to_bytes(3, "big")
        K2 = a3 + k + Y
        m2 = AES.new(K2, AES.MODE_ECB).decrypt(C0)

        bucket = table.get(m2[:PREFIX_LEN])
        if not bucket:
            continue

        # 버킷 내 full mid 일치 항목만 전체 검증
        for mid_full, X in bucket:
            if mid_full != m2:
                continue
            K1 = bytes.fromhex(aP_hex) + bytes.fromhex(k_hex) + X
            Ctest = AES.new(K2, AES.MODE_ECB).encrypt(
                        AES.new(K1, AES.MODE_ECB).encrypt(P_pad)
                    )
            if Ctest == C_PAIR:
                return K1, K2, X, Y
    return None

if __name__ == "__main__":
    print(f"[+] MITM attack start (k={k_hex})")

    left = build_left_table(k_hex)
    hit  = search_right_and_verify(k_hex, left)

    if not hit:
        print("[-] No matching key pair found.")
    else:
        K1, K2, X, Y = hit
        aC = bytes.fromhex(k_hex) + X
        a4 = bytes.fromhex(k_hex) + Y
        print("\n[+] KEY FOUND")
        print(f" aC = {aC.hex()}")
        print(f" a4 = {a4.hex()}")
        print(f" K1 = {K1.hex()}")
        print(f" K2 = {K2.hex()}")
