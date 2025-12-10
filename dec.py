from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

K1_hex = "a3f19c8d4e6b72f0e2377ecff747b2cd"
K2_hex = "5e8b41c2d9f07a36e2377ecff78e725f"

C2_hex = (
    "f0f1f84d807d9bfdf416a18ac5ab9c3b1a7a06e7b69e020d4"
    "35ac230c6f1695e50dc5a139d217332f270363bdccffe1b"
)

def main():
    try:
        K1 = bytes.fromhex(K1_hex)
        K2 = bytes.fromhex(K2_hex)
        C2 = bytes.fromhex(C2_hex)

        if len(K1) != 16 or len(K2) != 16:
            raise ValueError("K1/K2 길이가 16바이트(128비트)가 아닙니다.")

        # 1 K2로 1차 복호
        inter = AES.new(K2, AES.MODE_ECB).decrypt(C2)
        # 2 K1로 2차 복호
        padded = AES.new(K1, AES.MODE_ECB).decrypt(inter)
        # 3 PKCS#7 패딩 제거
        P2 = unpad(padded, AES.block_size)

        try:
            print("--- 암호문 C2 복호화 성공 ---")
            print("평문 P2:", P2.decode("utf-8"))
        except UnicodeDecodeError:
            print("--- 암호문 C2 복호화 성공(바이너리) ---")
            print("평문 P2 (bytes):", P2)

    except Exception as e:
        print("[!] 복호 중 오류:", e)

if __name__ == "__main__":
    main()