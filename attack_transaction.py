#d2 preimage 값
RECEIVER = "0xc40ae171869eF802090144Bdc4511C6D2855D3f3"
SALT     = "0x2942164490202799"
AMOUNT   = 1_000_000_000_000_000  #0.001 ETH

#keccak 해시값 계산 (pycryptodome 또는 pysha3 중 가능한 것을 사용)
def keccak256_bytes(data: bytes) -> bytes:

    try:
        from Crypto.Hash import keccak
        k = keccak.new(digest_bits=256) #keccak 해시 생성
        k.update(data)
        return k.digest()
    except Exception:
        import sha3 
        k = sha3.keccak_256()
        k.update(data)
        return k.digest()

#function selector 계산
def function_selector(signature: str) -> str:

    return "0x" + keccak256_bytes(signature.encode())[:4].hex()

#0x 제거 함수
def strip0x(s: str) -> str:

    return s[2:] if s.startswith("0x") else s

#왼쪽 패딩 함수
def leftpad32(h: str) -> str:

    return "0" * (64 - len(h)) + h

#오른쪽 패딩 함수
def rightpad32(h: str) -> str:

    return h + "0" * (64 - len(h))

#withdraw 호출용 calldata 생성 함수
def build_withdraw_calldata(receiver_addr: str, salt_bytes8_hex: str, amount_wei: int) -> str:

    #function selector 계산
    selector = function_selector("withdraw(address,bytes8,uint64)")

    #address / salt / ETH amount를 각각 정확한 길이(20B/8B/8B)의 hex 문자열로 정규화
    addr_20 = strip0x(receiver_addr).lower().rjust(40, "0")        #20B = 40 hex
    salt_8  = strip0x(salt_bytes8_hex).lower().rjust(16, "0")      #8B = 16 hex
    amt_8   = format(int(amount_wei), "x").lower().rjust(16, "0")  #8B = 16 hex

    #ABI 인코딩 규칙 적용
    #address(고정 20B)와 uint64는 왼쪽 패딩
    #bytes8(고정 길이 바이트)은 오른쪽 패딩
    word_addr = leftpad32(addr_20)   #address → 왼쪽 패딩
    word_salt = rightpad32(salt_8)   #bytes8  → 오른쪽 패딩
    word_amt  = leftpad32(amt_8)     #uint64  → 왼쪽 패딩

    #selector(4바이트) + 각 32바이트 워드들을 이어붙여 최종 calldata 생성
    return selector + word_addr + word_salt + word_amt

#toyhash preimage 생성 함수
def build_toyhash_preimage(salt_hex: str, receiver_addr: str, amount_wei: int) -> str:

    salt = strip0x(salt_hex).lower().rjust(16, "0")        #8B
    addr = strip0x(receiver_addr).lower().rjust(40, "0")   #20B
    amt  = format(int(amount_wei), "x").lower().rjust(16, "0")  #8B
    return salt + addr + amt

def main():
    calldata = build_withdraw_calldata(RECEIVER, SALT, AMOUNT)
    preimage = build_toyhash_preimage(SALT, RECEIVER, AMOUNT)

    #w2 출력
    print(f"calldata={calldata}")
    print(f"w2({SALT.lower()}, {RECEIVER.lower()}, {AMOUNT})")
    print(preimage)

#main 함수 실행
if __name__ == "__main__":
    main()