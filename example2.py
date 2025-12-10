"""
목적:
    function withdraw(address payable receiver, bytes8 salt, uint64 ethAmount)
    를 호출하기 위한 calldata를 만들고,
    과제 제출 형식에 맞게 3줄을 출력한다.

    1) answer2=<0x로 시작하는 calldata 전체>
    2) w2(<salt>, <receiver>, <amount_wei>)
    3) <preimage hex (0x 없이 소문자)>

핵심 규칙:
- Function selector: keccak256("withdraw(address,bytes8,uint64)")[:4] = 0xb421b368
- ABI 인코딩:
    address  -> 32바이트로 왼쪽 패딩(Left pad)
    bytes8   -> 32바이트로 오른쪽 패딩(Right pad)  # 고정 길이 bytesN은 우측 패딩
    uint64   -> 32바이트로 왼쪽 패딩(Left pad)
- toyhash preimage:
    preimage = salt(8B) || receiver(20B) || amount(8B)  # 0x 없이 hex 이어붙이기 (소문자)

기본값(인자를 생략했을 때 자동 사용):
    receiver = 0xc40ae171869ef802090144bdc4511c6d2855d3f3
    salt     = 0x2942164490202799
    amount   = 1000000000000000  # 0.001 ETH
"""

import argparse
import sys

import toyhash  #toyhash 파일 import

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

    return s[2:] if isinstance(s, str) and s.startswith("0x") else s

#왼쪽 패딩 함수
def leftpad32(hex_no0x: str) -> str:

    return "0" * (64 - len(hex_no0x)) + hex_no0x

#오른쪽 패딩 함수
def rightpad32(hex_no0x: str) -> str:

    return hex_no0x + "0" * (64 - len(hex_no0x))

#withdraw 호출용 calldata 생성 함수
def build_withdraw_calldata(receiver_addr: str, salt_bytes8_hex: str, amount_wei: int) -> str:
    """
    withdraw(address payable receiver, bytes8 salt, uint64 ethAmount)
    의 ABI-인코딩된 calldata를 만든다.
    순서: receiver(address), salt(bytes8), amount(uint64)
    반환: "0x" + 4바이트 셀렉터 + 3개 인자 워드(32바이트 × 3)
    """
    selector = function_selector("withdraw(address,bytes8,uint64)")

    # 주소/솔트/금액을 각각 정확한 길이(20B/8B/8B)의 hex 문자열로 정규화
    # - 모두 소문자로 통일
    addr_20 = strip0x(receiver_addr).lower().rjust(40, "0")       # 20바이트 → 40 hex
    salt_8  = strip0x(salt_bytes8_hex).lower().rjust(16, "0")     #  8바이트 → 16 hex
    amt_8   = format(int(amount_wei), "x").lower().rjust(16, "0") #  8바이트 → 16 hex

    # ABI 인코딩 규칙 적용:
    # - address(고정 20B)와 uint64는 왼쪽 패딩
    # - bytes8(고정 길이 바이트)은 오른쪽 패딩
    word_addr = leftpad32(addr_20)
    word_salt = rightpad32(salt_8)
    word_amt  = leftpad32(amt_8)

    # selector(4바이트) + 각 32바이트 워드들을 이어붙여 최종 calldata 생성
    return selector + word_addr + word_salt + word_amt

def build_toyhash_preimage(salt_hex: str, receiver_addr: str, amount_wei: int) -> str:
    """
    toyhash의 프리이미지를 과제 형식대로 만든다.
    preimage = salt(8B) || receiver(20B) || amount(8B)
    - 0x 접두사 없이
    - 모두 소문자 hex
    """
    salt = strip0x(salt_hex).lower().rjust(16, "0")        # 8바이트 = 16 hex
    addr = strip0x(receiver_addr).lower().rjust(40, "0")   # 20바이트 = 40 hex
    amt  = format(int(amount_wei), "x").lower().rjust(16, "0")  # 8바이트 = 16 hex
    return salt + addr + amt

# ---- CLI 인자 처리 ----
def parse_args_or_defaults():
    """
    --receiver, --salt, --amount-wei를 CLI로 받는다.
    셋 중 하나라도 빠지면 과제의 기본값(Task2 값)으로 자동 대입한다.
    """
    ap = argparse.ArgumentParser(description="Build calldata for withdraw(address,bytes8,uint64) and verify toyhash preimage.")
    ap.add_argument("--receiver", help="0x-prefixed EVM address (receiver)")
    ap.add_argument("--salt", help="0x-prefixed bytes8, e.g., 0x2942164490202799")
    ap.add_argument("--amount-wei", type=int, help="amount in wei (uint64)")
    args = ap.parse_args()

    # 세 값 중 하나라도 없으면 기본값 사용
    use_defaults = not (args.receiver and args.salt and (args.amount_wei is not None))
    if use_defaults:
        print("[info] No/partial CLI args detected. Using Task2 defaults.")
        args.receiver = (args.receiver or "0xc40ae171869ef802090144bdc4511c6d2855d3f3").lower()
        args.salt = (args.salt or "0x2942164490202799").lower()
        args.amount_wei = args.amount_wei if args.amount_wei is not None else 1_000_000_000_000_000
    else:
        # 들어온 값이 있으면 소문자로 정규화
        args.receiver = args.receiver.lower()
        args.salt = args.salt.lower()
    return args

def main():
    # 1) 인자 파싱 및 기본값 보정
    args = parse_args_or_defaults()

    # 2) calldata 및 preimage 생성
    calldata = build_withdraw_calldata(args.receiver, args.salt, args.amount_wei)
    preimage = build_toyhash_preimage(args.salt, args.receiver, args.amount_wei)

    # 3) (선택) toyhash로 해시 검증 시도
    #    - toyhash 구현에 따라 인자로 bytes/str 중 무엇을 기대할지 달라서,
    #      예외 발생 시 메시지만 참고용으로 남긴다.
    try:
        h = toyhash.toyhash(preimage)
    except Exception as e:
        h = f"[toyhash error: {e}]"

    # 4) 과제 제출용 3줄 출력 (자동 채점/복붙 친화적)
    #    a) answer2: 0x + selector + 인자 3개 워드(총 4개 워드)
    print(f"answer2={calldata}")
    #    b) w2: 사람이 보기 쉬운 (salt, receiving address, amount_wei) 튜플 표기
    print(f"w2({args.salt}, {args.receiver}, {args.amount_wei})")
    #    c) preimage: salt||receiver||amount (0x 없이 소문자 hex)
    print(preimage)

    # (참고) 필요시 toyhash 결과를 눈으로 비교하고 싶다면 주석 해제
    # print("toyhash(preimage):", h)

#main 함수 실행
if __name__ == "__main__":
    main()