from PIL import Image
from collections import Counter

INPUT  = "clue.png"
OUTPUT = "keyhint.png"
BLOCK  = 16
OFFSET = 0

def main():
    # 1) PNG → RGB 평탄화
    img = Image.open(INPUT).convert("RGB")
    w, h = img.size
    flat = bytearray()
    for r, g, b in img.getdata():
        flat += bytes((r, g, b))

    # 2) 위상 보정 (R/G/B 어디서 블록이 시작했는지 모름)
    flat = flat[OFFSET:] + flat[:OFFSET]

    # 3) 16바이트 블록 분할
    blocks = [bytes(flat[i:i+BLOCK]) for i in range(0, len(flat), BLOCK)]

    # 4) Counter로 빈도 계산 → 최빈(배경)일수록 더 어둡게 매핑
    cnt = Counter(blocks)
    ranked = [b for b, _ in cnt.most_common()]
    rank = {b: i for i, b in enumerate(ranked)}
    uniq = len(ranked)
    denom = max(1, uniq - 1)

    # 5) 각 블록을 회색 값으로 치환: rank 0(최빈)=검정, 희귀할수록 밝게
    out = bytearray(len(flat))
    pos = 0
    for blk in blocks:
        r = rank[blk]
        g = int(10 if r == 0 else 20 + 230 * (r / denom))
        L = min(BLOCK, len(flat) - pos)
        out[pos:pos+L] = bytes([g]) * L
        pos += L

    # 6) 다시 RGB 이미지 복원 (회색이므로 R=G=B)
    vis = Image.new("RGB", (w, h))
    i = 0
    for y in range(h):
        for x in range(w):
            r = out[i] if i < len(out) else 0; i += 1
            g = out[i] if i < len(out) else 0; i += 1
            b = out[i] if i < len(out) else 0; i += 1
            vis.putpixel((x, y), (r, g, b))

    vis.save(OUTPUT)
    print(f"[OK] saved {OUTPUT}  (offset={OFFSET}, unique_blocks={uniq})")

if __name__ == "__main__":
    main()
