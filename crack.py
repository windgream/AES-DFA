from AES import KeyExpansion, encrypt, FAULTMAP, SBOX, MULT, MC, INVRcon
from collections import Counter
from tqdm import tqdm
from pwn import xor
import secrets
import random


def gen_cipher(num: int = 10) -> None:
    "随机生成密钥和明文,并注入故障,生成密文数据集"
    key = secrets.token_bytes(16)
    plain = bytearray(secrets.token_bytes(16))
    Roundkey = KeyExpansion(key)

    with open("ciphers.txt", "w") as fault_file:
        cipher = encrypt(plain, Roundkey)  # 正确密文
        fault_file.write(cipher.hex() + "\n")

        for col in range(4):  # 4 列
            for _ in range(num):  # 在每一列随机位置注入故障
                i = col * 4 + random.randint(0, 3)
                value = random.randint(0, 255)
                cipher = encrypt(
                    plain,
                    Roundkey,
                    inject_round=9,
                    inject_index=i,
                    inject_value=value,
                )  # 故障密文
                fault_file.write(cipher.hex() + "\n")

    analysis_file.write(f"Key     {key.hex()}\n")
    analysis_file.write(f"Plain   {plain.hex()}\n")
    analysis_file.write(f"Cipher  {cipher.hex()}\n")


def crack_file(file: str) -> bytearray:
    "读取文件中的数据"
    ref = None
    r9faults = []
    for line in open(file):
        if len(line.split()) == 1:
            o = bytes.fromhex(line.strip())
            assert len(o) == 16
            if ref == None:
                ref = o
            else:
                r9faults.append(o)

    assert ref != None
    # 除去重复的故障密文
    r9faults = [x for i, x in enumerate(r9faults) if r9faults.index(x) == i]
    RoundKey10 = crack_bytes(r9faults, ref)
    RoundKey = ReverseRoundKey(RoundKey10)
    return RoundKey


def check(cipher: bytes, ref: bytes, encrypt: bool = True) -> int | None:
    "根据差分寻找注入错误的位置"
    # cipher: 注入故障的密文,ref: 正确的密文,返回值: 故障注入的列数
    diff = xor(cipher, ref)
    diffmap = [d != 0 for d in diff]

    # 通过密文受影响字节的位置,判断注入错误的位置是在第几列
    if diffmap in FAULTMAP[encrypt]:
        return FAULTMAP[encrypt].index(diffmap)


def get_compat(diff: int, tmult: int, encrypt: bool = True) -> list:
    "取 Z 的候选值范围"
    box = SBOX[not encrypt]

    # 将状态矩阵乘法表逆序
    # 简单来说,列混合操作把 Z 乘了 n,现在要把 Z 除以 n
    INVMULT = [0] * 256
    for i, mi in enumerate(MULT[tmult]):
        INVMULT[mi] = i

    # Z = INVMULT(nz) = INVMULT(S'(diff ^ S(Yi)) ^ Yi)
    # 遍历 S(Yi) 的所有可能取值 0 ~ 255,得到 Z 的所有可能取值的列表
    # candi[i][j] = Z,代表第 i 个关系式中当 S(Yi) 取值为 j 时, Z 的值为 Z
    return [INVMULT[box[S_Yi_ ^ diff] ^ Yi] for S_Yi_, Yi in enumerate(box)]


def get_cands(Diff: list, tmult: list, encrypt: bool = True) -> list:
    "取 (S(Y0), S(Y1), S(Y2), S(Y3)) 的候选值集合"

    # diff 是 4 个差分值, tmult 是差分所在位置在列混合时乘的系数
    # 分别得到在 4 个关系式 Z 的 4 * 255 个候选值列表
    # candi[i][j] = Z,代表第 i 个关系式中当 S(Yi) 取值为 j 时, Z 的值为 Z
    candi = [get_compat(di, ti, encrypt) for di, ti in zip(Diff, tmult)]

    # 对 4 个集合取交集,得到一个 Z 的候选值集合
    Z = set(candi[0]).intersection(*candi[1:])

    # candi[i][j] = (S(Yi), Z)
    # 代表第 i 个关系式中, 当 S(Yi) 取值为 S(Yi) 时, Z = Z
    candi = [[t for t in enumerate(ci) if t[1] in Z] for ci in candi]

    # cands[i] = [{S(Y0)}, {S(Y1)}, {S(Y2)}, {S(Y3)}]
    # 某个 Z 的候选值对应的 (S(Y0), S(Y1), S(Y2), S(Y3)) 的集合
    cands = [[set([j for (j, x) in c if x == z]) for c in candi] for z in Z]
    return cands


def absorb(i: int, cipher: bytes, ref: bytes, candidates: list, encrypt: bool = True)-> None:
    "吸收一组差分"

    # Diff 中存储了 4 个字节的差分 cipher ^ ref
    Diff = [c ^ r for c, r, f in zip(cipher, ref, FAULTMAP[encrypt][i]) if f]

    Cands = []
    mc = MC[encrypt]
    for M in mc:  # 故障注入的行未知, 因此遍历每一种列混合的系数
        Cands += get_cands(Diff, M, encrypt)

    if not candidates[i]:
        candidates[i] = Cands
    else:
        new_candidates = []
        # 对于某个(S(Y0), S(Y1), S(Y2), S(Y3))的候选值集合
        for Y0, Y1, Y2, Y3 in Cands:
            # 对于另一个(S(Y0), S(Y1), S(Y2), S(Y3))的候选值集合
            for _Y0, _Y1, _Y2, _Y3 in candidates[i]:
                # 如果四个 S(Yi) 都有交集
                if Y0 & _Y0 and Y1 & _Y1 and Y2 & _Y2 and Y3 & _Y3:
                    # 取 Cands 和 candidates[i] 的交集
                    new_candidates.append((Y0 & _Y0, Y1 & _Y1, Y2 & _Y2, Y3 & _Y3))

        # 更新 candidates[i]
        if new_candidates != []:
            candidates[i] = new_candidates
        else:
            candidates[i] += Cands


def crack_bytes(r9faults: list, ref: bytes, encrypt: bool = True) -> bytearray:
    "攻击差分字节"
    candidates = [[], [], [], []]  # (S(Y0), S(Y1), S(Y2), S(Y3))的候选列表
    recovered = [False, False, False, False]  # 4 个候选列表是否已经恢复
    RoundKey10 = bytearray(16)  # 用于存储恢复的密钥
    cnt = [0, 0, 0, 0]  # 记录每列的故障密文数目

    for cipher in r9faults:
        i = check(cipher, ref, encrypt)  # 通过密文受影响字节的位置,寻找注入错误的列
        if i is None or recovered[i]:
            continue  # 如果没有找到 i 或者 i 已经被恢复了，那么就跳过

        cnt[i] += 1  # i 列的故障密文数目加 1
        analysis_file.write(f"fault {i} {cipher.hex()}\n")

        absorb(i, cipher, ref, candidates, encrypt)  # 吸收一组差分,更新候选列表

        if (
            len(candidates[i]) == 1
            and len(candidates[i][0][0]) == 1
            and len(candidates[i][0][1]) == 1
            and len(candidates[i][0][2]) == 1
            and len(candidates[i][0][3]) == 1
        ):  # 如果 (S(Y0), S(Y1), S(Y2), S(Y3)) 的候选值只有一个
            # 获取密钥和差分密文所在的字节位置
            index = [k for k, y in zip(range(16), FAULTMAP[encrypt][i]) if y]
            O = [g for g, y in zip(ref, FAULTMAP[encrypt][i]) if y]

            # K_j = S(Y_i) ^ O_j,计算出密钥的字节
            for j in range(4):
                RoundKey10[index[j]] = list(candidates[i][0][j])[0] ^ O[j]

            recovered[i] = True  # 标记 i 已经恢复

        if False not in recovered:
            break  # 如果 4 组密钥字节都已经恢复,则退出

    analysis_file.write(f"fault cnt:{cnt}\n")
    cnt_tumples.append(tuple(cnt))  # 统计本次破解使用的密文数目

    if False in recovered:
        analysis_file.write("crack failed!\n")

    return RoundKey10


def ReverseRoundKey(RoundKey10: bytearray, Nr: int = 10) -> bytearray:
    "逆向还原轮密钥"
    K = bytearray(176)
    t = [0, 0, 0, 0]
    Nk = 4
    Nr *= 4

    K[160:] = RoundKey10
    for i in range(Nk + Nr - 1, Nk - 1, -1):
        for j in range(4):
            t[j] = K[(i - 1) * 4 + j]
        if i % Nk == 0:
            t = [SBOX[1][t[1]], SBOX[1][t[2]], SBOX[1][t[3]], SBOX[1][t[0]]]
            t[0] ^= INVRcon[i // Nk]
        for j in range(4):
            K[(i - Nk) * 4 + j] = K[i * 4 + j] ^ t[j]

    return K

if __name__ == "__main__":
    cnt_tumples = []
    with open("analysis.log", "w", encoding="utf-8") as analysis_file:
        crack_times = 1  # 破解 若干 个不同密文,统计使用的密文数目
        print(f"cracking...")
        for i in tqdm(range(crack_times)):
            analysis_file.write(f"crack {i+1:2}:\n")
            gen_cipher(num=10)  # 生成密文数据集,每列生成 10 个故障密文
            RoundKey = crack_file("ciphers.txt")  # 破解密钥

            analysis_file.write(f"get Key {RoundKey[:16].hex()}\n\n")
        print("done")

    cnt_dict = Counter(cnt_tumples)
    print(cnt_dict)
