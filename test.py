from AES import AddRoundKey, KeyExpansion, MixCloumn, ShiftRow, SubBytes
from typing import IO


def encrypt(
    state: bytearray, RoundKey: bytearray, f: IO[str], encrypt: bool = True
) -> bytearray:
    "提供输出的加密/解密函数"
    f.write(f"ENCRYPT\n") if encrypt else f.write(f"DECRYPT\n")
    WriteRoundKey(RoundKey)
    f.write(f"\n")
    f.write(f"Round start:\n")
    f.write(f"state        {state.hex()}\n")
    state = AddRoundKey(state, RoundKey[:16])
    f.write(f"RoundKey 0   {RoundKey[:16].hex()}\n")
    f.write(f"AddRoundKey  {state.hex()}\n\n")
    for i in range(1, 10):
        f.write(f"Round {i}:\n")
        state = SubBytes(state, encrypt)
        f.write(f"SubBytes     {state.hex()}\n")
        state = ShiftRow(state, encrypt)
        f.write(f"ShiftRow     {state.hex()}\n")
        state = MixCloumn(state, encrypt)
        f.write(f"MixCloumn    {state.hex()}\n")
        state = AddRoundKey(state, RoundKey[i * 16 : (i + 1) * 16])
        f.write(f"RoundKey {i}   {RoundKey[i * 16 : (i + 1) * 16].hex()}\n")
        f.write(f"AddRoundKey  {state.hex()}\n\n")
    f.write(f"Round 10:\n")
    state = SubBytes(state, encrypt)
    f.write(f"SubBytes     {state.hex()}\n")
    state = ShiftRow(state, encrypt)
    f.write(f"ShiftRow     {state.hex()}\n")
    state = AddRoundKey(state, RoundKey[160:])
    f.write(f"RoundKey 10  {RoundKey[160:].hex()}\n")
    f.write(f"AddRoundKey  {state.hex()}\n\n\n\n")
    return state


def WriteRoundKey(RoundKey: bytearray, Nr: int = 10):
    "打印轮密钥"
    for i in range(0, (Nr + 1) * 16, 16):  # Nr+1个轮密钥打印
        file.write(f"RoundKey{i//16:<4} {RoundKey[i : i + 16].hex()}\n")


if __name__ == "__main__":
    "使用课本上给出的数据检验 AES-128 算法的正确性"
    key = bytes.fromhex("00012001710198aeda79171460153594")
    plain = bytearray.fromhex("0001000101a198afda78173486153566")

    with open("test.log", "w") as file:
        # 加密
        Roundkey = KeyExpansion(key)
        cipher = encrypt(plain, Roundkey, file)

        # 解密
        invRoundkey = KeyExpansion(key, encrypt=False)
        plain = encrypt(cipher, invRoundkey, file, encrypt=False)

    print("AES-128 算法测试通过")
