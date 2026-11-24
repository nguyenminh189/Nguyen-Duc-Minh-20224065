from bai_des import IP, E, P


def permute(bits, table):
    result = []
    for i in table:
        result.append(bits[i - 1])
    return result


def print_table(name, bits, columns):
    print(name)
    for i in range(0, len(bits), columns):
        print(' '.join(bits[i:i + columns]))
    print()


if __name__ == '__main__':
    bits = ['b' + str(i) for i in range(64)]
    block = permute(bits, IP)
    L = block[:32]
    R = block[32:]
    print_table('IP', block, 8)
    print_table('E(L0) - bai viet tay', permute(L, E), 6)
    print_table('E(R0) - vong 1 DES', permute(R, E), 6)

    # s0...s31 la 32 bit dau ra S-box, khong phai ban ro.
    S = ['s' + str(i) for i in range(32)]
    output = permute(S, P)
    print_table('P(S)', output, 8)

    assert len(set(block)) == 64
    assert len(permute(R, E)) == 48
    assert len(set(output)) == 32
    print('Kiem tra kich thuoc va hoan vi: OK')
