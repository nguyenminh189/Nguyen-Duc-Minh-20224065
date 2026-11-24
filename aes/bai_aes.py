# AES-128: bang S-box va hang so Rcon.
S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def make_state(data):
    # AES xep byte theo cot, khong phai theo hang.
    state = []
    for r in range(4):
        state.append([data[4*c + r] for c in range(4)])
    return state


def state_hex(state):
    return ''.join(format(state[r][c], '02X')
                   for c in range(4) for r in range(4))


def print_state(name, state):
    print(name, '=', state_hex(state))
    for row in state:
        print(' '.join(format(x, '02X') for x in row))


def mul(a, b):
    # Nhan trong GF(2^8), modulo 0x11B.
    result = 0
    while b != 0:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return result


def sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = S_BOX[state[r][c]]


def shift_rows(state):
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]


def mix_columns(state):
    for c in range(4):
        a = state[0][c]
        b = state[1][c]
        d = state[2][c]
        e = state[3][c]
        state[0][c] = mul(2, a) ^ mul(3, b) ^ d ^ e
        state[1][c] = a ^ mul(2, b) ^ mul(3, d) ^ e
        state[2][c] = a ^ b ^ mul(2, d) ^ mul(3, e)
        state[3][c] = mul(3, a) ^ b ^ d ^ mul(2, e)


def add_round_key(state, key):
    for r in range(4):
        for c in range(4):
            state[r][c] ^= key[r][c]


def word_hex(word):
    return ''.join(format(x, '02X') for x in word)


def key_expansion(key):
    W = []
    for i in range(4):
        W.append(list(key[4*i:4*i+4]))
        print('W{} = {}'.format(i, word_hex(W[i])))

    for i in range(4, 44):
        temp = W[i-1][:]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            print('RotWord =', word_hex(temp))
            temp = [S_BOX[x] for x in temp]
            print('SubWord =', word_hex(temp))
            rc = RCON[i//4 - 1]
            print('Rcon =', format(rc, '02X') + '000000')
            temp[0] ^= rc
            print('g(W{}) = {}'.format(i-1, word_hex(temp)))
        word = []
        for j in range(4):
            word.append(W[i-4][j] ^ temp[j])
        W.append(word)
        print('W{} = {}'.format(i, word_hex(word)))

    keys = []
    for i in range(11):
        data = W[4*i] + W[4*i+1] + W[4*i+2] + W[4*i+3]
        keys.append(make_state(data))
        print('K{} = {}'.format(i, state_hex(keys[i])))
    return keys


def encrypt(plaintext, key):
    data = bytes.fromhex(plaintext)
    key_data = bytes.fromhex(key)
    if len(data) != 16 or len(key_data) != 16:
        raise ValueError('AES-128 can 16 byte voi P va K')
    state = make_state(data)
    print('Plaintext =', plaintext)
    print('Key =', key)
    keys = key_expansion(key_data)
    print_state('State ban dau', state)
    add_round_key(state, keys[0])
    print_state('AddRoundKey 0', state)

    for i in range(1, 11):
        print('\nVong', i)
        sub_bytes(state)
        print_state('SubBytes', state)
        shift_rows(state)
        print_state('ShiftRows', state)
        if i != 10:
            mix_columns(state)
            print_state('MixColumns', state)
        add_round_key(state, keys[i])
        print_state('AddRoundKey', state)
        if i == 1:
            round1 = state_hex(state)

    ciphertext = state_hex(state)
    print('Ciphertext =', ciphertext)
    return ciphertext, round1, state_hex(keys[1])


if __name__ == '__main__':
    print('AES - Bai tap tuan 11')
    plaintext = '00000000000000000000000000000011'
    key = '00000000000000000000000000000000'
    result, round1, K1 = encrypt(plaintext, key)
    assert K1 == '62636363626363636263636362636363'
    assert round1 == 'E0E138D9010000000100000001000000'
    assert result == '0410BEFCCDE6944B69DD007DEBE39A9D'
    print('Kiem tra tuan 11: Verify')

    print('\nAES - Vector chuan bo sung')
    plaintext = '00112233445566778899AABBCCDDEEFF'
    key = '000102030405060708090A0B0C0D0E0F'
    result, round1, K1 = encrypt(plaintext, key)
    assert result == '69C4E0D86A7B0430D8CDB78070B4C55A'
    assert round1 == '89D810E8855ACE682D1843D8CB128FE4'
    assert K1 == 'D6AA74FDD2AF72FADAA678F1D6AB76FE'
    print('Kiem tra vector chuan: FINISH')
