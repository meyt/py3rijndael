import copy
from py3rijndael.constants import (
    shifts, r_con, num_rounds, S, Si,
    U1, U2, U3, U4,
    T1, T2, T3, T4, T5, T6, T7, T8
)


class Rijndael:

    def __init__(self, key, block_size: int = 16):

        if block_size not in (16, 24, 32):
            raise ValueError('Invalid block size: %s' % str(block_size))

        if len(key) not in (16, 24, 32):
            raise ValueError('Invalid key size: %s' % str(len(key)))

        self.block_size = block_size

        rounds = num_rounds[len(key)][block_size]
        b_c = block_size // 4
        # encryption round keys
        k_e = [[0] * b_c for _ in range(rounds + 1)]
        # decryption round keys
        k_d = [[0] * b_c for _ in range(rounds + 1)]
        round_key_count = (rounds + 1) * b_c
        k_c = len(key) // 4

        # copy user material bytes into temporary ints
        tk = []
        for i in range(0, k_c):
            tk.append((ord(key[i * 4:i * 4 + 1]) << 24) | (ord(key[i * 4 + 1:i * 4 + 1 + 1]) << 16) |
                      (ord(key[i * 4 + 2: i * 4 + 2 + 1]) << 8) | ord(key[i * 4 + 3:i * 4 + 3 + 1]))

        # copy values into round key arrays
        t = 0
        j = 0
        while j < k_c and t < round_key_count:
            k_e[t // b_c][t % b_c] = tk[j]
            k_d[rounds - (t // b_c)][t % b_c] = tk[j]
            j += 1
            t += 1
        r_con_pointer = 0
        while t < round_key_count:
            # extrapolate using phi (the round key evolution function)
            tt = tk[k_c - 1]
            tk[0] ^= (S[(tt >> 16) & 0xFF] & 0xFF) << 24 ^ \
                     (S[(tt >> 8) & 0xFF] & 0xFF) << 16 ^ \
                     (S[tt & 0xFF] & 0xFF) << 8 ^ \
                     (S[(tt >> 24) & 0xFF] & 0xFF) ^ \
                     (r_con[r_con_pointer] & 0xFF) << 24
            r_con_pointer += 1
            if k_c != 8:
                for i in range(1, k_c):
                    tk[i] ^= tk[i - 1]
            else:
                for i in range(1, k_c // 2):
                    tk[i] ^= tk[i - 1]
                tt = tk[k_c // 2 - 1]
                tk[k_c // 2] ^= (S[tt & 0xFF] & 0xFF) ^ \
                                (S[(tt >> 8) & 0xFF] & 0xFF) << 8 ^ \
                                (S[(tt >> 16) & 0xFF] & 0xFF) << 16 ^ \
                                (S[(tt >> 24) & 0xFF] & 0xFF) << 24
                for i in range(k_c // 2 + 1, k_c):
                    tk[i] ^= tk[i - 1]
            # copy values into round key arrays
            j = 0
            while j < k_c and t < round_key_count:
                k_e[t // b_c][t % b_c] = tk[j]
                k_d[rounds - (t // b_c)][t % b_c] = tk[j]
                j += 1
                t += 1
        # inverse MixColumn where needed
        for r in range(1, rounds):
            for j in range(b_c):
                tt = k_d[r][j]
                k_d[r][j] = (
                    U1[(tt >> 24) & 0xFF] ^
                    U2[(tt >> 16) & 0xFF] ^
                    U3[(tt >> 8) & 0xFF] ^
                    U4[tt & 0xFF]
                )
        self.Ke = k_e
        self.Kd = k_d

    def encrypt(self, plaintext):
        if len(plaintext) != self.block_size:
            raise ValueError('wrong block length, expected ' + str(self.block_size) + ' got ' + str(len(plaintext)))
        k_e = self.Ke

        b_c = self.block_size // 4
        rounds = len(k_e) - 1
        if b_c == 4:
            s_c = 0
        elif b_c == 6:
            s_c = 1
        else:
            s_c = 2
        s1 = shifts[s_c][1][0]
        s2 = shifts[s_c][2][0]
        s3 = shifts[s_c][3][0]
        a = [0] * b_c
        # temporary work array
        t = []
        # plaintext to ints + key
        for i in range(b_c):
            t.append((ord(plaintext[i * 4]) << 24 |
                      ord(plaintext[i * 4 + 1]) << 16 |
                      ord(plaintext[i * 4 + 2]) << 8 |
                      ord(plaintext[i * 4 + 3])) ^ k_e[0][i])
        # apply round transforms
        for r in range(1, rounds):
            for i in range(b_c):
                a[i] = (T1[(t[i] >> 24) & 0xFF] ^
                        T2[(t[(i + s1) % b_c] >> 16) & 0xFF] ^
                        T3[(t[(i + s2) % b_c] >> 8) & 0xFF] ^
                        T4[t[(i + s3) % b_c] & 0xFF]) ^ k_e[r][i]
            t = copy.copy(a)
        # last round is special
        result = []
        for i in range(b_c):
            tt = k_e[rounds][i]
            result.append((S[(t[i] >> 24) & 0xFF] ^ (tt >> 24)) & 0xFF)
            result.append((S[(t[(i + s1) % b_c] >> 16) & 0xFF] ^ (tt >> 16)) & 0xFF)
            result.append((S[(t[(i + s2) % b_c] >> 8) & 0xFF] ^ (tt >> 8)) & 0xFF)
            result.append((S[t[(i + s3) % b_c] & 0xFF] ^ tt) & 0xFF)
        out = bytes()
        for xx in result:
            out += bytes([xx])
        return out

    def decrypt(self, cipher_text):
        if len(cipher_text) != self.block_size:
            raise ValueError(
                'wrong block length, expected %s got %s' % (
                    str(self.block_size),
                    str(len(cipher_text))
                )
            )

        k_d = self.Kd
        b_c = self.block_size // 4
        rounds = len(k_d) - 1
        if b_c == 4:
            s_c = 0
        elif b_c == 6:
            s_c = 1
        else:
            s_c = 2
        s1 = shifts[s_c][1][1]
        s2 = shifts[s_c][2][1]
        s3 = shifts[s_c][3][1]
        a = [0] * b_c
        # temporary work array
        t = [0] * b_c
        # cipher_text to ints + key
        for i in range(b_c):
            t[i] = (ord(cipher_text[i * 4: i * 4 + 1]) << 24 |
                    ord(cipher_text[i * 4 + 1: i * 4 + 1 + 1]) << 16 |
                    ord(cipher_text[i * 4 + 2: i * 4 + 2 + 1]) << 8 |
                    ord(cipher_text[i * 4 + 3: i * 4 + 3 + 1])) ^ k_d[0][i]
        # apply round transforms
        for r in range(1, rounds):
            for i in range(b_c):
                a[i] = (T5[(t[i] >> 24) & 0xFF] ^
                        T6[(t[(i + s1) % b_c] >> 16) & 0xFF] ^
                        T7[(t[(i + s2) % b_c] >> 8) & 0xFF] ^
                        T8[t[(i + s3) % b_c] & 0xFF]) ^ k_d[r][i]
            t = copy.copy(a)
        # last round is special
        result = []
        for i in range(b_c):
            tt = k_d[rounds][i]
            result.append((Si[(t[i] >> 24) & 0xFF] ^ (tt >> 24)) & 0xFF)
            result.append((Si[(t[(i + s1) % b_c] >> 16) & 0xFF] ^ (tt >> 16)) & 0xFF)
            result.append((Si[(t[(i + s2) % b_c] >> 8) & 0xFF] ^ (tt >> 8)) & 0xFF)
            result.append((Si[t[(i + s3) % b_c] & 0xFF] ^ tt) & 0xFF)
        return ''.join(map(chr, result))
