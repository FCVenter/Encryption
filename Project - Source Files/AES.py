class AES:

    def __init__(self, key):
        self.key = key
        self.round_constants = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
        self.BLOCK_SIZE = 16

    def encrypt(self, plaintext):
        """
        Encrypt the plaintext using AES encryption.
        """
        # Pad the plaintext
        plaintext = self.pad(plaintext)

        # Perform key expansion to generate round keys
        round_keys = self.key_expansion(self.key)

        # Break the plaintext into blocks
        blocks = [plaintext[i: i + self.BLOCK_SIZE] for i in range(0, len(plaintext), self.BLOCK_SIZE)]

        ciphertext_blocks = []

        # Encrypt each block
        for block in blocks:
            # Convert the block to a state matrix
            state = self.bytes_to_matrix(block)

            # Initial round key addition
            state = self.add_round_key(state, round_keys[:4])

            # Perform multiple rounds of encryption
            for i in range(1, 10):
                state = self.aes_round(state, round_keys[i * 4: (i + 1) * 4])

            # Perform the final round of encryption
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            state = self.add_round_key(state, round_keys[40:])

            # Convert the state matrix back to bytes and add it to the list of ciphertext blocks
            ciphertext_blocks.append(self.matrix_to_bytes(state))

        # Combine the ciphertext blocks into one byte string
        ciphertext = b''.join(ciphertext_blocks)

        return ciphertext

    def decrypt(self, ciphertext):
        """
        Decrypt the ciphertext using AES decryption.
        """
        # Perform key expansion to generate round keys
        round_keys = self.key_expansion(self.key)

        # Break the ciphertext into blocks
        blocks = [ciphertext[i: i + self.BLOCK_SIZE] for i in range(0, len(ciphertext), self.BLOCK_SIZE)]

        plaintext_blocks = []

        # Decrypt each block
        for block in blocks:
            # Convert the block to a state matrix
            state = self.bytes_to_matrix(block)

            # Initial round key addition
            state = self.add_round_key(state, round_keys[40:])

            # Perform multiple rounds of decryption
            for i in range(9, 0, -1):
                state = self.inv_shift_rows(state)
                state = self.inv_sub_bytes(state)
                state = self.add_round_key(state, round_keys[i * 4: (i + 1) * 4])
                state = self.inv_mix_columns(state)

            # Perform the final round of decryption
            state = self.inv_shift_rows(state)
            state = self.inv_sub_bytes(state)
            state = self.add_round_key(state, round_keys[:4])

            # Convert the state matrix back to bytes and add it to the list of plaintext blocks
            plaintext_blocks.append(self.matrix_to_bytes(state))

        # Combine the plaintext blocks into one byte string and remove the padding
        plaintext = self.unpad(b''.join(plaintext_blocks))

        return plaintext

    # AES supports key sizes of 16, 24, and 32 bytes
    # For simplicity, we'll only support a single key size
    KEY_SIZE = 16  # 16 bytes = 128 bits


    def sub_word(self, word):
        """
        Substitute each byte in a 4-byte word with a byte from the S-Box.
        """
        return [self.S_BOX[byte // 16][byte % 16] for byte in word]

    def rot_word(self, word):
        """
        Rotate the bytes in a 4-byte word to the left.
        """
        return word[1:] + [word[0]]

    # The S-Box used in the SubBytes step of AES. It's a 16x16 matrix representing all possible
    # values of a byte. The S-box was carefully designed to have certain mathematical properties
    # that help protect against linear and differential cryptanalysis.

    S_BOX = [
        # Each row represents a hexadecimal digit. For example, the first row represents
        # the possible bytes with the first hexadecimal digit being 0.
        # Each element in a row represents a possible second hexadecimal digit.
        # Therefore, the index of an element in this matrix corresponds to a byte value,
        # and the value of the element is the byte value after substitution.
        # The S-Box and Inverse S-Box used for the SubBytes and InvSubBytes steps

        [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
        [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
        [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
        [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
        [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
        [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
        [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
        [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
        [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
        [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
        [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
        [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
        [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
        [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
        [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
        [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
    ]


    # The Inverse S-Box used in the InvSubBytes step of AES. It's the inverse of the S-box,
    # meaning that it undoes the substitution of the SubBytes step.

    INV_S_BOX = [
        # Each row and element in a row is indexed in the same way as the S-box.
        # Therefore, the index of an element in this matrix corresponds to a substituted byte value,
        # and the value of the element is the original byte value before substitution.
        [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
        [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
        [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
        [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
        [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
        [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
        [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
        [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
        [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
        [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
        [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
        [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
        [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
        [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
        [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
        [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
        # ... 14 more rows
    ]

    # The MixColumns step in AES is a transformation that provides diffusion in the cipher.
    # The state matrix is multiplied by a fixed matrix in the finite field GF(2^8).
    # This operation works by replacing each byte of a column with a new byte that is a
    # function of all four bytes in the column. The multiplication operation is carried out in
    # the finite field GF(2^8) using a special `multiply` function.

    MIX_COLUMNS_MATRIX = [
        # Each number in the matrix corresponds to the coefficient of the byte at that position
        # in the column in the resulting linear combination.
        # The bytes are treated as coefficients of a polynomial over GF(2^8).

        # The polynomial represented by this row is: 2*x^3 + 3*x^2 + x + 1
        [0x02, 0x03, 0x01, 0x01],

        # The polynomial represented by this row is: x^3 + 2*x^2 + 3*x + 1
        [0x01, 0x02, 0x03, 0x01],

        # The polynomial represented by this row is: x^3 + x^2 + 2*x + 3
        [0x01, 0x01, 0x02, 0x03],

        # The polynomial represented by this row is: 3*x^3 + x^2 + x + 2
        [0x03, 0x01, 0x01, 0x02]
    ]

    # The inverse MixColumns step reverses the MixColumns operation by multiplying the state matrix by another fixed matrix.
    # This is possible because the MixColumns operation is invertible.

    INV_MIX_COLUMNS_MATRIX = [
        # Each number in the matrix corresponds to the coefficient of the byte at that position
        # in the column in the resulting linear combination.
        # The bytes are treated as coefficients of a polynomial over GF(2^8).

        # The polynomial represented by this row is: 14*x^3 + 11*x^2 + 13*x + 9
        [0x0e, 0x0b, 0x0d, 0x09],

        # The polynomial represented by this row is: 9*x^3 + 14*x^2 + 11*x + 13
        [0x09, 0x0e, 0x0b, 0x0d],

        # The polynomial represented by this row is: 13*x^3 + 9*x^2 + 14*x + 11
        [0x0d, 0x09, 0x0e, 0x0b],

        # The polynomial represented by this row is: 11*x^3 + 13*x^2 + 9*x + 14
        [0x0b, 0x0d, 0x09, 0x0e]
    ]

    def multiply(self, x, y):
        """
        Multiply two numbers in the GF(2^8) finite field defined
        by the irreducible polynomial x^8 + x^4 + x^3 + x + 1 = 0
        which is represented in hexadecimal form as 0x1b.
        """

        # Initialize multiplication result to 0
        multiplication = 0

        # We'll perform the multiplication bit by bit
        for i in range(8):

            # If the current bit of y is set, add the current value of x to the result
            if y & 1:
                multiplication ^= x

            # Check if the highest bit of x is set (this will determine whether to apply the modulo operation below)
            highest_bit_set = x & 0x80

            # Shift x one bit to the left, doubling its value
            x <<= 1

            # If the highest bit of the original x was set, reduce x modulo the irreducible polynomial (0x1b)
            if highest_bit_set:
                x ^= 0x1b

            # Shift y one bit to the right, effectively dividing it by 2
            y >>= 1

        # Return the result, truncated to 8 bits to ensure it fits into a single byte
        return multiplication & 0xff

    def sub_bytes(self, state):
        # Substitute each byte in the state for a byte in the S-Box
        for i in range(4):
            for j in range(4):
                byte = state[i][j]
                state[i][j] = self.S_BOX[byte // 16][byte % 16]
        return state


    def shift_rows(self, state):
        # Shift each row in the state to the left by an offset
        for i in range(4):
            state[i] = state[i][i:] + state[i][:i]
        return state

    def mix_columns(self, state):
        # Multiply the state matrix with the MixColumns matrix
        new_state = []
        for i in range(4):
            new_state.append([])
            for j in range(4):
                new_state[i].append(0)
                for k in range(4):
                    new_state[i][j] ^= self.multiply(state[k][j], self.MIX_COLUMNS_MATRIX[i][k])
        return new_state

    def add_round_key(self, state, round_key):
        # XOR the state with the round key
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i][j]
        return state

    def aes_round(self, state, round_key):
        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.mix_columns(state)
        state = self.add_round_key(state, round_key)
        return state

    def key_expansion(self, key):
        """
        Expand the initial key into a set of round keys for each round of encryption/decryption.
        """
        expanded_key = [key[i:i + 4] for i in range(0, len(key), 4)]
        while len(expanded_key) < 44:
            temp = list(expanded_key[-1])
            if len(expanded_key) % 4 == 0:
                temp = self.sub_word(self.rot_word(temp))
                temp[0] ^= self.round_constants[len(expanded_key) // 4 - 1]
            elif len(expanded_key) % 4 == 4 and len(key) == 32:
                temp = self.sub_word(temp)
            temp = [temp[i] ^ expanded_key[-4][i] for i in range(4)]
            expanded_key.append(bytes(temp))
        return expanded_key

    def inv_sub_bytes(self, state):
        """
        Substitute each byte in the state with a byte from the inverse S-Box.
        """
        for i in range(4):
            for j in range(4):
                byte = state[i][j]
                state[i][j] = self.INV_S_BOX[byte // 16][byte % 16]
        return state

    def inv_shift_rows(self, state):
        """
        Shift each row in the state to the right by an offset.
        """
        for i in range(4):
            state[i] = state[i][-i:] + state[i][:-i]
        return state

    def inv_mix_columns(self, state):
        """
        Multiply the state matrix with the inverse MixColumns matrix.
        """
        new_state = []
        for i in range(4):
            new_state.append([])
            for j in range(4):
                new_state[i].append(0)
                for k in range(4):
                    new_state[i][j] ^= self.multiply(state[k][j], self.INV_MIX_COLUMNS_MATRIX[i][k])
        return new_state

    def aes_final_round(self, state, round_key):
        """
        Perform the final round of AES encryption/decryption.
        """
        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)
        state = self.add_round_key(state, round_key)
        return state

    def pad(self, plaintext):
        """
        Pad the plaintext to ensure its length is a multiple of the block size.
        """
        padding_length = self.BLOCK_SIZE - (len(plaintext) % self.BLOCK_SIZE)
        padding = bytes([padding_length] * padding_length)
        return plaintext + padding

    def bytes_to_matrix(self, data):
        """
        Convert a byte array to a 4x4 matrix.
        """
        matrix = [[0] * 4 for _ in range(4)]
        for i in range(4):
            for j in range(4):
                matrix[j][i] = data[i * 4 + j]
        return matrix

    def matrix_to_bytes(self, matrix):
        """
        Convert a 4x4 matrix to a byte array.
        """
        data = []
        for i in range(4):
            for j in range(4):
                data.append(matrix[j][i])
        return bytes(data)

    def unpad(self, data):
        """
        Remove the padding from the data.
        """
        padding_length = data[-1]
        return data[:-padding_length]
