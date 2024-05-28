
# Constantes do AES
Sbox = [
    # Matriz de substituição de bytes (S-box) usada no passo de substituição de bytes
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

Rcon = [
    # Matriz de constantes da rodada (Rcon) usada na expansão da chave
    [0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1b, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00]
]

# Funções auxiliares
def sub_bytes(state):
    # Função de substituição de bytes usando a S-box
    for i in range(4):
        for j in range(4):
            state[i][j] = Sbox[state[i][j] >> 4][state[i][j] & 0x0F]

def shift_rows(state):
    # Função de deslocamento de linhas
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]

def mix_columns(state):
    # Função de mistura de colunas
    for i in range(4):
        a = state[i]
        b = [((x << 1) ^ (0x1B if (x & 0x80) else 0x00)) & 0xFF for x in a]
        state[i][0] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]
        state[i][1] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]
        state[i][2] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]
        state[i][3] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]

def add_round_key(state, key):
    # Função de adição da chave da rodada
    for i in range(4):
        for j in range(4):
            state[i][j] ^= key[i][j]

def key_expansion(key, Nk, Nb, Nr):
    # Função de expansão da chave
    expanded_key = [[0] * 4 for _ in range(Nb * (Nr + 1))]
    for i in range(Nk):
        for j in range(4):
            expanded_key[i][j] = key[i][j]
    for i in range(Nk, Nb * (Nr + 1)):
        temp = expanded_key[i - 1][:]
        if i % Nk == 0:
            temp = sub_word(rot_word(temp))
            for j in range(4):
                temp[j] ^= Rcon[i // Nk][j]
        elif Nk > 6 and i % Nk == 4:
            temp = sub_word(temp)
        for j in range(4):
            expanded_key[i][j] = expanded_key[i - Nk][j] ^ temp[j]
    return expanded_key

def sub_word(word):
    # Função de substituição de palavra usando a S-box
    return [Sbox[b >> 4][b & 0x0F] for b in word]

def rot_word(word):
    # Função de rotação de palavra (circular shift)
    return word[1:] + word[:1]

# Função para encriptar um bloco de 16 bytes
def encrypt_block(block, expanded_key, Nb, Nr):
    # matriz de 4x4
    state = [[0] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            state[j][i] = block[i * 4 + j]
    
    add_round_key(state, expanded_key[:Nb])
    
    for rnd in range(1, Nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, expanded_key[rnd * Nb:(rnd + 1) * Nb])
    
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, expanded_key[Nr * Nb:])
    
    encrypted_block = [0] * 16
    for i in range(4):
        for j in range(4):
            encrypted_block[i * 4 + j] = state[j][i]
    
    return encrypted_block

def encrypt(plaintext, key):
    # Função para encriptar o texto completo
    Nk = len(key) // 4  # Número de colunas da chave (4 para 128 bits, 6 para 192 bits, 8 para 256 bits)
    Nb = 4             # Número de colunas do estado (sempre 4 para AES)
    Nr = {4: 10, 6: 12, 8: 14}[Nk]  # Número de rodadas (10, 12, 14)
    
    # Converter a chave para uma matriz de bytes
    key_matrix = [[ord(key[i * 4 + j]) for j in range(4)] for i in range(Nk)]
    expanded_key = key_expansion(key_matrix, Nk, Nb, Nr)
    
    # Preencher o texto plano para que seja múltiplo de 16 bytes
    padded_plaintext = plaintext + (16 - len(plaintext) % 16) * chr(16 - len(plaintext) % 16)
    blocks = [padded_plaintext[i:i + 16] for i in range(0, len(padded_plaintext), 16)]
    
    encrypted_blocks = []
    for block in blocks:
        block_bytes = [ord(char) for char in block]
        encrypted_block = encrypt_block(block_bytes, expanded_key, Nb, Nr)
        encrypted_blocks.append(''.join([chr(b) for b in encrypted_block]))
    
    return ''.join(encrypted_blocks)

# Exemplo de uso
plaintext = "Texto de exemplo para encriptar usando AES!"

# Chaves válidas para AES
key_128 = "chave_secreta_ae"       # exatamente 16 caracteres
key_192 = "chave_secreta_aes_192!!!"  # exatamente 24 caracteres
key_256 = "chave_secreta_aes_256_bits!!!!!!"  # exatamente 32 caracteres

# Encriptar com AES-128
ciphertext_128 = encrypt(plaintext, key_128)
print(f"Texto Cifrado (AES-128): {ciphertext_128}")

# Encriptar com AES-192
ciphertext_192 = encrypt(plaintext, key_192)
print(f"Texto Cifrado (AES-192): {ciphertext_192}")

# Encriptar com AES-256
ciphertext_256 = encrypt(plaintext, key_256)
print(f"Texto Cifrado (AES-256): {ciphertext_256}")
