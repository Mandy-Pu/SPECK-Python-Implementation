def CicShiftRight(x, shift, wordSize):
    mask = (2 ** wordSize) - 1
    x = ((x >> shift) | (x << (wordSize - shift))) & mask
    return x

def CicShiftLeft(x, shift, wordSize):
    mask = (2 ** wordSize) - 1
    x = ((x << shift) | (x >> (wordSize - shift))) & mask
    return x

def keyInit(key, keySize, wordSize, Rounds):
    mask = (2 ** wordSize) - 1
    keyWord = keySize//wordSize
    l_key = [(key >> (x * wordSize)) & mask for x in range(1, keyWord)]
    roundKeys = [key & mask]

    for i in range(Rounds - 1):
        temp_l_key = RoundFunction(l_key[i], roundKeys[i], i, wordSize)
        l_key.append(temp_l_key[0])
        roundKeys.append(temp_l_key[1])

    return roundKeys

def RoundFunction(x,y,k, wordSize):
    mask = (2 ** wordSize) - 1
    
    if (wordSize == 16):
        alpha = 7
        beta = 2
    else:
        alpha = 8 
        beta = 3    

    x = CicShiftRight(x,alpha, wordSize)
    x = (x+y) & mask
    x = x ^ k

    y = CicShiftLeft(y,beta, wordSize)
    y = y ^ x   

    return x,y

def InvRoundFunction(x,y,k, wordSize):
    mask = (2 ** wordSize) 
    
    xor_xy = x ^ y
    y = CicShiftRight(xor_xy,3, wordSize)

    xor_xk = x ^ k
    msub = ((xor_xk - y) + mask) % mask
    x = CicShiftLeft(msub,8, wordSize) 

    return x,y

def Encrypt(PT, Key, wordSize, keySize):
    Parameters = {32: {64: 22}, 48: {72: 22, 96: 23},64: {96: 26, 128: 27},96: {96: 28, 144: 29},128: {128: 32, 192: 33, 256: 34}}
    Rounds = Parameters[2*wordSize][keySize]
 
    mask = (2 ** wordSize) - 1
    x = (PT >> wordSize) & mask
    y = PT & mask
   
    roundKeys = keyInit(Key, keySize, wordSize, Rounds)
    for i in range (Rounds):
        x,y = RoundFunction(x,y,roundKeys[i], wordSize)
        
    CT = (x << wordSize) + y
    return CT

def Decrypt(CT, Key, wordSize, keySize):
    Parameters = {32: {64: 22}, 48: {72: 22, 96: 23},64: {96: 26, 128: 27},96: {96: 28, 144: 29},128: {128: 32, 192: 33, 256: 34}}
    Rounds = Parameters[2*wordSize][keySize]

    mask = (2 ** wordSize) - 1
    x = (CT >> wordSize) & mask
    y = CT & mask
   
    roundKeys = keyInit(Key, keySize, wordSize, Rounds)

    for k in reversed(roundKeys): 
        x,y = InvRoundFunction(x,y,k, wordSize)

    PT = (x << wordSize) + y
    return PT


##################### SPECK 32/64 #####################
# key_64 = 0x1918111009080100
# pt_32 = 0x6574694c

# mySpeck = SpeckCipher(key_64, key_size=64, block_size=32)
# my_plaintext = pt_32
# speck_ciphertext = mySpeck.encrypt(my_plaintext)
# print(speck_ciphertext)

# ct = Encrypt(pt_32, key_64, 16, 64)
# print(ct)
# pt = Decrypt(ct,key_64, 16, 64)
# print(pt)

##################### SPECK 48/72 #####################
# key_72 = 0x1211100a0908020100
# pt_48 = 0x20796c6c6172

# mySpeck = SpeckCipher(key_72, key_size=72, block_size=48)
# my_plaintext = pt_48
# speck_ciphertext = mySpeck.encrypt(my_plaintext)
# print(speck_ciphertext)

# ct = Encrypt(pt_48, key_72, 48/2, 72)
# print(ct)
# pt = Decrypt(ct, key_72, 48/2, 72)
# print(pt)

##################### SPECK 48/96 #####################
# key_96 = 0x1a19181211100a0908020100
# pt_48 = 0x6d2073696874

# mySpeck = SpeckCipher(key_96, key_size=96, block_size=48)
# my_plaintext = pt_48
# speck_ciphertext = mySpeck.encrypt(my_plaintext)
# print(speck_ciphertext)

# ct = Encrypt(pt_48, key_96, 48/2, 96)
# print(ct)
# pt = Decrypt(ct, key_96, 48/2, 96)
# print(pt)

##################### SPECK 64/96 #####################
# key_96 = 0x131211100b0a090803020100
# pt_64 = 0x9f7952ec4175946c

# mySpeck = SpeckCipher(key_96, key_size=96, block_size=64)
# my_plaintext = pt_64
# speck_ciphertext = mySpeck.encrypt(my_plaintext)
# print(speck_ciphertext)

# ct = Encrypt(pt_64, key_96, 32, 96)
# print(ct)
# pt = Decrypt(ct, key_96, 32, 96)
# print(pt)

##################### SPECK 64/128 #####################
# key_128 = 0x1b1a1918131211100b0a090803020100
# pt_64 = 0x3b7265747475432d

# mySpeck = SpeckCipher(key_128, key_size=128, block_size=64)
# my_plaintext = pt_64
# speck_ciphertext = mySpeck.encrypt(my_plaintext)
# print(speck_ciphertext)

# ct = Encrypt(pt_64, key_128, 32, 128)
# print(ct)
# pt = Decrypt(ct, key_128, 32, 128)
# print(pt)

##################### SPECK 96/96 #####################
# key_96= 0x0d0c0b0a0908050403020100
# pt_96 = 0x65776f68202c656761737520

# mySpeck = SpeckCipher(key_96, key_size=96, block_size=96)
# my_plaintext = pt_96
# speck_ciphertext = mySpeck.encrypt(my_plaintext)
# print(speck_ciphertext)

# ct = Encrypt(pt_96, key_96, 96/2, 96)
# print(ct)
# pt = Decrypt(ct, key_96, 96/2, 96)
# print(pt)

##################### SPECK 96/144 #####################
# key_144 = 0x1514131211100d0c0b0a0908050403020100
# pt_96 = 0x656d6974206e69202c726576

# mySpeck = SpeckCipher(key_144, key_size=144, block_size=96)
# my_plaintext = pt_96
# speck_ciphertext = mySpeck.encrypt(my_plaintext)
# print(speck_ciphertext)

# ct = Encrypt(pt_96, key_144, 96/2, 144)
# print(ct)
# pt = Decrypt(ct, key_144, 96/2, 144)
# print(pt)

##################### SPECK 128/128 #####################
# key_128= 0x0f0e0d0c0b0a09080706050403020100
# pt_128= 0x6c617669757165207469206564616d20

# mySpeck = SpeckCipher(key_128, key_size=128, block_size=128)
# my_plaintext = pt_128
# speck_ciphertext = mySpeck.encrypt(my_plaintext)
# print(speck_ciphertext)

# ct = Encrypt(pt_128, key_128, 64, 128)
# print(ct)
# pt = Decrypt(ct, key_128, 64, 128)
# print(pt)

##################### SPECK 128/192 #####################
# key_192 = 0x17161514131211100f0e0d0c0b0a09080706050403020100
# pt_128 = 0x726148206665696843206f7420746e65

# mySpeck = SpeckCipher(key_192, key_size=192, block_size=128)
# my_plaintext = pt_128
# speck_ciphertext = mySpeck.encrypt(my_plaintext)
# print(speck_ciphertext)

# ct = Encrypt(pt_128, key_192, 64, 192)
# print(ct)
# pt = Decrypt(ct, key_192, 64, 192)
# print(pt)

##################### SPECK 128/256 #####################
key_256 = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
pt_128 = 0x65736f6874206e49202e72656e6f6f70

mySpeck = SpeckCipher(key_256, key_size=256, block_size=128)
my_plaintext = pt_128
speck_ciphertext = mySpeck.encrypt(my_plaintext)
print(speck_ciphertext)

ct = Encrypt(pt_128, key_256, 64, 256)
print(ct)
pt = Decrypt(ct, key_256, 64, 256)
print(pt)