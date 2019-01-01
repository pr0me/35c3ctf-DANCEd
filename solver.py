import numpy as np
from pwn import *

# bitwise rotate left op
rol = lambda val, r_bits: (val << r_bits % 32) & (2**32-1) | ((val & (2**32-1)) >> (32 - (r_bits % 32)))


def quarter_round(a, b, c, d):
    mod = 2**32
    b ^= rol((a + d), 7) % mod 
    c ^= rol((b + a), 9) % mod
    d ^= rol((c + b), 13) % mod
    a ^= rol((d + c), 18) % mod
    return a, b, c, d


# full salsa round (4 quarter rounds)
def full_round(block):
    for i in range(0, 4):
        block[(0 + i) % 4, i], block[(1 + i) % 4, i], block[(2 + i) % 4, i], block[(3 + i) % 4, i] = quarter_round(block[(0 + i) % 4, i], block[(1 + i) % 4, i], block[(2 + i) % 4, i], block[(3 + i) % 4, i])

    return block.T 


# apply salsa20 operations in reverse order
def reverse_qr(a, b, c, d):
    mod = 2**32
    a ^= rol((d + c), 18) % mod
    d ^= rol((c + b), 13) % mod
    c ^= rol((b + a), 9) % mod
    b ^= rol((a + d), 7) % mod 
    return a, b, c, d


# apply full salsa20 rounds in reverse order
def reverse_fr(block):
    block = block.T
    for i in range(3, -1, -1):
        block[(0 + i) % 4, i], block[(1 + i) % 4, i], block[(2 + i) % 4, i], block[(3 + i) % 4, i] = reverse_qr(block[(0 + i) % 4, i], block[(1 + i) % 4, i], block[(2 + i) % 4, i], block[(3 + i) % 4, i])
    return block
    

def invert(block):  
    print("INPUT:")
    print(block)
    block
    for i in range(0, 20):
        block = reverse_fr(block)
    print("REVERSED:")
    print(block)
    print("")
    return block


def solve():
    conn = remote("localhost", 11520)
    r = conn.recvuntil('>')
    conn.send("1")
    r = conn.recvuntil('>>')
    conn.send("2")
    r = conn.recvuntil(':')

    # get any token/reservation with a length of 64 (full block length)
    msg = "A" * (64 - len("salsa "))
    conn.sendline(msg)
    r = conn.recvuntil('>')
    token = r.split("token: ")[1].split('\n')[0].decode("hex")
    print(token)
    msg = "salsa " + msg
    
    # xor _prefix+your_msg_ with _token_ to get the keystream specific to the encryption of your reservation
    xor = [u8(a) ^ ord(b) for a,b in zip(token, msg)]
    stream = b''
    for x in xor:
        # stream += x.to_bytes(1, byteorder='little') # python3
        stream += p8(x)
    print(stream)

    np.set_printoptions(formatter={'int':hex})
    personal_block = np.zeros([4,4], dtype=np.uint32)
    i = 0
    for c in range(0, 4):
        for r in range(0, 4):
            personal_block[c][r] = u32(stream[i:i+4])
            i += 4
    
    initial_block = np.copy(personal_block)
    invert(initial_block)   
    
    # the interesting (randomized) part:
    print(hex(initial_block[1][2]), hex(initial_block[1][3]))
    
    # GENERATE KEY STREAM THE FLAG WAS ENCRYPTED WITH
    block = np.copy(initial_block) 
    # set counter variable to 0x0
    block[2][0] = 0
    # apply 20 rounds of salsa
    for i in range(0, 20):
        block = full_round(block)
    print("FLAG BLOCK:")
    print(block)
    
    # bring key stream into handy form
    flag_stream = b''
    for c in range(0, 4):
        for r in range(0, 4):
            flag_stream += p32(block[c][r])
    flag_stream = flag_stream.replace('0x', '')

    # get flag (0th reservation)
    conn.send('2')
    r = conn.recvuntil('>')
    flag_encrypted = r.split('\n')[2].decode("hex")

    # decrypt
    xor = [u8(a) ^ u8(b) for a,b in zip(flag_stream, flag_encrypted)]
    flag = b''
    for x in xor:
        flag += p8(x)
    print("\n[*] FLAG: " + flag)


if __name__ == '__main__':
    solve()