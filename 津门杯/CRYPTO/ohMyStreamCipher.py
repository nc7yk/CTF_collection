#!/usr/bin/env python
import hashlib, os, random, string
from signal import alarm
from secret import flag

assert(flag[:5] == "flag{" and flag[-1:] == "}")

secret = bytes.fromhex(flag[5:-1])
mask = 459642924442199950419910636725541032003
LENGTH = 8

class MyStreamCipher1:
    def __init__(self,k,s):
        s = hashlib.sha256(hashlib.sha256(s).digest()).digest()
        s_bin = bin(int.from_bytes(s[-LENGTH:],"big"))[2:].rjust(LENGTH * 8,"0")
        self.k = k
        self.state = [int(i) for i in s_bin]
    
    def __swap_state(self, a, b):
        self.state[a], self.state[b] = self.state[b], self.state[a]

    def change(self):
        j = 0
        for i in range(LENGTH * 8):
            j = (j + self.state[i] + self.k[i % len(self.k)]) % (LENGTH * 8)
            self.__swap_state(i, j)
        
    def __bytes__(self):
        s_bin = [str(i) for i in self.state]
        s_bin = "".join(s_bin)
        result = [int(s_bin[i:i+8],2) for i in range(0,LENGTH * 8,8)]
        return bytes(result)

class MyStreamCipher2:
    def __init__(self,key,mask):
        self.mask = mask
        self.state = key
        self.length = mask.bit_length()
        self.lengthmask = 2**self.length-1
    
    def next(self):
        nextdata = (self.state << 1) & self.lengthmask 
        i = self.state & self.mask & self.lengthmask 
        output = bin(i)[2:].count("1") & 1
        nextdata ^= output
        self.state = nextdata
        bl = [int(i) for i in bin(self.state)[2:].zfill(self.length)]
        result = bl[0] ^ bl[7] ^ bl[13] ^ bl[71] ^ bl[1] & bl[2] & bl[5] & bl[100] & bl[123] ^ bl[13] & bl[33] & bl[55] & bl[71] & bl[101] 
        return result

def proof_of_work():
    random.seed(os.urandom(8))
    proof = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(20)])
    digest = hashlib.sha256(proof.encode()).hexdigest()
    print("sha256(XXXX+%s) == %s" % (proof[4:],digest))
    print('Give me XXXX:')
    x = input()
    if len(x) != 4 or hashlib.sha256((x + proof[4:]).encode()).hexdigest() != digest: 
        return False
    return True


def main():
    alarm(60)
    if not proof_of_work():
        return
    try:
        key = os.urandom(LENGTH * 2)
        s = input("Please input your secret: ")
        s = bytes.fromhex(s)
        sc = MyStreamCipher1(key,s)
        sc.change()
        plain = bytes(sc) * 16
        print("If you give me a bitcoin, I will give you the plain, but I don't think you can do it, so I will continue :)")
        k = int.from_bytes(secret,byteorder="big")
        s = MyStreamCipher2(k,mask)
        cipher = []
        for i in range(LENGTH * 16):
            c = 0
            for j in range(8):
                c <<= 1
                c |= s.next()
            cipher.append(plain[i] ^ c)
        print("Here is your cipher: ",bytes(cipher).hex())
    except:
        print("Error!")

if __name__ == "__main__":
    main()
    