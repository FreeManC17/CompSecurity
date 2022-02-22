import bcrypt  # importing libraries
import hashlib  # importing libraries
import hashlib
from Crypto.PublicKey import RSA
alphabets = 'abcdefghijklmnopqrstuvwxyz'


def decrypt_caesar(num, text):
    results = ''
    for k in text.lower():
        try:
            i = (alphabets.index(k) - num) % 26
            results += alphabets[i]
        except ValueError:
            results += k
    return results.lower()


num = int(input("please input the shift:\t"))
text = input("please input the text: \t")
ciphertext = decrypt_caesar(num, text)
print("Decoded text: ", ciphertext)


key = RSA.generate(3072)
file = open('Rsakey.pem', 'wb')
file.write(key.exportKey('PEM'))
file.close()


Hash_Algorithms_available = hashlib.algorithms_available
print(Hash_Algorithms_available)

Output: {'sha256', 'md4', 'whirlpool', 'sha384', 'sha224', 'sm3', 'blake2s', 'blake2b', 'ripemd160', 'sha512_256', 'md5',
         'sha512_224', 'shake_128', 'sha512', 'sha1', 'sha3_384', 'sha3_256', 'sha3_512', 'md5-sha1', 'shake_256', 'sha3_224'}


module = hashlib.md5()  # selecting the hashing module
module.update(b"You are Awesome ")  # inputting the text and b implies bytecode
print(module.hexdigest())


input_password = b"YouareAwesome!"  # inputting the text and b implies bytecode
hashed_password = bcrypt.hashpw(input_password, bcrypt.gensalt())
print(hashed_password)
