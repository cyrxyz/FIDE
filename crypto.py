import pickle
import hashlib
import random
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

class Crypto:
    def __init__(self, key):
        assert len(key) == 32
        self.aes = AES.new(key[:16], AES.MODE_ECB)
        self.iv = int.from_bytes(key[16:], 'big')

    def load(self, loader):
        loader.add_option(
            name = "remote-addr",
            typespec = str,
            default = "127.0.0.1",
        )

    def encrypt(self, message):
        if message:
            head = 16 - (len(message) + 1) % 16
            heads = bytes([head + 1]) + bytes(head)
            message = self.aes.encrypt(heads + message + get_random_bytes(16))
            now = self.iv
            result = b''
            p = len(message)
            while p > 0:
                now = now ^ int.from_bytes(message[p - 16 : p], 'big')
                p -= 16
                result += now.to_bytes(16, 'big')
            return result  + get_random_bytes(random.randint(0,15))
        else:
            return b''
    def decrypt(self, message):
        if message:
            now = self.iv
            result = b''
            for i in range(len(message) // 16 - 2, -1, -1):
                now = (
                    int.from_bytes(message[i * 16 : (i + 1) * 16], 'big') ^
                    int.from_bytes(message[(i + 1) * 16 : (i + 2) * 16], 'big')
                )
                result += now.to_bytes(16, 'big')
            full = self.aes.decrypt(result)
            return full[full[0]:]
        else:
            return b''

    def checksum(self, message):
        return hashlib.blake2b(message).hexdigest()
    def pack(self, message):
        return self.encrypt(pickle.dumps(message))
    def unpack(self, message):
        return pickle.loads(self.decrypt(message))
