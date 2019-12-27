import os
import sys
import zipfile
import threading
import base64
import getopt
import random
import platform
from io import BytesIO

import mitmproxy.http
from mitmproxy import ctx
from mitmproxy.script import concurrent
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP

from crypto import Crypto

if __name__ == '__main__':
    def print_usage():
        print('usage:')
        print('  python server.py')
        print('  -h --help   print usage and exit')
        print('  -d --daemon run in daemon mode')
        print('  -p --port   server port, default 80')
        print('  -g --gen    generate RSA key and exit')
        exit()
    def gen_key():
        key = RSA.generate(2048)
        private_key = key.export_key()
        file_out = open("private.pem", "wb")
        file_out.write(private_key)
        public_key = key.publickey().export_key()
        file_out = open("public.pem", "wb")
        file_out.write(public_key)
        print('RSA key saved in private.pem and public.pem')
    try:
        opts, args = getopt.getopt(sys.argv[1:], "dhgp:", ["help", "daemon", "gen", "port="])
        assert(len(args) == 0)
        port = 80
        deamon = False
        for k, v in opts:
            if k in ('-h', '--help'):
                print_usage()
            if k in ('-d', '--daemon'):
                deamon = True
            elif k in ('-p', '--port'):
                port = int(v)
            elif k in ('-g', '--gen'):
                gen_key()
                exit()
        if not os.access('private.pem', os.R_OK):
            print('key private.pem not found, generate one')
            gen_key()
        print('listening at port {}...'.format(port))
        task = 'mitmdump -q -p {} -s server.py \
            --set block_global=false \
            --set keep_host_aders \
            -m reverse:http://0.0.0.0/'.format(port)
        if deamon:
            if platform.system() == 'Windows':
                os.system("start /min " + task)
                exit()
            else:
                os.system("nohup " + task + " > /dev/null 2>&1 &")
        else:
            os.system(task)
    except getopt.GetoptError:
        print_usage()
    except AssertionError:
        print_usage()

def get_client_pub_key(auth):
    auth = base64.b64decode(auth)

    private_key = RSA.import_key(open("private.pem").read())

    enc_session_key, rest = auth[: private_key.size_in_bytes()], auth[private_key.size_in_bytes() :]
    nonce, tag, ciphertext = rest[:16], rest[16:32], rest[32:]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return RSA.import_key(data.decode("utf-8"))

def code_recoding(code):
    prime = 0xfffffffb
    code += 0x15511551
    residue = (code * code) % prime
    code = residue if code + code < prime else prime - code
    code ^= 0x66ccffff
    return code


def to_send(key, code, auth):
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(auth)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(key)
    res = b"".join((code.to_bytes(4, 'big', signed=False), enc_session_key, cipher_aes.nonce, tag, ciphertext))
    return base64.b64encode(res)

class Server:
    def __init__(self):
        self.crypto = {}
        self.client_cnt = 0
    
    @concurrent
    def request(self, flow: mitmproxy.http.HTTPFlow):
        flow.code = ""
        try:
            if flow.request.path[:10] == "/submit?t=":
                assert random.random() >= 0.0001 # force update keys
                flow.code = flow.request.path[10:]
                assert flow.code in self.crypto
                zipb = BytesIO(flow.request.content)
                try:
                    zipf = zipfile.ZipFile(zipb, 'r')
                except zipfile.BadZipFile:
                    raise AssertionError
                assert len(zipf.namelist()) == 1
                checksum = zipf.namelist()[0]
                message = zipf.read(checksum)
                assert checksum == self.crypto[flow.code].checksum(message)
                
                flow.request = self.crypto[flow.code].unpack(message)
            elif flow.request.path == "/login":
                raise AssertionError
        except AssertionError:
            key = get_random_bytes(32)
            self.client_cnt += 1
            code = code_recoding(self.client_cnt)
            self.crypto[str(code)] = Crypto(key)
            client_pub_key = get_client_pub_key(flow.request.headers["Authorization"])
            auth = to_send(key, code, client_pub_key)
            flow.response = mitmproxy.http.HTTPResponse.make(
                401,
                b'{"code":401,"message":"Unauthorized"}',
                {
                    "Content-Type": "application/json",
                    "Authorization": auth
                }
            )
    @concurrent
    def response(self, flow: mitmproxy.http.HTTPFlow):
        if flow.response.status_code != 401 and flow.code:
            message = self.crypto[flow.code].pack(flow.response)
            flow.response = mitmproxy.http.HTTPResponse.make(
                flow.response.status_code,
                message,
                {
                    "Content-Type": "binary", 
                    "Authorization": self.crypto[flow.code].checksum(message)
                }
            )

addons = [Server()]
