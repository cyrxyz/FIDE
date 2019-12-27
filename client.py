import os
import sys
import zipfile
import threading
import base64
import getopt
import typing
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
        print('  python client.py')
        print('  -h --help   print usage and exit')
        print('  -d --daemon run in daemon mode')
        print('  -p --port   local port, default 8080')
        print('  -r --remote remote server, the default port is 80')
        print('                e.g. 1.2.3.4:8080; example.org')
        print('  -k --key    remote public key file, default ./public.pem')
        exit()
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hdp:r:k:", ["help", "deamon", "port=", "remote=", "key="])
        assert(len(args) == 0)
        deamon = False
        local_port = 0
        remote_addr = ""
        remote_port = 0
        remote_public = "public.pem"
        for k, v in opts:
            if k in ('-h', '--help'):
                print_usage()
            if k in ('-d', '--daemon'):
                deamon = True
            elif k in ('-p', '--port'):
                local_port = int(v)
            elif k in ('-r', '--remote'):
                if ':' in v:
                    remote_addr = v[:v.find(':')]
                    remote_port = int(v[v.find(':') + 1:])
                else:
                    remote_addr = v
                    remote_port = 80
            elif k in ('-k', '--key'):
                remote_public = v
        assert(local_port > 0)
        assert(remote_port > 0)
        if not os.access(remote_public, os.R_OK):
            print('remote key {} not found'.format(remote_public))
            print_usage()
        print('connecting to remote server {}:{}'.format(remote_addr, remote_port))
        print('start proxy at port {}...'.format(local_port))
        task = 'mitmdump -s client.py -q -p {} \
            --ssl-insecure \
            --set upstream_cert=false \
            --set remote_addr={} \
            --set remote_port={} \
            --set remote_public={}'.format(
                local_port,
                remote_addr,
                remote_port,
                remote_public
            )
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

class Client:
    def __init__(self):
        self.crypto = None
        self.code = "0"
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()
        self.auth = ""
    
    def load(self, loader):
        loader.add_option(name = "remote_addr", typespec = typing.Optional[str], default = None, help = "")
        loader.add_option(name = "remote_port", typespec = typing.Optional[int], default = None, help = "")
        loader.add_option(name = "remote_public", typespec = typing.Optional[str], default = None, help = "")

    def configure(self, updates):
        if "remote_addr" in updates and ctx.options.remote_addr is not None:
            self.remote_addr = ctx.options.remote_addr
        if "remote_port" in updates and ctx.options.remote_port is not None:
            self.remote_port = ctx.options.remote_port
        if "remote_public" in updates and ctx.options.remote_public is not None:
            self.remote_public = RSA.import_key(open(ctx.options.remote_public).read())
            self.auth = self.remote_crypt(self.public_key.export_key())

    def key_code(self, data):
        data = base64.b64decode(data)
        code, auth = int.from_bytes(data[:4], 'big', signed=False), data[4:]
        enc_session_key, rest = auth[:self.private_key.size_in_bytes()], auth[self.private_key.size_in_bytes():]
        nonce, tag, ciphertext = rest[:16], rest[16:32], rest[32:]
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        key = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return key, code

    def remote_crypt(self, data):
        session_key = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(self.remote_public)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        res = b"".join((enc_session_key, cipher_aes.nonce, tag, ciphertext))
        return base64.b64encode(res)

    def remote_url(self):
        return "http://{}:{}".format(self.remote_addr, self.remote_port)

    @concurrent
    def request(self, flow: mitmproxy.http.HTTPFlow):
        flow.retry = flow.request.path
        if flow.request.host not in ['127.0.0.1', 'localhost']:

            checksum = ""
            if self.crypto:
                message = self.crypto.pack(flow.request.copy())
                checksum = self.crypto.checksum(message)

                zipm = BytesIO()
                zipf = zipfile.ZipFile(
                    zipm,
                    'a',
                    zipfile.ZIP_STORED,
                    False
                )
                for zfile in zipf.filelist:
                    zfile.create_system = 0
                zipf.writestr(checksum, message)
                zipf.close()

                flow.request = mitmproxy.http.HTTPRequest.make(
                    'POST',
                    self.remote_url() + '/submit?t={}'.format(self.code),
                    zipm.getvalue(),
                    {
                        "Host": self.remote_addr,
                        "Connection": "keep-alive",
                        "Accept": "*/*",
                        "User-Agent": flow.request.headers.get("User-Agent", ""),
                        "Accept-Encoding": "br, gzip, deflate",
                        "Content-Type": "application/zip",
                        "Authorization": self.auth
                    }
                )
                flow.request.first_line_format = "relative"
            else:
                flow.request = mitmproxy.http.HTTPRequest.make(
                    'GET',
                    self.remote_url() + '/login',
                    b'',
                    {
                        "Host": self.remote_addr,
                        "Connection": "keep-alive",
                        "Accept": "*/*",
                        "User-Agent": flow.request.headers.get("User-Agent", ""),
                        "Accept-Encoding": "br, gzip, deflate",
                        "Authorization": self.auth
                    }
                )
                flow.request.first_line_format = "relative"
    
    @concurrent
    def response(self, flow: mitmproxy.http.HTTPFlow):
        if flow.response.status_code == 401:
            key, self.code = self.key_code(flow.response.headers["Authorization"])
            self.crypto = Crypto(key)
            flow.response = mitmproxy.http.HTTPResponse.make(
                302,
                b'',
                {
                    "Connection": "close",
                    "Location": flow.retry
                }
            )
            
        elif flow.request.host == self.remote_addr and \
        flow.request.path[:10] == "/submit?t=" and \
        "Authorization" in flow.response.headers:
            if flow.response.headers["Authorization"] == self.crypto.checksum(flow.response.content):
                flow.response = self.crypto.unpack(flow.response.content).copy()

addons = [Client()]
