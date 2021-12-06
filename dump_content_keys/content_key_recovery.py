#! /usr/bin/python

import sys
import frida
import Crypto.Cipher.PKCS1_OAEP as rsaoaep
import Crypto.Util as crypto_util
import Crypto.PublicKey.RSA as RSA
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

enc_session_key = ""
encryption_context = ""
message_loadkeys = ""
offset_loadkeys = ""
numOfKeys = ""
cert_raw = ""

def get_clear_session_key(cert_string, enc_session_key):
    provision_rsa_key = RSA.importKey(cert_raw)
    rsa_oaep_cipher = rsaoaep.new(provision_rsa_key)
    return rsa_oaep_cipher.decrypt(enc_session_key)

def gen_asset_key(session_key, encryption_context):
    cmac_obj = CMAC.new(session_key, ciphermod=AES)
    cmac_obj.update((b'\x01' + encryption_context))
    return cmac_obj.digest()

def get_clear_content_key(asset_key, loadkey_buffer, offset):
    iv = loadkey_buffer[offset + 0x12:offset + 0x22]
    enc_content_key = loadkey_buffer[offset + 0x24:offset + 0x44]
    decipher = AES.new(asset_key, AES.MODE_CBC, iv)
    content_key_w_pad = decipher.decrypt(enc_content_key)
    return crypto_util.Padding.unpad(content_key_w_pad, AES.block_size)

def get_clear_kctl_block(content_key, loadkey_buffer, offset):
    enc_kctl = loadkey_buffer[offset + 0x52:offset + 0x72]
    iv_kctl = loadkey_buffer[offset + 0x74:offset + 0x84]
    decipher = AES.new(content_key, AES.MODE_CBC, iv_kctl)
    kctl_pad = decipher.decrypt(enc_kctl)
    return crypto_util.Padding.unpad(kctl_pad, AES.block_size)


def get_keys():
    global enc_session_key, encryption_context, message_loadkeys, offset_loadkeys, numOfKeys, cert_raw
    session_key = get_clear_session_key(cert_raw, enc_session_key)
    print("session key: " + session_key.hex())
    asset_key = gen_asset_key(session_key, encryption_context)
    print("asset key: " + asset_key.hex() + "\n")

    for i in range(0, numOfKeys):
        offset = offset_loadkeys + i * 0x89
        content_key = get_clear_content_key(asset_key, message_loadkeys, offset)
        print("content key ID: " + message_loadkeys[offset:offset + 0x10].hex())
        print("content key: " + content_key.hex())
        kctl = get_clear_kctl_block(content_key, message_loadkeys, offset)
        print("kctl: " + str(kctl) + "\n")

def onMessage(message, data):
    global enc_session_key, encryption_context, message_loadkeys, offset_loadkeys, numOfKeys
    if message["type"] == "send":
        if (message["payload"] == "enc_session_key"):
            enc_session_key = bytearray([c for c in data])
        elif (message["payload"] == "encryption_context"):
            encryption_context = bytearray([c for c in data])
        elif (message["payload"] == "message_loadkeys"):
            message_loadkeys = bytearray([c for c in data])
        elif (message["payload"] == "numOfKeys"):
            numOfKeys = int.from_bytes(data, byteorder='little', signed=False)
        elif (message["payload"] == "offset_loadkeys"):
            offset_loadkeys = int.from_bytes(data, byteorder='little', signed=False)
            if (enc_session_key != "" and message_loadkeys != "" and encryption_context != ""):
                get_keys()

def usage():
    print(sys.argv[0] + " [legacy|new] <pem file>\n\nlegacy -> Android before version 7")

# Start

if len(sys.argv) != 3:
    usage()
    exit(-1)
    
if sys.argv[1] != 'legacy' and sys.argv[1] != 'new':
    usage()
    exit(-2)

if sys.argv[1] == 'legacy':
    mediadrm = 'mediaserver'
else:
    mediadrm = 'mediadrmserver'

device = frida.get_usb_device()
session = device.attach(mediadrm)
print("[+] Attached to " + mediadrm)

# OEMCrypto_DeriveKeysFromSessionKey and OEMCrypto_LoadKeys (_oecc21, _oecc35) JS
print("[+] Processing script for _oecc21 and _oecc35")

script_data = """
Math.cos = Module.getExportByName('libwvdrmengine.so', '_oecc21');
Interceptor.attach(Math.cos, {
    onEnter: function (args) {
        send("enc_session_key", args[1].readByteArray(args[2].toInt32()));      
        send("encryption_context", args[5].readByteArray(args[6].toInt32()));      
    },
    onLeave: function (retval) {
    }
});
Math.acos = Module.getExportByName('libwvdrmengine.so', '_oecc35');
Interceptor.attach(Math.acos, {
    onEnter: function (args) {
        send("message_loadkeys", args[1].readByteArray(args[2].toInt32()));      

        Math.sin = Memory.scanSync(args[1], args[2].toInt32(), "20 01 1A 86 01 0A 10");
        Math.tan = Memory.alloc(4);

        Math.tan.writeU32(args[7].toInt32());
        send("numOfKeys", Math.tan.readByteArray(4));

        Math.tan.writeU32(Math.sin[0].address.toInt32() - args[1].toInt32() + 7);
        send("offset_loadkeys", Math.tan.readByteArray(4));
    },
    onLeave: function (retval) {
    }
});
"""
script = session.create_script(script_data);
script.on('message', onMessage)
print("\t[+] Loading script")
script.load()
print("\t[+] Script loaded successfully")

with open(sys.argv[2], "rb") as f:
    cert_raw = f.read()

sys.stdin.read()

session.detach()
print("[+] Detached")
