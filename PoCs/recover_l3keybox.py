#! /usr/bin/python

import frida
import sys
import time

def isKeybox(data):
    if (data[0x78:0x7c] == [107, 98, 111, 120]): # "kbox" magic number
        return True
    return False

def printDeviceKey(keybox):
    deviceKey = [ str(hex(c)) for c in keybox[0x20:0x30]]
    print('Device key in hex: ' + ' '.join(deviceKey))

def onMunmap(message, data):
    if (message['type'] == "send"):
        raw = [c for c in data]
        if (isKeybox(raw)):
            tmp = str(int(round(time.time() * 1000)))
            fileName = "./keybox_" + tmp + ".raw"
            fd = open(fileName, 'wb')
            print("[+] Writing keybox file: " + fileName)
            fd.write(data)
            fd.close()
            printDeviceKey(raw)

def usage():
    print(sys.argv[0] + " [legacy|new]\n\nlegacy -> Android before version 7")

if len(sys.argv) != 2:
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

# munmap JS
print("[+] Processing script munmap")

munmap_data = """
Math.cos = Module.getExportByName('libwvdrmengine.so', 'munmap');
Interceptor.attach(Math.cos, {
    onEnter: function (args) {
        this.len = args[1].toInt32();
        if (this.len == 0x80) {
	    send("addr", args[0].readByteArray(this.len));
        }
    },
    onLeave: function (retval) {
    }
});
"""
script_munmap = session.create_script(munmap_data);
script_munmap.on('message', onMunmap)
print("\t[+] Loading script")
script_munmap.load()
print("\t[+] Script loaded successfully")

sys.stdin.read()
session.detach()
print("[+] Detached")

