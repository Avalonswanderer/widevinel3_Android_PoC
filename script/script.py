#! /usr/bin/python3

import frida
import time
import sys
import os

def usage():
    print(sys.argv[0] + " [legacy]\n\nlegacy -> Android before version 7")

def get_mediadrm_name():
    numberOfArgs = len(sys.argv)
    if numberOfArgs > 2:
        usage()
        exit(-1)
    elif numberOfArgs == 2:
        mode = sys.argv[1]
    else:
        mode = "new"
        
    if mode != 'legacy' and mode != 'new':
        usage()
        exit(-2)

    if mode == 'legacy':
        mediadrm = 'mediaserver'
    else:
        mediadrm = 'mediadrmserver'
    return mediadrm

def write2file(header, data, folder):
    if not os.path.exists(folder):
        os.makedirs(folder)
        
    fileName = folder + header + str(int(round(time.time() * 1000))) + ".bin";
    print("\t\t[+] Writing buffer to file: " + fileName)
    f = open(fileName, 'wb')
    f.write(data)
    f.close()

def onMessage(message, data):
    if message["type"] == "send":
        payload = message['payload']
        level, tag = payload.split(":")
        if (tag == "Init"):
            print("\t[·] Widevine DRM Initialization level: " + level)
        elif (tag == "Terminate"):
            print("\t[·] Widevine DRM Terminate level: " + level)
        elif (tag == "Open"):
            print("\t[·] Widevine DRM Open Session level: " + level)
        elif (tag == "Close"):
            print("\t[·] Widevine DRM Close Session level: " + level)
        elif (tag == "DecryptCENC"):
            print("\t[·] Widevine Decrypt CENC level: " + level)
        elif (tag == "LoadKeys" or tag == "GenericEncrypt" or tag == "GenericDecrypt"):
            print("\t[·] Widevine " + tag + " level: " + level)
            buffer = bytearray([c for c in data])
            write2file(tag + "_buffer_", buffer, "./" + tag + "_buffers/")
    else:
        print(message, file=sys.stderr)    

def main():
    device = frida.get_usb_device()
    mediadrm = get_mediadrm_name()
    session = device.attach(mediadrm)
    print("[+] Attached to " + mediadrm)

    print("[+] Processing Frida JS script")
    js_file = open("./js/script_frida_widevine_flow_overview.js", "r");
    script_data = js_file.read();
    script_instance = session.create_script(script_data);
    js_file.close()
    script_instance.on('message', onMessage)
    print("\t[+] Loading script L1")
    script_instance.load()
    print("\t[+] Script loaded successfully")

    script_data_l3 = script_data.replace("L1", "L3")
    script_data_l3 = script_data_l3.replace("liboemcrypto.so", "libwvdrmengine.so")
    script_data_l3 = script_data_l3.replace("_oecc", "_lcc")
    script_instance = session.create_script(script_data_l3);
    script_instance.on('message', onMessage)
    print("\t[+] Loading script L3 (libwvdrmengine.so)")
    script_instance.load()
    print("\t[+] Script loaded successfully")

    script_data_l3 = script_data_l3.replace("libwvdrmengine.so", "libwvhidl.so")
    script_instance = session.create_script(script_data_l3);
    script_instance.on('message', onMessage)
    print("\t[+] Loading script L3 (libwvhidl.so)")
    script_instance.load()
    print("\t[+] Script loaded successfully")

    print("[+] Listening...")
    sys.stdin.read()
    session.detach()
    print("[+] Detached")

if __name__ == '__main__':
    main()

