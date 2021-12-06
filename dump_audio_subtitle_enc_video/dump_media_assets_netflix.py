#! /usr/bin/python

import frida
import sys
import cbor2
import gzip
import json
import pycurl

folder = ''

def download_file_from_url(name, extension, url):
    print("[+] Writing " + name + extension + " file on FS.")
    f = open(name + extension,'wb')
    crl = pycurl.Curl()
    crl.setopt(crl.URL, url)
    crl.setopt(crl.WRITEDATA, f)
    crl.perform()
    crl.close()

def get_audio_or_video_tracks_urls(struct):
    urls = []
    for dict1 in struct:
        if 'streams' in dict1.keys():
            for dict2 in dict1['streams']:
                if 'urls' in dict2.keys():
                    for dict3 in dict2['urls']:
                        if 'url' in dict3.keys():
                            urls.append(dict3['url'])        
    return urls

def get_timedtext_tracks_urls(struct):
    urls = []
    for dict1 in struct:
        if 'ttDownloadables' in dict1.keys():
            for dict2 in dict1['ttDownloadables']:
                if 'downloadUrls' in dict1['ttDownloadables'][dict2]:
                    for key in dict1['ttDownloadables'][dict2]['downloadUrls']:
                        urls.append(dict1['ttDownloadables'][dict2]['downloadUrls'][key])
    return urls

def get_urls(cbor_data):
    my_urls = {'audio': [],
               'video': [],
               'text': []}
    if 62 in cbor_data:
        try:
            cbor_data_field_decompressed = gzip.decompress(cbor_data[62])
            json_dict_data_field = json.loads(cbor_data_field_decompressed)
            if 'result' in json_dict_data_field:
                if type(json_dict_data_field['result']) is list:
                    dict0 = json_dict_data_field['result'][0]
                    if 'audio_tracks' in dict0.keys():
                        my_urls['audio'] = get_audio_or_video_tracks_urls(dict0['audio_tracks'])
                    if 'video_tracks' in dict0.keys():
                        my_urls['video'] = get_audio_or_video_tracks_urls(dict0['video_tracks'])
                    if 'timedtexttracks' in dict0.keys():
                        my_urls['text'] = get_timedtext_tracks_urls(dict0['timedtexttracks'])
        except (gzip.BadGzipFile, json.decoder.JSONDecodeError):
            print('[-] Not gzip data response or bad JSON')

    return my_urls

def downloadAllFiles(folder, my_urls):
    cpt = 0
    for audio_url in my_urls['audio']:
        download_file_from_url(folder + '/audio_' + str(cpt), '.mp4', audio_url)
        cpt += 1
    cpt = 0
    for video_url in my_urls['video']:
        download_file_from_url(folder + '/video_' + str(cpt), '.mp4', video_url)
        cpt += 1
    cpt = 0
    for timedtext_url in my_urls['text']:
        download_file_from_url(folder + '/timedtext_' + str(cpt), '.xml', timedtext_url)
        cpt += 1

def writeUrls(folder, my_urls):
    print("[+] Writing urls_list on FS.")
    fd = open(folder + '/urls_list.txt', 'w')
    for element in my_urls:
        fd.write(element + ':\n')
        for url in my_urls[element]:
            fd.write('\t' + url + '\n')
        fd.write('\n')
    fd.close()
        
def onGenericDecrypt(message, data):
    global folder
    if (message['payload'] == "plaintext"):
        array = [c for c in data]
        cbor_data = cbor2.loads(bytearray(array))
        my_urls = get_urls(cbor_data)
        if my_urls['audio'] or my_urls['video'] or my_urls['text']:
            writeUrls(folder, my_urls)
            downloadAllFiles(folder, my_urls)

def usage():
    print(sys.argv[0] + " <out_directory> [legacy|new]\n\nlegacy -> Android before version 7")

if len(sys.argv) != 3:
    usage()
    exit(-1)
    
if sys.argv[2] != 'legacy' and sys.argv[2] != 'new':
    usage()
    exit(-2)
    
folder = sys.argv[1]
if sys.argv[2] == 'legacy':
    mediadrm = 'mediaserver'
else:
    mediadrm = 'mediadrmserver'

device = frida.get_usb_device()
session = device.attach(mediadrm)
print("[+] Attached to " + mediadrm)

# OEMCrypto_GenericDecrypt (_oecc25) JS
print("[+] Processing script _oecc25")

genericDecrypt_data = """
Math.cos = Module.getExportByName('libwvdrmengine.so', '_oecc25');
Interceptor.attach(Math.cos, {
    onEnter: function (args) {
	this.plaintext = args[5];
	this.len = args[2].toInt32();
    },
    onLeave: function (retval) {
	send("plaintext", this.plaintext.readByteArray(this.len));
    }
});
"""
script_genericDecrypt = session.create_script(genericDecrypt_data);
script_genericDecrypt.on('message', onGenericDecrypt)
print("\t[+] Loading script")
script_genericDecrypt.load()
print("\t[+] Script loaded successfully")

sys.stdin.read()
session.detach()
print("[+] Detached")

