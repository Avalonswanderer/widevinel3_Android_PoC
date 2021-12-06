# Proof-Of-Concept: Netflix Media Download and Widevine L3 Content Key & Keybox Recovery

## Usage

Download all content assests from Netflix (encrypted video, clear audio and subtitle). Launch the PoC once Netflix is running and select a media to stream.

```
$ ./dump_media_assets_netflix.py <out_directory> [legacy|new]

legacy -> for Android before Android 7
new -> for Android 7 and above
```

L3 content key recovery PoC needs to be run with Widevine L3. The PEM cert is the PKCS#8 DER file decrypted in OEMCrypto_RewrapdeviceRSAKey converted to PEM.

```
$ ./content_key_recovery.py [legacy|new] <pem file>

legacy -> for Android before Android 7
new -> for Android 7 and above
```
Recover the Widevine L3 Keybox. Lauch the PoC and play a media using the Widevine DRM L3.

```
$ ./recover_l3keybox.py [legacy|new]

legacy -> for Android before Android 7
new -> for Android 7 and above
```

