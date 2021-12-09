# Widevine Android Overview & Widevine L3 Android RoT recovery PoC

Dependencies:

- `Python3`
- `python3-frida-tools` 

In order to execute scripts, a Frida server needs to run on the targeted device with sufficient privileges for media system process inspection (e,g. media or root access).

## Script Widevine Android Lightweight Control Flow Overview

This control flow script aims to distinguish with certainty the usage of Widevine L1 and L3 mode wihtin Android devices. This lightweight overview hooks initialization and session creation with provisioning methods and decryption ones (both for CENC and generic purpose crypto methods), and dump transmitted buffers for further in-deph analysis. 

```
$ ./script.py [legacy|new]

legacy -> for Android before Android 7
new -> for Android 7 and above
```

## Proof-Of-Concept: Netflix Media Download and Widevine L3 Content Key & Keybox Recovery

### Netflix Media Asset Download

Download all content assets from Netflix (encrypted video, clear audio and subtitle). Launch the PoC once Netflix is running and select a media to stream.

```
$ ./dump_media_assets_netflix.py <out_directory> [legacy|new]

legacy -> for Android before Android 7
new -> for Android 7 and above
```

### Widevine Content Key Recovery

Content key recovery PoC to mimic the Widevine Key ladder starting from the Device RSA Key. The PEM cert is the PKCS#8 DER file decrypted in OEMCrypto_RewrapdeviceRSAKey converted to PEM.

```
$ ./content_key_recovery.py [legacy|new] <pem file>

legacy -> for Android before Android 7
new -> for Android 7 and above
```

### Widevine L3 Keybox Recovery

Recover the Widevine L3 Keybox. Lauch the PoC and play a media using the Widevine DRM L3.

```
$ ./recover_l3keybox.py [legacy|new]

legacy -> for Android before Android 7
new -> for Android 7 and above
```

## Responsible Disclosure

Our findings have been timely reported to all concerned parties following their responsible disclosure process. We emphasize that we timely reach out all the concerned parties, including Google Widevine and Netflix, in order to report the identified issues. In addition, we gave up all the keys that we succeeded to extract, so that they get revoked. Google assigned the CVE ID ['CVE-2021-0639'](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-0639) for us linked to the [Android Security Bulletin August 2021](https://source.android.com/security/bulletin/2021-08-01#widevine). Our goal is not to provide copyright infringement tools but to improve the state-of-the-art concerning kownledge of DRM internals.
