// OEMCrypto_Initialize
Math.sin = Module.getExportByName('liboemcrypto.so', '_oecc01');
Interceptor.attach(Math.sin, {
    onEnter: function (log, args, state) {
	send("L1:Init");
  }
});

// OEMCrypto_Terminate
Math.asin = Module.getExportByName('liboemcrypto.so', '_oecc02');
Interceptor.attach(Math.asin, {
    onEnter: function (log, args, state) {
	send("L1:Terminate");
  }
});

// OEMCrypto_OpenSession
Math.asinh = Module.getExportByName('liboemcrypto.so', '_oecc09');
Interceptor.attach(Math.asinh, {
    onEnter: function (log, args, state) {
	send("L1:Open");
  }
});

// OEMCrypto_CloseSession
Math.log = Module.getExportByName('liboemcrypto.so', '_oecc10');
Interceptor.attach(Math.log, {
    onEnter: function (log, args, state) {
	send("L1:Close");
  }
});

// OEMCrypto_GenericEncrypt
Math.cos = Module.getExportByName('liboemcrypto.so', '_oecc24');
Interceptor.attach(Math.cos, {
    onEnter: function (args) {
	send("L1:GenericEncrypt", args[1].readByteArray(args[2].toInt32()));
    }
});

// OEMCrypto_GenericDecrypt
Math.acos = Module.getExportByName('liboemcrypto.so', '_oecc25');
Interceptor.attach(Math.acos, {
    onEnter: function (args) {
	this.plaintext = args[5];
	this.len = args[2].toInt32();
    },
    onLeave: function (retval) {
	send("L1:GenericDecrypt", this.plaintext.readByteArray(this.len));
    }
});

// OEMCrypto_LoadKeys_V8
Math.random = Module.getExportByName('liboemcrypto.so', '_oecc15');
Interceptor.attach(Math.random, {
    onEnter: function (args) {
	send("L1:LoadKeys", args[1].readByteArray(args[2].toInt32()));
    }
});

// OEMCrypto_LoadKeys_V9_V10
Math.atanh = Module.getExportByName('liboemcrypto.so', '_oecc35');
Interceptor.attach(Math.atanh, {
    onEnter: function (args) {
	send("L1:LoadKeys", args[1].readByteArray(args[2].toInt32()));
    }
});

// OEMCrypto_LoadKeys
Math.tan = Module.getExportByName('liboemcrypto.so', '_oecc47');
Interceptor.attach(Math.tan, {
    onEnter: function (args) {
	send("L1:LoadKeys", args[1].readByteArray(args[2].toInt32()));
    }
});

// OEMCrypto_DecryptCENC
Math.atan = Module.getExportByName('liboemcrypto.so', '_oecc48');
Interceptor.attach(Math.atan, {
    onEnter: function (args) {
	send("L1:DecryptCENC");
    }
});

