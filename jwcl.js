"use strict";
// # JWCL
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = y[op[0] & 2 ? "return" : op[0] ? "throw" : "next"]) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [0, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
(function () {
    // ## Constants
    // Sizes
    var BITS_IN_BYTE = 8;
    var PRIVATE_KEY_LENGTH_BITS = 128;
    var PRIVATE_KEY_LENGTH_BYTES = PRIVATE_KEY_LENGTH_BITS / BITS_IN_BYTE;
    // Algorithms
    var BROWSER_AES_ALGO = 'AES-GCM';
    var BROWSER_SHA_ALGO = 'SHA-256';
    var BROWSER_HMAC_ALGO = 'HMAC';
    var BROWSER_RSA_ALGO = 'RSA-OAEP';
    var BROWSER_DSA_ALGO = 'ECDSA';
    // Configurations
    var PBKDF2_ITERATIONS = 10000;
    var AES_GCM_IV_LENGTH_BYTES = 96 / BITS_IN_BYTE;
    var AES_GCM_AUTH_TAG_LENGTH_BYTES = 16;
    // # Internal
    var crypto = window.crypto;
    var subtle = window.crypto.subtle;
    var hexReg = /[a-f0-9][a-f0-9]/g;
    var encoder = new TextEncoder('utf-8');
    var decoder = new TextDecoder('utf-8');
    // ## Internal
    function stob(string_) {
        return encoder.encode(string_);
    }
    function btos(binary) {
        var binaryArray = (binary instanceof ArrayBuffer) ? new Uint8Array(binary) : binary;
        return decoder.decode(binaryArray);
    }
    function byteToHex(byte_) {
        var hex = byte_.toString(16);
        return (hex.length === 1 ? '0' : '') + hex;
    }
    function btoh(binary) {
        var binaryArray = (binary instanceof ArrayBuffer) ? new Uint8Array(binary) : binary;
        return binaryArray.reduce(function (acc, val) { return acc + byteToHex(val); }, '');
    }
    function htob(hex) {
        var hexArray = hex.match(hexReg);
        if (!hexArray) {
            throw {
                name: 'JWCL',
                message: 'jwcl._internal.htob input is not hex'
            };
        }
        return Uint8Array.from(hexArray.map(function (val) { return Number.parseInt(val, 16); }));
    }
    // ## Random
    function browserRandom(bytes) {
        return __awaiter(this, void 0, void 0, function () {
            var output;
            return __generator(this, function (_a) {
                output = new Uint8Array(bytes);
                crypto.getRandomValues(output);
                return [2 /*return*/, btoh(output)];
            });
        });
    }
    // ## Hash
    function browserHash(plaintext, algorithm) {
        if (algorithm === void 0) { algorithm = BROWSER_SHA_ALGO; }
        return __awaiter(this, void 0, void 0, function () {
            var hash;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, crypto.subtle.digest(algorithm, stob(plaintext))];
                    case 1:
                        hash = _a.sent();
                        return [2 /*return*/, btoh(hash)];
                }
            });
        });
    }
    // # Private
    // ## Key
    function browserPrivateKey(op) {
        return __awaiter(this, void 0, void 0, function () {
            var key, key_;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (!op) {
                            return [2 /*return*/, browserRandom(PRIVATE_KEY_LENGTH_BYTES)];
                        }
                        if (!(op === 'encrypt' || op === 'decrypt')) return [3 /*break*/, 2];
                        return [4 /*yield*/, crypto.subtle.generateKey({
                                name: BROWSER_AES_ALGO,
                                length: PRIVATE_KEY_LENGTH_BITS
                            }, true, ['encrypt', 'decrypt'])];
                    case 1:
                        key = _a.sent();
                        return [3 /*break*/, 5];
                    case 2:
                        if (!(op === 'sign' || op === 'verify')) return [3 /*break*/, 4];
                        return [4 /*yield*/, crypto.subtle.generateKey({
                                name: BROWSER_HMAC_ALGO,
                                hash: BROWSER_SHA_ALGO
                            }, true, ['sign', 'verify'])];
                    case 3:
                        key = _a.sent();
                        return [3 /*break*/, 5];
                    case 4: throw {
                        name: 'JWCL',
                        message: "jwcl.private.key " + op + " is not a supported operation"
                    };
                    case 5: return [4 /*yield*/, crypto.subtle.exportKey('raw', key)];
                    case 6:
                        key_ = _a.sent();
                        return [2 /*return*/, btoh(key_)];
                }
            });
        });
    }
    // ## KDF
    function browserPrivateKdf(secret) {
        return __awaiter(this, void 0, void 0, function () {
            var masterKey, derivedKey, key;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, crypto.subtle.importKey('raw', stob(secret), {
                            name: 'PBKDF2'
                        }, false, ['deriveKey'])];
                    case 1:
                        masterKey = _a.sent();
                        return [4 /*yield*/, crypto.subtle.deriveKey({
                                'name': 'PBKDF2',
                                'salt': new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0]),
                                'iterations': PBKDF2_ITERATIONS,
                                'hash': BROWSER_SHA_ALGO
                            }, masterKey, {
                                'name': BROWSER_AES_ALGO,
                                'length': PRIVATE_KEY_LENGTH_BITS
                            }, true, ['encrypt', 'decrypt'])];
                    case 2:
                        derivedKey = _a.sent();
                        return [4 /*yield*/, crypto.subtle.exportKey('raw', derivedKey)];
                    case 3:
                        key = _a.sent();
                        return [2 /*return*/, btoh(key)];
                }
            });
        });
    }
    // ## Encrypt
    function browserPrivateEncrypt(key, iv, plaintext) {
        return __awaiter(this, void 0, void 0, function () {
            var algorithm, cryptoKey, ciphertext;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        algorithm = {
                            name: BROWSER_AES_ALGO,
                            iv: htob(iv)
                        };
                        return [4 /*yield*/, crypto.subtle.importKey('raw', htob(key), algorithm, false, ['encrypt'])];
                    case 1:
                        cryptoKey = _a.sent();
                        return [4 /*yield*/, crypto.subtle.encrypt(algorithm, cryptoKey, stob(plaintext))];
                    case 2:
                        ciphertext = _a.sent();
                        return [2 /*return*/, iv + btoh(ciphertext)];
                }
            });
        });
    }
    // ## Decrypt 
    function browserPrivateDecrypt(key, ciphertext) {
        return __awaiter(this, void 0, void 0, function () {
            var binaryCiphertext, algorithm, cryptoKey, plaintext;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        binaryCiphertext = htob(ciphertext);
                        algorithm = {
                            name: BROWSER_AES_ALGO,
                            iv: binaryCiphertext.subarray(0, AES_GCM_IV_LENGTH_BYTES)
                        };
                        return [4 /*yield*/, crypto.subtle.importKey('raw', htob(key), algorithm, false, ['decrypt'])];
                    case 1:
                        cryptoKey = _a.sent();
                        return [4 /*yield*/, crypto.subtle.decrypt(algorithm, cryptoKey, binaryCiphertext.subarray(AES_GCM_IV_LENGTH_BYTES))];
                    case 2:
                        plaintext = _a.sent();
                        return [2 /*return*/, btos(plaintext)];
                }
            });
        });
    }
    // ## Sign
    function browserPrivateSign(key, plaintext) {
        return __awaiter(this, void 0, void 0, function () {
            var algorithm, cryptoKey, signature;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        algorithm = {
                            name: BROWSER_HMAC_ALGO,
                            hash: BROWSER_SHA_ALGO
                        };
                        return [4 /*yield*/, crypto.subtle.importKey('raw', htob(key), algorithm, false, ['sign'])];
                    case 1:
                        cryptoKey = _a.sent();
                        return [4 /*yield*/, crypto.subtle.sign(algorithm.name, cryptoKey, stob(plaintext))];
                    case 2:
                        signature = _a.sent();
                        return [2 /*return*/, btoh(signature)];
                }
            });
        });
    }
    // ## Verify
    function browserPrivateVerify(key, signature, plaintext) {
        return __awaiter(this, void 0, void 0, function () {
            var algorithm, key_;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        algorithm = {
                            name: BROWSER_HMAC_ALGO,
                            hash: BROWSER_SHA_ALGO
                        };
                        return [4 /*yield*/, crypto.subtle.importKey('raw', htob(key), algorithm, false, ['verify'])];
                    case 1:
                        key_ = _a.sent();
                        return [2 /*return*/, crypto.subtle.verify(algorithm.name, key_, htob(signature), stob(plaintext))];
                }
            });
        });
    }
    // # Public TODO type all of the any's
    // ## Key
    function browserPublicKey(op) {
        return __awaiter(this, void 0, void 0, function () {
            var key;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (!(op === 'encrypt' || op === 'decrypt')) return [3 /*break*/, 2];
                        return [4 /*yield*/, crypto.subtle.generateKey({
                                name: BROWSER_RSA_ALGO,
                                modulusLength: 2048,
                                publicExponent: new Uint8Array([1, 0, 1]),
                                hash: { name: BROWSER_SHA_ALGO },
                            }, true, ['encrypt', 'decrypt'])];
                    case 1:
                        key = _a.sent();
                        return [3 /*break*/, 5];
                    case 2:
                        if (!(op === 'sign' || op === 'verify')) return [3 /*break*/, 4];
                        return [4 /*yield*/, crypto.subtle.generateKey({
                                name: BROWSER_DSA_ALGO,
                                namedCurve: 'P-256',
                            }, true, ['sign', 'verify'])];
                    case 3:
                        key = _a.sent();
                        return [3 /*break*/, 5];
                    case 4: throw {
                        name: 'JWCL',
                        message: "jwcl.public.key " + op + " is not a supported operation"
                    };
                    case 5: return [2 /*return*/, key];
                }
            });
        });
    }
    // ## Encrypt
    function browserPublicEncrypt(key, plaintext) {
        return __awaiter(this, void 0, void 0, function () {
            var ciphertext;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, crypto.subtle.encrypt({ name: BROWSER_RSA_ALGO }, key.publicKey, stob(plaintext))];
                    case 1:
                        ciphertext = _a.sent();
                        return [2 /*return*/, btoh(ciphertext)];
                }
            });
        });
    }
    // ## Decrypt
    function browserPublicDecrypt(key, ciphertext) {
        return __awaiter(this, void 0, void 0, function () {
            var plaintext;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, crypto.subtle.decrypt({ name: BROWSER_RSA_ALGO }, key.privateKey, htob(ciphertext))];
                    case 1:
                        plaintext = _a.sent();
                        return [2 /*return*/, btos(plaintext)];
                }
            });
        });
    }
    // ## Sign
    function browserPublicSign(key, plaintext) {
        return __awaiter(this, void 0, void 0, function () {
            var algorithm, signature;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        algorithm = {
                            name: BROWSER_DSA_ALGO,
                            hash: { name: BROWSER_SHA_ALGO }
                        };
                        return [4 /*yield*/, crypto.subtle.sign(algorithm, key.privateKey, stob(plaintext))];
                    case 1:
                        signature = _a.sent();
                        return [2 /*return*/, btoh(signature)];
                }
            });
        });
    }
    // ## Verify
    function browserPublicVerify(key, signature, plaintext) {
        return __awaiter(this, void 0, void 0, function () {
            var algorithm;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        algorithm = {
                            name: BROWSER_DSA_ALGO,
                            hash: { name: BROWSER_SHA_ALGO }
                        };
                        return [4 /*yield*/, crypto.subtle.verify(algorithm, key.publicKey, htob(signature), stob(plaintext))];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    }
    // # Export
    var random = browserRandom;
    var hash = browserHash;
    var private_ = {
        key: browserPrivateKey,
        kdf: browserPrivateKdf,
        encrypt: browserPrivateEncrypt,
        decrypt: browserPrivateDecrypt,
        sign: browserPrivateSign,
        verify: browserPrivateVerify
    };
    function encrypt(secret, message) {
        return __awaiter(this, void 0, void 0, function () {
            var key, iv;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, private_.kdf(secret)];
                    case 1:
                        key = _a.sent();
                        return [4 /*yield*/, random(AES_GCM_IV_LENGTH_BYTES)];
                    case 2:
                        iv = _a.sent();
                        return [4 /*yield*/, private_.encrypt(key, iv, message)];
                    case 3: return [2 /*return*/, _a.sent()];
                }
            });
        });
    }
    function decrypt(secret, encryptedMessage) {
        return __awaiter(this, void 0, void 0, function () {
            var key;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, private_.kdf(secret)];
                    case 1:
                        key = _a.sent();
                        return [4 /*yield*/, private_.decrypt(key, encryptedMessage)];
                    case 2: return [2 /*return*/, _a.sent()];
                }
            });
        });
    }
    function sign(secret, message) {
        return __awaiter(this, void 0, void 0, function () {
            var key;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, private_.kdf(secret)];
                    case 1:
                        key = _a.sent();
                        return [4 /*yield*/, private_.sign(key, message)];
                    case 2: return [2 /*return*/, _a.sent()];
                }
            });
        });
    }
    function verify(secret, signature, message) {
        return __awaiter(this, void 0, void 0, function () {
            var key;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, private_.kdf(secret)];
                    case 1:
                        key = _a.sent();
                        return [4 /*yield*/, private_.verify(key, signature, message)];
                    case 2: return [2 /*return*/, _a.sent()];
                }
            });
        });
    }
    var public_ = {
        key: browserPublicKey,
        encrypt: browserPublicEncrypt,
        decrypt: browserPublicDecrypt,
        sign: browserPublicSign,
        verify: browserPublicVerify
    };
    var _internal = {
        stob: stob,
        btos: btos,
        byteToHex: byteToHex,
        btoh: btoh,
        htob: htob
    };
    var jwcl = {
        random: random,
        hash: hash,
        private: private_,
        public: public_,
        encrypt: encrypt,
        decrypt: decrypt,
        sign: sign,
        verify: verify,
        _internal: _internal
    };
    this.jwcl = jwcl;
}).call(this);
//# sourceMappingURL=jwcl.js.map