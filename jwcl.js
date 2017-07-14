"use strict";
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
var _this = this;
(function () {
    // ## Crypto Constants
    var AES_BLOCK_SIZE_BYTES = 16;
    var AES_IV_SIZE = AES_BLOCK_SIZE_BYTES;
    var AUTH_TAG_SIZE_BYTES = 16;
    var BITS_IN_BYTE = 8;
    // ## Crypto Defaults
    var PRIVATE_KEY_LENGTH_BITS = 128;
    var PRIVATE_KEY_LENGTH_BYTES = PRIVATE_KEY_LENGTH_BITS / BITS_IN_BYTE;
    var PBKDF2_ITERATIONS = 10000;
    // TODO remove  
    var NOT_IMPLEMENTED = function () {
        throw {
            name: 'JWCL',
            message: 'not implemented'
        };
    };
    // # Browser
    var browser = function () {
        var crypto = window.crypto;
        var subtle = window.crypto.subtle;
        var hexReg = /[a-f0-9][a-f0-9]/g;
        var encoder = new TextEncoder('utf-8');
        var decoder = new TextDecoder('utf-8');
        // ## Internal
        var stob = function (string) {
            return encoder.encode(string);
        };
        var btos = function (binary) {
            var binaryArray = (binary instanceof ArrayBuffer) ? new Uint8Array(binary) : binary;
            return decoder.decode(binaryArray);
        };
        var byteToHex = function (_byte) {
            var hex = _byte.toString(16);
            return (hex.length === 1 ? '0' : '') + hex;
        };
        var btoh = function (binary) {
            var binaryArray = (binary instanceof ArrayBuffer) ? new Uint8Array(binary) : binary;
            return binaryArray.reduce(function (acc, val) { return acc + byteToHex(val); }, '');
        };
        var htob = function (hex) {
            var hexArray = hex.match(hexReg);
            if (!hexArray) {
                throw {
                    name: 'JWCL',
                    message: 'jwcl._internal.htob input is not hex'
                };
            }
            return Uint8Array.from(hexArray.map(function (val) { return Number.parseInt(val, 16); }));
        };
        // ## Crypto Defaults
        var HASH = 'SHA-256';
        var AES = 'AES-GCM';
        // ## Private Key
        // ## Key
        var privateKey = function (op) { return __awaiter(_this, void 0, void 0, function () {
            var cryptoKey, key;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (!op) {
                            return [2 /*return*/, random(PRIVATE_KEY_LENGTH_BYTES)];
                        }
                        if (!(op === 'encrypt' || op === 'decrypt')) return [3 /*break*/, 2];
                        return [4 /*yield*/, subtle.generateKey({
                                name: AES,
                                length: PRIVATE_KEY_LENGTH_BITS
                            }, true, ['encrypt', 'decrypt'])];
                    case 1:
                        cryptoKey = _a.sent();
                        return [3 /*break*/, 5];
                    case 2:
                        if (!(op === 'sign' || op === 'verify')) return [3 /*break*/, 4];
                        return [4 /*yield*/, subtle.generateKey({
                                name: 'HMAC',
                                hash: HASH
                            }, true, ['sign', 'verify'])];
                    case 3:
                        cryptoKey = _a.sent();
                        return [3 /*break*/, 5];
                    case 4: throw {
                        name: 'JWCL',
                        message: "jwcl.private.key " + op + " is not a supported operation"
                    };
                    case 5: return [4 /*yield*/, subtle.exportKey('raw', cryptoKey)];
                    case 6:
                        key = _a.sent();
                        return [2 /*return*/, btoh(key)];
                }
            });
        }); };
        // ## Kdf
        var purePrivateKdf = function (secret) { return __awaiter(_this, void 0, void 0, function () {
            var masterKey, derivedKey, key;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, subtle.importKey('raw', stob(secret), {
                            name: 'PBKDF2'
                        }, false, ['deriveKey'])];
                    case 1:
                        masterKey = _a.sent();
                        return [4 /*yield*/, subtle.deriveKey({
                                'name': 'PBKDF2',
                                'salt': new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0]),
                                'iterations': PBKDF2_ITERATIONS,
                                'hash': HASH
                            }, masterKey, {
                                'name': AES,
                                'length': PRIVATE_KEY_LENGTH_BITS
                            }, true, ['encrypt', 'decrypt'])];
                    case 2:
                        derivedKey = _a.sent();
                        return [4 /*yield*/, subtle.exportKey('raw', derivedKey)];
                    case 3:
                        key = _a.sent();
                        return [2 /*return*/, btoh(key)];
                }
            });
        }); };
        // ## Encrypt
        var purePrivateEncrypt = function (iv, key, plaintext) { return __awaiter(_this, void 0, void 0, function () {
            var algorithm, cryptoKey, ciphertext;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        algorithm = {
                            name: AES,
                            iv: htob(iv)
                        };
                        return [4 /*yield*/, subtle.importKey('raw', htob(key), algorithm, false, ['encrypt'])];
                    case 1:
                        cryptoKey = _a.sent();
                        return [4 /*yield*/, subtle.encrypt(algorithm, cryptoKey, stob(plaintext))];
                    case 2:
                        ciphertext = _a.sent();
                        return [2 /*return*/, iv + btoh(ciphertext)];
                }
            });
        }); };
        var privateEncrypt = function (key, plaintext) { return __awaiter(_this, void 0, void 0, function () {
            var iv;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, random(AES_IV_SIZE)];
                    case 1:
                        iv = _a.sent();
                        return [4 /*yield*/, purePrivateEncrypt(iv, key, plaintext)];
                    case 2: return [2 /*return*/, _a.sent()];
                }
            });
        }); };
        // ## Decrypt
        var purePrivateDecrypt = function (key, ciphertext) { return __awaiter(_this, void 0, void 0, function () {
            var binaryCiphertext, algorithm, cryptoKey, plaintext;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        binaryCiphertext = htob(ciphertext);
                        algorithm = {
                            name: AES,
                            iv: binaryCiphertext.subarray(0, AES_IV_SIZE)
                        };
                        return [4 /*yield*/, subtle.importKey('raw', htob(key), algorithm, false, ['decrypt'])];
                    case 1:
                        cryptoKey = _a.sent();
                        return [4 /*yield*/, subtle.decrypt(algorithm, cryptoKey, binaryCiphertext.subarray(AES_IV_SIZE))];
                    case 2:
                        plaintext = _a.sent();
                        return [2 /*return*/, btos(plaintext)];
                }
            });
        }); };
        // ## Sign
        var purePrivateSign = function (key, plaintext) { return __awaiter(_this, void 0, void 0, function () {
            var algorithm, cryptoKey, signature;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        algorithm = {
                            name: 'HMAC',
                            hash: HASH
                        };
                        return [4 /*yield*/, subtle.importKey('raw', htob(key), algorithm, false, ['sign'])];
                    case 1:
                        cryptoKey = _a.sent();
                        return [4 /*yield*/, subtle.sign(algorithm.name, cryptoKey, stob(plaintext))];
                    case 2:
                        signature = _a.sent();
                        return [2 /*return*/, btoh(signature)];
                }
            });
        }); };
        // ## Verify
        var purePrivateVerify = function (key, signature, plaintext) { return __awaiter(_this, void 0, void 0, function () {
            var algorithm, cryptoKey;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        algorithm = {
                            name: 'HMAC',
                            hash: HASH
                        };
                        return [4 /*yield*/, subtle.importKey('raw', htob(key), algorithm, false, ['verify'])];
                    case 1:
                        cryptoKey = _a.sent();
                        return [2 /*return*/, subtle.verify(algorithm.name, cryptoKey, htob(signature), stob(plaintext))];
                }
            });
        }); };
        // ## Random
        var random = function (bytes) { return __awaiter(_this, void 0, void 0, function () {
            var output;
            return __generator(this, function (_a) {
                output = new Uint8Array(bytes);
                crypto.getRandomValues(output);
                return [2 /*return*/, btoh(output)];
            });
        }); };
        // ## Hash
        var hash = function (plaintext, algorithm) {
            if (algorithm === void 0) { algorithm = HASH; }
            return __awaiter(_this, void 0, void 0, function () {
                var hash;
                return __generator(this, function (_a) {
                    switch (_a.label) {
                        case 0: return [4 /*yield*/, subtle.digest(algorithm, stob(plaintext))];
                        case 1:
                            hash = _a.sent();
                            return [2 /*return*/, btoh(hash)];
                    }
                });
            });
        };
        // ## Export
        return {
            _internal: {
                stob: stob,
                btos: btos,
                byteToHex: byteToHex,
                btoh: btoh,
                htob: htob
            },
            private: {
                key: privateKey,
                kdf: purePrivateKdf,
                _encrypt: purePrivateEncrypt,
                encrypt: privateEncrypt,
                decrypt: purePrivateDecrypt,
                sign: purePrivateSign,
                verify: purePrivateVerify
            },
            public: {
                key: NOT_IMPLEMENTED,
                encrypt: NOT_IMPLEMENTED,
                decrypt: NOT_IMPLEMENTED,
                sign: NOT_IMPLEMENTED,
                verify: NOT_IMPLEMENTED
            },
            random: random,
            hash: hash
        };
    };
    // # Node
    var node = function () {
        var crypto = require('crypto');
        // ## Crypto Defaults
        var HASH = 'sha256';
        var AES = 'id-aes128-GCM';
        // ## Private Key
        // ## Key
        var privateKey = function (op) { return __awaiter(_this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                if (op && !(['encrypt', 'decrypt', 'sign', 'verify'].includes(op))) {
                    throw {
                        name: 'JWCL',
                        message: "jwcl.private.key " + op + " is not a supported operation"
                    };
                }
                return [2 /*return*/, random(PRIVATE_KEY_LENGTH_BYTES)];
            });
        }); };
        // ## Kdf
        var purePrivateKdf = function (secret) { return __awaiter(_this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, new Promise(function (resolve, reject) {
                        crypto.pbkdf2(secret, Buffer.from([0, 0, 0, 0, 0, 0, 0, 0]).toString('utf8'), PBKDF2_ITERATIONS, PRIVATE_KEY_LENGTH_BYTES, HASH, function (err, buffer) {
                            if (err) {
                                reject(err);
                            }
                            else {
                                resolve(buffer.toString('hex'));
                            }
                        });
                    })];
            });
        }); };
        // ## Encrypt
        var purePrivateEncrypt = function (iv, key, plaintext) { return __awaiter(_this, void 0, void 0, function () {
            var cipher, ciphertext;
            return __generator(this, function (_a) {
                cipher = crypto.createCipheriv(AES, Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
                ciphertext = iv + cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
                return [2 /*return*/, ciphertext + cipher.getAuthTag().toString('hex')];
            });
        }); };
        var privateEncrypt = function (key, plaintext) { return __awaiter(_this, void 0, void 0, function () {
            var iv;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, random(AES_IV_SIZE)];
                    case 1:
                        iv = _a.sent();
                        return [4 /*yield*/, purePrivateEncrypt(iv, key, plaintext)];
                    case 2: return [2 /*return*/, _a.sent()];
                }
            });
        }); };
        // ## Decrypt
        // times 2 for hex
        var purePrivateDecrypt = function (key, ciphertext) { return __awaiter(_this, void 0, void 0, function () {
            var length, iv, ciphertext_, authTag, decipher;
            return __generator(this, function (_a) {
                length = ciphertext.length;
                iv = ciphertext.substring(0, AES_IV_SIZE * 2);
                ciphertext_ = ciphertext.substring(AES_IV_SIZE * 2, length - (AUTH_TAG_SIZE_BYTES * 2));
                authTag = ciphertext.substring(length - (AUTH_TAG_SIZE_BYTES * 2), length);
                decipher = crypto.createDecipheriv(AES, Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
                decipher.setAuthTag(Buffer.from(authTag, 'hex'));
                return [2 /*return*/, decipher.update(ciphertext_, 'hex', 'utf8') + decipher.final('utf8')];
            });
        }); };
        // ## Sign
        var purePrivateSign = function (key, plaintext) { return __awaiter(_this, void 0, void 0, function () {
            var hmac;
            return __generator(this, function (_a) {
                hmac = crypto.createHmac(HASH, Buffer.from(key, 'hex'));
                hmac.update(plaintext);
                return [2 /*return*/, hmac.digest('hex')];
            });
        }); };
        // ## Verify
        var purePrivateVerify = function (key, signature, plaintext) { return __awaiter(_this, void 0, void 0, function () {
            var hmac;
            return __generator(this, function (_a) {
                hmac = crypto.createHmac(HASH, Buffer.from(key, 'hex'));
                hmac.update(plaintext);
                return [2 /*return*/, hmac.digest('hex')
                        .split('')
                        .map(function (c, i) { return c === signature[i]; })
                        .reduce(function (x, y) {
                        return x && y;
                    }, true)];
            });
        }); };
        // ## Random
        var random = function (bytes) {
            return new Promise(function (resolve, reject) {
                crypto.randomBytes(bytes, function (err, buffer) {
                    if (err) {
                        reject(err);
                    }
                    else {
                        resolve(buffer.toString('hex'));
                    }
                });
            });
        };
        // ## Hash
        var hash = function (plaintext, algorithm) {
            if (algorithm === void 0) { algorithm = HASH; }
            return __awaiter(_this, void 0, void 0, function () {
                var hash;
                return __generator(this, function (_a) {
                    hash = crypto.createHash(algorithm);
                    hash.update(plaintext);
                    return [2 /*return*/, hash.digest('hex')];
                });
            });
        };
        return {
            private: {
                key: privateKey,
                kdf: purePrivateKdf,
                _encrypt: purePrivateEncrypt,
                encrypt: privateEncrypt,
                decrypt: purePrivateDecrypt,
                sign: purePrivateSign,
                verify: purePrivateVerify
            },
            public: {
                key: NOT_IMPLEMENTED,
                encrypt: NOT_IMPLEMENTED,
                decrypt: NOT_IMPLEMENTED,
                sign: NOT_IMPLEMENTED,
                verify: NOT_IMPLEMENTED
            },
            random: random,
            hash: hash
        };
    };
    var env = (function () { return (typeof module !== 'undefined' && module.exports) ? 'node' : 'browser'; })();
    var _jwcl = env === 'browser' ? browser() : node();
    // ## Encrypt
    var encrypt = function (secret, message) { return __awaiter(_this, void 0, void 0, function () {
        var key;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, _jwcl.private.kdf(secret)];
                case 1:
                    key = _a.sent();
                    return [4 /*yield*/, _jwcl.private.encrypt(key, message)];
                case 2: return [2 /*return*/, _a.sent()];
            }
        });
    }); };
    // ## Decrypt
    var decrypt = function (secret, encryptedMessage) { return __awaiter(_this, void 0, void 0, function () {
        var key;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, _jwcl.private.kdf(secret)];
                case 1:
                    key = _a.sent();
                    return [4 /*yield*/, _jwcl.private.decrypt(key, encryptedMessage)];
                case 2: return [2 /*return*/, _a.sent()];
            }
        });
    }); };
    // ## Sign
    var sign = function (secret, message) { return __awaiter(_this, void 0, void 0, function () {
        var key;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, _jwcl.private.kdf(secret)];
                case 1:
                    key = _a.sent();
                    return [4 /*yield*/, _jwcl.private.sign(key, message)];
                case 2: return [2 /*return*/, _a.sent()];
            }
        });
    }); };
    // ## Verify
    var verify = function (secret, signature, message) { return __awaiter(_this, void 0, void 0, function () {
        var key;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, _jwcl.private.kdf(secret)];
                case 1:
                    key = _a.sent();
                    return [4 /*yield*/, _jwcl.private.verify(key, signature, message)];
                case 2: return [2 /*return*/, _a.sent()];
            }
        });
    }); };
    var jwcl = Object.assign({}, _jwcl, {
        encrypt: encrypt,
        decrypt: decrypt,
        sign: sign,
        verify: verify
    });
    if (env === 'browser') {
        _this.jwcl = jwcl;
    }
    else if (env === 'node') {
        exports.jwcl = jwcl;
    }
}).call(this);
//# sourceMappingURL=jwcl.js.map