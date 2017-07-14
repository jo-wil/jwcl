"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
const jwcl = (() => {
    // ## Crypto Constants
    const AES_BLOCK_SIZE_BYTES = 16;
    const AES_IV_SIZE = AES_BLOCK_SIZE_BYTES;
    const AUTH_TAG_SIZE_BYTES = 16;
    const BITS_IN_BYTE = 8;
    // ## Crypto Defaults
    const PRIVATE_KEY_LENGTH_BITS = 128;
    const PRIVATE_KEY_LENGTH_BYTES = PRIVATE_KEY_LENGTH_BITS / BITS_IN_BYTE;
    const PBKDF2_ITERATIONS = 10000;
    // TODO remove  
    const NOT_IMPLEMENTED = () => {
        throw {
            name: 'JWCL',
            message: 'not implemented'
        };
    };
    // # Browser
    const browser = () => {
        const crypto = window.crypto;
        const subtle = window.crypto.subtle;
        const hexReg = /[a-f0-9][a-f0-9]/g;
        const encoder = new TextEncoder('utf-8');
        const decoder = new TextDecoder('utf-8');
        // ## Internal
        const stob = (string) => {
            return encoder.encode(string);
        };
        const btos = (binary) => {
            const binaryArray = (binary instanceof ArrayBuffer) ? new Uint8Array(binary) : binary;
            return decoder.decode(binaryArray);
        };
        const byteToHex = (_byte) => {
            const hex = _byte.toString(16);
            return (hex.length === 1 ? '0' : '') + hex;
        };
        const btoh = (binary) => {
            const binaryArray = (binary instanceof ArrayBuffer) ? new Uint8Array(binary) : binary;
            return binaryArray.reduce((acc, val) => acc + byteToHex(val), '');
        };
        const htob = (hex) => {
            const hexArray = hex.match(hexReg);
            if (!hexArray) {
                throw {
                    name: 'JWCL',
                    message: 'jwcl._internal.htob input is not hex'
                };
            }
            return Uint8Array.from(hexArray.map(val => Number.parseInt(val, 16)));
        };
        // ## Crypto Defaults
        const HASH = 'SHA-256';
        const AES = 'AES-GCM';
        // ## Private Key
        // ## Key
        const privateKey = (op) => __awaiter(this, void 0, void 0, function* () {
            if (!op) {
                return random(PRIVATE_KEY_LENGTH_BYTES);
            }
            let cryptoKey;
            if (op === 'encrypt' || op === 'decrypt') {
                cryptoKey = yield subtle.generateKey({
                    name: AES,
                    length: PRIVATE_KEY_LENGTH_BITS
                }, true, ['encrypt', 'decrypt']);
            }
            else if (op === 'sign' || op === 'verify') {
                cryptoKey = yield subtle.generateKey({
                    name: 'HMAC',
                    hash: HASH
                }, true, ['sign', 'verify']);
            }
            else {
                throw {
                    name: 'JWCL',
                    message: `jwcl.private.key ${op} is not a supported operation`
                };
            }
            const key = yield subtle.exportKey('raw', cryptoKey);
            return btoh(key);
        });
        // ## Kdf
        const privateKdf = (secret) => __awaiter(this, void 0, void 0, function* () {
            const masterKey = yield subtle.importKey('raw', stob(secret), {
                name: 'PBKDF2'
            }, false, ['deriveKey']);
            const derivedKey = yield subtle.deriveKey({
                'name': 'PBKDF2',
                'salt': new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0]),
                'iterations': PBKDF2_ITERATIONS,
                'hash': HASH
            }, masterKey, {
                'name': AES,
                'length': PRIVATE_KEY_LENGTH_BITS
            }, true, ['encrypt', 'decrypt']);
            const key = yield subtle.exportKey('raw', derivedKey);
            return btoh(key);
        });
        // ## Encrypt
        const privateEncrypt = (key, plaintext) => __awaiter(this, void 0, void 0, function* () {
            const iv = yield random(AES_IV_SIZE);
            const algorithm = {
                name: AES,
                iv: htob(iv)
            };
            const cryptoKey = yield subtle.importKey('raw', htob(key), algorithm, false, ['encrypt']);
            const ciphertext = yield subtle.encrypt(algorithm, cryptoKey, stob(plaintext));
            return iv + btoh(ciphertext);
        });
        // ## Decrypt
        const privateDecrypt = (key, ciphertext) => __awaiter(this, void 0, void 0, function* () {
            const binaryCiphertext = htob(ciphertext);
            const algorithm = {
                name: AES,
                iv: binaryCiphertext.subarray(0, AES_IV_SIZE)
            };
            const cryptoKey = yield subtle.importKey('raw', htob(key), algorithm, false, ['decrypt']);
            const plaintext = yield subtle.decrypt(algorithm, cryptoKey, binaryCiphertext.subarray(AES_IV_SIZE));
            return btos(plaintext);
        });
        // ## Sign
        const privateSign = (key, plaintext) => __awaiter(this, void 0, void 0, function* () {
            const algorithm = {
                name: 'HMAC',
                hash: HASH
            };
            const cryptoKey = yield subtle.importKey('raw', htob(key), algorithm, false, ['sign']);
            const signature = yield subtle.sign(algorithm.name, cryptoKey, stob(plaintext));
            return btoh(signature);
        });
        // ## Verify
        const privateVerify = (key, signature, plaintext) => __awaiter(this, void 0, void 0, function* () {
            const algorithm = {
                name: 'HMAC',
                hash: HASH
            };
            const cryptoKey = yield subtle.importKey('raw', htob(key), algorithm, false, ['verify']);
            return subtle.verify(algorithm.name, cryptoKey, htob(signature), stob(plaintext));
        });
        // ## Random
        const random = (bytes) => __awaiter(this, void 0, void 0, function* () {
            const output = new Uint8Array(bytes);
            crypto.getRandomValues(output);
            return btoh(output);
        });
        // ## Hash
        const hash = (plaintext, algorithm = HASH) => __awaiter(this, void 0, void 0, function* () {
            const hash = yield subtle.digest(algorithm, stob(plaintext));
            return btoh(hash);
        });
        // ## Encrypt
        const encrypt = (secret, message) => __awaiter(this, void 0, void 0, function* () {
            const key = yield privateKdf(secret);
            return yield privateEncrypt(key, message);
        });
        // ## Decrypt
        const decrypt = (secret, encryptedMessage) => __awaiter(this, void 0, void 0, function* () {
            const key = yield privateKdf(secret);
            return yield privateDecrypt(key, encryptedMessage);
        });
        // ## Sign
        const sign = (secret, message) => __awaiter(this, void 0, void 0, function* () {
            const key = yield privateKdf(secret);
            return yield privateSign(key, message);
        });
        // ## Verify
        const verify = (secret, signature, message) => __awaiter(this, void 0, void 0, function* () {
            const key = yield privateKdf(secret);
            return yield privateVerify(key, signature, message);
        });
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
                kdf: privateKdf,
                encrypt: privateEncrypt,
                decrypt: privateDecrypt,
                sign: privateSign,
                verify: privateVerify
            },
            public: {
                key: NOT_IMPLEMENTED,
                encrypt: NOT_IMPLEMENTED,
                decrypt: NOT_IMPLEMENTED,
                sign: NOT_IMPLEMENTED,
                verify: NOT_IMPLEMENTED
            },
            random: random,
            hash: hash,
            encrypt: encrypt,
            decrypt: decrypt,
            sign: sign,
            verify: verify
        };
    };
    // # Node
    const node = () => {
        const crypto = require('crypto');
        // ## Crypto Defaults
        const HASH = 'sha256';
        const AES = 'id-aes128-GCM';
        // ## Private Key
        // ## Key
        const privateKey = (op) => __awaiter(this, void 0, void 0, function* () {
            if (op && !(['encrypt', 'decrypt', 'sign', 'verify'].includes(op))) {
                throw {
                    name: 'JWCL',
                    message: `jwcl.private.key ${op} is not a supported operation`
                };
            }
            return random(PRIVATE_KEY_LENGTH_BYTES);
        });
        // ## Kdf
        const privateKdf = (secret) => __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => {
                crypto.pbkdf2(secret, Buffer.from([0, 0, 0, 0, 0, 0, 0, 0]).toString('utf8'), PBKDF2_ITERATIONS, PRIVATE_KEY_LENGTH_BYTES, HASH, (err, buffer) => {
                    if (err) {
                        reject(err);
                    }
                    else {
                        resolve(buffer.toString('hex'));
                    }
                });
            });
        });
        // ## Encrypt
        const privateEncrypt = (key, plaintext) => __awaiter(this, void 0, void 0, function* () {
            const iv = yield random(AES_IV_SIZE);
            const cipher = crypto.createCipheriv(AES, Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
            const ciphertext = iv + cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
            return ciphertext + cipher.getAuthTag().toString('hex');
        });
        // ## Decrypt
        // times 2 for hex
        const privateDecrypt = (key, ciphertext) => __awaiter(this, void 0, void 0, function* () {
            const length = ciphertext.length;
            const iv = ciphertext.substring(0, AES_IV_SIZE * 2);
            const ciphertext_ = ciphertext.substring(AES_IV_SIZE * 2, length - (AUTH_TAG_SIZE_BYTES * 2));
            const authTag = ciphertext.substring(length - (AUTH_TAG_SIZE_BYTES * 2), length);
            const decipher = crypto.createDecipheriv(AES, Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
            decipher.setAuthTag(Buffer.from(authTag, 'hex'));
            return decipher.update(ciphertext_, 'hex', 'utf8') + decipher.final('utf8');
        });
        // ## Sign
        const privateSign = (key, plaintext) => __awaiter(this, void 0, void 0, function* () {
            const hmac = crypto.createHmac(HASH, Buffer.from(key, 'hex'));
            hmac.update(plaintext);
            return hmac.digest('hex');
        });
        // ## Verify
        const privateVerify = (key, signature, plaintext) => __awaiter(this, void 0, void 0, function* () {
            const hmac = crypto.createHmac(HASH, Buffer.from(key, 'hex'));
            hmac.update(plaintext);
            return hmac.digest('hex')
                .split('')
                .map((c, i) => c === signature[i])
                .reduce((x, y) => {
                return x && y;
            }, true);
        });
        // ## Random
        const random = (bytes) => {
            return new Promise((resolve, reject) => {
                crypto.randomBytes(bytes, (err, buffer) => {
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
        const hash = (plaintext, algorithm = HASH) => __awaiter(this, void 0, void 0, function* () {
            const hash = crypto.createHash(algorithm);
            hash.update(plaintext);
            return hash.digest('hex');
        });
        // ## Encrypt
        const encrypt = (secret, message) => __awaiter(this, void 0, void 0, function* () {
            const key = yield privateKdf(secret);
            return yield privateEncrypt(key, message);
        });
        // ## Decrypt
        const decrypt = (secret, encryptedMessage) => __awaiter(this, void 0, void 0, function* () {
            const key = yield privateKdf(secret);
            return yield privateDecrypt(key, encryptedMessage);
        });
        // ## Sign
        const sign = (secret, message) => __awaiter(this, void 0, void 0, function* () {
            const key = yield privateKdf(secret);
            return yield privateSign(key, message);
        });
        // ## Verify
        const verify = (secret, signature, message) => __awaiter(this, void 0, void 0, function* () {
            const key = yield privateKdf(secret);
            return yield privateVerify(key, signature, message);
        });
        return {
            private: {
                key: privateKey,
                kdf: privateKdf,
                encrypt: privateEncrypt,
                decrypt: privateDecrypt,
                sign: privateSign,
                verify: privateVerify
            },
            public: {
                key: NOT_IMPLEMENTED,
                encrypt: NOT_IMPLEMENTED,
                decrypt: NOT_IMPLEMENTED,
                sign: NOT_IMPLEMENTED,
                verify: NOT_IMPLEMENTED
            },
            random: random,
            hash: hash,
            encrypt: encrypt,
            decrypt: decrypt,
            sign: sign,
            verify: verify
        };
    };
    if (typeof module !== 'undefined' && module.exports) {
        exports.jwcl = node();
    }
    else {
        return browser();
    }
})();
//# sourceMappingURL=jwcl.js.map