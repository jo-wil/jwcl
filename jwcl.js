"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
const jwcl = ((window_) => {
    const crypto = window_.crypto;
    const subtle = window_.crypto.subtle;
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
    const PRIVATE_KEY_LENGTH_BITS = 128;
    const PRIVATE_KEY_LENGTH_BYTES = 16;
    // ## Crypto Constants
    const AES_BLOCK_SIZE_BYTES = 16;
    const AES_IV_SIZE = AES_BLOCK_SIZE_BYTES;
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
    // ## Encrypt
    const privateEncrypt = (key, plaintext) => __awaiter(this, void 0, void 0, function* () {
        const iv = random(AES_IV_SIZE);
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
    const random = (bytes) => {
        const output = new Uint8Array(bytes);
        crypto.getRandomValues(output);
        return btoh(output);
    };
    // ## Hash
    const hash = (plaintext, algorithm = HASH) => __awaiter(this, void 0, void 0, function* () {
        const hash = yield subtle.digest(algorithm, stob(plaintext));
        return btoh(hash);
    });
    const _privateKdf = (secret) => __awaiter(this, void 0, void 0, function* () {
        const masterKey = yield subtle.importKey('raw', stob(secret), {
            name: 'PBKDF2'
        }, false, ['deriveKey']);
        const derivedKey = yield subtle.deriveKey({
            'name': 'PBKDF2',
            'salt': new Uint8Array(8),
            'iterations': 1000,
            'hash': HASH
        }, masterKey, {
            'name': AES,
            'length': PRIVATE_KEY_LENGTH_BITS
        }, true, ['encrypt', 'decrypt']);
        const key = yield subtle.exportKey('raw', derivedKey);
        return btoh(key);
    });
    // ## Encrypt
    const encrypt = (secret, message) => __awaiter(this, void 0, void 0, function* () {
        const key = yield _privateKdf(secret);
        const encryptedMessage = yield privateEncrypt(key, message);
        return encryptedMessage;
    });
    // ## Decrypt
    const decrypt = (secret, encryptedMessage) => __awaiter(this, void 0, void 0, function* () {
        const key = yield _privateKdf(secret);
        const message = yield privateDecrypt(key, encryptedMessage);
        return message;
    });
    // ## Sign
    const sign = (secret, message) => __awaiter(this, void 0, void 0, function* () {
        const key = yield _privateKdf(secret);
        const signature = yield privateSign(key, message);
        return signature;
    });
    // ## Verify
    const verify = (secret, signature, message) => __awaiter(this, void 0, void 0, function* () {
        const key = yield _privateKdf(secret);
        return yield privateVerify(key, signature, message);
    });
    // ## Export
    const NOT_IMPLEMENTED = () => {
        throw 'Not implemented';
    };
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
})(window);
//# sourceMappingURL=jwcl.js.map