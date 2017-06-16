type Hex = string;
type Op = 'encrypt' | 'decrypt' | 'sign' | 'verify';

const jwcl = ((window_) => {

    const crypto = window_.crypto;
    const subtle = window_.crypto.subtle;    

    const hexReg = /[a-f0-9][a-f0-9]/g;
    const encoder = new TextEncoder('utf-8');
    const decoder = new TextDecoder('utf-8');

    // ## Internal

    const stob = (string: string): Uint8Array => {
        return encoder.encode(string);
    };

    const btos = (binary: ArrayBuffer | ArrayBufferView): string => {
        const binaryArray = (binary instanceof ArrayBuffer) ? new Uint8Array(binary) : binary;
        return decoder.decode(binaryArray);
    };
 
    const byteToHex = (_byte: number): string => {
        const hex = _byte.toString(16);
        return (hex.length === 1 ? '0' : '') + hex;
    };
 
    const btoh = (binary: ArrayBuffer | Uint8Array): Hex => {
        const binaryArray = (binary instanceof ArrayBuffer) ? new Uint8Array(binary) : binary;
        return binaryArray.reduce( (acc, val) => acc + byteToHex(val), '');
    };
 
    const htob = (hex: Hex): Uint8Array => {
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

    const privateKey = async (op?: Op): Promise<Hex> => {
        if (!op) {
            return random(PRIVATE_KEY_LENGTH_BYTES);
        }
        let cryptoKey;
        if (op === 'encrypt' || op === 'decrypt') {
            cryptoKey = await subtle.generateKey({
                name: AES,
                length: PRIVATE_KEY_LENGTH_BITS
            }, true, ['encrypt', 'decrypt']);
        } else if (op === 'sign' || op === 'verify') {
            cryptoKey = await subtle.generateKey({
                name: 'HMAC',
                hash: HASH
            }, true, ['sign','verify']);
        } else {
            throw {
                name: 'JWCL',
                message: `jwcl.private.key ${op} is not a supported operation`
            };
        }
        const key = await subtle.exportKey('raw', cryptoKey);
        return btoh(key);
    };

    // ## Encrypt

    const privateEncrypt = async (key: Hex, plaintext: string): Promise<Hex> => {
        const iv = random(AES_IV_SIZE);
        const algorithm = {
            name: AES,
            iv: htob(iv)
        };
        const cryptoKey = await subtle.importKey('raw', htob(key), algorithm, false, ['encrypt']);
        const ciphertext = await subtle.encrypt(algorithm, cryptoKey, stob(plaintext));
        return iv + btoh(ciphertext);
    }; 

    // ## Decrypt
    
    const privateDecrypt = async (key: Hex, ciphertext: Hex): Promise<string> => {
        const binaryCiphertext = htob(ciphertext);
        const algorithm = {
            name: AES,
            iv: binaryCiphertext.subarray(0, AES_IV_SIZE)
        };
        const cryptoKey = await subtle.importKey('raw', htob(key), algorithm, false, ['decrypt']);
        const plaintext = await subtle.decrypt(algorithm, cryptoKey, binaryCiphertext.subarray(AES_IV_SIZE));
        return btos(plaintext);
    }; 

    // ## Sign
 
    const privateSign = async (key: Hex, plaintext: string): Promise<Hex> => {
        const algorithm = {
            name: 'HMAC',
            hash: HASH
        };
        const cryptoKey = await subtle.importKey('raw', htob(key), algorithm, false, ['sign']);
        const signature = await subtle.sign(algorithm.name, cryptoKey, stob(plaintext));
        return btoh(signature);
    };
    
    // ## Verify
    
    const privateVerify = async (key: Hex, signature: Hex, plaintext: string): Promise<boolean> => {
        const algorithm = {
            name: 'HMAC',
            hash: HASH
        };
        const cryptoKey = await subtle.importKey('raw', htob(key), algorithm, false, ['verify']);
        return subtle.verify(algorithm.name, cryptoKey, htob(signature), stob(plaintext));
    };

    // ## Random

    const random = (bytes: number): Hex => {
        const output = new Uint8Array(bytes);
        crypto.getRandomValues(output);
        return btoh(output);
    };

    // ## Hash

    const hash = async (plaintext: string, algorithm: string = HASH): Promise<Hex> => {
        const hash = await subtle.digest(algorithm, stob(plaintext));
        return btoh(hash);    
    };

    const _privateKdf = async (secret: string): Promise<Hex> => {
        const masterKey = await subtle.importKey('raw', stob(secret), { 
            name: 'PBKDF2' 
        }, false, ['deriveKey']);
        const derivedKey = await subtle.deriveKey({ 
            'name': 'PBKDF2',
            'salt': new Uint8Array(8), // TODO
            'iterations': 1000,
            'hash': HASH
        }, masterKey, { 
            'name': AES, 
            'length': PRIVATE_KEY_LENGTH_BITS 
        }, true, [ 'encrypt', 'decrypt' ]);
        const key = await subtle.exportKey('raw', derivedKey);
        return btoh(key);
    };

    // ## Encrypt
    
    const encrypt = async (secret: string, message: string): Promise<Hex> => {
        const key = await _privateKdf(secret);
        const encryptedMessage = await privateEncrypt(key, message);
        return encryptedMessage;
    };
    
    // ## Decrypt

    const decrypt = async (secret: string, encryptedMessage: Hex): Promise<Hex> => {
        const key = await _privateKdf(secret);
        const message = await privateDecrypt(key, encryptedMessage);
        return message;
    };
    
    // ## Sign
    
    const sign = async (secret: string, message: string): Promise<Hex> => {
        const key = await _privateKdf(secret);
        const signature = await privateSign(key, message);
        return signature;
    };
    
    // ## Verify
    
    const verify = async (secret: string, signature: Hex, message: string): Promise<boolean> => {
        const key = await _privateKdf(secret);
        return await privateVerify(key, signature, message);
    };

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
