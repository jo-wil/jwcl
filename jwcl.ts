type Hex = string;
type Op = 'encrypt' | 'decrypt' | 'sign' | 'verify';

const jwcl = (() => {

    // ## Crypto Constants

    const AES_BLOCK_SIZE_BYTES = 16;
    const AES_IV_SIZE = AES_BLOCK_SIZE_BYTES;
    const AUTH_TAG_SIZE_BYTES = 16;
    const BITS_IN_BYTE = 8;    

    // ## Crypto Defaults
    
    const PRIVATE_KEY_LENGTH_BITS = 128;
    const PRIVATE_KEY_LENGTH_BYTES = PRIVATE_KEY_LENGTH_BITS/BITS_IN_BYTE;
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

        // ## Kdf

        const privateKdf = async (secret: string): Promise<Hex> => {
            const masterKey = await subtle.importKey('raw', stob(secret), { 
                name: 'PBKDF2' 
            }, false, ['deriveKey']);
            const derivedKey = await subtle.deriveKey({ 
                'name': 'PBKDF2',
                'salt': new Uint8Array([0,0,0,0,0,0,0,0]), // TODO research this
                'iterations': PBKDF2_ITERATIONS,
                'hash': HASH
            }, masterKey, { 
                'name': AES, 
                'length': PRIVATE_KEY_LENGTH_BITS 
            }, true, [ 'encrypt', 'decrypt' ]);
            const key = await subtle.exportKey('raw', derivedKey);
            return btoh(key);
        };

        // ## Encrypt

        const privateEncrypt = async (key: Hex, plaintext: string): Promise<Hex> => {
            const iv = await random(AES_IV_SIZE);
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

        const random = async (bytes: number): Promise<Hex> => {
            const output = new Uint8Array(bytes);
            crypto.getRandomValues(output);
            return btoh(output);
        };

        // ## Hash

        const hash = async (plaintext: string, algorithm: string = HASH): Promise<Hex> => {
            const hash = await subtle.digest(algorithm, stob(plaintext));
            return btoh(hash);    
        };

        // ## Encrypt
        
        const encrypt = async (secret: string, message: string): Promise<Hex> => {
            const key = await privateKdf(secret);
            return await privateEncrypt(key, message);
        };
        
        // ## Decrypt

        const decrypt = async (secret: string, encryptedMessage: Hex): Promise<string> => {
            const key = await privateKdf(secret);
            return await privateDecrypt(key, encryptedMessage);
        };
        
        // ## Sign
        
        const sign = async (secret: string, message: string): Promise<Hex> => {
            const key = await privateKdf(secret);
            return await privateSign(key, message);
        };
        
        // ## Verify
        
        const verify = async (secret: string, signature: Hex, message: string): Promise<boolean> => {
            const key = await privateKdf(secret);
            return await privateVerify(key, signature, message);
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

        const privateKey = async (op?: Op): Promise<Hex> => {
            if (op && !(['encrypt', 'decrypt', 'sign', 'verify'].includes(op))) {
                throw {
                    name: 'JWCL',
                    message: `jwcl.private.key ${op} is not a supported operation`
                };
            }
            return random(PRIVATE_KEY_LENGTH_BYTES);
        };

        // ## Kdf
        
        const privateKdf = async (secret: string): Promise<Hex> => {
            return new Promise<Hex>((resolve, reject) => {
                crypto.pbkdf2(
                    secret, 
                    Buffer.from([0,0,0,0,0,0,0,0]).toString('utf8'), 
                    PBKDF2_ITERATIONS, 
                    PRIVATE_KEY_LENGTH_BYTES, 
                    HASH, 
                    (err: Error, buffer: Buffer) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(buffer.toString('hex'));
                        }
                    }
                );
            });
        };

        // ## Encrypt

        const privateEncrypt = async (key: Hex, plaintext: string): Promise<Hex> => {
            const iv = await random(AES_IV_SIZE);
            const cipher = crypto.createCipheriv(AES, Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
            const ciphertext = iv + cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
            return ciphertext + cipher.getAuthTag().toString('hex');
        };

        // ## Decrypt
        
        // times 2 for hex
        const privateDecrypt = async (key: Hex, ciphertext: Hex): Promise<string> => {
            const length = ciphertext.length;
            const iv = ciphertext.substring(0, AES_IV_SIZE * 2);
            const ciphertext_ = ciphertext.substring(AES_IV_SIZE * 2, length - (AUTH_TAG_SIZE_BYTES * 2));
            const authTag = ciphertext.substring(length - (AUTH_TAG_SIZE_BYTES * 2), length);
            const decipher = crypto.createDecipheriv(AES, Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
            decipher.setAuthTag(Buffer.from(authTag, 'hex'));
            return decipher.update(ciphertext_, 'hex', 'utf8') + decipher.final('utf8');
        };

        // ## Sign
     
        const privateSign = async (key: Hex, plaintext: string): Promise<Hex> => {
            const hmac = crypto.createHmac(HASH, Buffer.from(key, 'hex'));
            hmac.update(plaintext);
            return hmac.digest('hex');
        };
        
        // ## Verify
        
        const privateVerify = async (key: Hex, signature: Hex, plaintext: string): Promise<boolean> => {
            const hmac = crypto.createHmac(HASH, Buffer.from(key, 'hex'));
            hmac.update(plaintext);
            return hmac.digest('hex')
                .split('')
                .map((c: string, i: number) => c === signature[i])
                .reduce((x: boolean, y: boolean) => {
                    return x && y;
                }, true);
        };

        // ## Random

        const random = (bytes: number): Promise<Hex> => {
            return new Promise<Hex>((resolve, reject) => {
                crypto.randomBytes(bytes, (err: Error, buffer: Buffer) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(buffer.toString('hex'));
                    }
                });
            });
        };
 
        // ## Hash

        const hash = async (plaintext: string, algorithm: string = HASH): Promise<Hex> => {
            const hash = crypto.createHash(algorithm);
            hash.update(plaintext);
            return hash.digest('hex');
        };

        // ## Encrypt
        
        const encrypt = async (secret: string, message: string): Promise<Hex> => {
            const key = await privateKdf(secret);
            return await privateEncrypt(key, message);
        };
        
        // ## Decrypt

        const decrypt = async (secret: string, encryptedMessage: Hex): Promise<string> => {
            const key = await privateKdf(secret);
            return await privateDecrypt(key, encryptedMessage);
        };
        
        // ## Sign
        
        const sign = async (secret: string, message: string): Promise<Hex> => {
            const key = await privateKdf(secret);
            return await privateSign(key, message);
        };
        
        // ## Verify
        
        const verify = async (secret: string, signature: Hex, message: string): Promise<boolean> => {
            const key = await privateKdf(secret);
            return await privateVerify(key, signature, message);
        };

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
    } else {
        return browser();
    }

})();
