// # JWCL

// TODO HAS NODE STUFF IN THIS VERSION

// ### Types

type Hex = string;
type Op = 'encrypt' | 'decrypt' | 'sign' | 'verify';
type Env = 'browser' | 'node';

(function () {

    // ## Environment

    const env: Env = (typeof module !== 'undefined' && module.exports) ? 'node' : 'browser';

    // ## Constants

    // Sizes

    const BITS_IN_BYTE: number = 8;    
    const PRIVATE_KEY_LENGTH_BITS: number = 128;
    const PRIVATE_KEY_LENGTH_BYTES: number = PRIVATE_KEY_LENGTH_BITS/BITS_IN_BYTE;

    // Algorithms

    const NODE_AES_ALGO: string = 'id-aes128-GCM';
    const NODE_HASH_ALGO: string = 'sha256';
    const BROWSER_AES_ALGO: string = 'AES-GCM';
    const BROWSER_HASH_ALGO: string = 'SHA-256';

    // Configurations

    const PBKDF2_ITERATIONS: number = 10000; 
    const AES_GCM_IV_LENGTH_BYTES: number = 96/BITS_IN_BYTE;
    const AES_GCM_AUTH_TAG_LENGTH_BYTES: number = 16;

    // # Internal

    const crypto = env === 'browser' ? window.crypto : require('crypto');
    const hexReg = /[a-f0-9][a-f0-9]/g;
    const encoder = env === 'browser' ? new TextEncoder('utf-8') : undefined;
    const decoder = env === 'browser' ? new TextDecoder('utf-8') : undefined;

    // ## Internal

    function stob(string_: string): Uint8Array {
         if (!encoder) {
            throw {
                name: 'JWCL',
                message: 'jwcl._internal.stob TextEncoder is undefined'
            };
        }       
        return encoder.encode(string_);
    }

    function btos(binary: ArrayBuffer | ArrayBufferView): string {
        if (!decoder) {
            throw {
                name: 'JWCL',
                message: 'jwcl._internal.btos TextDecoder is undefined'
            };
        }
        const binaryArray = (binary instanceof ArrayBuffer) ? new Uint8Array(binary) : binary;
        return decoder.decode(binaryArray);
    }
 
    function byteToHex(byte_: number): string {
        const hex = byte_.toString(16);
        return (hex.length === 1 ? '0' : '') + hex;
    }
    
    function btoh(binary: ArrayBuffer | Uint8Array): Hex {
        const binaryArray = (binary instanceof ArrayBuffer) ? new Uint8Array(binary) : binary;
        return binaryArray.reduce( (acc, val) => acc + byteToHex(val), '');
    }
 
    function htob(hex: Hex): Uint8Array {
        const hexArray = hex.match(hexReg);
        if (!hexArray) {
            throw {
                name: 'JWCL',
                message: 'jwcl._internal.htob input is not hex'
            };
        }
        return Uint8Array.from(hexArray.map(val => Number.parseInt(val, 16)));
    }

    // ## Random

    function nodeRandom(bytes: number): Promise<Hex> {
        return new Promise<Hex>((resolve, reject) => {
            crypto.randomBytes(bytes, (err: Error, buffer: Buffer) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(buffer.toString('hex'));
                }
            });
        });
    }

    async function browserRandom(bytes: number): Promise<Hex> {
        const output = new Uint8Array(bytes);
        crypto.getRandomValues(output);
        return btoh(output);
    }

    // ## Hash
    
    async function nodeHash(plaintext: string, algorithm: string = NODE_HASH_ALGO): Promise<Hex> {
        const hash = crypto.createHash(algorithm);
        hash.update(plaintext);
        return hash.digest('hex');
    }
    
    async function browserHash(plaintext: string, algorithm: string = BROWSER_HASH_ALGO): Promise<Hex> {
        const hash = await crypto.subtle.digest(algorithm, stob(plaintext));
        return btoh(hash);    
    }
    
    // # Private

    // ## Key

    async function nodePrivateKey(op?: Op): Promise<Hex> {
        if (op && !(['encrypt', 'decrypt', 'sign', 'verify'].includes(op))) {
            throw {
                name: 'JWCL',
                message: `jwcl.private.key ${op} is not a supported operation`
            };
        }
        return nodeRandom(PRIVATE_KEY_LENGTH_BYTES);
    }

    async function browserPrivateKey(op?: Op): Promise<Hex> {
        if (!op) {
            return browserRandom(PRIVATE_KEY_LENGTH_BYTES);
        }
        // TODO const 
        let key;
        if (op === 'encrypt' || op === 'decrypt') {
            key = await crypto.subtle.generateKey({
                name: BROWSER_AES_ALGO,
                length: PRIVATE_KEY_LENGTH_BITS
            }, true, ['encrypt', 'decrypt']);
        } else if (op === 'sign' || op === 'verify') {
            key = await crypto.subtle.generateKey({
                name: 'HMAC',
                hash: BROWSER_HASH_ALGO
            }, true, ['sign','verify']);
        } else {
            throw {
                name: 'JWCL',
                message: `jwcl.private.key ${op} is not a supported operation`
            };
        }
        const key_ = await crypto.subtle.exportKey('raw', key);
        return btoh(key_);
    }

    // ## KDF

    function nodePrivateKdf(secret: string): Promise<Hex> {
        return new Promise<Hex>((resolve, reject) => {
            crypto.pbkdf2(
                secret, 
                Buffer.from([0,0,0,0,0,0,0,0]).toString('utf8'), 
                PBKDF2_ITERATIONS, 
                PRIVATE_KEY_LENGTH_BYTES, 
                NODE_HASH_ALGO, 
                (err: Error, buffer: Buffer) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(buffer.toString('hex'));
                    }
                }
            );
        });
    } 

    async function browserPrivateKdf(secret: string): Promise<Hex> {
        const masterKey = await crypto.subtle.importKey('raw', stob(secret), { 
            name: 'PBKDF2' 
        }, false, ['deriveKey']);
        const derivedKey = await crypto.subtle.deriveKey({ 
            'name': 'PBKDF2',
            'salt': new Uint8Array([0,0,0,0,0,0,0,0]), // TODO research this
            'iterations': PBKDF2_ITERATIONS,
            'hash': BROWSER_HASH_ALGO
        }, masterKey, { 
            'name': BROWSER_AES_ALGO, 
            'length': PRIVATE_KEY_LENGTH_BITS 
        }, true, [ 'encrypt', 'decrypt' ]);
        const key = await crypto.subtle.exportKey('raw', derivedKey);
        return btoh(key);
    }

    // ## Encrypt

    async function nodePrivateEncrypt(key: Hex, iv: Hex, plaintext: string): Promise<Hex> {
        const cipher = crypto.createCipheriv(NODE_AES_ALGO, Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
        const ciphertext = iv + cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
        return ciphertext + cipher.getAuthTag().toString('hex');
    }

    async function browserPrivateEncrypt(key: Hex, iv: Hex, plaintext: string): Promise<Hex> {
        const algorithm = {
            name: BROWSER_AES_ALGO,
            iv: htob(iv)
        };
        const cryptoKey = await crypto.subtle.importKey('raw', htob(key), algorithm, false, ['encrypt']);
        const ciphertext = await crypto.subtle.encrypt(algorithm, cryptoKey, stob(plaintext));
        return iv + btoh(ciphertext);  
    }

    // ## Decrypt 

    async function nodePrivateDecrypt(key: Hex, ciphertext: string): Promise<Hex> {
        const length = ciphertext.length;
        const iv = ciphertext.substring(0, AES_GCM_IV_LENGTH_BYTES * 2);
        const ciphertext_ = ciphertext.substring(AES_GCM_IV_LENGTH_BYTES * 2, length - (AES_GCM_AUTH_TAG_LENGTH_BYTES * 2));
        const authTag = ciphertext.substring(length - (AES_GCM_AUTH_TAG_LENGTH_BYTES * 2), length);
        const decipher = crypto.createDecipheriv(NODE_AES_ALGO, Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
        decipher.setAuthTag(Buffer.from(authTag, 'hex'));
        return decipher.update(ciphertext_, 'hex', 'utf8') + decipher.final('utf8');
    }

    async function browserPrivateDecrypt(key: Hex, ciphertext: string): Promise<Hex> {
        const binaryCiphertext = htob(ciphertext);
        const algorithm = {
            name: BROWSER_AES_ALGO,
            iv: binaryCiphertext.subarray(0, AES_GCM_IV_LENGTH_BYTES)
        };
        const cryptoKey = await crypto.subtle.importKey('raw', htob(key), algorithm, false, ['decrypt']);
        const plaintext = await crypto.subtle.decrypt(algorithm, cryptoKey, binaryCiphertext.subarray(AES_GCM_IV_LENGTH_BYTES));
        return btos(plaintext);
    }

    // ## Sign

    async function nodePrivateSign(key: Hex, plaintext: string): Promise<Hex> {
        const hmac = crypto.createHmac(NODE_HASH_ALGO, Buffer.from(key, 'hex'));
        hmac.update(plaintext);
        return hmac.digest('hex');
    }
    
    async function browserPrivateSign(key: Hex, plaintext: string): Promise<Hex> {
        const algorithm = {
            name: 'HMAC',
            hash: BROWSER_HASH_ALGO
        };
        const cryptoKey = await crypto.subtle.importKey('raw', htob(key), algorithm, false, ['sign']);
        const signature = await crypto.subtle.sign(algorithm.name, cryptoKey, stob(plaintext));
        return btoh(signature);
    }

    // ## Verify

    async function nodePrivateVerify(key: Hex, signature: Hex, plaintext: string): Promise<boolean> {
        const hmac = crypto.createHmac(NODE_HASH_ALGO, Buffer.from(key, 'hex'));
        hmac.update(plaintext);
        return hmac.digest('hex') === signature;
            // TODO constant time string compare???
            //.split('')
            //.map((c: string, i: number) => c === signature[i])
            //.reduce((x: boolean, y: boolean) => {
            //    return x && y;
            //}, true);
    }
    
    async function browserPrivateVerify(key: Hex, signature: Hex, plaintext: string): Promise<boolean> {
        const algorithm = {
            name: 'HMAC',
            hash: BROWSER_HASH_ALGO
        };
        const key_ = await crypto.subtle.importKey('raw', htob(key), algorithm, false, ['verify']);
        return crypto.subtle.verify(algorithm.name, key_, htob(signature), stob(plaintext));
    }

    // # Public TODO type all of the any's

    // ## Key

    // TODO async function nodePublicKey(op: Op): Promise<any> {}
    
    async function browserPublicKey(op: Op): Promise<any> {
        let key;
        if (op === 'encrypt' || op === 'decrypt') {
            key = await crypto.subtle.generateKey({
                name: 'RSA-OAEP',
                modulusLength: 2048, //can be 1024, 2048, or 4096
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: {name: 'SHA-256'}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
            }, true, ['encrypt', 'decrypt']);
        } else if (op === 'sign' || op === 'verify') {
            key = await crypto.subtle.generateKey({
                name: 'ECDSA',
                namedCurve: 'P-256',
            }, true, ['sign', 'verify']);
        } else {
            throw {
                name: 'JWCL',
                message: `jwcl.public.key ${op} is not a supported operation`
            };
        }
        return key; 
    } 
 
    // ## Encrypt

    async function browserPublicEncrypt(key: any, plaintext: string): Promise<Hex> {
        const ciphertext = await crypto.subtle.encrypt({name: 'RSA-OAEP'}, key.publicKey, stob(plaintext));
        return btoh(ciphertext);
    }

    // ## Decrypt
    
    async function browserPublicDecrypt(key: any, ciphertext: Hex): Promise<string> {
        const plaintext = await crypto.subtle.decrypt({name: 'RSA-OAEP'}, key.privateKey, htob(ciphertext));
        return btos(plaintext);
    }
    
    // ## Sign

    async function browserPublicSign(key: any, plaintext: string): Promise<Hex> {
        const algorithm = {
            name: 'ECDSA',
            hash: {name: 'SHA-256'}
        };
        const signature = await crypto.subtle.sign(algorithm, key.privateKey, stob(plaintext));
        return btoh(signature); 
    } 

    // ## Verify TODO
   
    async function browserPublicVerify(key: any, signature: Hex, plaintext: string): Promise<boolean> {
        const algorithm = {
            name: 'ECDSA',
            hash: {name: 'SHA-256'}
        };
        return await crypto.subtle.verify(algorithm, key.publicKey, htob(signature), stob(plaintext));
    }

    // # Export

    const random = env === 'browser' ? browserRandom : nodeRandom;
    const hash = env === 'browser' ? browserHash : nodeHash;

    const private_ = {
        key: env === 'browser' ? browserPrivateKey : nodePrivateKey, 
        kdf: env === 'browser' ? browserPrivateKdf : nodePrivateKdf, 
        encrypt: env === 'browser' ? browserPrivateEncrypt : nodePrivateEncrypt,
        decrypt: env === 'browser' ? browserPrivateDecrypt : nodePrivateDecrypt,
        sign: env === 'browser' ? browserPrivateSign : nodePrivateSign,
        verify: env === 'browser' ? browserPrivateVerify : nodePrivateVerify
    };

    async function encrypt(secret: string, message: string): Promise<Hex> {
        const key = await private_.kdf(secret);
        const iv = await random(AES_GCM_IV_LENGTH_BYTES); 
        return await private_.encrypt(key, iv, message);
    }
    
    async function decrypt(secret: string, encryptedMessage: Hex): Promise<string> {
        const key = await private_.kdf(secret);
        return await private_.decrypt(key, encryptedMessage);
    }
    
    async function sign(secret: string, message: string): Promise<Hex> {
        const key = await private_.kdf(secret);
        return await private_.sign(key, message);
    }
    
    async function verify(secret: string, signature: Hex, message: string): Promise<boolean> {
        const key = await private_.kdf(secret);
        return await private_.verify(key, signature, message);
    }

    const public_ = {
        key: env === 'browser' ? browserPublicKey : undefined,
        encrypt: env === 'browser' ? browserPublicEncrypt : undefined
        decrypt: env === 'browser' ? browserPublicDecrypt : undefined
        sign: env === 'browser' ? browserPublicSign : undefined,
        verify: env === 'browser' ? browserPublicVerify : undefined
    };

    const _internal = {
        stob: stob,
        btos: btos,
        byteToHex: byteToHex,
        btoh: btoh,
        htob: htob
    };

    const jwcl = {
        random: random,
        hash: hash,
        private: private_,
        public: public_,
        encrypt: encrypt,
        decrypt: decrypt,
        sign: sign,
        verify: verify,
        _internal: env === 'browser' ? _internal : undefined
    };

    if (env === 'browser') {
        this.jwcl = jwcl;
    } else if (env === 'node') {
        exports.jwcl = jwcl;
    }
 
}).call(this);
