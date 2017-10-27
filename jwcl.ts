// # JWCL

// ### Types

type Hex = string;
type Op = 'encrypt' | 'decrypt' | 'sign' | 'verify';

(function () {

    // ## Constants

    // Sizes

    const BITS_IN_BYTE: number = 8;    
    const PRIVATE_KEY_LENGTH_BITS: number = 128;
    const PRIVATE_KEY_LENGTH_BYTES: number = PRIVATE_KEY_LENGTH_BITS/BITS_IN_BYTE;

    // Algorithms

    const BROWSER_AES_ALGO: string = 'AES-GCM';
    const BROWSER_SHA_ALGO: string = 'SHA-256';
    const BROWSER_HMAC_ALGO: string = 'HMAC';
    const BROWSER_RSA_ALGO: string = 'RSA-OAEP';
    const BROWSER_DSA_ALGO: string = 'ECDSA';

    // Configurations

    const PBKDF2_ITERATIONS: number = 10000; 
    const AES_GCM_IV_LENGTH_BYTES: number = 96/BITS_IN_BYTE;
    const AES_GCM_AUTH_TAG_LENGTH_BYTES: number = 16;

    // # Internal

    const crypto = window.crypto;
    const subtle = window.crypto.subtle;
    const hexReg = /[a-f0-9][a-f0-9]/g;
    const encoder = new TextEncoder('utf-8');
    const decoder = new TextDecoder('utf-8');

    // ## Internal

    function stob(string_: string): Uint8Array {
        return encoder.encode(string_);
    }

    function btos(binary: ArrayBuffer | ArrayBufferView): string {
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

    async function browserRandom(bytes: number): Promise<Hex> {
        const output = new Uint8Array(bytes);
        crypto.getRandomValues(output);
        return btoh(output);
    }

    // ## Hash
    
    async function browserHash(plaintext: string, algorithm: string = BROWSER_SHA_ALGO): Promise<Hex> {
        const hash = await crypto.subtle.digest(algorithm, stob(plaintext));
        return btoh(hash);    
    }
    
    // # Private

    // ## Key

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
                name: BROWSER_HMAC_ALGO,
                hash: BROWSER_SHA_ALGO
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

    async function browserPrivateKdf(secret: string): Promise<Hex> {
        const masterKey = await crypto.subtle.importKey('raw', stob(secret), { 
            name: 'PBKDF2' 
        }, false, ['deriveKey']);
        const derivedKey = await crypto.subtle.deriveKey({ 
            'name': 'PBKDF2',
            'salt': new Uint8Array([0,0,0,0,0,0,0,0]), // TODO research this
            'iterations': PBKDF2_ITERATIONS,
            'hash': BROWSER_SHA_ALGO
        }, masterKey, { 
            'name': BROWSER_AES_ALGO, 
            'length': PRIVATE_KEY_LENGTH_BITS 
        }, true, [ 'encrypt', 'decrypt' ]);
        const key = await crypto.subtle.exportKey('raw', derivedKey);
        return btoh(key);
    }

    // ## Encrypt

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

    async function browserPrivateSign(key: Hex, plaintext: string): Promise<Hex> {
        const algorithm = {
            name: BROWSER_HMAC_ALGO,
            hash: BROWSER_SHA_ALGO
        };
        const cryptoKey = await crypto.subtle.importKey('raw', htob(key), algorithm, false, ['sign']);
        const signature = await crypto.subtle.sign(algorithm.name, cryptoKey, stob(plaintext));
        return btoh(signature);
    }

    // ## Verify

    async function browserPrivateVerify(key: Hex, signature: Hex, plaintext: string): Promise<boolean> {
        const algorithm = {
            name: BROWSER_HMAC_ALGO,
            hash: BROWSER_SHA_ALGO
        };
        const key_ = await crypto.subtle.importKey('raw', htob(key), algorithm, false, ['verify']);
        return crypto.subtle.verify(algorithm.name, key_, htob(signature), stob(plaintext));
    }

    // # Public TODO type all of the any's

    // ## Key
    
    async function browserPublicKey(op: Op): Promise<any> {
        let key;
        if (op === 'encrypt' || op === 'decrypt') {
            key = await crypto.subtle.generateKey({
                name: BROWSER_RSA_ALGO,
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: {name: BROWSER_SHA_ALGO},
            }, true, ['encrypt', 'decrypt']);
        } else if (op === 'sign' || op === 'verify') {
            key = await crypto.subtle.generateKey({
                name: BROWSER_DSA_ALGO,
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
        const ciphertext = await crypto.subtle.encrypt({name: BROWSER_RSA_ALGO}, key.publicKey, stob(plaintext));
        return btoh(ciphertext);
    }

    // ## Decrypt
    
    async function browserPublicDecrypt(key: any, ciphertext: Hex): Promise<string> {
        const plaintext = await crypto.subtle.decrypt({name: BROWSER_RSA_ALGO}, key.privateKey, htob(ciphertext));
        return btos(plaintext);
    }
    
    // ## Sign

    async function browserPublicSign(key: any, plaintext: string): Promise<Hex> {
        const algorithm = {
            name: BROWSER_DSA_ALGO,
            hash: {name: BROWSER_SHA_ALGO}
        };
        const signature = await crypto.subtle.sign(algorithm, key.privateKey, stob(plaintext));
        return btoh(signature); 
    } 

    // ## Verify
   
    async function browserPublicVerify(key: any, signature: Hex, plaintext: string): Promise<boolean> {
        const algorithm = {
            name: BROWSER_DSA_ALGO,
            hash: {name: BROWSER_SHA_ALGO}
        };
        return await crypto.subtle.verify(algorithm, key.publicKey, htob(signature), stob(plaintext));
    }

    // # Export

    const random = browserRandom;
    const hash = browserHash;

    const private_ = {
        key: browserPrivateKey, 
        kdf: browserPrivateKdf, 
        encrypt: browserPrivateEncrypt,
        decrypt: browserPrivateDecrypt,
        sign: browserPrivateSign,
        verify: browserPrivateVerify
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
        key: browserPublicKey,
        encrypt: browserPublicEncrypt,
        decrypt: browserPublicDecrypt,
        sign: browserPublicSign,
        verify: browserPublicVerify
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
        _internal: _internal
    };

    this.jwcl = jwcl;
 
}).call(this);
