// JWCL

var nb = (function () {
    return (typeof module !== 'undefined' && module.exports) ? 'node' : 'browser';
})();


QUnit.test('jwcl', function (assert) {
    assert.ok(jwcl, 'exists');
    assert.ok(jwcl.encrypt, 'encrypt exists');
    assert.ok(jwcl.decrypt, 'decrypt exists');
    assert.ok(jwcl.sign, 'sign exists');
    assert.ok(jwcl.verify, 'verify exists');
    assert.ok(jwcl.hash, 'hash exists');
    assert.ok(jwcl.random, 'random exists');
    assert.ok(jwcl.private, 'private exists');
    assert.ok(jwcl.private.key, 'private key exists');
    assert.ok(jwcl.private.kdf, 'private kdf exists');
    assert.ok(jwcl.private.encrypt, 'private encrypt exists');
    assert.ok(jwcl.private.decrypt, 'private decrypt exists');
    assert.ok(jwcl.private.sign, 'private sign exists');
    assert.ok(jwcl.private.verify, 'private verify exists');
    assert.ok(jwcl.public, 'public exists');
    assert.ok(jwcl.public.key, 'public key exists');
    assert.ok(jwcl.public.encrypt, 'public encrypt exists');
    assert.ok(jwcl.public.decrypt, 'public decrypt exists');
    assert.ok(jwcl.public.sign, 'public sign exists');
    
    if (nb === 'browser') {
        assert.ok(jwcl._internal, 'internal exists');
        assert.ok(jwcl._internal.stob, 'stob exists');
        assert.ok(jwcl._internal.btos, 'btos exists');
        assert.ok(jwcl._internal.byteToHex, 'byteToHex exists');
        assert.ok(jwcl._internal.htob, 'htob exists');
        assert.ok(jwcl._internal.btoh, 'btoh exists');
    }
});

// Internal

QUnit.test('jwcl._internal', function (assert) {
    if (nb === 'browser') {
        assert.strictEqual(jwcl._internal.btoh(jwcl._internal.stob('abc')), '616263', 'btos "abc"');
        assert.strictEqual(jwcl._internal.btos(jwcl._internal.htob('616263')), 'abc', 'stob "616263"');
        assert.strictEqual(jwcl._internal.byteToHex(65), '41', 'byteToHex "A"');
        assert.strictEqual(jwcl._internal.byteToHex(10), '0a', 'byteToHex 10');
        assert.strictEqual(jwcl._internal.btoh(new Uint8Array([10,65,129])), '0a4181', 'btoh 10,65,129');
        assert.deepEqual(jwcl._internal.htob('0a4181'), new Uint8Array([10,65,129]), 'htob 0a4181');
        
        assert.throws(function () {
            jwcl._internal.htob('zzzz');
        }, {
            name: 'JWCL',
            message: 'jwcl._internal.htob input is not hex'
        });    
    } else {
        assert.expect(0);
    }
});

// Private

// Kdf

QUnit.test('jwcl.private.kdf', function (assert) {
    var done = assert.async();
    jwcl.private.kdf('secret') 
    .then(function (result) {
        assert.strictEqual(32, result.length, 'length');
        assert.strictEqual('string', typeof result, 'type');
        done();
    });
});

// Key

QUnit.test('jwcl.private.key', function (assert) {
  
    var done1 = assert.async();
    var done2 = assert.async();
    
    Promise.all([
        jwcl.private.key(),
        jwcl.private.key('encrypt')
    ])
    .then(function (results) {
        assert.strictEqual(32, results[0].length, 'length');
        assert.strictEqual('string', typeof results[0], 'type');
        assert.strictEqual(32, results[1].length, 'length');
        assert.strictEqual('string', typeof results[1], 'type');
        done1();
    });
  
    jwcl.private.key('zzz')
    .catch(function (err) {
        assert.strictEqual(err.name, 'JWCL');
        assert.strictEqual(err.message, 'jwcl.private.key zzz is not a supported operation');
        done2();  
    });
});

// Encrypt and Decrypt

QUnit.test('jwcl.private encrypt decrypt', function (assert) {
    var done = assert.async();
    var key;
    jwcl.private.key('encrypt')
    .then(function (result) {
        key = result;
        return jwcl.private.encrypt(key, 'abc')
    })
    .then(function (ciphertext) {
        return jwcl.private.decrypt(key, ciphertext);
    })
    .then(function (plaintext) {
        assert.strictEqual(plaintext, 'abc', 'simple encrypt decrypt');
        done();
    });
});

// Sign and Verify

QUnit.test('jwcl.private sign verify', function (assert) {
    var done = assert.async();
    var key;
    jwcl.private.key('sign')
    .then(function (result) {
        key = result;
        return jwcl.private.sign(key, 'abc')
    })
    .then(function (signature) {
        return Promise.all([
            jwcl.private.verify(key, signature, 'abc'),
            jwcl.private.verify(key, signature, 'abcd')
        ]);
    })
    .then(function (results) {
        assert.strictEqual(results[0], true, 'simple sign verify true');
        assert.strictEqual(results[1], false, 'simple sign verify false');
        done();
    });
});

// Random

QUnit.test('jwcl.random', function (assert) {
    var done = assert.async();
    jwcl.random(16)
    .then(function (result) {
        assert.strictEqual(32, result.length, 'length');
        assert.strictEqual('string', typeof result, 'type');
        done();
    });
});

// Hash

QUnit.test('jwcl.hash', function (assert) {
    var done = assert.async();
    Promise.all([
        jwcl.hash('abc'),
        jwcl.hash('abc', nb === 'browser' ? 'SHA-256' : 'sha256'),
        jwcl.hash('abc', nb === 'browser' ? 'SHA-1' : 'sha1')
    ])
    .then(function (results) {
        assert.strictEqual(results[0], 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'simple hash');
        assert.strictEqual(results[1], 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'simple hash with provided algorithm');
        assert.strictEqual(results[2], 'a9993e364706816aba3e25717850c26c9cd0d89d', 'simple hash with provided algorithm');
        done();
    });    
});

// Encrypt Decrypt

QUnit.test('jwcl encrypt decrypt', function (assert) {
    var done = assert.async();
    jwcl.encrypt('secret','abc')
    .then(function (result) {
        return jwcl.decrypt('secret', result);
    })
    .then(function (result) {
        assert.strictEqual(result, 'abc', 'simple encrypt decrypt "abc"');
        done();
    });
});

// Sign and Verify

QUnit.test('jwcl sign verify', function (assert) {
    var done = assert.async();
    jwcl.sign('secret', 'abc')
    .then(function (signature) {
        return Promise.all([
            jwcl.verify('secret', signature, 'abc'),
            jwcl.verify('secret', signature, 'abcd')
        ]);
    })
    .then(function (results) {
        assert.strictEqual(results[0], true, 'simple sign verify true');
        assert.strictEqual(results[1], false, 'simple sign verify false');
        done();
    });
});
