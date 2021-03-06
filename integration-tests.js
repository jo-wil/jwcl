var jwcl = jwcl || require('./jwcl').jwcl;

var env = (function () {
    return (typeof module !== 'undefined' && module.exports) ? 'node' : 'browser';
})();

var tests = function () {
    console.log('----- INTEGRATION TESTS -----');
    var password = '1234';
    var iv = '000000000000000000000000';
    var key = '00000000000000000000000000000000';
    var plaintext = 'a secret message';
    var ciphertext = '00000000000000000000000062a8a9ab03c4c6e6d345a7ca02d3991d10aea34d0e90b0572f0a7a86ccef9060';
    var message = 'an important message';
    var signature = 'ce2c274ecfde0e1b0875b6e8a739af3a05816022177c853a10954b10e7f13189';
    Promise.all([
        jwcl.hash('abc'),
        jwcl.private.kdf('1234'),
        jwcl.private.encrypt(key, iv, plaintext),
        jwcl.private.decrypt(key, ciphertext),  
        jwcl.private.sign(key, message),
        jwcl.private.verify(key, signature, message)
    ])
    .then(function (results) {
        console.log('hash("abc") -> ', results[0]);
        console.log('kdf("1234") -> ', results[1]);
        console.log('encrypt("a secret message") -> ', results[2]);
        console.log('decrypt() -> ', results[3]);
        console.log('sign("an important message") -> ', results[4]);
        console.log('verify() -> ', results[5]);
    });
};

if (env === 'browser') {
    document.addEventListener('DOMContentLoaded', tests());
} else if (env === 'node') {
    tests();
}
