
const { SHA3 } = require('sha3');
const { SHAKE } = require('sha3');

const nttZetas = [
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962,
    2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017,
    732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047,
    1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239, 3058, 830,
    107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226,
    430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574,
    1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,
    418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,
    1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459,
    478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628];

const nttZetasInv = [
    1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535,
    1278, 1530, 1185, 1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465,
    1285, 2007, 2719, 2726, 2232, 2512, 75, 156, 3000, 2911, 2980, 872, 2685,
    1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676, 1755, 460, 291, 235,
    3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103, 1275, 2652,
    1065, 2881, 725, 1508, 2368, 398, 951, 247, 1421, 3222, 2499, 271, 90, 853,
    1860, 3203, 1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838, 1293, 2314, 552,
    2677, 2106, 1571, 205, 2918, 1542, 2721, 2597, 2312, 681, 130, 1602, 1871,
    829, 2946, 3065, 1325, 2756, 1861, 1474, 1202, 2367, 3147, 1752, 2707, 171,
    3127, 3042, 1907, 1836, 1517, 359, 758, 1441];

const paramsK = 2;
const paramsN = 256;
const paramsQ = 3329;
const paramsQinv = 62209;
const paramsETA1 = 3;
const paramsETA2 = 2;

// ----------------------------------------------------------------------------------------------
// From http://baagoe.com/en/RandomMusings/javascript/
// Johannes Baagøe <baagoe@baagoe.com>, 2010
// ----------------------------------------------------------------------------------------------
// From: https://github.com/FuKyuToTo/lattice-based-cryptography
// ----------------------------------------------------------------------------------------------
// Secure Random Integer Generator
function Mash() {
    var n = 0xefc8249d;

    var mash = function (data) {
        data = data.toString();
        for (var i = 0; i < data.length; i++) {
            n += data.charCodeAt(i);
            var h = 0.02519603282416938 * n;
            n = h >>> 0;
            h -= n;
            h *= n;
            n = h >>> 0;
            h -= n;
            n += h * 0x100000000; // 2^32
        }
        return (n >>> 0) * 2.3283064365386963e-10; // 2^-32
    };
    mash.version = "Mash 0.9";
    return mash;
}
function Alea() {
    return (function (args) {
        var s0 = 0;
        var s1 = 0;
        var s2 = 0;
        var c = 1;

        if (args.length === 0) {
            args = [+new Date()];
        }
        var mash = Mash();
        s0 = mash(" ");
        s1 = mash(" ");
        s2 = mash(" ");

        for (var i = 0; i < args.length; i++) {
            s0 -= mash(args[i]);
            if (s0 < 0) {
                s0 += 1;
            }
            s1 -= mash(args[i]);
            if (s1 < 0) {
                s1 += 1;
            }
            s2 -= mash(args[i]);
            if (s2 < 0) {
                s2 += 1;
            }
        }
        mash = null;

        var random = function () {
            var t = 2091639 * s0 + c * 2.3283064365386963e-10; // 2^-32
            s0 = s1;
            s1 = s2;
            return (s2 = t - (c = t | 0));
        };
        random.uint32 = function () {
            return random() * 0x100000000; // 2^32
        };
        random.fract53 = function () {
            return random() + ((random() * 0x200000) | 0) * 1.1102230246251565e-16; // 2^-53
        };
        random.version = "Alea 0.9";
        random.args = args;
        return random;
    })(Array.prototype.slice.call(arguments));
}

//prng
var random = Alea();
var seed = random.args;
random = Alea(seed);

// Returns the next pseudorandom, uniformly distributed integer between 0(inclusive) and q-1(inclusive)
function nextInt(n) {
    return Math.floor(random() * n); //prng.js -> random()
}

function hexToDec(hexString) {
    return parseInt(hexString, 16);
}

// start KYBER code
function KeyGen512() {
    // IND-CPA keypair
    var indcpakeys = indcpaKeypair();

    var indcpaPublicKey = indcpakeys[0];
    var indcpaPrivateKey = indcpakeys[1];

    // FO transform to make IND-CCA2

    // get hash of indcpapublickey
    const buffer1 = Buffer.from(indcpaPublicKey);
    const hash1 = new SHA3(256);
    hash1.update(buffer1);
    var buf_str = hash1.digest('hex');
    // convert hex string to array
    var pkh = new Array(32);
    for (i = 0; i < 32; i++) {
        pkh[i] = hexToDec(buf_str[2 * i] + buf_str[2 * i + 1]);
    }

    // read 32 random values (0-255) into a 32 byte array
    var rnd = new Array(32);
    for (var i = 0; i < 32; i++) {
        rnd[i] = nextInt(256);
    }

    // concatenate to form IND-CCA2 private key: sk + pk + h(pk) + rnd
    var privateKey = indcpaPrivateKey;
    for (var i = 0; i < indcpaPublicKey.length; i++) {
        privateKey.push(indcpaPublicKey[i]);
    }
    for (var i = 0; i < pkh.length; i++) {
        privateKey.push(pkh[i]);
    }
    for (var i = 0; i < rnd.length; i++) {
        privateKey.push(rnd[i]);
    }

    var keys = new Array(2);
    keys[0] = indcpaPublicKey;
    keys[1] = privateKey;
    return keys;
}

// Generate (c, ss) from pk
function Encrypt512(pk) {

    // random 32 bytes
    var m = new Array(32);
    for (var i = 0; i < 32; i++) {
        m[i] = nextInt(256);
    }

    // hash m with SHA3-256
    const buffer1 = Buffer.from(m);
    const hash1 = new SHA3(256);
    hash1.update(buffer1);
    var buf_tmp = hash1.digest('hex');
    // convert hex string to array
    var mh = new Array(32);
    for (i = 0; i < 32; i++) {
        mh[i] = hexToDec(buf_tmp[2 * i] + buf_tmp[2 * i + 1]);
    }

    // hash pk with SHA3-256
    const buffer2 = Buffer.from(pk);
    const hash2 = new SHA3(256);
    hash2.update(buffer2);
    var buf_tmp = hash2.digest('hex');
    // convert hex string to array
    var pkh = new Array(32);
    for (i = 0; i < 32; i++) {
        pkh[i] = hexToDec(buf_tmp[2 * i] + buf_tmp[2 * i + 1]);
    }

    // hash mh and pkh with SHA3-512
    const buffer3 = Buffer.from(mh);
    const buffer4 = Buffer.from(pkh);
    const hash3 = new SHA3(512);
    hash3.update(buffer3).update(buffer4);
    var kr_str = hash3.digest('hex');
    // convert hex string to array
    var kr = new Array(32);
    for (i = 0; i < 64; i++) {
        kr[i] = hexToDec(kr_str[2 * i] + kr_str[2 * i + 1]);
    }
    var kr1 = kr.slice(0, 32);
    var kr2 = kr.slice(32, 64);

    // generate ciphertext c
    var c = indcpaEncrypt(pk, mh, kr2);

    // hash ciphertext with SHA3-256
    const buffer5 = Buffer.from(c);
    const hash4 = new SHA3(256);
    hash4.update(buffer5);
    var ch_str = hash4.digest('hex');
    // convert hex string to array
    var ch = new Array(32);
    for (i = 0; i < 32; i++) {
        ch[i] = hexToDec(ch_str[2 * i] + ch_str[2 * i + 1]);
    }

    // hash kr1 and ch with SHAKE-256
    const buffer6 = Buffer.from(kr1);
    const buffer7 = Buffer.from(ch);
    const hash5 = new SHAKE(256);
    hash5.update(buffer6).update(buffer7);
    var ss_str = hash5.digest('hex');
    // convert hex string to array
    var ss = new Array(32);
    for (i = 0; i < 32; i++) {
        ss[i] = hexToDec(ss_str[2 * i] + ss_str[2 * i + 1]);
    }

    // output (c, ss)
    var result = new Array(2);
    result[0] = c;
    result[1] = ss;

    return result;
}

// Decrypts the ciphertext to obtain the shared secret (symmetric key)
function Decrypt512(c, privateKey) {

    // extract sk, pk, pkh and z
    var sk = privateKey.slice(0, 768);
    var pk = privateKey.slice(768, 1568);
    var pkh = privateKey.slice(1568, 1600);
    var z = privateKey.slice(1600, 1632);

    // IND-CPA decrypt
    var m = indcpaDecrypt(c, sk);

    // hash m and pkh with SHA3-512
    const buffer1 = Buffer.from(m);
    const buffer2 = Buffer.from(pkh);
    const hash1 = new SHA3(512);
    hash1.update(buffer1).update(buffer2);
    var kr_str = hash1.digest('hex');
    // convert hex string to array
    var kr = new Array(64);
    for (i = 0; i < 64; i++) {
        kr[i] = hexToDec(kr_str[2 * i] + kr_str[2 * i + 1]);
    }
    var kr1 = kr.slice(0, 32);
    var kr2 = kr.slice(32, 64);

    // IND-CPA encrypt
    var cmp = indcpaEncrypt(pk, m, kr2);

    // compare c and cmp
    var fail = ArrayCompare(c, cmp) - 1;

    // hash c with SHA3-256
    const buffer3 = Buffer.from(c);
    const hash2 = new SHA3(256);
    hash2.update(buffer3);
    var ch_str = hash2.digest('hex');
    // convert hex string to array
    var ch = new Array(32);
    for (i = 0; i < 32; i++) {
        ch[i] = hexToDec(ch_str[2 * i] + ch_str[2 * i + 1]);
    }

    if (!fail){
        // hash kr1 and ch with SHAKE-256
        const buffer4 = Buffer.from(kr1);
        const buffer5 = Buffer.from(ch);
        const hash3 = new SHAKE(256);
        hash3.update(buffer4).update(buffer5);
        var ss_str = hash3.digest('hex');
        // convert hex string to array
        var ss = new Array(32);
        for (i = 0; i < 32; i++) {
            ss[i] = hexToDec(ss_str[2 * i] + ss_str[2 * i + 1]);
        }
    } 
    else{
        // hash z and ch with SHAKE-256
        const buffer6 = Buffer.from(z);
        const buffer7 = Buffer.from(ch);
        const hash4 = new SHAKE(256);
        hash4.update(buffer6).update(buffer7);
        var ss_str = hash4.digest('hex');
        // convert hex string to array
        var ss = new Array(32);
        for (i = 0; i < 32; i++) {
            ss[i] = hexToDec(ss_str[2 * i] + ss_str[2 * i + 1]);
        }
    }
    return ss;
}

// indcpaKeypair generates public and private keys for the CPA-secure
// public-key encryption scheme underlying Kyber.
function indcpaKeypair() {

    // random bytes for seed
    var rnd = new Array(32);
    for (var i = 0; i < 32; i++) {
        rnd[i] = nextInt(256);
    }

    // hash rnd with SHA3-512
    const buffer1 = Buffer.from(rnd);
    const hash1 = new SHA3(512);
    hash1.update(buffer1);
    var seed_str = hash1.digest('hex');
    // convert hex string to array
    var seed = new Array(64);
    for (i = 0; i < 64; i++) {
        seed[i] = hexToDec(seed_str[2 * i] + seed_str[2 * i + 1]);
    }
    var publicSeed = seed.slice(0, 32);
    var noiseSeed = seed.slice(32, 64);

    // generate public matrix A (already in NTT form)
    var a = generateMatrixA(publicSeed, false, paramsK);

    // sample secret s
    var s = new Array(paramsK);
    var nonce = 0;
    for (var i = 0; i < paramsK; i++) {
        s[i] = sample1(noiseSeed, nonce);
        nonce = nonce + 1;
    }

    // sample noise e
    var e = new Array(paramsK);
    for (var i = 0; i < paramsK; i++) {
        e[i] = sample1(noiseSeed, nonce);
        nonce = nonce + 1;
    }

    // perform number theoretic transform on secret s
    for (var i = 0; i < paramsK; i++) {
        s[i] = ntt(s[i]);
    }

    // perform number theoretic transform on error/noise e
    for (var i = 0; i < paramsK; i++) {
        e[i] = ntt(e[i]);
    }

    // barrett reduction
    for (var i = 0; i < paramsK; i++) {
        s[i] = reduce(s[i]);
    }

    // KEY COMPUTATION
    // A.s + e = pk

    // calculate A.s
    var pk = new Array(paramsK);
    for (var i = 0; i < paramsK; i++) {
        // montgomery reduction
        pk[i] = polyToMont(multiply(a[i], s));
    }

    // calculate addition of e
    for (var i = 0; i < paramsK; i++) {
        pk[i] = add(pk[i], e[i]);
    }
    
    // barrett reduction
    for (var i = 0; i < paramsK; i++) {
        pk[i] = reduce(pk[i]);
    }

    // ENCODE KEYS
    var keys = new Array(2);
    
    // PUBLIC KEY
    // turn polynomials into byte arrays
    keys[0] = [];
    var bytes = [];
    for (var i = 0; i < paramsK; i++) {
        bytes = polyToBytes(pk[i]);
        for (var j = 0; j < bytes.length; j++) {
            keys[0].push(bytes[j]);
        }
    }
    // append public seed
    for (var i = 0; i < publicSeed.length; i++) {
        keys[0].push(publicSeed[i]);
    }

    // PRIVATE KEY
    // turn polynomials into byte arrays
    keys[1] = [];
    var bytes = [];
    for (var i = 0; i < paramsK; i++) {
        bytes = polyToBytes(s[i]);
        for (var j = 0; j < bytes.length; j++) {
            keys[1].push(bytes[j]);
        }
    }

    return keys;
}




// indcpaEncrypt is the encryption function of the CPA-secure
// public-key encryption scheme underlying Kyber.
function indcpaEncrypt(pk1, msg, coins) {

    // DECODE PUBLIC KEY
    var pk = new Array(paramsK);
    var start;
    var end;
    for (var i = 0; i < paramsK; i++) {
        start = (i * 384);
        end = (i + 1) * 384;
        pk[i] = polyFromBytes(pk1.slice(start, end));
    }
    var seed = pk1.slice(768, 800);

    // generate transpose of public matrix A
    var at = generateMatrixA(seed, true);

    // sample random vector r
    var r = new Array(paramsK);
    var nonce = 0;
    for (var i = 0; i < paramsK; i++) {
        r[i] = sample1(coins, nonce);
        nonce = nonce + 1;
    }

    // sample error vector e1
    var e1 = new Array(paramsK);
    for (var i = 0; i < paramsK; i++) {
        e1[i] = sample2(coins, nonce);
        nonce = nonce + 1;
    }

    // sample e2
    var e2 = sample2(coins, nonce);

    // perform number theoretic transform on random vector r
    for (var i = 0; i < paramsK; i++) {
        r[i] = ntt(r[i]);
    }

    // barrett reduction
    for (var i = 0; i < paramsK; i++) {
        r[i] = reduce(r[i]);
    }

    // ENCRYPT COMPUTATION
    // A.r + e1 = u
    // pk.r + e2 + m = v

    // calculate A.r
    var u = new Array(paramsK);
    for (i = 0; i < paramsK; i++) {
        u[i] = multiply(at[i], r);
    }

    // perform inverse number theoretic transform on A.r
    for (var i = 0; i < paramsK; i++) {
        u[i] = nttInverse(u[i]);
    }

    // calculate addition of e1
    for (var i = 0; i < paramsK; i++) {
        u[i] = add(u[i], e1[i]);
    }

    // decode message m
    var m = polyFromMsg(msg);

    // calculate pk.r
    var v = multiply(pk, r);

    // perform inverse number theoretic transform on pk.r
    v = nttInverse(v);

    // calculate addition of e2
    v = add(v, e2);

    // calculate addition of m
    v = add(v, m);

    // barrett reduction
    for (var i = 0; i < paramsK; i++) {
        u[i] = reduce(u[i]);
    }

    // barrett reduction
    v = reduce(v);

    // compress
    var c1 = compress1(u);
    var c2 = compress2(v);

    // return c1 || c2
    return c1.concat(c2);
}

// indcpaDecrypt is the decryption function of the CPA-secure
// public-key encryption scheme underlying Kyber.
function indcpaDecrypt(c, privateKey) {

    var result = indcpaUnpackCiphertext(c);

    var bp = result[0];
    var v = result[1];

    var privateKeyPolyvec = indcpaUnpackPrivateKey(privateKey);

    for (var i = 0; i < paramsK; i++) {
        bp[i] = ntt(bp[i]);
    }

    var mp = multiply(privateKeyPolyvec, bp);

    var mp = nttInverse(mp);

    var mp = subtract(v, mp);

    var mp = reduce(mp);

    return polyToMsg(mp);
}

// indcpaUnpackPrivateKey de-serializes the private key and represents
// the inverse of indcpaPackPrivateKey.
function indcpaUnpackPrivateKey(packedPrivateKey) {
    return polyvecFromBytes(packedPrivateKey);
}

// polyvecFromBytes deserializes a vector of polynomials.
function polyvecFromBytes(a) {
    var r = new Array(paramsK);
    for (var i = 0; i < paramsK; i++) {
        r[i] = new Array(384);
    }
    var start;
    var end;
    for (var i = 0; i < paramsK; i++) {
        start = (i * 384);
        end = (i + 1) * 384;
        r[i] = polyFromBytes(a.slice(start, end));
    }
    return r;
}

// polyToBytes serializes a polynomial into an array of bytes.
function polyToBytes(a) {
    var t0, t1;
    var r = new Array(384);
    var a2 = subtract_q(a); // Returns: a - q if a >= q, else a (each coefficient of the polynomial)
    // for 0-127
    for (var i = 0; i < paramsN / 2; i++) {
        // get two coefficient entries in the polynomial
        t0 = uint16(a2[2 * i]);
        t1 = uint16(a2[2 * i + 1]);

        // convert the 2 coefficient into 3 bytes
        r[3 * i + 0] = byte(t0 >> 0); // byte() does mod 256 of the input (output value 0-255)
        r[3 * i + 1] = byte(t0 >> 8) | byte(t1 << 4);
        r[3 * i + 2] = byte(t1 >> 4);
    }
    return r;
}

// polyFromBytes de-serialises an array of bytes into a polynomial,
// and represents the inverse of polyToBytes.
function polyFromBytes(a) {
    var r = new Array(384).fill(0);
    for (var i = 0; i < paramsN / 2; i++) {
        r[2 * i] = int16(((uint16(a[3 * i + 0]) >> 0) | (uint16(a[3 * i + 1]) << 8)) & 0xFFF);
        r[2 * i + 1] = int16(((uint16(a[3 * i + 1]) >> 4) | (uint16(a[3 * i + 2]) << 4)) & 0xFFF);
    }
    return r;
}

// polyToMsg converts a polynomial to a 32-byte message
// and represents the inverse of polyFromMsg.
function polyToMsg(a) {
    var msg = new Array(32);
    var t;
    var a2 = subtract_q(a);
    for (var i = 0; i < paramsN / 8; i++) {
        msg[i] = 0;
        for (var j = 0; j < 8; j++) {
            t = (((uint16(a2[8 * i + j]) << 1) + uint16(paramsQ / 2)) / uint16(paramsQ)) & 1;
            msg[i] |= byte(t << j);
        }
    }
    return msg;
}

// polyFromMsg converts a 32-byte message to a polynomial.
function polyFromMsg(msg) {
    var r = new Array(384).fill(0); // each element is int16 (0-65535)
    var mask; // int16
    for (var i = 0; i < paramsN / 8; i++) {
        for (var j = 0; j < 8; j++) {
            mask = -1 * int16((msg[i] >> j) & 1);
            r[8 * i + j] = mask & int16((paramsQ + 1) / 2);
        }
    }
    return r;
}

// polyReduce applies Barrett reduction to all coefficients of a polynomial.
function polyReduce(r) {
    for (var i = 0; i < paramsN; i++) {
        r[i] = barrett(r[i]);
    }
    return r;
}



// generateMatrixA deterministically generates a matrix `A` (or the transpose of `A`)
// from a seed. Entries of the matrix are polynomials that look uniformly random.
// Performs rejection sampling on the output of an extendable-output function (XOF).
function generateMatrixA(seed, transposed) {
    var a = new Array(paramsK);
    var output = new Array(3 * 168);
    const xof = new SHAKE(128);
    var ctr = 0;
    for (var i = 0; i < paramsK; i++) {

        a[i] = new Array(paramsK);
        var transpose = new Array(2);

        for (var j = 0; j < paramsK; j++) {

            // set if transposed matrix or not
            transpose[0] = j;
            transpose[1] = i;
            if (transposed) {
                transpose[0] = i;
                transpose[1] = j;
            }

            // obtain xof of (seed+i+j) or (seed+j+i) depending on above code
            // output is 672 bytes in length
            xof.reset();
            const buffer1 = Buffer.from(seed);
            const buffer2 = Buffer.from(transpose);
            xof.update(buffer1).update(buffer2);
            var buf_str = xof.digest({ buffer: Buffer.alloc(672), format: 'hex' });
            // convert hex string to array
            for (var n = 0; n < 672; n++) {
                output[n] = hexToDec(buf_str[2 * n] + buf_str[2 * n + 1]);
            }

            // run rejection sampling on the output from above
            var outputlen = 3 * 168;
            var result = new Array(2);
            result = indcpaRejUniform(output.slice(0,504), outputlen, paramsN);
            a[i][j] = result[0]; // the result here is an NTT-representation
            ctr = result[1]; // keeps track of index of output array from sampling function

            while (ctr < paramsN) { // if the polynomial hasnt been filled yet with mod q entries

                var outputn = output.slice(504, 672); // take last 168 bytes of byte array from xof

                var result1 = new Array(2);
                result1 = indcpaRejUniform(outputn, 168, paramsN-ctr); // run sampling function again
                var missing = result1[0]; // here is additional mod q polynomial coefficients
                var ctrn = result1[1]; // how many coefficients were accepted and are in the output
                // starting at last position of output array from first sampling function until 256 is reached
                for (var k = ctr; k < paramsN; k++) { 
                    a[i][j][k] = missing[k-ctr]; // fill rest of array with the additional coefficients until full
                }
                ctr = ctr + ctrn; // update index
            }

        }
    }
    return a;
}

// indcpaRejUniform runs rejection sampling on uniform random bytes
// to generate uniform random integers modulo `Q`.
function indcpaRejUniform(buf, bufl, len) {
    var r = new Array(384).fill(0);
    var val0, val1; // d1, d2 in kyber documentation
    var pos = 0; // i
    var ctr = 0; // j

    while (ctr < len && pos + 3 <= bufl) {

        // compute d1 and d2
        val0 = (uint16((buf[pos]) >> 0) | (uint16(buf[pos + 1]) << 8)) & 0xFFF;
        val1 = (uint16((buf[pos + 1]) >> 4) | (uint16(buf[pos + 2]) << 4)) & 0xFFF;

        // increment input buffer index by 3
        pos = pos + 3;

        // if d1 is less than 3329
        if (val0 < paramsQ) {
            // assign to d1
            r[ctr] = val0;
            // increment position of output array
            ctr = ctr + 1;
        }
        if (ctr < len && val1 < paramsQ) {
            r[ctr] = val1;
            ctr = ctr + 1;
        }

        
    }

    var result = new Array(2);
    result[0] = r; // returns polynomial NTT representation
    result[1] = ctr; // ideally should return 256
    return result;
}

// sample1 samples a polynomial deterministically from a seed
// and nonce, with the output polynomial being close to a centered
// binomial distribution with parameter paramsETA1 = 3.
function sample1(seed, nonce) {
    var l = paramsETA1 * paramsN / 4;
    var p = prf(l, seed, nonce);
    return byteopsCbd(p);
}

// sample2 samples a polynomial deterministically from a seed
// and nonce, with the output polynomial being close to a centered
// binomial distribution with parameter paramsETA2 = 2.
function sample2(seed, nonce) {
    var l = paramsETA2 * paramsN / 4;
    var p = prf(l, seed, nonce);
    return byteopsCbd2(p);
}

// prf provides a pseudo-random function (PRF) which returns
// a byte array of length `l`, using the provided key and nonce
// to instantiate the PRF's underlying hash function.
function prf(l, key, nonce) {
    var buf = new Array(l);
    var nonce_arr = new Array(1);
    nonce_arr[0] = nonce;
    const hash = new SHAKE(256);
    hash.reset();
    const buffer1 = Buffer.from(key);
    const buffer2 = Buffer.from(nonce_arr);
    hash.update(buffer1).update(buffer2);
    var hash_str = hash.digest({ buffer: Buffer.alloc(l), format: 'hex' }); // 128 long byte array
    // convert hex string to array
    for (var n = 0; n < l; n++) {
        buf[n] = hexToDec(hash_str[2 * n] + hash_str[2 * n + 1]);
    }
    return buf;
}

// byteopsCbd computes a polynomial with coefficients distributed
// according to a centered binomial distribution with parameter paramsETA1,
// given an array of uniformly random bytes.
function byteopsCbd(buf) {
    var t, d;
    var a, b;
    var r = new Array(384).fill(0); 
    for (var i = 0; i < paramsN/4; i++) {
        t = byteopsLoad24(buf.slice(3*i, buf.length));
        d = t & 0x00249249;
        d = d + ((t >> 1) & 0x00249249);
        d = d + ((t >> 2) & 0x00249249);
        for (var j = 0; j < 4; j++) {
            a = int16((d >> (6*j + 0)) & 0x7);
            b = int16((d >> (6*j + paramsETA1)) & 0x7);
            r[4*i+j] = a - b;
        }
    }
    return r;
}

// byteopsCbd2 computes a polynomial with coefficients distributed
// according to a centered binomial distribution with parameter paramsETA2,
// given an array of uniformly random bytes.
function byteopsCbd2(buf) {
    var t, d;
    var a, b;
    var r = new Array(384).fill(0); 
    for ( var i = 0; i < paramsN/8; i++) {
        t = byteopsLoad32(buf.slice(4*i,buf.length));
        d = t & 0x55555555;
        d = d + ((t >> 1) & 0x55555555);
        for (var j = 0; j < 8; j++) {
            a = int16((d >> (4*j + 0)) & 0x3);
            b = int16((d >> (4*j + paramsETA2)) & 0x3);
            r[8*i+j] = a - b;
        }
    }
    return r;
}

// byteopsLoad24 returns a 32-bit unsigned integer loaded from byte x.
function byteopsLoad24(x) {
	var r;
	r = uint32(x[0]);
	r = r | (uint32(x[1]) << 8);
	r = r | (uint32(x[2]) << 16);
	return r;
}

// byteopsLoad32 returns a 32-bit unsigned integer loaded from byte x.
function byteopsLoad32(x) {
	var r;
	r = uint32(x[0]);
	r = r | (uint32(x[1]) << 8);
	r = r | (uint32(x[2]) << 16);
	r = r | (uint32(x[3]) << 24);
	return r
}

// ntt performs an inplace number-theoretic transform (NTT) in `Rq`.
// The input is in standard order, the output is in bit-reversed order.
function ntt(r) {
    var j = 0;
    var k = 1;
    var zeta;
    var t;
    // 128, 64, 32, 16, 8, 4, 2
    for (var l = 128; l >= 2; l >>= 1) {
        // 0, 
        for (var start = 0; start < 256; start = j + l) {
            zeta = nttZetas[k];
            k = k + 1;
            // for each element in the subsections (128, 64, 32, 16, 8, 4, 2) starting at an offset
            for (j = start; j < start + l; j++) {
                // compute the modular multiplication of the zeta and each element in the subsection
                t = nttFqMul(zeta, r[j + l]); // t is mod q
                // overwrite each element in the subsection as the opposite subsection element minus t
                r[j + l] = r[j] - t;
                // add t back again to the opposite subsection
                r[j] = r[j] + t;
                
            }
        }
    }
    return r;
}

// nttFqMul performs multiplication followed by Montgomery reduction
// and returns a 16-bit integer congruent to `a*b*R^{-1} mod Q`.
function nttFqMul(a, b) {
    return byteopsMontgomeryReduce(a * b);
}

// reduce applies Barrett reduction to all coefficients of a polynomial.
function reduce(r) {
    for (var i = 0; i < paramsN; i++) {
        r[i] = barrett(r[i]);
    }
    return r;
}

// barrett computes a Barrett reduction; given
// a integer `a`, returns a integer congruent to
// `a mod Q` in {0,...,Q}.
function barrett(a) {
    var v = ( (1<<24) + paramsQ / 2) / paramsQ;
    var t = v * a >> 24;
    t = t * paramsQ;
    return a - t;
}

// byteopsMontgomeryReduce computes a Montgomery reduction; given
// a 32-bit integer `a`, returns `a * R^-1 mod Q` where `R=2^16`.
function byteopsMontgomeryReduce(a) {
    var u = int16(int32(a) * paramsQinv);
    var t = u * paramsQ;
    t = a - t;
    t >>= 16;
    return int16(t);
}

// polyToMont performs the in-place conversion of all coefficients
// of a polynomial from the normal domain to the Montgomery domain.
function polyToMont(r) {
    // var f = int16(((uint64(1) << 32) >>> 0) % uint64(paramsQ));
    var f = 1353; // if paramsQ changes then this needs to be updated
    for (var i = 0; i < paramsN; i++) {
        r[i] = byteopsMontgomeryReduce(int32(r[i]) * int32(f));
    }
    return r;
}

// pointwise-multiplies elements of polynomial-vectors
// `a` and `b`, accumulates the results into `r`, and then multiplies by `2^-16`.
function multiply(a, b) {
    var r = polyBaseMulMontgomery(a[0], b[0]);
    var t;
    for (var i = 1; i < paramsK; i++) {
        t = polyBaseMulMontgomery(a[i], b[i]);
        r = add(r, t);
    }
    return reduce(r);
}

// polyBaseMulMontgomery performs the multiplication of two polynomials
// in the number-theoretic transform (NTT) domain.
function polyBaseMulMontgomery(a, b) {
    var rx, ry;
    for (var i = 0; i < paramsN / 4; i++) {
        rx = nttBaseMul(
            a[4 * i + 0], a[4 * i + 1],
            b[4 * i + 0], b[4 * i + 1],
            nttZetas[64 + i]
        );
        ry = nttBaseMul(
            a[4 * i + 2], a[4 * i + 3],
            b[4 * i + 2], b[4 * i + 3],
            -nttZetas[64 + i]
        );
        a[4 * i + 0] = rx[0];
        a[4 * i + 1] = rx[1];
        a[4 * i + 2] = ry[0];
        a[4 * i + 3] = ry[1];
    }
    return a;
}

// nttBaseMul performs the multiplication of polynomials
// in `Zq[X]/(X^2-zeta)`. Used for multiplication of elements
// in `Rq` in the number-theoretic transformation domain.
function nttBaseMul(a0, a1, b0, b1, zeta) {
    var r = new Array(2);
    r[0] = nttFqMul(a1, b1);
    r[0] = nttFqMul(r[0], zeta);
    r[0] = r[0] + nttFqMul(a0, b0);
    r[1] = nttFqMul(a0, b1);
    r[1] = r[1] + nttFqMul(a1, b0);
    return r;
}

// adds two polynomials.
function add(a, b) {
    var c = new Array(384);
    for (var i = 0; i < paramsN; i++) {
        c[i] = a[i] + b[i];
    }
    return c;
}

// subtracts two polynomials.
function subtract(a, b) {
    for (var i = 0; i < paramsN; i++) {
        a[i] = a[i] - b[i];
    }
    return a;
}

// nttInverse performs an inplace inverse number-theoretic transform (NTT)
// in `Rq` and multiplication by Montgomery factor 2^16.
// The input is in bit-reversed order, the output is in standard order.
function nttInverse(r) {
    var j = 0;
    var k = 0;
    var zeta;
    var t;
    for (var l = 2; l <= 128; l <<= 1) {
        for (var start = 0; start < 256; start = j + l) {
            zeta = nttZetasInv[k];
            k = k + 1;
            for (j = start; j < start + l; j++) {
                t = r[j];
                r[j] = barrett(t + r[j + l]);
                r[j + l] = t - r[j + l];
                r[j + l] = nttFqMul(zeta, r[j + l]);
            }
        }
    }
    for (j = 0; j < 256; j++) {
        r[j] = nttFqMul(r[j], nttZetasInv[127]);
    }
    return r;
}

// indcpaUnpackCiphertext de-serializes and decompresses the ciphertext
// from a byte array, and represents the approximate inverse of
// indcpaPackCiphertext.
function indcpaUnpackCiphertext(c) {
    var b = polyvecDecompress(c.slice(0, 640));
    var v = polyDecompress(c.slice(640, 1088));
    var result = new Array(2);
    result[0] = b;
    result[1] = v;
    return result;
}

// compress1 lossily compresses and serializes a vector of polynomials.
function compress1(u) {
    var rr = 0;
    var r = new Array(640);
    var t = new Array(4);
    for (var i = 0; i < paramsK; i++) {
        for (var j = 0; j < paramsN / 4; j++) {
            for (var k = 0; k < 4; k++) {
                // parse {0,...,3328} to {0,...,1023}
                t[k] = (((u[i][4 * j + k] << 10) + paramsQ / 2) / paramsQ) & 0b1111111111;
            }
            // converts 4 12-bit coefficients {0,...,3328} to 5 8-bit bytes {0,...,255}
            // 48 bits down to 40 bits per block
            r[rr + 0] = byte(t[0] >> 0);
            r[rr + 1] = byte((t[0] >> 8) | (t[1] << 2));
            r[rr + 2] = byte((t[1] >> 6) | (t[2] << 4));
            r[rr + 3] = byte((t[2] >> 4) | (t[3] << 6));
            r[rr + 4] = byte((t[3] >> 2));
            rr = rr + 5;
        }
    }
    return r;
}

// compress2 lossily compresses and subsequently serializes a polynomial.
function compress2(v) {
    var rr = 0;
    var r = new Array(128);
    var t = new Array(8);
    for (var i = 0; i < paramsN / 8; i++) {
        for (var j = 0; j < 8; j++) {
            t[j] = byte(((v[8 * i + j] << 4) + paramsQ / 2) / paramsQ) & 0b1111;
        }
        r[rr + 0] = t[0] | (t[1] << 4);
        r[rr + 1] = t[2] | (t[3] << 4);
        r[rr + 2] = t[4] | (t[5] << 4);
        r[rr + 3] = t[6] | (t[7] << 4);
        rr = rr + 4;
    }
    return r;
}

// polyvecDecompress de-serializes and decompresses a vector of polynomials and
// represents the approximate inverse of compress1. Since compression is lossy,
// the results of decompression will may not match the original vector of polynomials.
function polyvecDecompress(a) {
    var r = new Array(paramsK);
    for (var i = 0; i < paramsK; i++) {
        r[i] = new Array(384);
    }
    var aa = 0;
    var t = new Array(4);
    for (var i = 0; i < paramsK; i++) {
        for (var j = 0; j < paramsN / 4; j++) {
            t[0] = (uint16(a[aa + 0]) >> 0) | (uint16(a[aa + 1]) << 8);
            t[1] = (uint16(a[aa + 1]) >> 2) | (uint16(a[aa + 2]) << 6);
            t[2] = (uint16(a[aa + 2]) >> 4) | (uint16(a[aa + 3]) << 4);
            t[3] = (uint16(a[aa + 3]) >> 6) | (uint16(a[aa + 4]) << 2);
            aa = aa + 5;
            for (var k = 0; k < 4; k++) {
                r[i][4 * j + k] = int16((((uint32(t[k] & 0x3FF) >>> 0) * (uint32(paramsQ) >>> 0) >>> 0) + 512) >> 10 >>> 0);
            }
        }
    }
    return r;
}

// subtract_q applies the conditional subtraction of q to each coefficient of a polynomial.
// if a is 3329 then convert to 0
// Returns:     a - q if a >= q, else a
function subtract_q(r) {
    for (var i = 0; i < paramsN; i++) {
        r[i] = r[i] - paramsQ; // should result in a negative integer
        // push left most signed bit to right most position
        // javascript does bitwise operations in signed 32 bit
        // add q back again if left most bit was 0 (positive number)
        r[i] = r[i] + ((r[i] >> 31) & paramsQ);
    }
    return r;
}

// polyDecompress de-serializes and subsequently decompresses a polynomial,
// representing the approximate inverse of compress2.
// Note that compression is lossy, and thus decompression will not match the
// original input.
function polyDecompress(a) {
    var r = new Array(384);
    var aa = 0;
    for (var i = 0; i < paramsN / 2; i++) {
        r[2 * i + 0] = int16(((uint16(a[aa] & 15) * uint16(paramsQ)) + 8) >> 4);
        r[2 * i + 1] = int16(((uint16(a[aa] >> 4) * uint16(paramsQ)) + 8) >> 4);
        aa = aa + 1;
    }
    return r;
}

function byte(n) {
    n = n % 256;
    return n;
}

/* 
// not needed, just here for reference
function int8(n){
    var end = -128;
    var start = 127;
    
    if( n >= end && n <= start){
        return n;
    }
    if( n < end){
        n = n+129;
        n = n%256;
        n = start + n;
        return n;
    }
    if( n > start){
        n = n-128;
        n = n%256;
        n = end + n;
        return n;
    }
}

function uint8(n){
    n = n%256;
    return n;
}
*/

function int16(n) {
    var end = -32768;
    var start = 32767;

    if (n >= end && n <= start) {
        return n;
    }
    if (n < end) {
        n = n + 32769;
        n = n % 65536;
        n = start + n;
        return n;
    }
    if (n > start) {
        n = n - 32768;
        n = n % 65536;
        n = end + n;
        return n;
    }
}

function uint16(n) {
    n = n % 65536;
    return n;
}


function int32(n) {
    var end = -2147483648;
    var start = 2147483647;

    if (n >= end && n <= start) {
        return n;
    }
    if (n < end) {
        n = n + 2147483649;
        n = n % 4294967296;
        n = start + n;
        return n;
    }
    if (n > start) {
        n = n - 2147483648;
        n = n % 4294967296;
        n = end + n;
        return n;
    }
}

// any bit operations to be done in uint32 must have >>> 0
// javascript calculates bitwise in SIGNED 32 bit so you need to convert
function uint32(n) {
    n = n % 4294967296;
    return n;
}

// compares two arrays and returns 1 if they are the same or 0 if not
function ArrayCompare(a, b) {
    // check array lengths
    if (a.length != b.length) {
        return 0;
    }
    // check contents
    for (var i = 0; i < a.length; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}


// test run function
function TestK512(){

    // read values from PQCkemKAT_1632.rsp
    // sk, ct, ss

    var fs = require('fs');
    var textByLine = fs.readFileSync('PQCkemKAT_1632.rsp').toString().split("\n");

    // console.log(textByLine.length); // seems to be an array of strings (lines)
    var sk100 = [];
    var ct100 = [];
    var ss100 = [];
    var counter = 0;
    while (counter < textByLine.length){
        if (textByLine[counter][0] == 'c' && textByLine[counter][1] == 't'){
            var tmp = [];
            for (j = 0; j < 768; j++) {
                tmp[j] = hexToDec(textByLine[counter][2 * j + 5] + textByLine[counter][2 * j + 1 + 5]);
            }
            ct100.push(tmp);
            counter = counter + 1;
            continue;
        }
        else if(textByLine[counter][0] == 's' && textByLine[counter][1] == 's'){
            var tmp = [];
            for (j = 0; j < 32; j++) {
                tmp[j] = hexToDec(textByLine[counter][2 * j + 5] + textByLine[counter][2 * j + 1 + 5]);
            }
            ss100.push(tmp);
            counter = counter + 1;
            continue;
        }
        else if(textByLine[counter][0] == 's' && textByLine[counter][1] == 'k'){
            var tmp = [];
            for (j = 0; j < 1632; j++) {
                tmp[j] = hexToDec(textByLine[counter][2 * j + 5] + textByLine[counter][2 * j + 1 + 5]);
            }
            sk100.push(tmp);
            counter = counter + 1;
            continue;
        }
        else{
            counter = counter + 1;
        }
    }

    var failures = 0;

    // for each case (100 total)
    // test if ss equals Decrypt512(c,sk)
    for (var i=0; i<100; i++){
        var ss2 = Decrypt512(ct100[i],sk100[i]);

        // success if both symmetric keys are the same
        if (ArrayCompare(ss100[i], ss2)){
            console.log("Test run [", i, "] success");
        }
        else{
            console.log("Test run [", i, "] fail");
            failures += 1;
        }
    }

    if(failures==0){
        console.log(" ");
        console.log("All test runs successful.")
    }
    else{
        console.log(" ");
        console.log(failures, " test cases have failed.")
    }
    return
}

// test here
/*******************************************************

TestK512();

// To generate a public and private key pair (pk, sk)
var pk_sk = KeyGen512();
var pk = pk_sk[0];
var sk = pk_sk[1];

// To generate a random 256 bit symmetric key (ss) and its encapsulation (c)
var c_ss = Encrypt512(pk);
var c = c_ss[0];
var ss1 = c_ss[1];

// To decapsulate and obtain the same symmetric key
var ss2 = Decrypt512(c, sk);

console.log("ss1", ss1);
console.log("ss2",ss2);

// returns 1 if both symmetric keys are the same
console.log(ArrayCompare(ss1, ss2));
********************************************************/