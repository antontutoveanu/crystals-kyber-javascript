
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

const paramsK = 3;
const paramsN = 256;
const paramsQ = 3329;
const paramsQinv = 62209;
const paramsETA = 2;

const paramsPolyBytes = 384;
const Kyber768SKBytes = 1152 + ((1152 + 32) + 2 * 32);
const paramsPolyCompressedBytesK768 = 128;
const paramsPolyvecCompressedBytesK768 = 3 * 320; // 960

// ----------------------------------------------------------------------------------------------
// From http://baagoe.com/en/RandomMusings/javascript/
// Johannes Baagøe <baagoe@baagoe.com>, 2010
// ----------------------------------------------------------------------------------------------
// From: https://github.com/FuKyuToTo/lattice-based-cryptography
// ----------------------------------------------------------------------------------------------
// Secure Random Int Generator
function Mash() {
    let n = 0xefc8249d;

    let mash = function (data) {
        data = data.toString();
        for (let i = 0; i < data.length; i++) {
            n += data.charCodeAt(i);
            let h = 0.02519603282416938 * n;
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
        let s0 = 0;
        let s1 = 0;
        let s2 = 0;
        let c = 1;

        if (args.length === 0) {
            args = [+new Date()];
        }
        let mash = Mash();
        s0 = mash(" ");
        s1 = mash(" ");
        s2 = mash(" ");

        for (let i = 0; i < args.length; i++) {
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

        let random = function () {
            let t = 2091639 * s0 + c * 2.3283064365386963e-10; // 2^-32
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
let random = Alea();
let seed = random.args;
random = Alea(seed);

// Returns the next pseudorandom, uniformly distributed integer between 0(inclusive) and q-1(inclusive)
function nextInt(n) {
    return Math.floor(random() * n); //prng.js -> random()
}

function hexToDec(hexString) {
    return parseInt(hexString, 16);
}

// start KYBER code
export function KeyGen768() {
    // IND-CPA keypair
    let indcpakeys = indcpaKeypair();

    let indcpaPublicKey = indcpakeys[0];
    let indcpaPrivateKey = indcpakeys[1];

    // FO transform to make IND-CCA2

    // get hash of indcpapublickey
    const buffer1 = Buffer.from(indcpaPublicKey);
    const hash1 = new SHA3(256);
    hash1.update(buffer1);
    let buf_str = hash1.digest('hex');
    // convert hex string to array
    let pkh = new Array(32);
    for (let i = 0; i < 32; i++) {
        pkh[i] = hexToDec(buf_str[2 * i] + buf_str[2 * i + 1]);
    }

    // read 32 random values (0-255) into a 32 byte array
    let rnd = new Array(32);
    for (let i = 0; i < 32; i++) {
        rnd[i] = nextInt(256);
    }

    // concatenate to form IND-CCA2 private key: sk + pk + h(pk) + rnd
    let privateKey = indcpaPrivateKey;
    for (let i = 0; i < indcpaPublicKey.length; i++) {
        privateKey.push(indcpaPublicKey[i]);
    }
    for (let i = 0; i < pkh.length; i++) {
        privateKey.push(pkh[i]);
    }
    for (let i = 0; i < rnd.length; i++) {
        privateKey.push(rnd[i]);
    }

    let keys = new Array(2);
    keys[0] = indcpaPublicKey;
    keys[1] = privateKey;
    return keys;
}

// Generate (c, ss) from pk
export function Encrypt768(pk) {

    // random 32 bytes
    let m = new Array(32);
    for (let i = 0; i < 32; i++) {
        m[i] = nextInt(256);
    }

    // hash m with SHA3-256
    const buffer1 = Buffer.from(m);
    const hash1 = new SHA3(256);
    hash1.update(buffer1);
    let buf_tmp = hash1.digest('hex');
    // convert hex string to array
    let mh = new Array(32);
    for (let i = 0; i < 32; i++) {
        mh[i] = hexToDec(buf_tmp[2 * i] + buf_tmp[2 * i + 1]);
    }

    // hash pk with SHA3-256
    const buffer2 = Buffer.from(pk);
    const hash2 = new SHA3(256);
    hash2.update(buffer2);
    buf_tmp = hash2.digest('hex');
    // convert hex string to array
    let pkh = new Array(32);
    for (let i = 0; i < 32; i++) {
        pkh[i] = hexToDec(buf_tmp[2 * i] + buf_tmp[2 * i + 1]);
    }

    // hash mh and pkh with SHA3-512
    const buffer3 = Buffer.from(mh);
    const buffer4 = Buffer.from(pkh);
    const hash3 = new SHA3(512);
    hash3.update(buffer3).update(buffer4);
    let kr_str = hash3.digest('hex');
    // convert hex string to array
    let kr = new Array(32);
    for (let i = 0; i < 64; i++) {
        kr[i] = hexToDec(kr_str[2 * i] + kr_str[2 * i + 1]);
    }
    let kr1 = kr.slice(0, 32);
    let kr2 = kr.slice(32, 64);

    // generate ciphertext c
    let c = indcpaEncrypt(pk, mh, kr2);

    // hash ciphertext with SHA3-256
    const buffer5 = Buffer.from(c);
    const hash4 = new SHA3(256);
    hash4.update(buffer5);
    let ch_str = hash4.digest('hex');
    // convert hex string to array
    let ch = new Array(32);
    for (let i = 0; i < 32; i++) {
        ch[i] = hexToDec(ch_str[2 * i] + ch_str[2 * i + 1]);
    }

    // hash kr1 and ch with SHAKE-256
    const buffer6 = Buffer.from(kr1);
    const buffer7 = Buffer.from(ch);
    const hash5 = new SHAKE(256);
    hash5.update(buffer6).update(buffer7);
    let ss_str = hash5.digest('hex');
    // convert hex string to array
    let ss = new Array(32);
    for (let i = 0; i < 32; i++) {
        ss[i] = hexToDec(ss_str[2 * i] + ss_str[2 * i + 1]);
    }

    // output (c, ss)
    let result = new Array(2);
    result[0] = c;
    result[1] = ss;

    return result;
}

// Decrypts the ciphertext to obtain the shared secret (symmetric key)
export function Decrypt768(c, privateKey) {

    // extract sk, pk, pkh and z
    let sk = privateKey.slice(0, 1152);
    let pk = privateKey.slice(1152, 2336);
    let pkh = privateKey.slice(2336, 2368);
    let z = privateKey.slice(2368, 2400);

    // IND-CPA decrypt
    let m = indcpaDecrypt(c, sk);

    // hash m and pkh with SHA3-512
    const buffer1 = Buffer.from(m);
    const buffer2 = Buffer.from(pkh);
    const hash1 = new SHA3(512);
    hash1.update(buffer1).update(buffer2);
    let kr_str = hash1.digest('hex');
    // convert hex string to array
    let kr = new Array(64);
    for (let i = 0; i < 64; i++) {
        kr[i] = hexToDec(kr_str[2 * i] + kr_str[2 * i + 1]);
    }
    let kr1 = kr.slice(0, 32);
    let kr2 = kr.slice(32, 64);

    // IND-CPA encrypt
    let cmp = indcpaEncrypt(pk, m, kr2);

    // compare c and cmp
    let fail = ArrayCompare(c, cmp) - 1;

    // hash c with SHA3-256
    const buffer3 = Buffer.from(c);
    const hash2 = new SHA3(256);
    hash2.update(buffer3);
    let ch_str = hash2.digest('hex');
    // convert hex string to array
    let ch = new Array(32);
    for (let i = 0; i < 32; i++) {
        ch[i] = hexToDec(ch_str[2 * i] + ch_str[2 * i + 1]);
    }
    
    let ss = new Array(32);

    if (!fail){
        // hash kr1 and ch with SHAKE-256
        const buffer4 = Buffer.from(kr1);
        const buffer5 = Buffer.from(ch);
        const hash3 = new SHAKE(256);
        hash3.update(buffer4).update(buffer5);
        let ss_str = hash3.digest('hex');
        // convert hex string to array
        for (let i = 0; i < 32; i++) {
            ss[i] = hexToDec(ss_str[2 * i] + ss_str[2 * i + 1]);
        }
    } 
    else{
        // hash z and ch with SHAKE-256
        const buffer6 = Buffer.from(z);
        const buffer7 = Buffer.from(ch);
        const hash4 = new SHAKE(256);
        hash4.update(buffer6).update(buffer7);
        let ss_str = hash4.digest('hex');
        // convert hex string to array
        for (let i = 0; i < 32; i++) {
            ss[i] = hexToDec(ss_str[2 * i] + ss_str[2 * i + 1]);
        }
    }
    return ss;
}

// indcpaKeypair generates public and private keys for the CPA-secure
// public-key encryption scheme underlying Kyber.
function indcpaKeypair() {

    // random bytes for seed
    let rnd = new Array(32);
    for (let i = 0; i < 32; i++) {
        rnd[i] = nextInt(256);
    }

    // hash rnd with SHA3-512
    const buffer1 = Buffer.from(rnd);
    const hash1 = new SHA3(512);
    hash1.update(buffer1);
    let seed_str = hash1.digest('hex');
    // convert hex string to array
    let seed = new Array(64);
    for (let i = 0; i < 64; i++) {
        seed[i] = hexToDec(seed_str[2 * i] + seed_str[2 * i + 1]);
    }
    let publicSeed = seed.slice(0, 32);
    let noiseSeed = seed.slice(32, 64);

    // generate public matrix A (already in NTT form)
    let a = generateMatrixA(publicSeed, false, paramsK);

    // sample secret s
    let s = new Array(paramsK);
    let nonce = 0;
    for (let i = 0; i < paramsK; i++) {
        s[i] = sample(noiseSeed, nonce);
        nonce = nonce + 1;
    }

    // sample noise e
    let e = new Array(paramsK);
    for (let i = 0; i < paramsK; i++) {
        e[i] = sample(noiseSeed, nonce);
        nonce = nonce + 1;
    }

    // perform number theoretic transform on secret s
    for (let i = 0; i < paramsK; i++) {
        s[i] = ntt(s[i]);
    }

    // perform number theoretic transform on error/noise e
    for (let i = 0; i < paramsK; i++) {
        e[i] = ntt(e[i]);
    }

    // barrett reduction
    for (let i = 0; i < paramsK; i++) {
        s[i] = reduce(s[i]);
    }

    // KEY COMPUTATION
    // A.s + e = pk

    // calculate A.s
    let pk = new Array(paramsK);
    for (let i = 0; i < paramsK; i++) {
        // montgomery reduction
        pk[i] = polyToMont(multiply(a[i], s));
    }

    // calculate addition of e
    for (let i = 0; i < paramsK; i++) {
        pk[i] = add(pk[i], e[i]);
    }
    
    // barrett reduction
    for (let i = 0; i < paramsK; i++) {
        pk[i] = reduce(pk[i]);
    }

    // ENCODE KEYS
    let keys = new Array(2);
    
    // PUBLIC KEY
    // turn polynomials into byte arrays
    keys[0] = [];
    let bytes = [];
    for (let i = 0; i < paramsK; i++) {
        bytes = polyToBytes(a[i]);
        for (let j = 0; j < bytes.length; j++) {
            keys[0].push(bytes[j]);
        }
    }
    // append public seed
    for (let i = 0; i < publicSeed.length; i++) {
        keys[0].push(publicSeed[i]);
    }

    // PRIVATE KEY
    // turn polynomials into byte arrays
    keys[1] = [];
    bytes = [];
    for (let i = 0; i < paramsK; i++) {
        bytes = polyToBytes(a[i]);
        for (let j = 0; j < bytes.length; j++) {
            keys[1].push(bytes[j]);
        }
    }

    return keys;
}




// indcpaEncrypt is the encryption function of the CPA-secure
// public-key encryption scheme underlying Kyber.
function indcpaEncrypt(pk1, msg, coins) {

    // DECODE PUBLIC KEY
    let pk = new Array(paramsK);
    let start;
    let end;
    for (let i = 0; i < paramsK; i++) {
        start = (i * 384);
        end = (i + 1) * 384;
        pk[i] = polyFromBytes(pk1.slice(start, end));
    }
    let seed = pk1.slice(1152, 1184);

    // generate transpose of public matrix A
    let at = generateMatrixA(seed, true);

    // sample random vector r
    let r = new Array(paramsK);
    let nonce = 0;
    for (let i = 0; i < paramsK; i++) {
        r[i] = sample(coins, nonce);
        nonce = nonce + 1;
    }

    // sample error vector e1
    let e1 = new Array(paramsK);
    for (let i = 0; i < paramsK; i++) {
        e1[i] = sample(coins, nonce);
        nonce = nonce + 1;
    }

    // sample e2
    let e2 = sample(coins, nonce);

    // perform number theoretic transform on random vector r
    for (let i = 0; i < paramsK; i++) {
        r[i] = ntt(r[i]);
    }

    // barrett reduction
    for (let i = 0; i < paramsK; i++) {
        r[i] = reduce(r[i]);
    }

    // ENCRYPT COMPUTATION
    // A.r + e1 = u
    // pk.r + e2 + m = v

    // calculate A.r
    let u = new Array(paramsK);
    for (let i = 0; i < paramsK; i++) {
        u[i] = multiply(at[i], r);
    }

    // perform inverse number theoretic transform on A.r
    for (let i = 0; i < paramsK; i++) {
        u[i] = nttInverse(u[i]);
    }

    // calculate addition of e1
    for (let i = 0; i < paramsK; i++) {
        u[i] = add(u[i], e1[i]);
    }

    // decode message m
    let m = polyFromMsg(msg);

    // calculate pk.r
    let v = multiply(pk, r);

    // perform inverse number theoretic transform on pk.r
    v = nttInverse(v);

    // calculate addition of e2
    v = add(v, e2);

    // calculate addition of m
    v = add(v, m);

    // barrett reduction
    for (let i = 0; i < paramsK; i++) {
        u[i] = reduce(u[i]);
    }

    // barrett reduction
    v = reduce(v);

    c = indcpaPackCiphertext(u, v);

    return c;
}

// indcpaDecrypt is the decryption function of the CPA-secure
// public-key encryption scheme underlying Kyber.
function indcpaDecrypt(c, privateKey) {

    let result = indcpaUnpackCiphertext(c);

    let bp = result[0];
    let v = result[1];

    let privateKeyPolyvec = indcpaUnpackPrivateKey(privateKey);

    for (let i = 0; i < paramsK; i++) {
        bp[i] = ntt(bp[i]);
    }

    let mp = multiply(privateKeyPolyvec, bp);

    mp = nttInverse(mp);

    mp = polySub(v, mp);

    mp = reduce(mp);

    return polyToMsg(mp);
}

// indcpaUnpackPrivateKey de-serializes the private key and represents
// the inverse of indcpaPackPrivateKey.
function indcpaUnpackPrivateKey(packedPrivateKey) {
    return polyvecFromBytes(packedPrivateKey);
}

// polyvecFromBytes deserializes a vector of polynomials.
function polyvecFromBytes(a) {
    let r = new Array(paramsK);
    for (let i = 0; i < paramsK; i++) {
        r[i] = new Array(384);
    }
    let start;
    let end;
    for (let i = 0; i < paramsK; i++) {
        start = (i * paramsPolyBytes);
        end = (i + 1) * paramsPolyBytes;
        r[i] = polyFromBytes(a.slice(start, end));
    }
    return r;
}

// polyToBytes serializes a polynomial into an array of bytes.
function polyToBytes(a) {
    let t0, t1;
    let r = new Array(384);
    let a2 = polyCSubQ(a); // Returns: a - q if a >= q, else a (each coefficient of the polynomial)
    // for 0-127
    for (let i = 0; i < paramsN / 2; i++) {
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
    let r = new Array(384).fill(0);
    for (let i = 0; i < paramsN / 2; i++) {
        r[2 * i] = int16(((uint16(a[3 * i + 0]) >> 0) | (uint16(a[3 * i + 1]) << 8)) & 0xFFF);
        r[2 * i + 1] = int16(((uint16(a[3 * i + 1]) >> 4) | (uint16(a[3 * i + 2]) << 4)) & 0xFFF);
    }
    return r;
}

// polyToMsg converts a polynomial to a 32-byte message
// and represents the inverse of polyFromMsg.
function polyToMsg(a) {
    let msg = new Array(32);
    let t;
    let a2 = polyCSubQ(a);
    for (let i = 0; i < paramsN / 8; i++) {
        msg[i] = 0;
        for (let j = 0; j < 8; j++) {
            t = (((uint16(a2[8 * i + j]) << 1) + uint16(paramsQ / 2)) / uint16(paramsQ)) & 1;
            msg[i] |= byte(t << j);
        }
    }
    return msg;
}

// polyFromMsg converts a 32-byte message to a polynomial.
function polyFromMsg(msg) {
    let r = new Array(384).fill(0); // each element is int16 (0-65535)
    let mask; // int16
    for (let i = 0; i < paramsN / 8; i++) {
        for (let j = 0; j < 8; j++) {
            mask = -1 * int16((msg[i] >> j) & 1);
            r[8 * i + j] = mask & int16((paramsQ + 1) / 2);
        }
    }
    return r;
}

// polyReduce applies Barrett reduction to all coefficients of a polynomial.
function polyReduce(r) {
    for (let i = 0; i < paramsN; i++) {
        r[i] = barrett(r[i]);
    }
    return r;
}



// generateMatrixA deterministically generates a matrix `A` (or the transpose of `A`)
// from a seed. Entries of the matrix are polynomials that look uniformly random.
// Performs rejection sampling on the output of an extendable-output function (XOF).
function generateMatrixA(seed, transposed) {
    let a = new Array(3);
    let output = new Array(3 * 168);
    const xof = new SHAKE(128);
    let ctr = 0;
    for (let i = 0; i < paramsK; i++) {

        a[i] = new Array(paramsK);
        let transpose = new Array(2);

        for (let j = 0; j < paramsK; j++) {

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
            let buf_str = xof.digest({ buffer: Buffer.alloc(672), format: 'hex' });
            // convert hex string to array
            for (let n = 0; n < 672; n++) {
                output[n] = hexToDec(buf_str[2 * n] + buf_str[2 * n + 1]);
            }

            // run rejection sampling on the output from above
            let outputlen = 3 * 168; // 504
            let result = new Array(2);
            result = indcpaRejUniform(output.slice(0,504), outputlen, paramsN);
            a[i][j] = result[0]; // the result here is an NTT-representation
            ctr = result[1]; // keeps track of index of output array from sampling function

            while (ctr < paramsN) { // if the polynomial hasnt been filled yet with mod q entries

                let outputn = output.slice(504, 672); // take last 168 bytes of byte array from xof

                let result1 = new Array(2);
                result1 = indcpaRejUniform(outputn, 168, paramsN-ctr); // run sampling function again
                let missing = result1[0]; // here is additional mod q polynomial coefficients
                let ctrn = result1[1]; // how many coefficients were accepted and are in the output
                // starting at last position of output array from first sampling function until 256 is reached
                for (let k = ctr; k < paramsN; k++) { 
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
    let r = new Array(384).fill(0);
    let val0, val1; // d1, d2 in kyber documentation
    let pos = 0; // i
    let ctr = 0; // j

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

    let result = new Array(2);
    result[0] = r; // returns polynomial NTT representation
    result[1] = ctr; // ideally should return 256
    return result;
}

// sample samples a polynomial deterministically from a seed
// and nonce, with the output polynomial being close to a centered
// binomial distribution with parameter paramsETA = 2.
function sample(seed, nonce) {
    let l = paramsETA * paramsN / 4;
    let p = indcpaPrf(l, seed, nonce);
    return byteopsCbd(p);
}

// indcpaPrf provides a pseudo-random function (PRF) which returns
// a byte array of length `l`, using the provided key and nonce
// to instantiate the PRF's underlying hash function.
function indcpaPrf(l, key, nonce) {
    let buf = new Array(l);
    let nonce_arr = new Array(1);
    nonce_arr[0] = nonce;
    const hash = new SHAKE(256);
    hash.reset();
    const buffer1 = Buffer.from(key);
    const buffer2 = Buffer.from(nonce_arr);
    hash.update(buffer1).update(buffer2);
    let hash_str = hash.digest({ buffer: Buffer.alloc(l), format: 'hex' }); // 128 long byte array
    // convert hex string to array
    for (let n = 0; n < l; n++) {
        buf[n] = hexToDec(hash_str[2 * n] + hash_str[2 * n + 1]);
    }
    return buf;
}

// byteopsCbd computes a polynomial with coefficients distributed
// according to a centered binomial distribution with parameter paramsETA,
// given an array of uniformly random bytes.
function byteopsCbd(buf) {
    let t, d;
    let a, b;
    let r = new Array(384).fill(0); 
    for (let i = 0; i < paramsN / 8; i++) {
        t = (byteopsLoad32(buf.slice(4 * i, buf.length)) >>> 0);
        d = ((t & 0x55555555) >>> 0);
        d = (d + ((((t >> 1) >>> 0) & 0x55555555) >>> 0) >>> 0);
        for (let j = 0; j < 8; j++) {
            a = int16((((d >> (4 * j + 0)) >>> 0) & 0x3) >>> 0);
            b = int16((((d >> (4 * j + paramsETA)) >>> 0) & 0x3) >>> 0);
            r[8 * i + j] = a - b;
        }
    }
    return r;
}

// byteopsLoad32 returns a 32-bit unsigned integer loaded from byte x.
function byteopsLoad32(x) {
    let r;
    r = uint32(x[0]);
    r = (((r | (uint32(x[1]) << 8)) >>> 0) >>> 0);
    r = (((r | (uint32(x[2]) << 16)) >>> 0) >>> 0);
    r = (((r | (uint32(x[3]) << 24)) >>> 0) >>> 0);
    return uint32(r);
}

// ntt performs an inplace number-theoretic transform (NTT) in `Rq`.
// The input is in standard order, the output is in bit-reversed order.
function ntt(r) {
    let j = 0;
    let k = 1;
    let zeta;
    let t;
    // 128, 64, 32, 16, 8, 4, 2
    for (let l = 128; l >= 2; l >>= 1) {
        // 0, 
        for (let start = 0; start < 256; start = j + l) {
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
    for (let i = 0; i < paramsN; i++) {
        r[i] = barrett(r[i]);
    }
    return r;
}

// barrett computes a Barrett reduction; given
// a integer `a`, returns a integer congruent to
// `a mod Q` in {0,...,Q}.
function barrett(a) {
    let v = ( (1<<24) + paramsQ / 2) / paramsQ;
    let t = v * a >> 24;
    t = t * paramsQ;
    return a - t;
}

// byteopsMontgomeryReduce computes a Montgomery reduction; given
// a 32-bit integer `a`, returns `a * R^-1 mod Q` where `R=2^16`.
function byteopsMontgomeryReduce(a) {
    let u = int16(int32(a) * paramsQinv);
    let t = u * paramsQ;
    t = a - t;
    t >>= 16;
    return int16(t);
}

// polyToMont performs the in-place conversion of all coefficients
// of a polynomial from the normal domain to the Montgomery domain.
function polyToMont(r) {
    // let f = int16(((uint64(1) << 32) >>> 0) % uint64(paramsQ));
    let f = 1353; // if paramsQ changes then this needs to be updated
    for (let i = 0; i < paramsN; i++) {
        r[i] = byteopsMontgomeryReduce(int32(r[i]) * int32(f));
    }
    return r;
}

// pointwise-multiplies elements of polynomial-vectors
// `a` and `b`, accumulates the results into `r`, and then multiplies by `2^-16`.
function multiply(a, b) {
    let r = polyBaseMulMontgomery(a[0], b[0]);
    let t;
    for (let i = 1; i < paramsK; i++) {
        t = polyBaseMulMontgomery(a[i], b[i]);
        r = add(r, t);
    }
    return reduce(r);
}

// polyBaseMulMontgomery performs the multiplication of two polynomials
// in the number-theoretic transform (NTT) domain.
function polyBaseMulMontgomery(a, b) {
    let rx, ry;
    for (let i = 0; i < paramsN / 4; i++) {
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
    let r = new Array(2);
    r[0] = nttFqMul(a1, b1);
    r[0] = nttFqMul(r[0], zeta);
    r[0] = r[0] + nttFqMul(a0, b0);
    r[1] = nttFqMul(a0, b1);
    r[1] = r[1] + nttFqMul(a1, b0);
    return r;
}

// add adds two polynomials.
function add(a, b) {
    let c = new Array(384);
    for (let i = 0; i < paramsN; i++) {
        c[i] = a[i] + b[i];
    }
    return c;
}

// polySub subtracts two polynomials.
function polySub(a, b) {
    for (let i = 0; i < paramsN; i++) {
        a[i] = a[i] - b[i];
    }
    return a;
}

// nttInverse performs an inplace inverse number-theoretic transform (NTT)
// in `Rq` and multiplication by Montgomery factor 2^16.
// The input is in bit-reversed order, the output is in standard order.
function nttInverse(r) {
    let j = 0;
    let k = 0;
    let zeta;
    let t;
    for (let l = 2; l <= 128; l <<= 1) {
        for (let start = 0; start < 256; start = j + l) {
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

// indcpaPackCiphertext serializes the ciphertext as a concatenation of
// the compressed and serialized vector of polynomials `b` and the
// compressed and serialized polynomial `v`.
function indcpaPackCiphertext(b, v) {
    let arr1 = polyvecCompress(b);
    let arr2 = polyCompress(v);
    return arr1.concat(arr2);
}

// indcpaUnpackCiphertext de-serializes and decompresses the ciphertext
// from a byte array, and represents the approximate inverse of
// indcpaPackCiphertext.
function indcpaUnpackCiphertext(c) {
    let b = polyvecDecompress(c.slice(0, 960));
    let v = polyDecompress(c.slice(960, 1088));
    let result = new Array(2);
    result[0] = b;
    result[1] = v;
    return result;
}

// polyvecCompress lossily compresses and serializes a vector of polynomials.
function polyvecCompress(a) {

    a = polyvecCSubQ(a);

    let rr = 0;

    let r = new Array(paramsPolyvecCompressedBytesK768);

    let t = new Array(4);
    for (let i = 0; i < paramsK; i++) {
        for (let j = 0; j < paramsN / 4; j++) {
            for (let k = 0; k < 4; k++) {
                t[k] = uint16((((a[i][4 * j + k] << 10) + paramsQ / 2) / paramsQ) & 0x3ff);
            }
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

// polyvecDecompress de-serializes and decompresses a vector of polynomials and
// represents the approximate inverse of polyvecCompress. Since compression is lossy,
// the results of decompression will may not match the original vector of polynomials.
function polyvecDecompress(a) {
    let r = new Array(paramsK);
    for (let i = 0; i < paramsK; i++) {
        r[i] = new Array(384);
    }
    let aa = 0;
    let t = new Array(4);
    for (let i = 0; i < paramsK; i++) {
        for (let j = 0; j < paramsN / 4; j++) {
            t[0] = (uint16(a[aa + 0]) >> 0) | (uint16(a[aa + 1]) << 8);
            t[1] = (uint16(a[aa + 1]) >> 2) | (uint16(a[aa + 2]) << 6);
            t[2] = (uint16(a[aa + 2]) >> 4) | (uint16(a[aa + 3]) << 4);
            t[3] = (uint16(a[aa + 3]) >> 6) | (uint16(a[aa + 4]) << 2);
            aa = aa + 5;
            for (let k = 0; k < 4; k++) {
                r[i][4 * j + k] = int16((((uint32(t[k] & 0x3FF) >>> 0) * (uint32(paramsQ) >>> 0) >>> 0) + 512) >> 10 >>> 0);
            }
        }
    }
    return r;
}

// polyvecCSubQ applies the conditional subtraction of `Q` to each coefficient
// of each element of a vector of polynomials.
function polyvecCSubQ(r) {
    for (let i = 0; i < paramsK; i++) {
        r[i] = polyCSubQ(r[i]);
    }
    return r;
}

// polyCSubQ applies the conditional subtraction of `Q` to each coefficient
// of a polynomial.
function polyCSubQ(r) {
    for (let i = 0; i < paramsN; i++) {
        r[i] = byteopsCSubQ(r[i]);
    }
    return r;
}

// polyCompress lossily compresses and subsequently serializes a polynomial.
function polyCompress(a) {
    let t = new Array(8);
    a = polyCSubQ(a);
    let rr = 0;
    let r = new Array(paramsPolyCompressedBytesK768);
    for (let i = 0; i < paramsN / 8; i++) {
        for (let j = 0; j < 8; j++) {
            t[j] = byte(((a[8 * i + j] << 4) + paramsQ / 2) / paramsQ) & 15;
        }
        r[rr + 0] = t[0] | (t[1] << 4);
        r[rr + 1] = t[2] | (t[3] << 4);
        r[rr + 2] = t[4] | (t[5] << 4);
        r[rr + 3] = t[6] | (t[7] << 4);
        rr = rr + 4;
    }
    return r;
}

// polyDecompress de-serializes and subsequently decompresses a polynomial,
// representing the approximate inverse of polyCompress.
// Note that compression is lossy, and thus decompression will not match the
// original input.
function polyDecompress(a) {
    let r = new Array(384);
    let aa = 0;
    for (let i = 0; i < paramsN / 2; i++) {
        r[2 * i + 0] = int16(((uint16(a[aa] & 15) * uint16(paramsQ)) + 8) >> 4);
        r[2 * i + 1] = int16(((uint16(a[aa] >> 4) * uint16(paramsQ)) + 8) >> 4);
        aa = aa + 1;
    }
    return r;
}

// byteopsCSubQ conditionally subtracts Q from a.
// if a is 3329 then convert to 0
// Returns:     a - q if a >= q, else a
function byteopsCSubQ(a) {
    a = a - paramsQ; // should result in a negative integer
    // push left most signed bit to right most position
    // remember javascript does bitwise operations in signed 32 bit
    // add q back again if left most bit was 0 (positive number)
    a = a + ((a >> 31) & paramsQ);
    return a;
}

function byte(n) {
    n = n % 256;
    return n;
}

/* 
// commented out because not needed, just here for reference
function int8(n){
    let end = -128;
    let start = 127;
    
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
    let end = -32768;
    let start = 32767;

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
    let end = -2147483648;
    let start = 2147483647;

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
    for (let i = 0; i < a.length; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}


// test run function
function TestK768(){

    // read values from PQCkemKAT_2400.rsp
    // sk, ct, ss

    let fs = require('fs');
    let textByLine = fs.readFileSync('PQCkemKAT_2400.rsp').toString().split("\n");

    // console.log(textByLine.length); // seems to be an array of strings (lines)
    let sk100 = [];
    let ct100 = [];
    let ss100 = [];
    let counter = 0;
    while (counter < textByLine.length){
        if (textByLine[counter][0] == 'c' && textByLine[counter][1] == 't'){
            let tmp = [];
            for (let j = 0; j < 1088; j++) {
                tmp[j] = hexToDec(textByLine[counter][2 * j + 5] + textByLine[counter][2 * j + 1 + 5]);
            }
            ct100.push(tmp);
            counter = counter + 1;
            continue;
        }
        else if(textByLine[counter][0] == 's' && textByLine[counter][1] == 's'){
            let tmp = [];
            for (let j = 0; j < 32; j++) {
                tmp[j] = hexToDec(textByLine[counter][2 * j + 5] + textByLine[counter][2 * j + 1 + 5]);
            }
            ss100.push(tmp);
            counter = counter + 1;
            continue;
        }
        else if(textByLine[counter][0] == 's' && textByLine[counter][1] == 'k'){
            let tmp = [];
            for (let j = 0; j < 2400; j++) {
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

    let failures = 0;

    // for each case (100 total)
    // test if ss equals Decrypt768(c,sk)
    for (let i=0; i<100; i++){
        let ss2 = Decrypt768(ct100[i],sk100[i]);

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

TestK768();

// To generate a public and private key pair (pk, sk)
let pk_sk = KeyGen768();
let pk = pk_sk[0];
let sk = pk_sk[1];

// To generate a random 256 bit symmetric key (ss) and its encapsulation (c)
let c_ss = Encrypt768(pk);
let c = c_ss[0];
let ss1 = c_ss[1];

// To decapsulate and obtain the same symmetric key
let ss2 = Decrypt768(c, sk);

console.log("ss1", ss1);
console.log("ss2",ss2);

// returns 1 if both symmetric keys are the same
console.log(ArrayCompare(ss1, ss2));
********************************************************/