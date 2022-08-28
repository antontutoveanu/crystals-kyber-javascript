/*****************************************************************************************************************************/
// imports
const { SHA3, SHAKE } = require('sha3');
const webcrypto = require('crypto').webcrypto;
/*****************************************************************************************************************************/
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

const paramsK = 4;
const paramsN = 256;
const paramsQ = 3329;
const paramsQinv = 62209;
const paramsETA = 2;
/*****************************************************************************************************************************/
// CRYSTALS-KYBER JAVASCRIPT

// 1. KeyGen
KeyGen1024 = function() {
    // IND-CPA keypair
    let indcpakeys = indcpaKeyGen();

    let pk = indcpakeys[0];
    let sk = indcpakeys[1];

    // FO transform to make IND-CCA2

    // get hash of pk
    const buffer1 = Buffer.from(pk);
    const hash1 = new SHA3(256);
    hash1.update(buffer1);
    let pkh = hash1.digest();

    // read 32 random values (0-255) into a 32 byte array
    let rnd = new Uint8Array(32);
    webcrypto.getRandomValues(rnd); // web api cryptographically strong random values

    // concatenate to form IND-CCA2 private key: sk + pk + h(pk) + rnd
    for (let i = 0; i < pk.length; i++) {
        sk.push(pk[i]);
    }
    for (let i = 0; i < pkh.length; i++) {
        sk.push(pkh[i]);
    }
    for (let i = 0; i < rnd.length; i++) {
        sk.push(rnd[i]);
    }

    let keys = new Array(2);
    keys[0] = pk;
    keys[1] = sk;
    return keys;
}
/*****************************************************************************************************************************/
// 2. Encrypt
Encrypt1024 = function(pk) {

    // random 32 bytes
    let m = new Uint8Array(32);
    webcrypto.getRandomValues(m); // web api cryptographically strong random values

    // hash m with SHA3-256
    const buffer1 = Buffer.from(m);
    const hash1 = new SHA3(256);
    hash1.update(buffer1);
    let mh = hash1.digest();

    // hash pk with SHA3-256
    const buffer2 = Buffer.from(pk);
    const hash2 = new SHA3(256);
    hash2.update(buffer2);
    let pkh = hash2.digest();

    // hash mh and pkh with SHA3-512
    const buffer3 = Buffer.from(mh);
    const buffer4 = Buffer.from(pkh);
    const hash3 = new SHA3(512);
    hash3.update(buffer3).update(buffer4);
    let kr = new Uint8Array(hash3.digest());
    let kr1 = kr.slice(0, 32);
    let kr2 = kr.slice(32, 64);

    // generate ciphertext c
    let c = indcpaEncrypt(pk, mh, kr2);

    // hash ciphertext with SHA3-256
    const buffer5 = Buffer.from(c);
    const hash4 = new SHA3(256);
    hash4.update(buffer5);
    let ch = hash4.digest();

    // hash kr1 and ch with SHAKE-256
    const buffer6 = Buffer.from(kr1);
    const buffer7 = Buffer.from(ch);
    const hash5 = new SHAKE(256);
    hash5.update(buffer6).update(buffer7);
    let ss = hash5.digest();

    // output (c, ss)
    let result = new Array(2);
    result[0] = c;
    result[1] = ss;

    return result;
}
/*****************************************************************************************************************************/
// 3. Decrypt
Decrypt1024 = function(c, privateKey) {

    // extract sk, pk, pkh and z
    let sk = privateKey.slice(0, 1536); // indcpa secret key
    let pk = privateKey.slice(1536, 3104); // indcpa public key
    let pkh = privateKey.slice(3104, 3136); // sha3-256 hash
    let z = privateKey.slice(3136, 3168);

    // IND-CPA decrypt
    let m = indcpaDecrypt(c, sk);

    // hash m and pkh with SHA3-512
    const buffer1 = Buffer.from(m);
    const buffer2 = Buffer.from(pkh);
    const hash1 = new SHA3(512);
    hash1.update(buffer1).update(buffer2);
    let kr = new Uint8Array(hash1.digest());
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
    let ch = hash2.digest();

    let ss = [];
    if (!fail){
        // hash kr1 and ch with SHAKE-256
        const buffer4 = Buffer.from(kr1);
        const buffer5 = Buffer.from(ch);
        const hash3 = new SHAKE(256);
        hash3.update(buffer4).update(buffer5);
        ss = hash3.digest();
    } 
    else{
        // hash z and ch with SHAKE-256
        const buffer6 = Buffer.from(z);
        const buffer7 = Buffer.from(ch);
        const hash4 = new SHAKE(256);
        hash4.update(buffer6).update(buffer7);
        ss = hash4.digest();
    }
    return ss;
}
/*****************************************************************************************************************************/
// indcpaKeyGen generates public and private keys for the CPA-secure
// public-key encryption scheme underlying Kyber.
function indcpaKeyGen() {

    // random bytes for seed
    let rnd = new Uint8Array(32);
    webcrypto.getRandomValues(rnd); // web api cryptographically strong random values

    // hash rnd with SHA3-512
    const buffer1 = Buffer.from(rnd);
    const hash1 = new SHA3(512);
    hash1.update(buffer1);
    let seed = new Uint8Array(hash1.digest());
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
        bytes = polyToBytes(pk[i]);
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
        bytes = polyToBytes(s[i]);
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
    let seed = pk1.slice(1536, 1568);

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
    for (i = 0; i < paramsK; i++) {
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

    // compress
    let c1 = compress1(u);
    let c2 = compress2(v);

    // return c1 || c2
    return c1.concat(c2);
}

// indcpaDecrypt is the decryption function of the CPA-secure
// public-key encryption scheme underlying Kyber.
function indcpaDecrypt(c, privateKey) {

    // extract ciphertext
    let u = decompress1(c.slice(0, 1408));
    let v = decompress2(c.slice(1408, 1568));

    let privateKeyPolyvec = polyvecFromBytes(privateKey);

    for (let i = 0; i < paramsK; i++) {
        u[i] = ntt(u[i]);
    }

    let mp = multiply(privateKeyPolyvec, u);

    mp = nttInverse(mp);

    mp = subtract(v, mp);

    mp = reduce(mp);

    return polyToMsg(mp);
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
        start = (i * 384);
        end = (i + 1) * 384;
        r[i] = polyFromBytes(a.slice(start, end));
    }
    return r;
}

// polyToBytes serializes a polynomial into an array of bytes.
function polyToBytes(a) {
    let t0, t1;
    let r = new Array(384);
    let a2 = subtract_q(a); // Returns: a - q if a >= q, else a (each coefficient of the polynomial)
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
    let a2 = subtract_q(a);
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



// generateMatrixA deterministically generates a matrix `A` (or the transpose of `A`)
// from a seed. Entries of the matrix are polynomials that look uniformly random.
// Performs rejection sampling on the output of an extendable-output function (XOF).
function generateMatrixA(seed, transposed) {
    let a = new Array(paramsK);
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
            let output = new Uint8Array(xof.digest({ buffer: Buffer.alloc(672)}));

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
    let p = prf(l, seed, nonce);
    return byteopsCbd(p);
}

// prf provides a pseudo-random function (PRF) which returns
// a byte array of length `l`, using the provided key and nonce
// to instantiate the PRF's underlying hash function.
function prf(l, key, nonce) {
    let nonce_arr = new Array(1);
    nonce_arr[0] = nonce;
    const hash = new SHAKE(256);
    hash.reset();
    const buffer1 = Buffer.from(key);
    const buffer2 = Buffer.from(nonce_arr);
    hash.update(buffer1).update(buffer2);
    let buf = hash.digest({ buffer: Buffer.alloc(l)}); // 128 long byte array
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

// adds two polynomials.
function add(a, b) {
    let c = new Array(384);
    for (let i = 0; i < paramsN; i++) {
        c[i] = a[i] + b[i];
    }
    return c;
}

// subtracts two polynomials.
function subtract(a, b) {
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

// compress1 lossily compresses and serializes a vector of polynomials.
function compress1(u) {
    let rr = 0;
    let r = new Array(1408); // 4 * 352
    let t = new Array(8);
    for (let i = 0; i < paramsK; i++) {
        for (let j = 0; j < paramsN/8; j++) {
            for (let k = 0; k < 8; k++) {
                t[k] = uint16((((uint32(u[i][8*j+k]) << 11 >>> 0) + uint32(paramsQ/2)) / uint32(paramsQ)) & 0x7ff >>> 0);
            }
            r[rr+0] = byte((t[0] >> 0));
            r[rr+1] = byte((t[0] >> 8) | (t[1] << 3));
            r[rr+2] = byte((t[1] >> 5) | (t[2] << 6));
            r[rr+3] = byte((t[2] >> 2));
            r[rr+4] = byte((t[2] >> 10) | (t[3] << 1));
            r[rr+5] = byte((t[3] >> 7) | (t[4] << 4));
            r[rr+6] = byte((t[4] >> 4) | (t[5] << 7));
            r[rr+7] = byte((t[5] >> 1));
            r[rr+8] = byte((t[5] >> 9) | (t[6] << 2));
            r[rr+9] = byte((t[6] >> 6) | (t[7] << 5));
            r[rr+10] = byte((t[7] >> 3));
            rr = rr + 11;
        }
    }
    return r;
}

// compress2 lossily compresses and subsequently serializes a polynomial.
function compress2(v) {
    let rr = 0;
    let r = new Array(160);
    let t = new Array(8);
    for (let i = 0; i < paramsN/8; i++) {
        for (let j = 0; j < 8; j++) {
            t[j] = byte(((uint32(v[8*i+j])<<5 >>> 0)+uint32(paramsQ/2))/uint32(paramsQ)) & 31;
        }
        r[rr+0] = byte((t[0] >> 0) | (t[1] << 5));
        r[rr+1] = byte((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
        r[rr+2] = byte((t[3] >> 1) | (t[4] << 4));
        r[rr+3] = byte((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
        r[rr+4] = byte((t[6] >> 2) | (t[7] << 3));
        rr = rr + 5;
    }
    return r;
}

// decompress1 de-serializes and decompresses a vector of polynomials and
// represents the approximate inverse of compress1. Since compression is lossy,
// the results of decompression may not match the original vector of polynomials.
function decompress1(a) {
    let r = new Array(paramsK);
    for (let i = 0; i < paramsK; i++) {
        r[i] = new Array(384);
    }
    let aa = 0;
    let t = new Array(8);
    for (let i = 0; i < paramsK; i++) {
        for (let j = 0; j < paramsN/8; j++) {
            t[0] = (uint16(a[aa+0]) >> 0) | (uint16(a[aa+1]) << 8);
            t[1] = (uint16(a[aa+1]) >> 3) | (uint16(a[aa+2]) << 5);
            t[2] = (uint16(a[aa+2]) >> 6) | (uint16(a[aa+3]) << 2) | (uint16(a[aa+4]) << 10);
            t[3] = (uint16(a[aa+4]) >> 1) | (uint16(a[aa+5]) << 7);
            t[4] = (uint16(a[aa+5]) >> 4) | (uint16(a[aa+6]) << 4);
            t[5] = (uint16(a[aa+6]) >> 7) | (uint16(a[aa+7]) << 1) | (uint16(a[aa+8]) << 9);
            t[6] = (uint16(a[aa+8]) >> 2) | (uint16(a[aa+9]) << 6);
            t[7] = (uint16(a[aa+9]) >> 5) | (uint16(a[aa+10]) << 3);
            aa = aa + 11;
            for (let k = 0; k < 8; k++) {
                r[i][8*j+k] = (uint32(t[k] & 0x7FF) * paramsQ + 1024) >> 11;
            }
        }
    }
    return r;
}

// subtract_q applies the conditional subtraction of q to each coefficient of a polynomial.
// if a is 3329 then convert to 0
// Returns:     a - q if a >= q, else a
function subtract_q(r) {
    for (let i = 0; i < paramsN; i++) {
        r[i] = r[i] - paramsQ; // should result in a negative integer
        // push left most signed bit to right most position
        // javascript does bitwise operations in signed 32 bit
        // add q back again if left most bit was 0 (positive number)
        r[i] = r[i] + ((r[i] >> 31) & paramsQ);
    }
    return r;
}

// decompress2 de-serializes and subsequently decompresses a polynomial,
// representing the approximate inverse of compress2.
// Note that compression is lossy, and thus decompression will not match the
// original input.
function decompress2(a) {
    let r = new Array(384);
    let t = new Array(8);
    let aa = 0;
    for (let i = 0; i < paramsN/8; i++) {
        t[0] = (a[aa+0] >> 0);
        t[1] = (a[aa+0] >> 5) | (a[aa+1] << 3);
        t[2] = (a[aa+1] >> 2);
        t[3] = (a[aa+1] >> 7) | (a[aa+2] << 1);
        t[4] = (a[aa+2] >> 4) | (a[aa+3] << 4);
        t[5] = (a[aa+3] >> 1);
        t[6] = (a[aa+3] >> 6) | (a[aa+4] << 2);
        t[7] = (a[aa+4] >> 3);
        aa = aa + 5;
        for (let j = 0; j < 8; j++) {
            r[8*i+j] = int16(((uint32(t[j]&31 >>> 0) * uint32(paramsQ)) + 16) >> 5);
        }
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
function hexToDec(hexString) {
    return parseInt(hexString, 16);
}
// test run function
Test1024 = function(){
    // read values from PQCkemKAT_3168.rsp
    // sk, ct, ss

    let fs = require('fs');
    let textByLine = fs.readFileSync('./node_modules/crystals-kyber/PQCkemKAT_3168.rsp').toString().split("\n");

    // console.log(textByLine.length); // seems to be an array of strings (lines)
    let sk100 = [];
    let ct100 = [];
    let ss100 = [];
    let counter = 0;
    while (counter < textByLine.length){
        if (textByLine[counter][0] == 'c' && textByLine[counter][1] == 't'){
            let tmp = [];
            for (j = 0; j < 1568; j++) {
                tmp[j] = hexToDec(textByLine[counter][2 * j + 5] + textByLine[counter][2 * j + 1 + 5]);
            }
            ct100.push(tmp);
            counter = counter + 1;
            continue;
        }
        else if(textByLine[counter][0] == 's' && textByLine[counter][1] == 's'){
            let tmp = [];
            for (j = 0; j < 32; j++) {
                tmp[j] = hexToDec(textByLine[counter][2 * j + 5] + textByLine[counter][2 * j + 1 + 5]);
            }
            ss100.push(tmp);
            counter = counter + 1;
            continue;
        }
        else if(textByLine[counter][0] == 's' && textByLine[counter][1] == 'k'){
            let tmp = [];
            for (j = 0; j < 3168; j++) {
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
    // test if ss equals Decrypt1024(c,sk)
    for (let i=0; i<100; i++){
        let ss2 = Decrypt1024(ct100[i],sk100[i]);

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

    // To generate a public and private key pair (pk, sk)
    let pk_sk = KeyGen1024();
    let pk = pk_sk[0];
    let sk = pk_sk[1];

    // To generate a random 256 bit symmetric key (ss) and its encapsulation (c)
    let c_ss = Encrypt1024(pk);
    let c = c_ss[0];
    let ss1 = c_ss[1];

    // To decapsulate and obtain the same symmetric key
    let ss2 = Decrypt1024(c, sk);

    console.log();
    console.log("ss1",ss1);
    console.log("ss2",ss2);

    // returns 1 if both symmetric keys are the same
    console.log(ArrayCompare(ss1, ss2));
    return
}

// Export functions to index.js (entry point)
exports.KeyGen1024 = KeyGen1024;
exports.Encrypt1024 = Encrypt1024;
exports.Decrypt1024 = Decrypt1024;
exports.Test1024 = Test1024;