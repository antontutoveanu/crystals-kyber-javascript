import {KeyGen512, Encrypt512, Decrypt512, TestK512} from './kyber512';
import {KeyGen768, Encrypt768, Decrypt768, TestK768} from './kyber768';
import {KeyGen1024, Encrypt1024, Decrypt1024, TestK1024} from './kyber1024';

// 512
export function K512_KeyGen(){
    let pk_sk = KeyGen512();
    return pk_sk;
}

export function K512_Encrypt(pk){
    let c_ss = Encrypt512(pk);
    return c_ss;
}

export function K512_Decrypt(c,sk){
    let ss = Decrypt512(c,sk);
    return ss;
}

export function K512_Test(){
    TestK512();
}

// 768
export function K768_KeyGen(){
    let pk_sk = KeyGen768();
    return pk_sk;
}

export function K768_Encrypt(pk){
    let c_ss = Encrypt768(pk);
    return c_ss;
}

export function K768_Decrypt(c,sk){
    let ss = Decrypt768(c,sk);
    return ss;
}

export function K768_Test(){
    TestK768();
}

// 1024
export function K1024_KeyGen(){
    let pk_sk = KeyGen1024();
    return pk_sk;
}

export function K1024_Encrypt(pk){
    let c_ss = Encrypt1024(pk);
    return c_ss;
}

export function K1024_Decrypt(c,sk){
    let ss = Decrypt1024(c,sk);
    return ss;
}

export function K1024_Test(){
    TestK1024();
}