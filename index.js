import {KeyGen768, Encrypt768, Decrypt768} from './kyber768';

export function K768_KeyGen(){
    var pk_sk = KeyGen768();
    return pk_sk;
}

export function K768_Encrypt(pk){
    var c_ss = Encrypt768(pk);
    return c_ss;
}

export function K768_Decrypt(c,sk){
    var ss = Decrypt768(c,sk);
    return ss;
}