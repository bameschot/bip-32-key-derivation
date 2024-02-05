package com.ameschot.keyderiv.functions

import com.ameschot.keyderiv.CKDPriv
import com.ameschot.keyderiv.HARDENED_KEY_IDX
import com.ameschot.keyderiv.N
import com.ameschot.keyderiv.model.ExtendedPrivateKey
import com.ameschot.keyderiv.model.ExtendedPublicKey
import com.ameschot.keyderiv.seed

fun deriveFromPath(seed:ByteArray, path:String): KeyPair {
    return deriveFromPath(seed(seed),path)
}

fun deriveFromPath(parent: ExtendedPrivateKey, path:String, depth:Byte=0): KeyPair {

    val sPath = path.split("/", limit = 2)

    val kp =
    //request key is master key
    if(sPath[0] == "m")
        KeyPair(
            FullPrivateKey(parent, ser32(0x00000000), depth, 0),
            FullPublicKey(N(parent), ser32(0x00000000), depth, 0)
        )
    else{
        //derive from (hardended) index
        val idx = if (sPath[0].last() == 'H') (sPath[0].subSequence(0,sPath[0].length-1)).toString().toLong() + HARDENED_KEY_IDX else sPath[0].toLong()
        val pk = CKDPriv(parent,idx)
        val fingerprint = fingerprintFromPublic(N(parent))
        KeyPair(
            FullPrivateKey(pk, fingerprint, depth, idx),
            FullPublicKey(N(pk), fingerprint, depth, idx)
        )
    }

    //if no more path return the requested key
    if(sPath.size==1 || depth+1>Byte.MAX_VALUE){
        return kp
    }

    //derive the next part of the path
    return deriveFromPath(kp.priv.extendedPrivateKey,sPath[1],(depth + 1).toByte())
}

class KeyPair(val priv: FullPrivateKey, val pub: FullPublicKey){

    fun toPublicJWK() =
        toJWK(pub.toPublic())
}

class FullPrivateKey(
    val extendedPrivateKey: ExtendedPrivateKey,
    val parentFingerprint:ByteArray,
    val depth:Byte,
    val i:Long
){
    fun toBase58Key() =
        btcSerPriv(extendedPrivateKey, parentFingerprint,depth, i)

    fun toPrivate() =
        toPrivateKey(extendedPrivateKey.k)
}

class FullPublicKey(
    val extendedPublicKey: ExtendedPublicKey,
    val parentFingerprint:ByteArray,
    val depth:Byte,
    val i:Long
){
    fun toBase58Key() =
        btcSerPub(extendedPublicKey, parentFingerprint,depth, i)

    fun toPublic() =
        toPublicKey(extendedPublicKey.K)
}