package com.ameschot.keyderiv.slip10.functions

import com.ameschot.keyderiv.slip10.CKDPriv
import com.ameschot.keyderiv.slip10.HARDENED_KEY_IDX
import com.ameschot.keyderiv.slip10.N
import com.ameschot.keyderiv.slip10.model.ExtendedPrivateKey
import com.ameschot.keyderiv.slip10.model.ExtendedPublicKey
import com.ameschot.keyderiv.slip10.seed

fun deriveFromPath(seed:ByteArray,path:String, curve: Curve): KeyPair {
    return deriveFromPath(seed(seed, curve),path, curve = curve)
}

fun deriveFromPath(parent: ExtendedPrivateKey,path:String, depth:Byte=0, curve:Curve): KeyPair {

    val sPath = path.split("/", limit = 2)

    val kp =
    //request key is master key
    if(sPath[0] == "m")
        KeyPair(
            FullPrivateKey(parent, ser32(0x00000000), depth, 0,curve),
            FullPublicKey(N(parent,curve), ser32(0x00000000), depth, 0,curve),
            curve
        )
    else{
        //derive from (hardended) index
        val idx = if (sPath[0].last() == 'H') (sPath[0].subSequence(0,sPath[0].length-1)).toString().toLong() + HARDENED_KEY_IDX else sPath[0].toLong()
        val pk = CKDPriv(parent,idx, curve)
        val fingerprint = fingerprintFromPublic(N(parent, curve))
        KeyPair(
            FullPrivateKey(pk, fingerprint, depth, idx,curve),
            FullPublicKey(N(pk, curve), fingerprint, depth, idx,curve),
            curve
        )
    }

    //if no more path return the requested key
    if(sPath.size==1 || depth+1>Byte.MAX_VALUE){
        return kp
    }

    //derive the next part of the path
    return deriveFromPath(kp.priv.extendedPrivateKey, sPath[1],(depth + 1).toByte(),curve)
}

class KeyPair(val priv: FullPrivateKey, val pub: FullPublicKey, val curve: Curve){

    fun toPublicJWK() =
        toJWK(pub.toPublic())
}

class FullPrivateKey(
    val extendedPrivateKey: ExtendedPrivateKey,
    val parentFingerprint:ByteArray,
    val depth:Byte,
    val i:Long,
    val curve: Curve
){
    fun toBase58Key() =
        btcSerPriv(extendedPrivateKey, parentFingerprint,depth, i)

    fun toHexKey() = extendedPrivateKey.k.toString(16).padStart(64,'0')

    fun toPrivate() =
        toPrivateKey(extendedPrivateKey.k, curve)
}

class FullPublicKey(
    val extendedPublicKey: ExtendedPublicKey,
    val parentFingerprint:ByteArray,
    val depth:Byte,
    val i:Long,
    val curve: Curve
){
    fun toBase58Key() =
        btcSerPub(extendedPublicKey, parentFingerprint,depth, i)

    fun toHexKey() = byteToHex(extendedPublicKey.K.getEncoded(true))

    fun toPublic() =
        toPublicKey(extendedPublicKey.K, curve)
}