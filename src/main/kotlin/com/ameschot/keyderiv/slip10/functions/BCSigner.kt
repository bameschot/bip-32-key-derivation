package com.ameschot.keyderiv.slip10.functions

import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

val SIGN_ALG = "SHA512withECDSA"
val SIGN_PROVIDER = "BC"

fun sign(data: ByteArray, privateKey:PrivateKey):ByteArray{
    val signature: Signature = Signature.getInstance(SIGN_ALG, SIGN_PROVIDER)
    signature.initSign(privateKey)
    signature.update(data)
    return signature.sign()
}


fun verify(data:ByteArray, sig: ByteArray, publicKey:PublicKey): Boolean {
    val signature: Signature = Signature.getInstance(SIGN_ALG, SIGN_PROVIDER)
    signature.initVerify(publicKey)
    signature.update(data)
    return signature.verify(sig)
}