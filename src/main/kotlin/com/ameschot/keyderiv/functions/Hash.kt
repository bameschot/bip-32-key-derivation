package com.ameschot.keyderiv.functions

import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.KeyParameter
import java.security.MessageDigest


fun HMACSHA512(key: ByteArray, data:ByteArray): ByteArray {
    //create digest with key
    val hmac = HMac(SHA512Digest())
    hmac.init(KeyParameter(key))

    //add data
    val hmacIn: ByteArray = data
    hmac.update(hmacIn, 0, hmacIn.size)
    val hmacOut = ByteArray(hmac.macSize)

    //create hmac and return
    hmac.doFinal(hmacOut, 0)
    return hmacOut;
}

fun sha256(data: ByteArray):ByteArray{
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(data)

    return digest.digest()
}

fun ripedm160(data: ByteArray):ByteArray{
    val digest = MessageDigest.getInstance("RIPEMD160")
    digest.update(data)

    return digest.digest()
}

fun HASH160(data: ByteArray) =
    ripedm160(sha256(data))