package com.ameschot.keyderiv.functions

import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey

val KEY_ALG = "EC"

fun toPrivateKey(k:BigInteger):PrivateKey{
    val privateKeySpec = ECPrivateKeySpec(k, spec)
    val keyFactory: KeyFactory = KeyFactory.getInstance(KEY_ALG)
    return keyFactory.generatePrivate(privateKeySpec)
}

fun toPublicKey(ecPoint: ECPoint):PublicKey{
    val publicKeySpec = ECPublicKeySpec(ecPoint, spec)
    val keyFactory: KeyFactory = KeyFactory.getInstance(KEY_ALG)
    return keyFactory.generatePublic(publicKeySpec)
}
