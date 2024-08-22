package com.ameschot.keyderiv.slip10.functions

import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.math.ec.rfc8032.Ed25519.Algorithm.Ed25519
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey

val KEY_ALG = "EC"

fun toPrivateKey(k:BigInteger, curve:Curve):PrivateKey{
    val privateKeySpec = ECPrivateKeySpec(k, curve.spec)
    val keyFactory: KeyFactory = KeyFactory.getInstance(KEY_ALG)
    return keyFactory.generatePrivate(privateKeySpec)
}

fun toPublicKey(ecPoint: ECPoint,curve:Curve):PublicKey{
    val publicKeySpec = ECPublicKeySpec(ecPoint, curve.spec)
    val keyFactory: KeyFactory = KeyFactory.getInstance(KEY_ALG)
    return keyFactory.generatePublic(publicKeySpec)
}
