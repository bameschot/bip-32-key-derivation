package com.ameschot.keyderiv.slip10.functions

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import java.math.BigInteger


enum class Curve(val spec: ECNamedCurveParameterSpec, val seedPw:String){
    secp256k1(ECNamedCurveTable.getParameterSpec("secp256k1"),"Bitcoin seed"),
    p256(ECNamedCurveTable.getParameterSpec("secp256r1"),"Nist256p1 seed"),
    ed25519(ECNamedCurveTable.getParameterSpec("curve25519"),"ed25519 seed"); // ed25519? curve25519

    fun n() = spec.n
    //point(p): returns the coordinate pair resulting from EC point multiplication (repeated application of the EC group operation) of the secp256k1 base point with the integer p.
    fun point(p:BigInteger) = spec.g.multiply(p)!!
}