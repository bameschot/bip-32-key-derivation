package com.ameschot.keyderiv.functions

import org.bouncycastle.jce.ECNamedCurveTable
import java.math.BigInteger

val spec= ECNamedCurveTable.getParameterSpec("secp256k1") //use curve secp256r1 for P-256 nimbus compatibility
//val bcCurve = spec.curve;
//val conversionSpec = ECNamedCurveSpec(spec.name, spec.curve, spec.g, spec.n)
//val curve = conversionSpec.curve

//point(p): returns the coordinate pair resulting from EC point multiplication (repeated application of the EC group operation) of the secp256k1 base point with the integer p.
fun point(p:BigInteger) = spec.g.multiply(p)!!

fun n() = spec.n
