package com.ameschot.keyderiv.functions

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import java.security.PublicKey
import java.security.interfaces.ECPublicKey


fun toJWK(publicKey: PublicKey) =
     ECKey.Builder(Curve.SECP256K1, publicKey as ECPublicKey).build()!!