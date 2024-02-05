package com.ameschot.keyderiv

import com.ameschot.keyderiv.functions.*
import com.ameschot.keyderiv.model.ExtendedPrivateKey
import com.ameschot.keyderiv.model.ExtendedPublicKey
import org.bouncycastle.math.ec.ECPoint
import java.lang.RuntimeException
import java.math.BigInteger

/*
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 */

val HARDENED_KEY_IDX = 0x80000000

fun CKDPriv(eXPriv: ExtendedPrivateKey, i:Long): ExtendedPrivateKey {

    //Check whether i ≥ 231 (whether the child is a hardened key).
    //If so (hardened child): let I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i)). (Note: The 0x00 pads the private key to make it 33 bytes long.)
    //If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i)).
    val I =
        if(i>= HARDENED_KEY_IDX){
            HMACSHA512(
                key = eXPriv.c,
                data = concatHardenedPrivateKeyData(eXPriv.k,i)
            )
        }
        else{
            HMACSHA512(
                key = eXPriv.c,
                data = concatNormalPrivateKeyData(eXPriv.k,i)
            )
        }

    //Split I into two 32-byte sequences, IL and IR.
    val IL = I.copyOfRange(0,32)
    val IR = I.copyOfRange(32,64)

    //The returned child key ki is parse256(IL) + kpar (mod n).
    //In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid, and one should proceed with the next value for i. (Note: this has probability lower than 1 in 2127.)
    val ilp = parse256(IL)
    if(ilp>= n()){
        throw RuntimeException("Invalid, parse256(IL) >= n, $ilp")
    }

    val ki = (ilp.plus(eXPriv.k)).mod(n())

    if(ki==BigInteger.ZERO){
        throw RuntimeException("Invalid, ki ==0, $ki")
    }

    //The returned chain code ci is IR.
    val ci = IR

    //return the new extended key
    return ExtendedPrivateKey(ki,ci)
}

private fun concatHardenedPrivateKeyData(k:BigInteger, i: Long):ByteArray{
    val out = ByteArray(1+32+4)

    //header
    ByteArray(1) { 0x0 }.copyInto(out)

    //ser256(kpar)
    //key as 32 byte array
    ser256(k).copyInto(out,1)

    //ser32(i)
    //index as 4 byte array
    ser32(i).copyInto(out,33)

    return out
}

private fun concatNormalPrivateKeyData(k:BigInteger, i: Long):ByteArray{
    val out = ByteArray(1+32+4)

    //serP(point(kpar))
    //key as 32 byte array
    serP(point(k)).copyInto(out)


    //index as 4 byte array
    ser32(i).copyInto(out,33)

    return out
}

fun N(eXPriv: ExtendedPrivateKey): ExtendedPublicKey {
    return ExtendedPublicKey(point(eXPriv.k),eXPriv.c)
}

fun CKDPub(eXPub: ExtendedPublicKey, i:Long): ExtendedPublicKey {

    //Check whether i ≥ 231 (whether the child is a hardened key).
    //If so (hardened child): return failure
    if(i>= HARDENED_KEY_IDX)
        throw RuntimeException("Invalid public key derivation from hardened key, i>=$HARDENED_KEY_IDX, $i")

    //If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i)).
    val I = HMACSHA512(
        key = eXPub.c,
        data = concatPublicKeyData(eXPub.K,i)
    )

    //Split I into two 32-byte sequences, IL and IR.
    val IL = I.copyOfRange(0,32)
    val IR = I.copyOfRange(32,64)

    //The returned child key Ki is point(parse256(IL)) + Kpar.
    //In case parse256(IL) ≥ n or Ki is the point at infinity, the resulting key is invalid, and one should proceed with the next value for i.

    val ilp = parse256(IL)
    if(ilp>= n()){
        throw RuntimeException("Invalid, parse256(IL) >= n, $ilp")
    }
    val ki = point(ilp).add(eXPub.K)
    if(ki.isInfinity){
        throw RuntimeException("Invalid, ki == infinity, $ki")
    }

    //The returned chain code ci is IR.
    val ci = IR

    //return the new extended key
    return ExtendedPublicKey(ki,ci)

}

private fun concatPublicKeyData(K:ECPoint, i: Long):ByteArray{
    val out = ByteArray(32+4)

    //serP(point(kpar))
    //key as 32 byte array
    serP(K).copyInto(out)

    //index as 4 byte array
    ser32(i).copyInto(out,32)

    return out
}

fun seed(S: ByteArray): ExtendedPrivateKey {

    //Generate a seed byte sequence S of a chosen length (between 128 and 512 bits; 256 bits is advised) from a (P)RNG.
    //Calculate I = HMAC-SHA512(Key = "Bitcoin seed", Data = S)
    val I = HMACSHA512("Bitcoin seed".toByteArray(),S)

    //Split I into two 32-byte sequences, IL and IR.
    //Split I into two 32-byte sequences, IL and IR.
    val IL = I.copyOfRange(0,32)
    val IR = I.copyOfRange(32,64)

    //Use parse256(IL) as master secret key, and IR as master chain code.
    val k = parse256(IL)
    val c = IR

    //In case parse256(IL) is 0 or parse256(IL) ≥ n, the master key is invalid.
    if(k == BigInteger.ZERO)
        throw RuntimeException("Invalid, ki == 0, $k")

    if(k >= n())
        throw RuntimeException("Invalid, ki >= n, $k")

    return ExtendedPrivateKey(k,c)
}
