package com.ameschot.keyderiv.slip10.functions

import io.github.novacrypto.base58.Base58
import com.ameschot.keyderiv.slip10.model.ExtendedPrivateKey
import com.ameschot.keyderiv.slip10.model.ExtendedPublicKey
import org.apache.commons.codec.binary.Hex
import java.math.BigInteger
import java.util.Base64


val VERSION_MAIN_PUB  = BigInteger.valueOf(0x0488B21E).toByteArray()
val VERSION_MAIN_PRIV = BigInteger.valueOf(0x0488ADE4).toByteArray()



fun btcSerPriv(extendedPrivateKey: ExtendedPrivateKey, parentFingerprint:ByteArray, depth:Byte, i:Long):String{
    val out = ByteArray(78+4)

    //version 4 bytes
    VERSION_MAIN_PRIV.copyInto(out)

    //depth 1 byte
    byteArrayOf(depth).copyInto(out,4)

    //fingerprint 4 bytes
    parentFingerprint.copyInto(out,5,0,4)

    //child number 4 bytes
    ser32(i).copyInto(out, 9)

    //chain code 32 bytes
    extendedPrivateKey.c.copyInto(out, 13)

    //key 33 bytes
    val keyData = ByteArray(33)
    byteArrayOf(0x0).copyInto(keyData)
    ser256(extendedPrivateKey.k).copyInto(keyData,1)
    keyData.copyInto(out, 45)

    //checksum
    checksum(out.sliceArray(0..77)).copyInto(out,78,0,4)

    return Base58.base58Encode(out)!!
}

fun serPub(key:String){
    val bytes = Base58.base58Decode("xpubBIiyHgHfZtNKgAAAAAvPWubeODconHIdHb6YLx+JbtGV53Ha9TPorlGXn1g9AkZh1IJZ4NsITXdTi+AMw8So4ywOAdToDey6axhKkwK2")


}

fun btcSerPub(extendedPublicKey: ExtendedPublicKey, parentFingerprint:ByteArray, depth:Byte, i:Long):String{
    val out = ByteArray(78+4)

    //version 4 bytes
    VERSION_MAIN_PUB.copyInto(out)

    //depth 1 byte
    byteArrayOf(depth).copyInto(out,4)

    //fingerprint 4 bytes
    parentFingerprint.copyInto(out,5,0,4)

    //child number 4 bytes
    ser32(i).copyInto(out, 9)

    //chain code 32 bytes
    extendedPublicKey.c.copyInto(out, 13)

    //key 33 bytes
    serP(extendedPublicKey.K).copyInto(out, 45)

    //checksum
    checksum(out.sliceArray(0..77)).copyInto(out,78,0,4)

    return Base58.base58Encode(out)!!
}
fun fingerprintFromPublic(extendedPublicKey: ExtendedPublicKey):ByteArray{
    val fp = ByteArray(4)
    HASH160(serP(extendedPublicKey.K)).copyInto(fp,0,0,4)
    return fp;
}

fun checksum(b:ByteArray) = sha256(sha256(b)).sliceArray(0..3)

fun byteToHex(b:ByteArray):String{
    return Hex.encodeHexString(b)
}
fun hexToByte(hex: String): ByteArray {
    return Hex.decodeHex(hex)!!
}

