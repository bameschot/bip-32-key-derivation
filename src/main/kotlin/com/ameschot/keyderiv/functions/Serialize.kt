package com.ameschot.keyderiv.functions

import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger


//ser32(i): serialize a 32-bit unsigned integer i as a 4-byte sequence, most significant byte first.
@OptIn(ExperimentalUnsignedTypes::class)
fun ser32(p: Long): ByteArray =
    byteArrayOf((p shr 24).toByte(), (p shr 16).toByte(), (p shr 8).toByte(), p.toByte())

@OptIn(ExperimentalUnsignedTypes::class)
fun f4ByteArrayToInt(b: ByteArray) =
        ((b[0]).toLong() shl 24) +
        ((b[1]).toLong() shl 16) +
        ((b[2]).toLong() shl 8) +
        (b[3]).toLong()

//ser256(p): serializes the integer p as a 32-byte sequence, most significant byte first.
fun ser256(value: BigInteger): ByteArray {
    val b = value.toByteArray()
    if(b.size<=32)
        return b.copyInto(ByteArray(32), 32 - b.size)
    else
        return b.copyInto(ByteArray(32), 0,1,33)
}


//serP(P): serializes the coordinate pair P = (x,y) as a byte sequence using SEC1's compressed form: (0x02 or 0x03) || ser256(x), where the header byte depends on the parity of the omitted y coordinate.
//https://www.javadoc.io/doc/org.bouncycastle/bcprov-jdk15on/1.50/org/bouncycastle/math/ec/ECPoint.html#getEncoded(boolean)
fun serP(p: ECPoint):ByteArray = p.getEncoded(true)


//parse256(p): interprets a 32-byte sequence as a 256-bit number, most significant byte first.
fun parse256(p:ByteArray) = BigInteger(1,p)


