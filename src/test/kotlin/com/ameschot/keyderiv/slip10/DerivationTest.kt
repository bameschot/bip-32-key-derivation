package com.ameschot.keyderiv.slip10

import com.ameschot.keyderiv.slip10.model.ExtendedPrivateKey
import com.ameschot.keyderiv.slip10.functions.*
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECKeyGenerationParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import kotlin.math.round
import kotlin.test.assertTrue

class DerivationTest {

    init {
        Security.insertProviderAt(BouncyCastleProvider(), 1)
        Security.setProperty("crypto.policy", "unlimited");
    }

    @Test
    fun testExp(){
        val k = "BIiyHgHfZtNKgAAAAAvPWubeODconHIdHb6YLx+JbtGV53Ha9TPorlGXn1g9AkZh1IJZ4NsITXdTi+AMw8So4ywOAdToDey6axhKkwK2"
        val pk = "xpubBIiyHgHfZtNKgAAAAAvPWubeODconHIdHb6YLx+JbtGV53Ha9TPorlGXn1g9AkZh1IJZ4NsITXdTi+AMw8So4ywOAdToDey6axhKkwK2"


    }

    @Test
    fun testKeyGenFromPath() {
        val curve = Curve.p256

        //create a master key from a generate ec key and a chosen start chain code
        val masterKey = ExtendedPrivateKey(generateECKeyD(curve), BigInteger.valueOf(565434445234).toByteArray())
        val data = "I consent to transfer one can of tuna to Purr Holdings SaRL".toByteArray()
        val keysToGenerate = 1000
        val printFreq = 100

        val keypairs = mutableListOf<KeyPair>()
        var gs = System.currentTimeMillis()
        (0..keysToGenerate).forEach {
            keypairs.add(deriveFromPath(masterKey, "m/${it}H",curve = curve))
            if ((it % (keysToGenerate / printFreq)) == 0 && it > 0) {
                println("${round(it.toDouble() / keysToGenerate.toDouble() * 100.0)}% generated")
            }
        }
        var tm = System.currentTimeMillis() - gs

        println("Generated $keysToGenerate in $tm ms (1 per ${keysToGenerate / (tm)} ms)")
        println("time: ${(tm)/60000} minutes")

        //sign for each key the data and store the signature
        gs = System.currentTimeMillis()
        val signatures = mutableListOf<ByteArray>()
        (0..keysToGenerate).forEach {
            signatures.add(
                sign(data, keypairs[it].priv.toPrivate())
            )
            if ((it % (keysToGenerate / printFreq)) == 0 && it > 0) {
                println("${round(it.toDouble() / keysToGenerate.toDouble() * 100.0)}% Signed")
            }
        }
        tm = System.currentTimeMillis() - gs
        println("Signed $keysToGenerate in $tm ms (1 per ${keysToGenerate / tm} ms)")


        //verify the signature for each key the data and assert the response
        gs = System.currentTimeMillis()
        (0..keysToGenerate).forEach {
            assertTrue { verify(data,signatures[it], keypairs[it].pub.toPublic()) }
            if ((it % (keysToGenerate / printFreq)) == 0 && it > 0) {
                println("${round(it.toDouble() / keysToGenerate.toDouble() * 100.0)}% Verified")
            }
        }
        tm = System.currentTimeMillis() - gs
        println("Verified $keysToGenerate in $tm ms (1 per ${keysToGenerate / tm} ms)")


        //for a random index regenerate the keypair and validate the signature with it
        val sr = SecureRandom()
        val tests = 1000
        (0..tests).forEach {
            val index = sr.nextInt(0,keysToGenerate)
            val kp = deriveFromPath(masterKey, "m/${index}H", curve=curve)

            println("-------------------[$it/$tests]-------------------")
            println("For hardened index $index (m/${index}H)")
            println("Public Key : ${kp.pub.toBase58Key()}")
            println("Private Key: ${kp.priv.toBase58Key()}")
            println("data       : ${byteToHex(data)}")
            println("signature  : ${byteToHex(signatures[index])}")
            val res = verify(data,signatures[index], kp.pub.toPublic())
            println("verified    : $res")
        }
    }

    fun generateECKeyD(curve:Curve): BigInteger {
        val ecKeyGeneratorParams =
            ECKeyGenerationParameters(ECDomainParameters(curve.spec.curve, curve.spec.g, curve.spec.n, curve.spec.h, curve.spec.seed), SecureRandom())
        val generator = ECKeyPairGenerator()
        generator.init(ecKeyGeneratorParams);
        val keyPair = generator.generateKeyPair();

        return (keyPair.private as ECPrivateKeyParameters).d!!
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun t() {
        println("Hello World!")

        Security.insertProviderAt(BouncyCastleProvider(), 1)
        Security.setProperty("crypto.policy", "unlimited");

        val curve = Curve.secp256k1

        //ser32
        println("ser32---------------------")
        println("s32 t 5442u")
        val s32 = ser32(5442)
        println(s32.size)
        s32.forEach { print("$it, ") }
        println()
        println(f4ByteArrayToInt(s32))


        //ser 256
        println("ser256---------------------")
        println("s256 t 453")
        val s256 = ser256(BigInteger.valueOf(453))
        println(s256.size)
        s256.forEach { print("$it, ") }
        println()
        println(parse256(s256))

        //serP
        println("serP---------------------")
        val pt = curve.point(BigInteger.valueOf(1337))
        println("point: $pt")
        val p = serP(pt)
        p.forEach { print("${it.toHexString()}, ") }
        println()

        //hmacsha512
//    println("hmacsha512---------------------")
//    val I = HMACSHA512(
//        key = ser256(BigInteger.valueOf(5423)),
//        data = concatNormalKeyData(BigInteger.valueOf(21323232312321),3)
//    )
//    println(I.size)

        println("points---------------------")
        println(curve.point(BigInteger.valueOf(234342)).add(curve.point(BigInteger.valueOf(21))).isValid)

        println("CKDPriv---------------------")
        println(CKDPriv(ExtendedPrivateKey(BigInteger.valueOf(1337), BigInteger.valueOf(546554656).toByteArray()), 0, curve))


        println("Sign---------------------")
        var rootKey = ExtendedPrivateKey(BigInteger.valueOf(1337), BigInteger.valueOf(546554656).toByteArray())

        var ePrivk = CKDPriv(rootKey, 0,curve)
        var ePubk = N(ePrivk,curve)

        var privk = toPrivateKey(ePrivk.k,curve)
        var pubk = toPublicKey(ePubk.K,curve)
        var jwk = toJWK(pubk)
        println(jwk.toJSONString())


        var data = "two-lhamas".toByteArray()
        var sig = sign(data, privk)

        println("verify ${verify(data, sig, pubk)}")
    }

}