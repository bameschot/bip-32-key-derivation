package com.ameschot.keyderiv.slip10


import com.ameschot.keyderiv.slip10.functions.*
import io.github.novacrypto.base58.Base58
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.jupiter.api.Test
import java.security.Security
import kotlin.test.assertEquals

class BIP32VectorTest {

    var curve:Curve;

    init {
        Security.insertProviderAt(BouncyCastleProvider(), 1)
        Security.setProperty("crypto.policy", "unlimited");
        curve = Curve.secp256k1
    }

    @Test
    fun v1(){
        //Seed (hex): 000102030405060708090a0b0c0d0e0f
        val seed = hexToByte("000102030405060708090a0b0c0d0e0f")

        //Chain m
        testVector(seed,
            "m",
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        )

        // Chain m/0H
        testVector(seed,
            "m/0H",
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
        )

        //Chain m/0H/1H
        testVector(seed,
            "m/0H/1H",
            "xpub6ASuArnff48dT9zQbv67D8j2gBLHdPJhjjsmkk57psHHUvWoUkkq77QgZTWQMswEbBB9RmvhqrEuXmo1bXngtnrMaz1rxrGoya4BENLG83t",
            "xprv9wTYmMFmpgaLEfuwVtZ6qznJ89VoDvarNWxAxMfWGXkJc8BewDSaZK6CiDSuSkuwp4YsTHxuKY1JywkBbiTPZsZ7963ZXv8yFTTwwbbLWkK"
        )

        //Chain m/0H/1
        testVector(seed,
            "m/0H/1",
            "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
        )

        //Chain m/0H/1/2H
        testVector(seed,
            "m/0H/1/2H",
            "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
            "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
        )

        //Chain m/0H/1/2H/2
        testVector(seed,
            "m/0H/1/2H/2",
            "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
            "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
        )

        //Chain m/0H/1/2H/2/1000000000
        testVector(seed,
            "m/0H/1/2H/2/1000000000",
            "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
            "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
        )
    }

    @Test
    fun v2(){
        //Seed (hex): fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
        val seed = hexToByte("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")

        //Chain m
        testVector(seed,
            "m",
            "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
            "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
        )

        // Chain m/0
        testVector(seed,
            "m/0",
            "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
            "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
        )

        //Chain m/0/2147483647H
        testVector(seed,
            "m/0/2147483647H",
            "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
            "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"
        )

        //Chain m/0/2147483647H/1
        testVector(seed,
            "m/0/2147483647H/1",
            "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
            "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"
        )

        //Chain m/0/2147483647H/1/2147483646H
        testVector(seed,
            "m/0/2147483647H/1/2147483646H",
            "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
            "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"
        )

        //Chain m/0/2147483647H/1/2147483646H/2
        testVector(seed,
            "m/0/2147483647H/1/2147483646H/2",
            "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
            "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"
        )

    }

    @Test
    fun v3(){
        //Seed (hex): 4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be
        val seed = hexToByte("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be")

        //Chain m
        testVector(seed,
            "m",
            "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
            "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
        )

        //Chain m/0H
        testVector(seed,
            "m/0H",
            "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
            "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"
        )
    }

    @Test
    fun v4(){
        //Seed (hex): 3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678
        val seed = hexToByte("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678")

        //Chain m
        testVector(seed,
            "m",
            "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
            "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv"
        )

        //Chain m/0H
        testVector(seed,
            "m/0H",
            "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
            "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G"
        )

        //Chain m/0H/1H
        testVector(seed,
            "m/0H/1H",
            "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt",
            "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1"
        )
    }

    @Test
    fun v0(){
        Security.insertProviderAt(BouncyCastleProvider(), 1)
        Security.setProperty("crypto.policy", "unlimited");

        val pkvPrv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        val pkvPub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        val pkvDecode = Base58.base58Decode(pkvPrv)
        //println(byteToHex(pkvDecode.sliceArray(13..33)))


        println("--------")
        //TODO: parse
        val sb = hexToByte("000102030405060708090a0b0c0d0e0f")
        //BigInteger("000102030405060708090a0b0c0d0e0f",16).toByteArray().copyInto(sb,1)
        val extendedMasterPrvKey = seed(sb,curve)
        val resPrv = btcSerPriv(extendedMasterPrvKey, ser32(0x00000000),0x0,0)

        val resDecode = Base58.base58Decode(resPrv)
        //println(byteToHex(resDecode.sliceArray(13..33)))

        val extendedMasterPubKey = N(extendedMasterPrvKey, curve)
        val resPub = btcSerPub(extendedMasterPubKey, ser32(0x00000000),0x0,0)

        println("vec prv: $pkvPrv")
        println("res prv: $resPrv")

        println("vec pub: $pkvPub")
        println("res pub: $resPub")

        val extendedPrvKey_1 = CKDPriv(extendedMasterPrvKey, HARDENED_KEY_IDX, curve = curve)
        val extendedPubKey_1 = N(extendedPrvKey_1, curve)
        val prv1_fp = fingerprintFromPublic(extendedMasterPubKey)
        println(byteToHex(prv1_fp))
        println("3442193e")
        val resPrv_1 = btcSerPriv(extendedPrvKey_1, prv1_fp,0x01, HARDENED_KEY_IDX)
        val resPub_1 = btcSerPub(extendedPubKey_1, prv1_fp,0x01, HARDENED_KEY_IDX)

        //0x3442193e
        val resss = deriveFromPath(extendedMasterPrvKey,"m/0H", curve =  curve)

        println("vec prv_1h: xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7")
        println("res prv_1h: $resPrv_1")
        println("rph prv_1h: ${resss.priv.toBase58Key()}")

        println("vec pub_1h: xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")
        println("res pub_1h: $resPub_1")
        println("rph pub_1h: ${resss.pub.toBase58Key()}")





    }

    fun testVector(seed:ByteArray,path:String,vectorB58PubKey :String,vectorB58PrivKey:String){
        val kp = deriveFromPath(seed,path, curve = curve)
        println("--------------------------------------------")
        println(path)

        assertEquals(vectorB58PubKey, kp.pub.toBase58Key())
        println("Public (v == r)")
        println(vectorB58PubKey)
        println(kp.pub.toBase58Key())

        assertEquals(vectorB58PrivKey, kp.priv.toBase58Key())
        println("Private (v == r)")
        println(vectorB58PrivKey)
        println(kp.priv.toBase58Key())
    }


}