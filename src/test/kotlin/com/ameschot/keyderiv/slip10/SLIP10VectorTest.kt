package com.ameschot.keyderiv.slip10


import com.ameschot.keyderiv.slip10.functions.*
import io.github.novacrypto.base58.Base58
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.Fingerprint
import org.junit.jupiter.api.Test
import java.security.Security
import kotlin.test.assertEquals

class SLIP10VectorTest {

    init {
        Security.insertProviderAt(BouncyCastleProvider(), 1)
        Security.setProperty("crypto.policy", "unlimited");
    }

    @Test
    fun v1(){
        val curve = Curve.secp256k1
        //Seed (hex): 000102030405060708090a0b0c0d0e0f
        val seed = hexToByte("000102030405060708090a0b0c0d0e0f")

        //Chain m
        testVector(seed,
            "m",
            "00000000",
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
            "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
            curve
        )

        // Chain m/0H
        testVector(seed,
            "m/0H",
            "3442193e",
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
            "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
            curve
        )

        //Chain m/0H/1
        testVector(seed,
            "m/0H/1",
            "5c1bd648",
            "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
            "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c",
            curve
        )

        //Chain m/0H/1/2H
        testVector(seed,
            "m/0H/1/2H",
            "bef5a2f9",
            "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
            "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
            "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2",
            curve
        )

        //Chain m/0H/1/2H/2
        testVector(seed,
            "m/0H/1/2H/2",
            "ee7ab90c",
            "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
            "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
            "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29",
            curve
        )

        //Chain m/0H/1/2H/2/1000000000
        testVector(seed,
            "m/0H/1/2H/2/1000000000",
            "d880d7d8",
            "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
            "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
            "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011",
            curve
        )
    }

    @Test
    fun v2(){
        val curve = Curve.p256
        //Seed (hex): 000102030405060708090a0b0c0d0e0f
        val seed = hexToByte("000102030405060708090a0b0c0d0e0f")

        //Chain m
        testVector(seed,
            "m",
            "00000000",
            "beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea",
            "612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2",
            "0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8",
            curve
        )

        // Chain m/0H
        testVector(seed,
            "m/0H",
            "be6105b5",
            "3460cea53e6a6bb5fb391eeef3237ffd8724bf0a40e94943c98b83825342ee11",
            "6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c",
            "0384610f5ecffe8fda089363a41f56a5c7ffc1d81b59a612d0d649b2d22355590c",
            curve
        )

        //Chain m/0H/1
        testVector(seed,
            "m/0H/1",
            "9b02312f",
            "4187afff1aafa8445010097fb99d23aee9f599450c7bd140b6826ac22ba21d0c",
            "284e9d38d07d21e4e281b645089a94f4cf5a5a81369acf151a1c3a57f18b2129",
            "03526c63f8d0b4bbbf9c80df553fe66742df4676b241dabefdef67733e070f6844",
            curve
        )

        //Chain m/0H/1/2H
        testVector(seed,
            "m/0H/1/2H",
            "b98005c1",
            "98c7514f562e64e74170cc3cf304ee1ce54d6b6da4f880f313e8204c2a185318",
            "694596e8a54f252c960eb771a3c41e7e32496d03b954aeb90f61635b8e092aa7",
            "0359cf160040778a4b14c5f4d7b76e327ccc8c4a6086dd9451b7482b5a4972dda0",
            curve
        )

        //Chain m/0H/1/2H/2
        testVector(seed,
            "m/0H/1/2H/2",
            "0e9f3274",
            "ba96f776a5c3907d7fd48bde5620ee374d4acfd540378476019eab70790c63a0",
            "5996c37fd3dd2679039b23ed6f70b506c6b56b3cb5e424681fb0fa64caf82aaa",
            "029f871f4cb9e1c97f9f4de9ccd0d4a2f2a171110c61178f84430062230833ff20",
            curve
        )

        //Chain m/0H/1/2H/2/1000000000
        testVector(seed,
            "m/0H/1/2H/2/1000000000",
            "8b2b5c4b",
            "b9b7b82d326bb9cb5b5b121066feea4eb93d5241103c9e7a18aad40f1dde8059",
            "21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119",
            "02216cd26d31147f72427a453c443ed2cde8a1e53c9cc44e5ddf739725413fe3f4",
            curve
        )
    }

    //@Test
    fun v3(){
        val curve = Curve.ed25519
        //Seed (hex): 000102030405060708090a0b0c0d0e0f
        val seed = hexToByte("000102030405060708090a0b0c0d0e0f")

        //Chain m
        testVector(seed,
            "m",
            "00000000",
            "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
            "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed",
            curve
        )

        // Chain m/0H
        testVector(seed,
            "m/0H",
            "ddebc675",
            "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
            "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c",
            curve
        )

//        //Chain m/0H/1
//        testVector(seed,
//            "m/0H/1",
//            "9b02312f",
//            "4187afff1aafa8445010097fb99d23aee9f599450c7bd140b6826ac22ba21d0c",
//            "284e9d38d07d21e4e281b645089a94f4cf5a5a81369acf151a1c3a57f18b2129",
//            "03526c63f8d0b4bbbf9c80df553fe66742df4676b241dabefdef67733e070f6844",
//            curve
//        )
//
//        //Chain m/0H/1/2H
//        testVector(seed,
//            "m/0H/1/2H",
//            "b98005c1",
//            "98c7514f562e64e74170cc3cf304ee1ce54d6b6da4f880f313e8204c2a185318",
//            "694596e8a54f252c960eb771a3c41e7e32496d03b954aeb90f61635b8e092aa7",
//            "0359cf160040778a4b14c5f4d7b76e327ccc8c4a6086dd9451b7482b5a4972dda0",
//            curve
//        )
//
//        //Chain m/0H/1/2H/2
//        testVector(seed,
//            "m/0H/1/2H/2",
//            "0e9f3274",
//            "ba96f776a5c3907d7fd48bde5620ee374d4acfd540378476019eab70790c63a0",
//            "5996c37fd3dd2679039b23ed6f70b506c6b56b3cb5e424681fb0fa64caf82aaa",
//            "029f871f4cb9e1c97f9f4de9ccd0d4a2f2a171110c61178f84430062230833ff20",
//            curve
//        )
//
//        //Chain m/0H/1/2H/2/1000000000
//        testVector(seed,
//            "m/0H/1/2H/2/1000000000",
//            "8b2b5c4b",
//            "b9b7b82d326bb9cb5b5b121066feea4eb93d5241103c9e7a18aad40f1dde8059",
//            "21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119",
//            "02216cd26d31147f72427a453c443ed2cde8a1e53c9cc44e5ddf739725413fe3f4",
//            curve
//        )
    }

    fun testVector(seed:ByteArray,path:String,
                   fingerprint :String,
                   chainCode:String,
                   private:String,
                   public:String,
                   curve:Curve
    ){
        val kp = deriveFromPath(seed,path, curve = curve)
        println("--------------------------------------------")
        println(path)

        val rfp = byteToHex(kp.pub.parentFingerprint)
        assertEquals(fingerprint,rfp)
        println("fingerprint (v == r)")
        println(fingerprint)
        println(rfp)

        val rcc = byteToHex(kp.priv.extendedPrivateKey.c)
        assertEquals(chainCode, rcc)
        println("chainCode (v == r)")
        println(chainCode)
        println(rcc)

        val resPrv = kp.priv.toHexKey()
        assertEquals(private, resPrv)
        println("private (v == r)")
        println(private)
        println(resPrv)

        val resPub = kp.pub.toHexKey()
        assertEquals(public, resPub)
        println("private (v == r)")
        println(public)
        println(resPub)

    }


}