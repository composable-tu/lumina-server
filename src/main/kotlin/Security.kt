package org.linlangwen

import com.auth0.jwt.JWT
import com.tencent.kona.KonaProvider
import com.tencent.kona.crypto.spec.SM2ParameterSpec
import com.tencent.kona.crypto.spec.SM2PrivateKeySpec
import com.tencent.kona.crypto.spec.SM2PublicKeySpec
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.linlangwen.utils.SM3WithSM2Algorithm
import java.security.*
import java.util.*

fun Application.configureSecurity() {
    Security.addProvider(KonaProvider())
    val jwtAudience = environment.config.property("jwt.audience").getString()
    val jwtDomain = environment.config.property("jwt.domain").getString()
    val jwtRealm = environment.config.property("jwt.realm").getString()

    val publicKeyHex = environment.config.property("jwt.sm2.publicKey").getString()
    val privateKeyHex = environment.config.property("jwt.sm2.privateKey").getString()

    val keyPair = generateOrLoadSM2KeyPair(publicKeyHex, privateKeyHex)

    authentication {
        jwt {
            realm = jwtRealm
            verifier(
                JWT.require(SM3WithSM2Algorithm(null, keyPair.public)).withAudience(jwtAudience).withIssuer(jwtDomain)
                    .acceptLeeway(10).build()
            )
            validate { credential ->
                if (credential.payload.audience.contains(jwtAudience)) JWTPrincipal(credential.payload) else null
            }
            challenge { _, _ ->
                call.respondText("无效的 Token", status = HttpStatusCode.Unauthorized)
            }
        }
    }
}

fun Route.generateJWT(weixinOpenId: String): String {
    // 加载密钥对
    val publicKeyHex = environment.config.property("jwt.sm2.publicKey").getString()
    val privateKeyHex = environment.config.property("jwt.sm2.privateKey").getString()
    val keyPair = generateOrLoadSM2KeyPair(publicKeyHex, privateKeyHex)

    // 从配置读取参数
    val issuer = environment.config.property("jwt.issuer").getString()
    val expiresIn = environment.config.property("jwt.expiresIn").getString().toLongOrNull() ?: 604800

    return JWT.create().withSubject(weixinOpenId).withClaim("weixinOpenId", weixinOpenId).withIssuer(issuer).withAudience(environment.config.property("jwt.audience").getString())
        .withIssuedAt(Date()).withExpiresAt(Date(System.currentTimeMillis() + expiresIn * 1000))
        .sign(SM3WithSM2Algorithm(keyPair.private, keyPair.public))
}

// 生成或加载 SM2 密钥对（示例实现）
fun generateOrLoadSM2KeyPair(publicKeyHex: String, privateKeyHex: String): KeyPair {
    // 实际项目中应从安全存储读取，此处示例从配置加载
    return try {
        KeyPair(
            decodeSM2PublicKey(publicKeyHex), decodeSM2PrivateKey(privateKeyHex)
        )
    } catch (e: Exception) {
        println(e.message)
        // 生成 SM2 新密钥对，且生产环境需持久化
        val newKeyPair = generateSM2KeyPair()
        // 此处应导出并保存到环境变量，这里是示例，生成密钥并打印
        println("Generated SM2 Public Key: ${encodeSM2Key(newKeyPair.public)}")
        println("Generated SM2 Private Key: ${encodeSM2Key(newKeyPair.private)}")
        newKeyPair
    }
}

fun generateSM2KeyPair(): KeyPair {
    val keyPairGenerator = KeyPairGenerator.getInstance("SM2", KonaProvider.NAME)
    val spec = SM2ParameterSpec.instance()
    keyPairGenerator.initialize(spec)
    return keyPairGenerator.generateKeyPair()
}

fun encodeSM2Key(key: Key): String {
    return Base64.getEncoder().encodeToString(key.encoded)
}

fun decodeSM2PublicKey(hex: String): PublicKey {
    val keyBytes = Base64.getDecoder().decode(hex)
    val keySpec = SM2PublicKeySpec(keyBytes)
    return KeyFactory.getInstance("SM2", KonaProvider.NAME).generatePublic(keySpec)
}

fun decodeSM2PrivateKey(hex: String): PrivateKey {
    val keyBytes = Base64.getDecoder().decode(hex)
    val keySpec = SM2PrivateKeySpec(keyBytes)
    return KeyFactory.getInstance("SM2", KonaProvider.NAME).generatePrivate(keySpec)
}

