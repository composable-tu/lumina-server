package org.lumina

import com.auth0.jwt.JWT
import com.tencent.kona.KonaProvider
import com.tencent.kona.crypto.CryptoInsts
import com.tencent.kona.crypto.spec.SM2ParameterSpec
import com.tencent.kona.crypto.spec.SM2PrivateKeySpec
import com.tencent.kona.crypto.spec.SM2PublicKeySpec
import io.ktor.http.*
import io.ktor.http.auth.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.lumina.fields.ReturnInvalidReasonFields.INVALID_JWT
import org.lumina.utils.security.SM3WithSM2Algorithm
import java.security.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.security.sasl.AuthenticationException

fun Application.configureSecurity() {
    Security.addProvider(KonaProvider())
    val envVar = getEnvVar()
    authentication {
        jwt {
            realm = envVar.jwtRealm
            authHeader { call ->
                val header = call.request.parseAuthorizationHeader() as? HttpAuthHeader.Single ?: return@authHeader null

                if (!header.authScheme.equals("Bearer", ignoreCase = true)) throw AuthenticationException(INVALID_JWT)

                val token = header.blob
                val isJwe = token.count { it == '.' } == 4

                if (!isJwe) throw AuthenticationException(INVALID_JWT) else {
                    val decrypted = try {
                        decryptJWE(token, envVar.encKeyPair.private)
                    } catch (_: Exception) {
                        throw AuthenticationException(INVALID_JWT)
                    }
                    HttpAuthHeader.Single("Bearer", decrypted)
                }
            }
            verifier(
                JWT.require(SM3WithSM2Algorithm(null, envVar.signKeyPair.public)).withAudience(envVar.jwtAudience)
                    .withIssuer(envVar.jwtIssuer).withSubject(envVar.jwtDomain).acceptLeeway(10).build()
            )
            validate { credential ->
                JWTPrincipal(credential.payload)
            }
            challenge { _, _ ->
                call.respondText(INVALID_JWT, status = HttpStatusCode.Unauthorized)
            }
        }
    }
}

fun Route.generateJWE(weixinOpenId: String, weixinUnionId: String? = null): String {
    val jwtExpiresIn = environment.config.property("jwt.expiresIn").getString().toLongOrNull() ?: 28800
    val envVar = getEnvVar()
    return createJWE(
        JWT.create().withClaim("weixinOpenId", weixinOpenId).apply {
            if (weixinUnionId != null) withClaim("weixinUnionId", weixinUnionId)
        }.withIssuer(envVar.jwtIssuer).withAudience(envVar.jwtAudience).withSubject(envVar.jwtDomain)
            .withIssuedAt(Date()).withExpiresAt(Date(System.currentTimeMillis() + jwtExpiresIn * 1000))
            .sign(SM3WithSM2Algorithm(envVar.signKeyPair.private, envVar.signKeyPair.public)), envVar.encKeyPair.public
    )
}

private fun createJWE(payload: String, publicKey: PublicKey): String {
    // 生成随机CEK（SM4密钥）
    val cek = ByteArray(16).apply { SecureRandom().nextBytes(this) }
    val sm4Key: SecretKey = SecretKeySpec(cek, "SM4")

    // 加密CEK（使用SM2公钥）
    val sm2Cipher = CryptoInsts.getCipher("SM2")
    sm2Cipher.init(Cipher.WRAP_MODE, publicKey)
    val encryptedKey = sm2Cipher.wrap(sm4Key)

    // 准备GCM参数
    val iv = ByteArray(12).apply { SecureRandom().nextBytes(this) }
    val gcmSpec = GCMParameterSpec(128, iv)

    // 加密payload（使用SM4-GCM）
    val cipher = CryptoInsts.getCipher("SM4/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, sm4Key, gcmSpec)
    val cipherText = cipher.doFinal(payload.toByteArray(Charsets.UTF_8))
    val authTag = cipherText.copyOfRange(cipherText.size - 16, cipherText.size)
    val encryptedData = cipherText.copyOfRange(0, cipherText.size - 16)

    // 构建JWE头部
    val header = Base64.getUrlEncoder().withoutPadding().encodeToString(
        """{"alg":"SM2","enc":"SM4/GCM/NoPadding"}""".toByteArray()
    )

    // 组装JWE各部分
    return listOf(
        header,
        Base64.getUrlEncoder().withoutPadding().encodeToString(encryptedKey),
        Base64.getUrlEncoder().withoutPadding().encodeToString(iv),
        Base64.getUrlEncoder().withoutPadding().encodeToString(encryptedData),
        Base64.getUrlEncoder().withoutPadding().encodeToString(authTag)
    ).joinToString(".")
}

// 解密JWE（验证时使用）
private fun decryptJWE(token: String, privateKey: PrivateKey): String {
    val parts = token.split(".")
    if (parts.size != 5) throw AuthenticationException(INVALID_JWT)

    try {
        // 解码各部分
        Base64.getUrlDecoder().decode(parts[0])
        val encryptedKey = Base64.getUrlDecoder().decode(parts[1])
        val iv = Base64.getUrlDecoder().decode(parts[2])
        val encryptedData = Base64.getUrlDecoder().decode(parts[3])
        val authTag = Base64.getUrlDecoder().decode(parts[4])

        // 解密CEK（使用SM2私钥）
        val sm2Cipher = CryptoInsts.getCipher("SM2")
        sm2Cipher.init(Cipher.UNWRAP_MODE, privateKey)
        val sm4Key = sm2Cipher.unwrap(encryptedKey, "SM4", Cipher.SECRET_KEY)

        // 组合加密数据+认证标签
        val cipherText = encryptedData + authTag

        // 解密payload（使用SM4-GCM）
        val gcmSpec = GCMParameterSpec(128, iv)
        val cipher = CryptoInsts.getCipher("SM4/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, sm4Key, gcmSpec)
        val plainText = cipher.doFinal(cipherText)

        return String(plainText, Charsets.UTF_8)
    } catch (_: Exception) {
        throw AuthenticationException(INVALID_JWT)
    }
}

// 生成或加载 SM2 密钥对（示例实现）
private fun generateOrLoadSM2KeyPair(publicKeyHex: String, privateKeyHex: String): KeyPair {
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

private fun generateSM2KeyPair(): KeyPair {
    val keyPairGenerator = KeyPairGenerator.getInstance("SM2", KonaProvider.NAME)
    val spec = SM2ParameterSpec.instance()
    keyPairGenerator.initialize(spec)
    return keyPairGenerator.generateKeyPair()
}

private fun encodeSM2Key(key: Key): String {
    return Base64.getEncoder().encodeToString(key.encoded)
}

private fun decodeSM2PublicKey(hex: String): PublicKey {
    val keyBytes = Base64.getDecoder().decode(hex)
    val keySpec = SM2PublicKeySpec(keyBytes)
    return KeyFactory.getInstance("SM2", KonaProvider.NAME).generatePublic(keySpec)
}

private fun decodeSM2PrivateKey(hex: String): PrivateKey {
    val keyBytes = Base64.getDecoder().decode(hex)
    val keySpec = SM2PrivateKeySpec(keyBytes)
    return KeyFactory.getInstance("SM2", KonaProvider.NAME).generatePrivate(keySpec)
}


private data class EnvVar(
    val jwtDomain: String,
    val jwtRealm: String,
    val jwtIssuer: String,
    val jwtAudience: String,
    val signKeyPair: KeyPair,
    val encKeyPair: KeyPair
)

private fun Application.getEnvVar(): EnvVar {
    val jwtDomain = environment.config.property("jwt.domain").getString()
    val jwtRealm = environment.config.property("jwt.realm").getString()
    val jwtIssuer = environment.config.property("jwt.issuer").getString()
    val jwtAudience = environment.config.property("jwt.audience").getString()

    val signPublicKeyHex = environment.config.property("jwt.sm2.signPublicKey").getString()
    val signPrivateKeyHex = environment.config.property("jwt.sm2.signPrivateKey").getString()
    val signKeyPair = generateOrLoadSM2KeyPair(signPublicKeyHex, signPrivateKeyHex)

    val encPublicKeyHex = environment.config.property("jwt.sm2.encPublicKey").getString()
    val encPrivateKeyHex = environment.config.property("jwt.sm2.encPrivateKey").getString()
    val encKeyPair = generateOrLoadSM2KeyPair(encPublicKeyHex, encPrivateKeyHex)
    return EnvVar(jwtDomain, jwtRealm, jwtIssuer, jwtAudience, signKeyPair, encKeyPair)
}

private fun Route.getEnvVar(): EnvVar {
    val jwtDomain = environment.config.property("jwt.domain").getString()
    val jwtRealm = environment.config.property("jwt.realm").getString()
    val jwtIssuer = environment.config.property("jwt.issuer").getString()
    val jwtAudience = environment.config.property("jwt.audience").getString()

    val signPublicKeyHex = environment.config.property("jwt.sm2.signPublicKey").getString()
    val signPrivateKeyHex = environment.config.property("jwt.sm2.signPrivateKey").getString()
    val signKeyPair = generateOrLoadSM2KeyPair(signPublicKeyHex, signPrivateKeyHex)

    val encPublicKeyHex = environment.config.property("jwt.sm2.encPublicKey").getString()
    val encPrivateKeyHex = environment.config.property("jwt.sm2.encPrivateKey").getString()
    val encKeyPair = generateOrLoadSM2KeyPair(encPublicKeyHex, encPrivateKeyHex)
    return EnvVar(jwtDomain, jwtRealm, jwtIssuer, jwtAudience, signKeyPair, encKeyPair)
}
