package org.lumina.utils.security

import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.SignatureGenerationException
import com.auth0.jwt.exceptions.SignatureVerificationException
import com.auth0.jwt.interfaces.DecodedJWT
import com.tencent.kona.KonaProvider
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.util.*

class SM3WithSM2Algorithm(private val privateKey: PrivateKey?, private val publicKey: PublicKey) :
    Algorithm("SM3WithSM2", "SM3WithSM2") {
    companion object {
        fun getInstance(publicKey: PublicKey, privateKey: PrivateKey? = null): SM3WithSM2Algorithm {
            return SM3WithSM2Algorithm(privateKey, publicKey)
        }
    }

    override fun verify(jwt: DecodedJWT) {
        try {
            val header = jwt.header
            val payload = jwt.payload
            val signatureBytes = Base64.getUrlDecoder().decode(jwt.signature)

            val signature = Signature.getInstance("SM3WithSM2", KonaProvider.NAME)
            signature.initVerify(publicKey)
            val data = "${header}.${payload}".toByteArray(Charsets.UTF_8)
            signature.update(data)
            if (!signature.verify(signatureBytes)) throw SignatureVerificationException(this)
        } catch (e: Exception) {
            throw SignatureVerificationException(this, e)
        }
    }

    override fun sign(data: ByteArray): ByteArray {
        if (privateKey == null) throw IllegalArgumentException("Private key is required for signing.")
        try {
            val signature = Signature.getInstance("SM3WithSM2", KonaProvider.NAME)
            signature.initSign(privateKey)
            signature.update(data)
            return signature.sign()
        } catch (e: Exception) {
            throw SignatureGenerationException(this, e)
        }
    }
}