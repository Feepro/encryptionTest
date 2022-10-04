package com.example.encryptiontest

import java.nio.charset.Charset
import java.security.spec.KeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object AES256 {
    var SECRET_KEY = "my_super_secret_key"
    var SALT = "ssshhhhhhhhhhh!!!!"

    fun encrypt(strToEncrypt: String): String? {
        try {
            val iv = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            val ivspec = IvParameterSpec(iv)
            val factory: SecretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val spec: KeySpec = PBEKeySpec(SECRET_KEY.toCharArray(), SALT.toByteArray(), 65536, 256)
            val tmp: SecretKey = factory.generateSecret(spec)
            val secretKey = SecretKeySpec(tmp.getEncoded(), "AES")
            val cipher: Cipher = Cipher.getInstance("AES/ECB/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec)
            return Base64.getEncoder()
                .encodeToString(cipher.doFinal(strToEncrypt.toByteArray(Charset.forName("UTF-8"))))
        } catch (e: Exception) {
            println("Error while encrypting: $e")
        }
        return null
    }
    fun decrypt(strToDecrypt: String?): String? {
        try {
            val iv = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            val ivspec = IvParameterSpec(iv)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val spec: KeySpec = PBEKeySpec(SECRET_KEY.toCharArray(), SALT.toByteArray(), 65536, 256)
            val tmp = factory.generateSecret(spec)
            val secretKey = SecretKeySpec(tmp.encoded, "AES")
            val cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING")
            cipher.init(Cipher.DECRYPT_MODE, secretKey)
            return String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)))
        } catch (e: java.lang.Exception) {
            println("Error while decrypting: $e")
        }
        return null
    }
}