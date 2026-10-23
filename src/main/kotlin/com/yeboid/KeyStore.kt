package com.yeboid

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Implementations must encrypt at rest and throw on read/write/delete errors. */
interface SecureStore {
    fun get(key: String): String?
    fun put(key: String, value: String)
    fun remove(key: String)
}

/** Android Keystore AES-GCM key; ciphertext preferences must be excluded from cloud/device backups. */
class AndroidKeyStore(context: Context, namespace: String) : SecureStore {
    val preferencesName = "yeboid-" + java.security.MessageDigest.getInstance("SHA-256")
        .digest(namespace.toByteArray()).joinToString("") { "%02x".format(it) }
    private val preferences = context.getSharedPreferences(preferencesName, Context.MODE_PRIVATE)
    private val alias = "com.yeboid.$preferencesName"
    private fun secret(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = ks.getKey(alias, null)
        if (existing != null) return existing as SecretKey
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        }.generateKey()
    }
    @Synchronized override fun get(key: String): String? {
        val encoded = preferences.getString(key, null) ?: return null
        val bytes = Base64.decode(encoded, Base64.NO_WRAP)
        require(bytes.size > 12) { "YeboID: invalid_ciphertext" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secret(), GCMParameterSpec(128, bytes.copyOfRange(0, 12)))
        cipher.updateAAD(key.toByteArray())
        return cipher.doFinal(bytes.copyOfRange(12, bytes.size)).toString(Charsets.UTF_8)
    }
    @Synchronized override fun put(key: String, value: String) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secret()); cipher.updateAAD(key.toByteArray())
        val encoded = Base64.encodeToString(cipher.iv + cipher.doFinal(value.toByteArray()), Base64.NO_WRAP)
        check(preferences.edit().putString(key, encoded).commit()) { "YeboID: storage_write_failed" }
    }
    @Synchronized override fun remove(key: String) {
        check(preferences.edit().remove(key).commit()) { "YeboID: storage_delete_failed" }
    }
}
