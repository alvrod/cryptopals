package com.alvrod.cryptopals.ciphers

import javax.crypto.Cipher
import javax.crypto.spec.{SecretKeySpec, IvParameterSpec}

object AES {
  def encryptECB(bytes: Array[Byte], key: Array[Byte]): Array[Byte] = {
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"))
    cipher.doFinal(bytes)
  }

  def decryptECB(ciphertext: Array[Byte], key: Array[Byte]): Array[Byte] = {
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"))
    cipher.doFinal(ciphertext)
  }
}
