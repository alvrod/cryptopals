package com.alvrod.cryptopals.ciphers

import java.util
import javax.crypto.Cipher
import javax.crypto.spec.{SecretKeySpec, IvParameterSpec}

import com.alvrod.cryptopals.Convert
import com.alvrod.cryptopals.breakers.RepetitionScore

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

  // AES ECB blocks always are 16 bytes
  def detectECB(cipherHexLines: Iterator[String]): String = {
    val mostRepeated = cipherHexLines
      .map(line => (line, RepetitionScore.countRepeats(Convert.hexToBytes(line))))
      .maxBy { case (line, score) => score }
    mostRepeated._1
  }
}
