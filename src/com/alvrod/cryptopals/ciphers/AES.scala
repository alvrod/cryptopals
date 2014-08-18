package com.alvrod.cryptopals.ciphers

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

import com.alvrod.cryptopals.{Combine, Convert}
import com.alvrod.cryptopals.breakers.RepetitionScore

import scala.collection.mutable

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

  def decryptECBSingle(ciphertext: Array[Byte], key: Array[Byte]): Array[Byte] = {
    val cipher = Cipher.getInstance("AES/ECB/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"))
    cipher.doFinal(ciphertext)
  }

  // AES blocks always are 16 bytes
  def detectECB(cipherHexLines: Iterator[String]): String = {
    val mostRepeated = cipherHexLines
      .map(line => (line, RepetitionScore.countRepeats(Convert.hexToBytes(line))))
      .maxBy { case (line, score) => score }
    mostRepeated._1
  }

  def encryptCBC(bytes: Array[Byte], iv: Array[Byte], key: Array[Byte]): Array[Byte] = {
    val input = PadPKCS7.pad(bytes, 16).grouped(16).toList

    var builder = new mutable.ListBuffer[Array[Byte]]
    var previous = iv
    for (byte <- input) {
      previous = AES.encryptECB(Combine.xor(previous, byte), key)
      builder.append(previous)
    }

    builder.flatten.toArray
  }

  def decryptCBC(bytes: Array[Byte], iv: Array[Byte], key: Array[Byte]): Array[Byte] = {
    val input = bytes.grouped(16).toList

    var builder = new mutable.ListBuffer[Array[Byte]]
    var previous = iv
    for (block <- input) {
      val plaintext = Combine.xor(previous, decryptECBSingle(block, key))
      builder.append(plaintext)
      previous = block
    }

    //PadPKCS7.unpadPkcs7(builder.flatten.toArray)
    builder.flatten.toArray
  }

}
