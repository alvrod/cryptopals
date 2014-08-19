package com.alvrod.cryptopals.ciphers

import javax.crypto.{KeyGenerator, Cipher}
import javax.crypto.spec.SecretKeySpec

import com.alvrod.cryptopals.{Combine, Convert}
import com.alvrod.cryptopals.breakers.RepetitionScore

import scala.collection.mutable
import scala.util.Random

object AES {
  val random = new Random()

  def encryptSecret(plaintext: Array[Byte]): (String, Array[Byte]) = {
    val key = generateKey()
    val appendByteCount = random.nextInt(6) /* 0..5 */ + 5 // 5..10
    val input = random.nextString(appendByteCount).getBytes ++ plaintext ++ random.nextString(appendByteCount).getBytes
    if (random.nextBoolean()) {
      ("ecb", encryptECB(input, key))
    }
    else {
      val iv = Array.fill[Byte](16) {0x0}
      random.nextBytes(iv)
      ("cbc", encryptCBC(input, iv, key))
    }
  }

  def encryptECB(bytes: Array[Byte], key: Array[Byte]): Array[Byte] = {
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"))
    cipher.doFinal(bytes)
  }

  def encryptEcbSingle(bytes: Array[Byte], key: Array[Byte]): Array[Byte] = {
    val cipher = Cipher.getInstance("AES/ECB/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"))
    cipher.doFinal(bytes)
  }

  def decryptECB(ciphertext: Array[Byte], key: Array[Byte]): Array[Byte] = {
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"))
    cipher.doFinal(ciphertext)
  }

  def decryptEcbSingle(ciphertext: Array[Byte], key: Array[Byte]): Array[Byte] = {
    val cipher = Cipher.getInstance("AES/ECB/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"))
    cipher.doFinal(ciphertext)
  }

  def generateKey(): Array[Byte] = {
    val gen = KeyGenerator.getInstance("AES")
    gen.init(128)
    gen.generateKey().getEncoded
  }

  def encryptCBC(bytes: Array[Byte], iv: Array[Byte], key: Array[Byte]): Array[Byte] = {
    val input = PadPKCS7.pad(bytes, 16).grouped(16).toList

    val builder = new mutable.ListBuffer[Array[Byte]]
    var previous = iv
    for (block <- input) {
      previous = AES.encryptEcbSingle(Combine.xor(previous, block), key)
      builder.append(previous)
    }

    builder.flatten.toArray
  }

  def decryptCBC(bytes: Array[Byte], iv: Array[Byte], key: Array[Byte]): Array[Byte] = {
    val input = bytes.grouped(16).toList

    val builder = new mutable.ListBuffer[Array[Byte]]
    var previous = iv
    for (block <- input) {
      val plaintext = Combine.xor(previous, decryptEcbSingle(block, key))
      builder.append(plaintext)
      previous = block
    }

    //PadPKCS7.unpadPkcs7(builder.flatten.toArray)
    builder.flatten.toArray
  }

}
