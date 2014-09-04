package com.alvrod.cryptopals.ciphers

import javax.crypto.{KeyGenerator, Cipher}
import javax.crypto.spec.SecretKeySpec

import com.alvrod.cryptopals.{Combine, Convert}
import com.alvrod.cryptopals.breakers.RepetitionScore

import scala.collection.mutable
import scala.util.Random

object AES {
  val random = new Random()
  val secretKey = generateKey()
  val decoder = new sun.misc.BASE64Decoder()

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

  // AES-128-ECB(your-string || unknown-string, random-key)
  def encryptEcbSecretKey(plaintext: Array[Byte]): Array[Byte] = {
    val key = secretKey
    val appendTextBase64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    val appendBytes = decoder.decodeBuffer(appendTextBase64) // the "unknown string"

    val input = plaintext ++ appendBytes
    encryptECB(input, key)
  }

  // AES-128-ECB(random bytes || your-string || unknown-string, random-key)
  def encryptEcbSecretKeyWithRandomStart(plaintext: Array[Byte]): Array[Byte] = {
    val key = secretKey
    val appendTextBase64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    val appendBytes = decoder.decodeBuffer(appendTextBase64) // the "unknown string"

    val randomCount = random.nextInt(500)
    val randomBytes = new Array[Byte](randomCount)
    random.nextBytes(randomBytes)

    val input = randomBytes ++ plaintext ++ appendBytes
    encryptECB(input, key)
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
