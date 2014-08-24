package com.alvrod.cryptopals.breakers

import java.nio.charset.Charset
import java.util

import com.alvrod.cryptopals.Convert
import com.alvrod.cryptopals.ciphers.AES

import scala.collection.mutable.ArrayBuffer

object AesMode {
  // AES blocks always are 16 bytes
  def detectECB(cipherHexLines: Iterator[String]): String = {
    val mostRepeated = cipherHexLines
      .map(line => (line, RepetitionScore.countRepeats(Convert.hexToBytes(line))))
      .maxBy { case (line, score) => score }
    mostRepeated._1
  }

  def modeOracle(mysteryEncrypter: (Array[Byte]) => (String, Array[Byte])): (String, String) = {
    val plaintext = ("a" * 100).getBytes
    val (mode, ciphertext) = mysteryEncrypter(plaintext)
    val repeats = RepetitionScore.countRepeats(ciphertext)
    val guessedMode =
      if (repeats > 20) {
        "ecb"
      }
      else {
        "cbc"
      }
    (guessedMode, mode)
  }

  // block size, block mode, decrypted secret text
  def breakEcbSimple(): (Int, String, String) = {
    import AES.encryptEcbSecretKey

    def guessBlockSize(): Int = {
      val blockSizes = (2 to 40)
        .map(size => AES.encryptEcbSecretKey(Array.fill(size) { 'A'.toByte }))
        .map(ciphertext => ciphertext.length)
        .toList

      val pairs = blockSizes zip blockSizes.tail
      pairs.collectFirst( { case (a, b) if a != b => b - a }).getOrElse(0)
    }

    // get the ciphertexts for AAAAAAA?, where ? = a, b, c, ...
    // indexed by ciphertext
    def findMatchingBlock(block: Array[Byte], searchBlock: Array[Byte]): Char = {
      val almostBlock = block
      val found = (Byte.MinValue to Byte.MaxValue)
        .map(byte => {
          val plaintext = almostBlock ++ Array(byte.toByte)
          val ciphertext = encryptEcbSecretKey(plaintext)
          val cipherBlock = ciphertext.slice(0, searchBlock.length)
          (cipherBlock, byte.toChar)
        })
        .collectFirst {case (candidate, char) if util.Arrays.equals(searchBlock, candidate) => char}
      found.getOrElse('?')
    }

    def breakByte(mask: String, plaintext: String, blockSize: Int, length: Int): Char = {
      val ciphertext = encryptEcbSecretKey(mask.getBytes)

      val guessBlock = (mask + plaintext)
        .getBytes
        .slice(length - blockSize, length) // last char unknown, of course. so 15 useful bytes
      val searchBlock = ciphertext.slice(length - blockSize, length)

      findMatchingBlock(guessBlock, searchBlock)
    }

    val myEncrypt = (plaintext: Array[Byte]) => ("?", encryptEcbSecretKey(plaintext))
    val (guessedMode, mode) = AesMode.modeOracle(myEncrypt)

    val blockSize = guessBlockSize()
    val pureCipher = encryptEcbSecretKey(Array[Byte]())

    var mask = "A" * (pureCipher.length - 1)
    val plaintext = StringBuilder.newBuilder
    while (mask.length > 0) {
      val nextChar = breakByte(mask, plaintext.toString(), blockSize, pureCipher.length)
      mask = mask.drop(1)
      plaintext.append(nextChar)
    }

    (blockSize, guessedMode, plaintext.toString())
  }
}
