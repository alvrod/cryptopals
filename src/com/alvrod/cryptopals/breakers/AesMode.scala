package com.alvrod.cryptopals.breakers

import java.util
import com.alvrod.cryptopals.{Euclid, Convert}
import com.alvrod.cryptopals.ciphers.{PadPKCS7, AES}

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

    def guessBlockSize(oracle: Array[Byte] => Array[Byte]): Int = {
      val blockSizes = (2 to 40)
        .map(size => oracle(Array.fill(size) { 'A'.toByte }))
        .map(ciphertext => ciphertext.length)
        .toList

      val pairs = blockSizes zip blockSizes.tail
      pairs.collectFirst( { case (a, b) if a != b => b - a }).getOrElse(0)
    }

    // get the ciphertexts for AAAAAAA?, where ? = a, b, c, ...
    // indexed by ciphertext
    def findMatchingBlock(block: Array[Byte], searchBlock: Array[Byte], length: Int): Char = {
      val almostBlock = block
      val found = (Byte.MinValue to Byte.MaxValue)
        .map(byte => {
          val plaintext = almostBlock ++ Array(byte.toByte)
          val ciphertext = encryptEcbSecretKey(plaintext)
          val offset = ciphertext.length - length - searchBlock.length
          val cipherBlock = ciphertext.slice(offset, offset + searchBlock.length)
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

      findMatchingBlock(guessBlock, searchBlock, length)
    }

    val myEncrypt = (plaintext: Array[Byte]) => ("?", encryptEcbSecretKey(plaintext))
    val (guessedMode, mode) = AesMode.modeOracle(myEncrypt)

    val blockSize = guessBlockSize(encryptEcbSecretKey)
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

  def encryptDropRandom(myText: Array[Byte], blockSize: Int): Array[Byte] = {
    var secretTextPosition = -1
    var ciphertext: Array[Byte] = Array.empty
    var markCipher: Array[Byte] = Array.empty
    val marker = Array.fill(blockSize * 4) { '_'.toByte }
    // blocks filled with glorious underscores

    while (secretTextPosition < 0) {
      ciphertext = AES.encryptEcbSecretKeyWithRandomStart(marker ++ myText)
      val blocks = ciphertext.grouped(16).toList

      var end = false
      var blockIndex = 0
      while (!end && blockIndex < blocks.length) {
        val block = blocks(blockIndex)
        val allEqual = blocks.take(4).forall(bytes => block.sameElements(bytes))
        if (allEqual) {
          markCipher = block
          secretTextPosition = blockIndex + blockSize * 4
          end = true
        }

        blockIndex = blockIndex + 1
      }
    }
    require(markCipher.length == blockSize, "Unable to find marker")
    val res = ciphertext.drop(secretTextPosition)
    require(res.length % blockSize == 0,
      s"Inconsistent marker with length ${res.length} found, ciphertext length ${ciphertext.length}")
    res
  }

  // block size, block mode, decrypted secret text
  def breakEcbHard(): (Int, String, String) = {
    import AES.encryptEcbSecretKeyWithRandomStart

    def guessBlockSize(oracle: Array[Byte] => Array[Byte]): Int = {
      val blockSizes = (2 to 40)
        .map(size => oracle(Array.fill(size) {
        'A'.toByte
      }))
        .map(ciphertext => ciphertext.length)

      Euclid.gcd(blockSizes)
    }

    def findMatchingBlock(block: Array[Byte], searchBlock: Array[Byte]): Char = {
      val found = (0 to Byte.MaxValue)
        .par
        .map(byte => {
          val plaintext = block ++ Array(byte.toByte)
          val ciphertext = encryptDropRandom(plaintext, searchBlock.length)
          val cipherBlock = ciphertext.take(searchBlock.length)

        (cipherBlock, byte.toChar)
      })
        .toList
        .collectFirst { case (candidate, char) if util.Arrays.equals(searchBlock, candidate) => char}
      found.getOrElse('?')
    }

    def breakByte(plaintext: String, blockSize: Int): Char = {
                      // 16         0,1,2....144        16
      val fillCount = blockSize - (plaintext.length % blockSize)
      val (maskBlock, drop) = (Array.fill[Byte](fillCount - 1) { 0x1 }, plaintext.length / blockSize)
      val ciphertext = encryptDropRandom(maskBlock, blockSize)

      val guessBlock = (maskBlock ++  plaintext.getBytes)
        .drop(blockSize * drop)
        .take(blockSize - 1)
       // last char unknown, of course. so 15 useful bytes

      val searchBlock = ciphertext
        .drop(blockSize * drop)
        .take(blockSize)
      findMatchingBlock(guessBlock, searchBlock)
    }

    val myEncrypt = (plaintext: Array[Byte]) => ("?", encryptEcbSecretKeyWithRandomStart(plaintext))
    val (guessedMode, mode) = AesMode.modeOracle(myEncrypt)

    val blockSize = guessBlockSize(encryptEcbSecretKeyWithRandomStart)

    // find out where the secret text begins, after encrypting my marker
    val pureCipher = encryptDropRandom(Array[Byte](), blockSize)
    println(s"secret text is ${pureCipher.length} chars long") // 144

    val plaintext = StringBuilder.newBuilder
    while (plaintext.length < pureCipher.length) {
      val nextChar = breakByte(plaintext.toString(), blockSize)
      println(nextChar)
      plaintext.append(nextChar)
    }

    (blockSize, guessedMode, plaintext.toString())
  }
}
