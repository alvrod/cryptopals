package com.alvrod.cryptopals.breakers

import com.alvrod.cryptopals.Convert

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
}
