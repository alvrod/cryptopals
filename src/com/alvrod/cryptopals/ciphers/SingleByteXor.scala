package com.alvrod.cryptopals.ciphers

import com.alvrod.cryptopals.breakers.FrequencyScore
import com.alvrod.cryptopals.{Convert, Combine}

object SingleByteXor {
  def decrypt(hex: String, key: Byte): String = {
    val bytes = Convert.hexToBytes(hex)
    val decryptedBytes = Combine.singleByteXor(bytes, key)
    Convert.bytesToHex(decryptedBytes)
  }

  def break(hex: String): String = {
    val bestKey = (0 to 256)
      .map(byte => (byte, decrypt(hex, byte.toByte)))
      .map { case (key, candidate) => (key, FrequencyScore.getFrequency(candidate)) }
      .maxBy { case (key, score) => score }
    decrypt(hex, bestKey._1.toByte)
  }

  def detect(lines: Iterator[String]): String = {
    lines
      .map(line => break(line))
      .map(candidate => (candidate, FrequencyScore.getFrequency(candidate)))
      .maxBy { case (candidate, score) => score }._1
  }
}
