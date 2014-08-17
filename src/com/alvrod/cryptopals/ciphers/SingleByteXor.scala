package com.alvrod.cryptopals.ciphers

import com.alvrod.cryptopals.breakers.FrequencyScore
import com.alvrod.cryptopals.{Convert, Combine}

object SingleByteXor {
  def decrypt(bytes: Array[Byte], key: Byte): Array[Byte] = {
    Combine.singleByteXor(bytes, key)
  }

  def break(bytes: Array[Byte]): (Byte, Array[Byte]) = {
    val bestKey = (0 to 256)
      .map(byte => (byte, decrypt(bytes, byte.toByte)))
      .map { case (key, candidate) => (key, FrequencyScore.getFrequency(candidate)) }
      .maxBy { case (key, score) => score }
    val foundKey = bestKey._1.toByte
    (foundKey, decrypt(bytes, foundKey))
  }

  def detect(lines: Iterator[String]): Array[Byte] = {
    lines
      .map(line => break(Convert.hexToBytes(line)))
      .map(candidate => (candidate._2, FrequencyScore.getFrequency(candidate._2)))
      .maxBy { case (candidate, score) => score }
      ._1
  }
}
