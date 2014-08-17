package com.alvrod.cryptopals.ciphers

import com.alvrod.cryptopals.breakers.FrequencyScore
import com.alvrod.cryptopals.{Combine, Convert}

object RepeatingByteXor {
  def encrypt(bytes: Array[Byte], key: Array[Byte]): Array[Byte] = {
    Combine.xor(bytes, Stream.continually(key.toStream).flatten.take(bytes.length).toArray)
  }

  def decrypt(bytes: Array[Byte], key: Array[Byte]): Array[Byte] = {
    bytes
  }
}