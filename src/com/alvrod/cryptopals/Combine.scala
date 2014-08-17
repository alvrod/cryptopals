package com.alvrod.cryptopals

object Combine {
  def xor(b1: Array[Byte], b2:Array[Byte]): Array[Byte] = {
    if (b1 == null || b2 == null || b1.length != b2.length) {
      throw new IllegalArgumentException("Invalid input")
    }

    b1.zip(b2).map(pair => (pair._1 ^ pair._2).toByte)
  }

  def singleByteXor(input: Array[Byte], key: Byte): Array[Byte] = {
    val expandedKey = Array.fill(input.length){ key }
    xor(input, expandedKey)
  }

  def hammingDistance(b1: Array[Byte], b2: Array[Byte]): Int = {
    Combine.xor(b1, b2)
      .map(byte => Integer.bitCount(byte))
      .sum
  }
}
