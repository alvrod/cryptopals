package com.alvrod.cryptopals.ciphers

import com.alvrod.cryptopals.breakers.FrequencyScore
import com.alvrod.cryptopals.{Combine, Convert}

object RepeatingByteXor {
  def encrypt(bytes: Array[Byte], key: Array[Byte]): Array[Byte] = {
    Combine.xor(bytes, Stream.continually(key.toStream).flatten.take(bytes.length).toArray)
  }

  def break(bytes: Array[Byte]): Array[Byte] = {
    val keySizes = (2 to 40)
      .map(keySize => (keySize, normalizedKeyDistance(bytes, keySize)))
      .sortBy { case (keySize, distance) => distance }
      .take(3)

    val candidates = keySizes
      .map(keySize => breakKeyForKeySize(bytes, keySize._1))
      .map(key => encrypt(bytes, key))

    val candidatesAscii = candidates.map(c => new String(c)).toList

    candidates.map(candidate => (candidate, FrequencyScore.getFrequency(candidate)))
      .maxBy { case (candidate, score) => score }
      ._1
  }

  def breakKeyForKeySize(bytes: Array[Byte], keySize: Int): Array[Byte] = {
    val blocks = bytes.grouped(keySize).filter(block => block.length == keySize).toList
    val keyByteIndex = 0 until keySize
    val transposedBlocks = keyByteIndex.map(index => blocks.map(block => block(index)).toArray)
    val keys = transposedBlocks.map(block => SingleByteXor.break(block)._1)
    keys.toArray
  }

  def normalizedKeyDistance(bytes: Array[Byte], keySize: Int): Double = {
    val keySizeGroups = bytes
      .grouped(keySize)
      .toList
      .dropRight(1)

    val pairs = keySizeGroups zip keySizeGroups.tail
    val sum = pairs
      .map { case (a, b) => Combine.hammingDistance(a, b).toDouble / keySize.toDouble }
      .sum

    sum / keySizeGroups.length.toDouble
  }
}