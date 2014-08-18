package com.alvrod.cryptopals.breakers

import java.util

object RepetitionScore {
  def occurrences(block: Array[Byte], all: List[Array[Byte]]): Int = {
    all.count(test => util.Arrays.equals(block, test))
  }

  def countRepeats(ciphertext: Array[Byte]): Int = {
    val blocks = ciphertext.grouped(16).toList

    blocks.map(block => occurrences(block, blocks)).sum
  }
}
