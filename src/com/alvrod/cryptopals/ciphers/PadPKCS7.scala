package com.alvrod.cryptopals.ciphers

object PadPKCS7 {
  def closestMultiple(num: Int, modulus: Int): Int = {
    num + (-num % modulus + modulus) % modulus
  }

  def pad(input: Array[Byte], padToMultipleOf: Int): Array[Byte] = {
    val inputLength = input.length
    val finalLength = closestMultiple(inputLength, padToMultipleOf)
    val padLength = finalLength - inputLength match {
      case 0 => padToMultipleOf
      case difference: Int => difference
    }

    val padBytes = Array.fill(padLength) { padLength.toByte }

    input ++ padBytes
  }

  def unpadPkcs7(padded: Array[Byte]): Array[Byte] = {
    padded.dropRight(padded.last)
  }
}
