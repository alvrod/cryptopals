package com.alvrod.cryptopals

import java.nio.ByteBuffer

/*
     Converting the hex string
  49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
     Should produce
  SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
*/

object Convert {
  def printByte(in: Int) {
    println(String.format("%8s", Integer.toBinaryString(in)).replace(' ', '0'))
  }

  // base64: A = 0, a = 26, 0 = 52
  def encodeBase64(in: Int): Char = {
    val int =
      if (in <= 25) {
        in + 65 // A
      }
      else if (in <= 51) {
        in - 26 + 97 // a
      }
      else if (in <= 61) {
        in - 52 + 48 // 0
      }
      else if (in == 62) {
        '+'
      }
      else {
        '/'
      }
    int.toChar
  }

  def hexToIntValue(hex: Char): Int = {
    if (hex >= '0' && hex <= '9') {
      hex - '0'
    }
    else if (hex >= 'A' && hex <= 'Z') {
      hex - 'A'  + 10
    }
    else {
      hex - 'a' + 10
    }
  }

  def byteToHexChar(byte: Int): Char = {
    val intCode =
      if (byte < 10) {
        byte + '0'
      }
      else {
        byte + 'a' - 10
      }
    intCode.toChar
  }

  def byteToHexValue(byte: Byte): String = {
    val c2 = byteToHexChar(byte & 0xF)
    val c1 = byteToHexChar(byte >> 4)
    s"$c1$c2"
  }

  def hexToBytes(in: String): Array[Byte] = {
    val hex = in.dropRight(in.length % 2)
    val builder = ByteBuffer.allocate(in.length / 2)
    for (index <- 0 to hex.length - 2 by 2) {
      builder.put((hexToIntValue(hex.charAt(index)) << 4 | hexToIntValue(hex.charAt(index + 1))).toByte)
    }
    builder.array()
  }

  def hexToAscii(hex: String): String = {
    val bytes = hexToBytes(hex)
    new String(bytes)
  }

  def bytesToHex(bytes: Array[Byte]): String = {
    bytes.map(b => byteToHexValue(b)).mkString
  }

  def hexToBase64(hex: String): String = {
    var count24 = 0
    var bits: Int = 0
    // in has 4 useful bits, on the right
    def nextChar(hex: Char): Option[Int] = {
      count24 = (count24 % 3) + 1
      val in = hexToIntValue(hex)

      // in: 0000abcd
      count24 match {
        case 1 =>
          bits = in << 2 //00abcd00
          None

        case 2 =>
          val res = bits | (in >>> 2) // 00xxxx00 | 000000ab -> 00xxxxab
          bits = (in << 4) & 0x30 // abcd0000 & 00110000 -> 00cd0000
          Some(res)

        case 3 =>
          Some(bits | in) // 00xx0000 | 0000abcd -> 00xxabcd
      }
    }
    if (hex == null) {
      null
    }
    else {
      val builder = StringBuilder.newBuilder
      hex
        .dropRight(hex.length % 2) // if hex has even length, drop 0, if odd length drop 1 to ensure even length
        .map(char => nextChar(char))
        .filter(char => char.isDefined)
        .foreach(char => builder.append(encodeBase64(char.get)))

      // The '==' sequence indicates that the last group contained only one byte, and '=' indicates that it contained two bytes.
      count24 match {
        case 1 =>
          builder.append(encodeBase64(bits))
          builder.append("=")

        case 2 =>
          builder.append(encodeBase64(bits))
          builder.append("==")

        case _ =>
      }
      builder.toString()
    }
  }
}