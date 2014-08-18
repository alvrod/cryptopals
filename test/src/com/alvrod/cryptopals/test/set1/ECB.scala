package com.alvrod.cryptopals.test.set1

import com.alvrod.cryptopals.Convert
import com.alvrod.cryptopals.ciphers.{AES, RepeatingByteXor, SingleByteXor}
import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

import scala.io.Source

@RunWith(classOf[JUnitRunner])
class ECB extends FunSuite {
  test("Yellow Submarine") {
    val source = Source.fromURL("http://cryptopals.com/static/challenge-data/7.txt")
    val ciphertextBase64 = source.getLines().foldLeft("")((acc, item) => acc + item)
    val decoder = new sun.misc.BASE64Decoder()
    val ciphertext = decoder.decodeBuffer(ciphertextBase64)
    val plaintextBytes = AES.decryptECB(ciphertext, "YELLOW SUBMARINE".getBytes)
    println(new String(plaintextBytes))
  }

  test("Detect ECB") {
    val source = Source.fromURL("http://cryptopals.com/static/challenge-data/8.txt")
    val hexLines = source.getLines()
    val ecb = AES.detectECB(hexLines)
    println(ecb)
  }
}
