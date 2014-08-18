package com.alvrod.cryptopals.test.set2

import com.alvrod.cryptopals.ciphers.AES
import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

import scala.io.Source

@RunWith(classOf[JUnitRunner])
class CBC extends FunSuite {
  test("Yellow Submarine") {
    val source = Source.fromURL("http://cryptopals.com/static/challenge-data/10.txt")
    val ciphertextBase64 = source.getLines().foldLeft("")((acc, item) => acc + item)
    //val ciphertextBase64 = source.getLines().mkString
    val decoder = new sun.misc.BASE64Decoder()
    val ciphertext = decoder.decodeBuffer(ciphertextBase64)
    val plaintextBytes = AES.decryptCBC(ciphertext, Array.fill(16)(0x0), "YELLOW SUBMARINE".getBytes)
    println(new String(plaintextBytes))
  }

}
