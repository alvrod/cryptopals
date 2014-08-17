package com.alvrod.cryptopals.test.set1

import com.alvrod.cryptopals.Convert
import com.alvrod.cryptopals.ciphers.SingleByteXor
import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

import scala.io.Source

@RunWith(classOf[JUnitRunner])
class DecryptXor extends FunSuite {
  test("Website sample, single line") {
    val inputHex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    val decrypted = SingleByteXor.break(Convert.hexToBytes(inputHex))
    println(Convert.hexToAscii(Convert.bytesToHex(decrypted)))
  }

  test("Website sample, multiple lines") {
    val source = Source.fromURL("http://cryptopals.com/static/challenge-data/4.txt")
    val detected = SingleByteXor.detect(source.getLines())
    println(Convert.hexToAscii(Convert.bytesToHex(detected)))
  }
}
