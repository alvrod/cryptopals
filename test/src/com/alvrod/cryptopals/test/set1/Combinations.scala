package com.alvrod.cryptopals.test.set1

import com.alvrod.cryptopals.{Combine, Convert}
import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class Combinations extends FunSuite {
  test("Website xor sample") {
    val hex1 = "1c0111001f010100061a024b53535009181c"
    val hex2 = "686974207468652062756c6c277320657965"

    expectResult("746865206b696420646f6e277420706c6179") {
      val b1 = Convert.hexToBytes(hex1)
      val b2 = Convert.hexToBytes(hex2)
      val xored = Combine.xor(b1, b2)
      Convert.bytesToHex(xored)
    }
  }

  test("Hamming distance") {
    val a = "this is a test".getBytes
    val b = "wokka wokka!!!".getBytes
    expectResult(37) {
      Combine.hammingDistance(a, b)
    }
  }
}
