package com.alvrod.cryptopals.test.set2

import com.alvrod.cryptopals.breakers.AesMode
import com.alvrod.cryptopals.ciphers.AES
import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class BreakEcb extends FunSuite {
  test("Break ECB byte by byte, simple") {
    val (blockSize, mode, plaintext) = AesMode.breakEcbSimple()
    expectResult(16) {blockSize}
    expectResult("ecb") {mode}
    println(new String(plaintext))
  }
}
