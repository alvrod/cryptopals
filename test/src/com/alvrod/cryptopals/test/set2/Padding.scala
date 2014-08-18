package com.alvrod.cryptopals.test.set2


import com.alvrod.cryptopals.Convert
import com.alvrod.cryptopals.ciphers.{PadPKCS7, AES, RepeatingByteXor, SingleByteXor}
import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

import scala.io.Source

@RunWith(classOf[JUnitRunner])
class Padding extends FunSuite {
  test("YELLOW SUBMARINE") {
    expectResult(("YELLOW SUBMARINE".getBytes ++ Array(0x4, 0x4, 0x4, 0x4)).toList) {
      PadPKCS7.pad("YELLOW SUBMARINE".getBytes, 20).toList
    }
  }
}
