package com.alvrod.cryptopals.test.set2


import com.alvrod.cryptopals.Convert
import com.alvrod.cryptopals.ciphers.{PadPKCS7, AES, RepeatingByteXor, SingleByteXor}
import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class Padding extends FunSuite {
  test("YELLOW SUBMARINE") {
    expectResult(("YELLOW SUBMARINE".getBytes ++ Array(0x4, 0x4, 0x4, 0x4)).toList) {
      PadPKCS7.pad("YELLOW SUBMARINE".getBytes, 20).toList
    }
  }

  test("Unpad OK") {
    val padded = PadPKCS7.pad("YELLOW SUBMARINE".getBytes, 16)

    expectResult("YELLOW SUBMARINE".getBytes.toList) {
      PadPKCS7.unpadPkcs7(padded).toList
    }
  }

  test("Unpad exceptions") {
    val wrong1 = "ICE ICE BABY".getBytes ++ Array.fill[Byte](4){0x5}
    val wrong2 = "ICE ICE BABY".getBytes ++ Array[Byte](0x1, 0x2, 0x3, 0x4)

    intercept[IllegalArgumentException] {
      PadPKCS7.unpadPkcs7(wrong1)
    }

    intercept[IllegalArgumentException] {
      PadPKCS7.unpadPkcs7(wrong2)
    }

  }
}
