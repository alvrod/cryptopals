package com.alvrod.cryptopals.test.set2

import com.alvrod.cryptopals.breakers.AesMode
import com.alvrod.cryptopals.ciphers.AES
import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class EcbCbcDetectionOracle extends FunSuite {
  test("Guess mode") {
    for (i <- 1 to 10000) {
      val (guessedMode, mode) = AesMode.modeOracle(AES.encryptSecret)
      expectResult(mode) {
        guessedMode
      }
    }
  }
}
