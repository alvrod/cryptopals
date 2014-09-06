package com.alvrod.cryptopals.test.set2

import com.alvrod.cryptopals.breakers.{BitFlipper, AesMode}
import com.alvrod.cryptopals.ciphers.AES
import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

class CbcBitflipping extends FunSuite {
  test("naive") {
    val naive = ";admin=true;"
    val (ciphertext, iv) = AES.encryptCbcBitflipping(naive)
    expectResult(false) {
      BitFlipper.isAdmin(ciphertext, iv)
    }
  }

  test("flip it") {
    val (sneaky, iv) = BitFlipper.findFlipAdminInput()
    expectResult(true) {BitFlipper.isAdmin(sneaky, iv)}
  }

}
