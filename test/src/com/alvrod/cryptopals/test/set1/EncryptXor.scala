package com.alvrod.cryptopals.test.set1

import com.alvrod.cryptopals.Convert
import com.alvrod.cryptopals.ciphers.{RepeatingByteXor, SingleByteXor}
import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class EncryptXor extends FunSuite {
  test("Website sample") {
    val key = "ICE"

    expectResult("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f") {
      val plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
      val ciphertext = RepeatingByteXor.encrypt(plaintext.getBytes, key.getBytes)
      val hexcipher = Convert.bytesToHex(ciphertext)
      hexcipher
    }
  }
}
