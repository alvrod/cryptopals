package com.alvrod.cryptopals.test.set2

import com.alvrod.cryptopals.ciphers.{PadPKCS7, AES}
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

  test("Encrypt, decrypt with CBC") {
    val key = "YELLOW SUBMARINE".getBytes
    val plaintext = "For millions of years mankind lived just like the animals. Then something happened which unleashed the power of our imagination: We learned to talk"
    val iv = AES.generateKey()
    val ciphertext = AES.encryptCBC(plaintext.getBytes, iv, key)

    val decrypted = new String(PadPKCS7.unpadPkcs7(AES.decryptCBC(ciphertext, iv, key)))
    expectResult(plaintext) {
      decrypted
    }
  }

}
