package com.alvrod.cryptopals.test.set3

import com.alvrod.cryptopals.Euclid
import com.alvrod.cryptopals.breakers.AesMode
import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class BreakEcbWithRandom extends FunSuite {
  test("Find where secret text begins") {
    for (i <- 0 to 100) {
      val cipher = AesMode.encryptDropRandom(Array.empty, 16)
      expectResult(144) { cipher.length }
    }
  }

  test("Find where my text begins") {
    for (i <- 0 to 1000) {
      val cipher = AesMode.encryptDropRandom("YELLOW SUBMARINE".getBytes, 16)
      expectResult(160) { cipher.length }
    }
  }

  test("Cutoff gives equal ciphertexts") {
    val cipher = AesMode.encryptDropRandom(Array.empty, 16)
    val cipher2 = AesMode.encryptDropRandom(Array.empty, 16)
    cipher.sameElements(cipher2)
  }

  test("Cutoff with content gives equal ciphertexts") {
    val content = "El agua de vino que tiene asuncion no es blanco ni tinto ni tiene color".getBytes
    val cipher = AesMode.encryptDropRandom(content, 16)
    val cipher2 = AesMode.encryptDropRandom(content, 16)
    cipher.sameElements(cipher2)
  }

  test("gcd") {
    expectResult(2) { Euclid.gcd(4, 2) }

    expectResult(16) { Euclid.gcd(Array(16 * 5, 16 * 7, 16 * 14))} // 80, 112, 224
  }

  test("Break ECB byte by byte, simple") {
    val (blockSize, mode, plaintext) = AesMode.breakEcbSimple()
    expectResult(16) {blockSize}
    expectResult("ecb") {mode}
    println(new String(plaintext))
    expectResult(true) {plaintext.startsWith("Rollin' in my 5.0")}
  }

  test("Break ECB byte by byte, harder") {
    val (blockSize, mode, plaintext) = AesMode.breakEcbHard()
    expectResult(16) {blockSize}
    expectResult("ecb") {mode}
    println(new String(plaintext))
    expectResult(true) {plaintext.startsWith("Rollin' in my 5.0")}
  }
}
