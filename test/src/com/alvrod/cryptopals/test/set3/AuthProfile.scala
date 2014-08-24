package com.alvrod.cryptopals.test.set3
import com.alvrod.cryptopals.breakers.AesMode
import com.alvrod.cryptopals.ciphers.AES
import com.alvrod.cryptopals.web.{Profile, ParsingUtil}
import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class AuthProfile extends FunSuite {
  test("Disallow metacharacters in email") {
    val email = "foo@bar.com&role=admin"
    val profile = Profile(email)
    expectResult("user") {profile.role}
    expectResult("foo@bar.comroleadmin") {profile.email}
    expectResult(10) {profile.uid}
  }
}
