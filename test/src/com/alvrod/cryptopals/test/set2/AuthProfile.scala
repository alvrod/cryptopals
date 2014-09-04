package com.alvrod.cryptopals.test.set2

import com.alvrod.cryptopals.breakers.EcbProfile
import com.alvrod.cryptopals.web.{AuthService, Profile}
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

  test("Create, encrypt, decrypt") {
    val encryptedProfile = AuthService.profileFor("me@my.domain.com")
    val profile = AuthService.openUserProfile(encryptedProfile)
    expectResult("user") {profile.role}
    expectResult("me@my.domain.com") {profile.email}
    expectResult(10) {profile.uid}
  }

  test("Turn user into admin") {
    val adminCipher = EcbProfile.breakCookie

    val profile = AuthService.openUserProfile(adminCipher)
    expectResult("admin") {profile.role}
    expectResult("XXXXXXXXXXXXX") {profile.email}
    expectResult(10) {profile.uid}
  }
}
