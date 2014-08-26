package com.alvrod.cryptopals.breakers

import com.alvrod.cryptopals.ciphers.PadPKCS7
import com.alvrod.cryptopals.web.{AuthService, Profile}

/*
Using only
  the user input to profile_for() (as an oracle to generate "valid" ciphertexts)
  and the ciphertexts themselves,
  make a role=admin profile.
 */
object EcbProfile {
  def breakCookie: Array[Byte] = {
    val adminBytes = PadPKCS7.pad("admin".getBytes, 16)
    val adminStr = new String(adminBytes)

    // find out what is the result of encrypting "admin"
    // this will encrypt
    // email=XXXXXXXXXXadminPPPPPPPPPPP&uid=10&role=user
    //                 ^               ^               ^  
    val encryptedProfile = AuthService.profileFor("XXXXXXXXXX" + adminStr)
    val adminCipher = encryptedProfile.slice(16, 32)

    // this will encrypt
    // email=XXXXXXXXXXXXX&uid=10&role=user
    //                 ^               ^               ^
    // so that the last block is user + padding
    val breakableProfile = AuthService.profileFor("XXXXXXXXXXXXX")

    // now paste the admin block over the user block
    breakableProfile.slice(0, 32) ++ adminCipher
  }
}
