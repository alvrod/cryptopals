package com.alvrod.cryptopals.web

import com.alvrod.cryptopals.ciphers.AES
import AES.secretKey

object AuthService {
  def profileFor(email: String): Array[Byte] = {
    val profile = Profile(email)
    val encodedProfile = profile.encode
    AES.encryptECB(encodedProfile.getBytes, secretKey)
  }

  def openUserProfile(encryptedProfile: Array[Byte]): Profile = {
    val encodedProfile = new String(AES.decryptECB(encryptedProfile, secretKey))
    Profile.fromEncoded(encodedProfile)
  }
}
