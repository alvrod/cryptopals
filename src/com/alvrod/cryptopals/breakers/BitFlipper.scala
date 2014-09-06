package com.alvrod.cryptopals.breakers

import com.alvrod.cryptopals.ciphers.AES

object BitFlipper {
  def isAdmin(ciphertext: Array[Byte], iv: Array[Byte]): Boolean = {
    val plaintext = new String(AES.decryptCBC(ciphertext, iv, AES.secretKey), "ISO-8859-1")
    println(plaintext)
    plaintext.contains(";admin=true;")
  }

  // return something that decrypts to ;admin=true;
  def findFlipAdminInput(): (Array[Byte], Array[Byte]) = {
    val input =
      "YE3admin5true3NE"

    // 2 blocks + my text + 3 blocks
    val (ciphertext, iv) = AES.encryptCbcBitflipping(input + input)
    // = - 61 - 0011 1101
    // 5 - 53 - 0011 0101
    //     8 == 0000 1000

    // ; - 59 - 0011 1011
    // 3 - 51 - 0011 0011
    //     8 == 0000 1000
    ciphertext(40) = (ciphertext(40) ^ 0x8).toByte
    ciphertext(45) = (ciphertext(45) ^ 0x8).toByte
    ciphertext(34) = (ciphertext(34) ^ 0x8).toByte
    (ciphertext, iv)
  }
}