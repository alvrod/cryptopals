package com.alvrod.cryptopals.web

class Profile(_email: String, val uid: Int, val role: String) {
  val email = _email.replace("&", "").replace("=", "")

  def encode: String = {
    ParsingUtil.encodeKv(Map(
      "email" -> email,
      "uid" -> uid.toString,
      "role" -> role
    ))
  }
}

object Profile {
  def apply(email: String): Profile = {
    new Profile(email, 10, "user")
  }

  def fromEncoded(encoded: String): Profile = {
    val values = ParsingUtil.parseKvEncoded(encoded)
    new Profile(
      values.getOrElse("email", ""),
      Integer.parseInt(values.getOrElse("uid", "0")),
      values.getOrElse("role", "")
    )
  }
}