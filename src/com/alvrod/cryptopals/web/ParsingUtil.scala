package com.alvrod.cryptopals.web

object ParsingUtil {
  def parseKvEncoded(encoded: String): Map[String, String] = {
    encoded.split('&')
      .map(pair => pair.split('='))
      .filter(parts => parts.length == 2)
      .map(parts => (parts(0), parts(1)))
      .toMap
  }

  def encodeKv(map: Map[String, String]): String = {
    map
      .map { case (key, value) => s"$key=$value"}
      .mkString("&")
  }

  def quoteOut(input: String, quotables: Array[Char]): String = {
    var result: String = input
    for (quote <- quotables) {
      result = result.replaceAll(quote.toString, "\"" + quote + "\"")
    }
    result
  }
}