package com.alvrod.cryptopals.test.set3
import com.alvrod.cryptopals.breakers.AesMode
import com.alvrod.cryptopals.ciphers.AES
import com.alvrod.cryptopals.web.ParsingUtil
import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class KvEncode extends FunSuite {
  test ("Website sample") {
    val encoded = "foo=bar&baz=qux&zap=zazzle"
    val mapped = ParsingUtil.parseKvEncoded(encoded)
    expectResult("bar") {mapped("foo")}
    expectResult("qux") {mapped("baz")}
    expectResult("zazzle") {mapped("zap")}
  }

  test ("Encode") {
    val encoded = "foo=bar&baz=qux&zap=zazzle"
    val mapped = ParsingUtil.parseKvEncoded(encoded)
    expectResult(encoded) { ParsingUtil.encodeKv(mapped) }
  }
}
