package com.alvrod.cryptopals.test.set2

import com.alvrod.cryptopals.breakers.BitFlipper
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

  test ("The function should quote out the ; and = characters.") {
    val input = "key=value;otherKey=otherValue;rest="
    val quoted = ParsingUtil.quoteOut(input, Array(';', '='))
    expectResult("""key"="value";"otherKey"="otherValue";"rest"="""") { quoted }
  }
}
