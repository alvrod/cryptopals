package com.alvrod.cryptopals.test.set1

import com.alvrod.cryptopals.Convert
import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class Conversions extends FunSuite {
  test("Website sample") {
    expectResult("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t") {
      Convert.hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
    }
  }

  test("One hex less from website") {
    expectResult("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb28=") {
      Convert.hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6")
    }
  }

  test("Two hex less from website") {
    expectResult("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb28=") {
      Convert.hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f")
    }
  }

  test("Three hex less from website") {
    expectResult("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hybw==") {
      Convert.hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6")
    }
  }

  test("Four hex less from website") {
    expectResult("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hybw==") {
      Convert.hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f")
    }
  }

  test("Five hex less from website") {
    expectResult("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hy") {
      Convert.hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726")
    }
  }

  test("Null hex") {
    expectResult(null) {
      Convert.hexToBase64(null)
    }
  }

  test("Empty hex") {
    expectResult("") {
      Convert.hexToBase64("")
    }
  }

  test("Hex to text") {
    expectResult("I am the walrus") {
      Convert.hexToAscii("4920616d207468652077616c727573")
    }
  }
}
