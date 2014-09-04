package com.alvrod.cryptopals

object Euclid {
  def gcd(a: Int, b: Int) : Int =
    if (a == b) {
      a
    }
    else if (a > b) {
      gcd(a - b, a)
    }
    else {
      gcd(a, b - a)
    }

  // gcd is associative: GCD(a,b,c,d) is the same as GCD(GCD(GCD(a,b),c),d)
  def gcd(numbers: Seq[Int]): Int = numbers.reduce(gcd)
}
