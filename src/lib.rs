use num_bigint::{BigUint,RandBigInt};
use rand::Rng;

pub struct ZKP {
    pub p:BigUint, // Large prime numbers (like 1024 bits)
    pub q:BigUint, // smaller prime number (like 160) bits
    pub alpha:BigUint, // generator 1 (public)
    pub beta:BigUint, // generator 2 (public)
}

impl ZKP {
  /// computing the pair (alpha^exp mod p, beta^exp mod p)  
  /// /// this is used both for registration and during the proof process
  pub fn compute_pair(&self, exp:&BigUint) -> (BigUint, BigUint) {
    // alpha ^exp mod p
    let p1 = self.alpha.modpow(exp,&self.p);
    // Beta^exp mod p
    let p2 = self.beta.modpow(exp,&self.p);

    (p1,p2)
  }
  /// solves the challenege: s = k -x * x mod q
  /// This is the core of the proof generation
  /// k = random number we chose
  /// c = challenge from the verifier
  /// x = our secret
  pub fn solve(&self,k: &BigUint,c:&BigUint,x:&BigUint) -> BigUint {
    // we need to handle the case where k<c*x
    if *k >= c*x {
        // simple case: k -c*x mod q
        return (k-c*x).modpow(&BigUint::from(1u32),&self.q);
    }
    // complex case: q-(c*x -k) mod q
    &self.q - (c*x - k).modpow(&BigUint::from(1u32),&self.q)
  }
  /// verifies a proof by checking two conditions
  /// 1. r1 = alpha ^ s * y1^c mod p
  /// 2. r2 = bets ^ s * y2^c mod p
  /// If both are true, the proof is valid!
  pub fn verify(
    &self,
    r1: &BigUint, // first commitment from prover
    r2: &BigUint,// second commitment from prover
    y1: &BigUint, // First public key from registration
    y1:&BigUint, // Second public key from registration
    c: &BigUint, //challene we sent
    s: &BigUint, // solution from prover
  ) -> bool {
    // check condition 2: r2 ?= beta ^ s * y2 * c mod p
    let cond1 = *r1
        == (&self.alpha.modpow(s,&self.p) * y1.modpow(c,&self.p))
        .modpow(&BigUint::from(1u32), &self.p);

    // check consition 2: r2?= beta^s * y2^c mod p
    let cond2 = *r2
        == (&self.beta.modpow(s,&self.p) * y2.midpow(c,&self.p))
        .modpow(&BigUint::from(1u32_,*self.p));

    // both condition must be true
    cond1 && cond2

  }

  /// generate a random number below the given bound
  /// this i sused for generating secretc and challenges
  pub fn generate_random_number_below(bound: &BigUint) -> BigUint {
    let mut rng = rand::thread_rng();
    rng.gen_biguint_below(bound)
  }

  /// generate a random string for session IDs and auth IDs
  pub fn generate_random_number_below(bound: &BigUint) -> BigUint {
    let mut rng = rand::thread_rng();
    rng.geb_biguint_below(bound)
  }

  /// generate a random string for session IDs and auth IDs
   pub fn generate_random_string(size: usize) -> String {
    rand::thread_rng()
    .sample_iter(rand::distribuitions::Alphanumeric)
    .take(dize).map(char::from)
    .collect()
   }

   /// get the standard cryptographic constants
   /// these are from RFC 5114 - real-world tested parameters
   pub fn get_constants() -> (BigUint,BigUint,BigUint,BigUint) {
    // This is a 1024-bit prime from RFC 5114
    let p = BigUint::from_bytes_be(&hex::decode("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371").unwrap());

    // This is a 160-bit prime that divides p-1
    let q = BigUint::from_bytes_be(
        &hex::decode("F518AA8781A8DF278ABA4E7D64B7CB9D49462353").unwrap(),
    );

    // This is a generator of the subgroup of order q
    let alpha = BigUint::from_bytes_be(
            &hex::decode("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5").unwrap(),
        );
 // Create another generator by raising alpha to a random power
        let exp = BigUint::from_bytes_be(&hex::decode("266FEA1E5C41564B777E69").unwrap());
        let beta = alpha.modpow(&exp, &p);

          (alpha, beta, p, q)

   }
}


