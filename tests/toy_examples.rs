// Integration tests for ZKP using small, easy-to-verify numbers
use num_bigint::BigUint;
use rust_zkp_chaum_pedersen::ZKP;

#[test]
fn test_different_toy_parameters() {
    println!("🔄 Testing with different small parameters");
    
    // Use mathematically correct parameters
    let alpha = BigUint::from(2u32);   // 2 is a generator
    let beta = BigUint::from(4u32);    // 4 = 2^2, also a generator
    let p = BigUint::from(11u32);      // Small prime
    let q = BigUint::from(5u32);       // Prime that divides p-1=10
    
    let zkp = ZKP { p, q: q.clone(), alpha, beta };

    let x = BigUint::from(2u32);   // Secret
    let k = BigUint::from(3u32);   // Nonce
    let c = BigUint::from(1u32);   // Challenge

    // Run full protocol
    let (y1, y2) = zkp.compute_pair(&x);
    let (r1, r2) = zkp.compute_pair(&k);
    let s = zkp.solve(&k, &c, &x);
    let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);

    println!("📊 Results with valid parameters:");
    println!("   y1 = {}, y2 = {}", y1, y2);
    println!("   r1 = {}, r2 = {}", r1, r2);
    println!("   s = {}", s);
    println!("   Verification: {}", result);

    assert!(result);
    println!("✅ Different parameter test passed!");
}