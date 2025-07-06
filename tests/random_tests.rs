// Tests using random numbers to ensure robustness
use num_bigint::BigUint;
use rust_zkp_chaum_pedersen::ZKP;

#[test]
fn test_small_numbers_with_random_values() {
    println!("🎲 Testing ZKP with small parameters but random k and c");
    
    // Still use small, predictable base parameters
    let alpha = BigUint::from(4u32);
    let beta = BigUint::from(9u32);
    let p = BigUint::from(23u32);
    let q = BigUint::from(11u32);
    
    let zkp = ZKP {
        p: p.clone(),
        q: q.clone(),
        alpha: alpha.clone(),
        beta: beta.clone(),
    };

    // Fixed secret for reproducibility
    let x = BigUint::from(6u32);
    
    // But randomize the proof parameters
    let k = ZKP::generate_random_number_below(&q);
    let c = ZKP::generate_random_number_below(&q);

    println!("🔧 Parameters: α={}, β={}, p={}, q={}", alpha, beta, p, q);
    println!("🔑 Fixed secret: x = {}", x);
    println!("🎲 Random nonce: k = {}", k);
    println!("🎲 Random challenge: c = {}", c);

    // Run the protocol
    let (y1, y2) = zkp.compute_pair(&x);
    let (r1, r2) = zkp.compute_pair(&k);
    let s = zkp.solve(&k, &c, &x);

    println!("📋 Public keys: y1={}, y2={}", y1, y2);
    println!("🔐 Commitments: r1={}, r2={}", r1, r2);
    println!("🧮 Solution: s={}", s);

    // This should always work regardless of random numbers!
    let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);
    println!("✅ Verification: {}", result);
    assert!(result);

    println!("🎉 Random values test passed!");
}

#[test]
fn test_multiple_random_rounds() {
    println!("🔄 Testing multiple rounds with different random values");
    
    let alpha = BigUint::from(4u32);
    let beta = BigUint::from(9u32);
    let p = BigUint::from(23u32);
    let q = BigUint::from(11u32);
    
    let zkp = ZKP {
        p: p.clone(),
        q: q.clone(),
        alpha: alpha.clone(),
        beta: beta.clone(),
    };

    let x = BigUint::from(6u32);  // Keep same secret

    // Test 10 different authentication rounds
    for round in 1..=10 {
        let k = ZKP::generate_random_number_below(&q);
        let c = ZKP::generate_random_number_below(&q);

        let (y1, y2) = zkp.compute_pair(&x);  // Same public keys
        let (r1, r2) = zkp.compute_pair(&k);  // Different commitments each time
        let s = zkp.solve(&k, &c, &x);

        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);
        
        println!("Round {}: k={}, c={}, s={}, verified={}", round, k, c, s, result);
        assert!(result, "Round {} failed!", round);
    }

    println!("✅ All 10 random rounds passed!");
}

#[test]
fn test_random_secrets() {
    println!("🎯 Testing with completely random secrets");
    
    let alpha = BigUint::from(4u32);
    let beta = BigUint::from(9u32);
    let p = BigUint::from(23u32);
    let q = BigUint::from(11u32);
    
    let zkp = ZKP {
        p: p.clone(),
        q: q.clone(),
        alpha: alpha.clone(),
        beta: beta.clone(),
    };

    // Test 5 different users with different random secrets
    for user_id in 1..=5 {
        let x = ZKP::generate_random_number_below(&q);  // Random secret
        let k = ZKP::generate_random_number_below(&q);  // Random nonce
        let c = ZKP::generate_random_number_below(&q);  // Random challenge

        let (y1, y2) = zkp.compute_pair(&x);
        let (r1, r2) = zkp.compute_pair(&k);
        let s = zkp.solve(&k, &c, &x);
        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);

        println!("User {}: secret={}, verified={}", user_id, x, result);
        assert!(result, "User {} failed verification!", user_id);
    }

    println!("✅ All random users verified successfully!");
}

#[test]
fn test_edge_cases_with_random() {
    println!("🔍 Testing edge cases with random numbers");
    
    let alpha = BigUint::from(4u32);
    let beta = BigUint::from(9u32);
    let p = BigUint::from(23u32);
    let q = BigUint::from(11u32);
    
    let zkp = ZKP {
        p: p.clone(),
        q: q.clone(),
        alpha: alpha.clone(),
        beta: beta.clone(),
    };

    // Test case: k < c*x (tests the modular arithmetic in solve())
    let x = BigUint::from(8u32);   // Large secret
    let k = BigUint::from(2u32);   // Small nonce
    let c = BigUint::from(9u32);   // Large challenge
    
    // This means k < c*x, so we test the "complex case" in solve()
    assert!(k < &c * &x, "This should test the k < c*x case");

    let (y1, y2) = zkp.compute_pair(&x);
    let (r1, r2) = zkp.compute_pair(&k);
    let s = zkp.solve(&k, &c, &x);
    let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);

    println!("Edge case: k={}, c={}, x={}, c*x={}", k, c, x, &c * &x);
    println!("Solution s={}, verified={}", s, result);
    assert!(result);

    println!("✅ Edge case test passed!");
}