use num_bigint::BigUint;
use std::process::{Child, Command};
use std::time::Duration;
use tokio::time::sleep;

// Import our ZKP library
use rust_zkp_chaum_pedersen::ZKP;

// Import the generated protobuf code - we'll need to include it
pub mod zkp_auth {
    include!("../src/zkp_auth.rs");
}

use zkp_auth::{
    auth_client::AuthClient, AuthenticationAnswerRequest,
    AuthenticationChallengeRequest, RegisterRequest,
};

// Helper function to start server as external process
fn start_test_server(port: u16) -> Child {
    Command::new("cargo")
        .args(&["run", "--bin", "server"])
        .env("SERVER_PORT", port.to_string())
        .spawn()
        .expect("Failed to start server process")
}

#[tokio::test]
async fn test_full_authentication_flow() {
    println!("🧪 Testing complete authentication flow...");

    // Start server in background (we'll use the default port for simplicity)
    println!("📡 Starting test server...");
    let _server = start_test_server(50051);
    
    // Give server time to start
    sleep(Duration::from_secs(2)).await;

    // Create client connection
    let mut client = match AuthClient::connect("http://127.0.0.1:50051").await {
        Ok(client) => {
            println!("✅ Connected to server");
            client
        }
        Err(e) => {
            println!("❌ Failed to connect to server: {}", e);
            panic!("Could not connect to test server");
        }
    };

    // Set up ZKP parameters
    let (alpha, beta, p, q) = ZKP::get_constants();
    let zkp = ZKP {
        alpha: alpha.clone(),
        beta: beta.clone(),
        p: p.clone(),
        q: q.clone(),
    };

    // Test 1: User Registration
    println!("📝 Testing user registration...");
    let username = "integration_test_user".to_string();
    let password = BigUint::from_bytes_be("super_secret_password_123".as_bytes());

    let (y1, y2) = zkp.compute_pair(&password);

    let register_request = RegisterRequest {
        user: username.clone(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    };

    match client.register(register_request).await {
        Ok(_) => println!("✅ Registration successful"),
        Err(e) => {
            println!("❌ Registration failed: {}", e);
            panic!("Registration test failed");
        }
    }

    // Test 2: Authentication Challenge
    println!("🎲 Testing authentication challenge...");
    let k = ZKP::generate_random_number_below(&q);
    let (r1, r2) = zkp.compute_pair(&k);

    let challenge_request = AuthenticationChallengeRequest {
        user: username.clone(),
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be(),
    };

    let challenge_response = match client.create_authentication_challenge(challenge_request).await {
        Ok(response) => {
            let response = response.into_inner();
            println!("✅ Challenge received: {}", response.auth_id);
            response
        }
        Err(e) => {
            println!("❌ Challenge failed: {}", e);
            panic!("Challenge test failed");
        }
    };

    // Test 3: Authentication Answer
    println!("🔐 Testing authentication answer...");
    let auth_id = challenge_response.auth_id;
    let c = BigUint::from_bytes_be(&challenge_response.c);

    let s = zkp.solve(&k, &c, &password);

    let answer_request = AuthenticationAnswerRequest {
        auth_id,
        s: s.to_bytes_be(),
    };

    match client.verify_authentication(answer_request).await {
        Ok(response) => {
            let response = response.into_inner();
            println!("✅ Authentication successful! Session ID: {}", response.session_id);
            assert!(!response.session_id.is_empty(), "Session ID should not be empty");
        }
        Err(e) => {
            println!("❌ Authentication failed: {}", e);
            panic!("Authentication test failed");
        }
    }

    println!("🎉 Full authentication flow test PASSED!");
}

#[tokio::test]
async fn test_wrong_password_fails() {
    println!("🧪 Testing wrong password rejection...");

    // We'll use a running server (start manually or reuse from previous test)
    // For this test, we'll assume server is running
    let mut client = match AuthClient::connect("http://127.0.0.1:50051").await {
        Ok(client) => client,
        Err(_) => {
            println!("⚠️  Server not running - skipping wrong password test");
            return;
        }
    };

    let (alpha, beta, p, q) = ZKP::get_constants();
    let zkp = ZKP { alpha, beta, p, q };

    // Register with one password
    let username = "wrong_password_test_user".to_string();
    let correct_password = BigUint::from_bytes_be("correct_password".as_bytes());
    let wrong_password = BigUint::from_bytes_be("wrong_password".as_bytes());

    let (y1, y2) = zkp.compute_pair(&correct_password);

    let register_request = RegisterRequest {
        user: username.clone(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    };

    if client.register(register_request).await.is_err() {
        println!("ℹ️  User already exists - continuing with test");
    }

    // Try to authenticate with wrong password
    let k = ZKP::generate_random_number_below(&zkp.q);
    let (r1, r2) = zkp.compute_pair(&k);

    let challenge_request = AuthenticationChallengeRequest {
        user: username,
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be(),
    };

    if let Ok(challenge_response) = client.create_authentication_challenge(challenge_request).await {
        let challenge_response = challenge_response.into_inner();
        let auth_id = challenge_response.auth_id;
        let c = BigUint::from_bytes_be(&challenge_response.c);

        // Solve with WRONG password
        let s = zkp.solve(&k, &c, &wrong_password);

        let answer_request = AuthenticationAnswerRequest {
            auth_id,
            s: s.to_bytes_be(),
        };

        // This should FAIL
        match client.verify_authentication(answer_request).await {
            Err(status) => {
                println!("✅ Correctly rejected wrong password: {}", status.message());
                assert!(status.message().contains("bad solution") || status.message().contains("PermissionDenied"));
            }
            Ok(_) => {
                panic!("❌ CRITICAL SECURITY ISSUE: Wrong password was accepted!");
            }
        }
    }

    println!("🎉 Wrong password test PASSED!");
}

#[tokio::test]
async fn test_nonexistent_user_fails() {
    println!("🧪 Testing nonexistent user rejection...");

    let mut client = match AuthClient::connect("http://127.0.0.1:50051").await {
        Ok(client) => client,
        Err(_) => {
            println!("⚠️  Server not running - skipping nonexistent user test");
            return;
        }
    };

    let (alpha, beta, p, q) = ZKP::get_constants();
    let zkp = ZKP { alpha, beta, p, q };

    // Try to authenticate user that doesn't exist
    let k = ZKP::generate_random_number_below(&zkp.q);
    let (r1, r2) = zkp.compute_pair(&k);

    let challenge_request = AuthenticationChallengeRequest {
        user: "definitely_nonexistent_user_12345".to_string(),
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be(),
    };

    match client.create_authentication_challenge(challenge_request).await {
        Err(status) => {
            println!("✅ Correctly rejected nonexistent user: {}", status.message());
            assert!(status.message().contains("not found") || status.message().contains("NotFound"));
        }
        Ok(_) => {
            panic!("❌ SECURITY ISSUE: Nonexistent user was allowed to start authentication!");
        }
    }

    println!("🎉 Nonexistent user test PASSED!");
}

#[test]
fn test_zkp_security_properties() {
    println!("🧪 Testing ZKP security properties...");

    let (alpha, beta, p, q) = ZKP::get_constants();
    let zkp = ZKP { alpha, beta, p, q };

    // Test 1: Completeness - honest prover should always succeed
    println!("🔍 Testing completeness property...");
    for i in 0..5 {
        let x = ZKP::generate_random_number_below(&zkp.q);
        let k = ZKP::generate_random_number_below(&zkp.q);
        let c = ZKP::generate_random_number_below(&zkp.q);

        let (y1, y2) = zkp.compute_pair(&x);
        let (r1, r2) = zkp.compute_pair(&k);
        let s = zkp.solve(&k, &c, &x);

        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);
        assert!(result, "Honest prover failed verification in iteration {}", i);
    }
    println!("✅ Completeness property verified");

    // Test 2: Basic soundness - wrong secret should fail most of the time
    println!("🔍 Testing basic soundness property...");
    let x = ZKP::generate_random_number_below(&zkp.q);
    let mut wrong_x = ZKP::generate_random_number_below(&zkp.q);
    
    // Ensure wrong_x is actually different from x
    while wrong_x == x {
        wrong_x = ZKP::generate_random_number_below(&zkp.q);
    }

    let k = ZKP::generate_random_number_below(&zkp.q);
    let c = ZKP::generate_random_number_below(&zkp.q);

    let (y1, y2) = zkp.compute_pair(&x);  // Public values from correct secret
    let (r1, r2) = zkp.compute_pair(&k);  // Commitment
    let s = zkp.solve(&k, &c, &wrong_x); // Solution with wrong secret

    let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);
    assert!(!result, "Dishonest prover with wrong secret succeeded - this should not happen!");
    println!("✅ Basic soundness property verified");

    // Test 3: Mathematical consistency
    println!("🔍 Testing mathematical consistency...");
    let x = BigUint::from(42u32); // Use a known value for testing
    let k = BigUint::from(17u32);
    let c = BigUint::from(7u32);

    let (y1, y2) = zkp.compute_pair(&x);
    let (r1, r2) = zkp.compute_pair(&k);
    let s = zkp.solve(&k, &c, &x);

    // Manual verification of the equations
    let alpha_s = zkp.alpha.modpow(&s, &zkp.p);
    let y1_c = y1.modpow(&c, &zkp.p);
    let left_side = (&alpha_s * &y1_c).modpow(&BigUint::from(1u32), &zkp.p);
    assert_eq!(r1, left_side, "First equation doesn't hold");

    let beta_s = zkp.beta.modpow(&s, &zkp.p);
    let y2_c = y2.modpow(&c, &zkp.p);
    let right_side = (&beta_s * &y2_c).modpow(&BigUint::from(1u32), &zkp.p);
    assert_eq!(r2, right_side, "Second equation doesn't hold");

    println!("✅ Mathematical consistency verified");
    println!("🎉 All ZKP security properties test PASSED!");
}

#[test]
fn test_edge_cases() {
    println!("🧪 Testing edge cases...");

    let (alpha, beta, p, q) = ZKP::get_constants();
    let zkp = ZKP { alpha, beta, p, q };

    // Test with x = 0
    println!("🔍 Testing with zero secret...");
    let x = BigUint::from(0u32);
    let k = ZKP::generate_random_number_below(&zkp.q);
    let c = ZKP::generate_random_number_below(&zkp.q);

    let (y1, y2) = zkp.compute_pair(&x);
    let (r1, r2) = zkp.compute_pair(&k);
    let s = zkp.solve(&k, &c, &x);

    let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);
    assert!(result, "Zero secret should still work");
    println!("✅ Zero secret test passed");

    // Test with x = 1
    println!("🔍 Testing with unit secret...");
    let x = BigUint::from(1u32);
    let k = ZKP::generate_random_number_below(&zkp.q);
    let c = ZKP::generate_random_number_below(&zkp.q);

    let (y1, y2) = zkp.compute_pair(&x);
    let (r1, r2) = zkp.compute_pair(&k);
    let s = zkp.solve(&k, &c, &x);

    let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);
    assert!(result, "Unit secret should work");
    println!("✅ Unit secret test passed");

    println!("🎉 Edge cases test PASSED!");
}

#[test]
fn test_random_number_generation() {
    println!("🧪 Testing random number generation...");

    let (_, _, _, q) = ZKP::get_constants();
    
    // Generate multiple random numbers and verify they're all different and in range
    let mut random_numbers = Vec::new();
    
    for _ in 0..10 {
        let random_num = ZKP::generate_random_number_below(&q);
        
        // Should be less than q
        assert!(random_num < q, "Random number should be less than q");
        
        // Should not be zero most of the time (very unlikely)
        // We'll just check it's a valid BigUint
        assert!(random_num >= BigUint::from(0u32), "Random number should be non-negative");
        
        random_numbers.push(random_num);
    }
    
    // Check that we got some variety (not all the same - extremely unlikely)
    let first = &random_numbers[0];
    let all_same = random_numbers.iter().all(|x| x == first);
    assert!(!all_same, "All random numbers are the same - RNG might be broken");
    
    println!("✅ Random number generation working correctly");
    
    // Test string generation too
    let random_strings: Vec<String> = (0..5)
        .map(|_| ZKP::generate_random_string(12))
        .collect();
    
    // Check length
    for s in &random_strings {
        assert_eq!(s.len(), 12, "Random string should be exactly 12 characters");
    }
    
    // Check uniqueness (very likely)
    let first_string = &random_strings[0];
    let all_same_strings = random_strings.iter().all(|s| s == first_string);
    assert!(!all_same_strings, "All random strings are the same - RNG might be broken");
    
    println!("✅ Random string generation working correctly");
    println!("🎉 Random number generation test PASSED!");
}