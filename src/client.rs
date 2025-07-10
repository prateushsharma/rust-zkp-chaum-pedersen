use num_bigint::BigUint;
use std::io::stdin;

// Import our generated gRPC code
pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

// Import the specific types we need from the generated code
use zkp_auth::{
    auth_client::AuthClient,           // The client to connect to our server
    AuthenticationAnswerRequest,       // Request to send our solution
    AuthenticationChallengeRequest,    // Request to ask for a challenge
    RegisterRequest,                   // Request to register a new user
};

// Import our ZKP library
use rust_zkp_chaum_pedersen::ZKP;

#[tokio::main]  // This makes our main function async
async fn main() {
    // Buffer to store user input
    let mut buf = String::new();
    
    // Get the mathematical constants for our ZKP protocol
    let (alpha, beta, p, q) = ZKP::get_constants();
    
    // Create a ZKP instance with these constants
    let zkp = ZKP {
        alpha: alpha.clone(),
        beta: beta.clone(),
        p: p.clone(),
        q: q.clone(),
    };

    // Step 1: Connect to the server
    println!("🔌 Connecting to ZKP Authentication Server...");
    let mut client = AuthClient::connect("http://127.0.0.1:5005")
        .await
        .expect("❌ Could not connect to the server");
    println!("✅ Connected to the server successfully!");

    // Step 2: Get username from user
    println!("\n📝 === REGISTRATION PHASE ===");
    println!("Please provide your username:");
    stdin()
        .read_line(&mut buf)
        .expect("❌ Could not read username from input");
    let username = buf.trim().to_string();
    buf.clear(); // Clear buffer for next input

    // Step 3: Get password from user for registration
    println!("Please provide your password:");
    stdin()
        .read_line(&mut buf)
        .expect("❌ Could not read password from input");
    
    // Convert password string to BigUint (this is our secret 'x')
    let password = BigUint::from_bytes_be(buf.trim().as_bytes());
    buf.clear();

    // Step 4: Generate registration values (y1, y2)
    println!("🔐 Generating registration proof...");
    let (y1, y2) = zkp.compute_pair(&password);
    
    // What's happening here:
    // y1 = alpha^password mod p
    // y2 = beta^password mod p
    // These are our "public commitments" - they prove we know the password
    // without revealing what the password actually is!

    // Step 5: Send registration request to server
    let register_request = RegisterRequest {
        user: username.clone(),
        y1: y1.to_bytes_be(),  // Convert BigUint to bytes for network transmission
        y2: y2.to_bytes_be(),
    };

    let _response = client
        .register(register_request)
        .await
        .expect("❌ Could not register with server");

    println!("✅ Registration was successful!");

    // Step 6: Now let's authenticate (login)
    println!("\n🔐 === AUTHENTICATION PHASE ===");
    println!("Please provide your password again (to login):");
    stdin()
        .read_line(&mut buf)
        .expect("❌ Could not read password from input");
    let login_password = BigUint::from_bytes_be(buf.trim().as_bytes());
    buf.clear();

    // Step 7: Generate random number 'k' for this authentication session
    println!("🎲 Generating random challenge values...");
    let k = ZKP::generate_random_number_below(&q);
    
    // Step 8: Compute commitment values for this session
    let (r1, r2) = zkp.compute_pair(&k);
    
    // What's happening:
    // r1 = alpha^k mod p
    // r2 = beta^k mod p
    // These are our "session commitments" - they start the authentication

    // Step 9: Send authentication challenge request
    let challenge_request = AuthenticationChallengeRequest {
        user: username.clone(),
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be(),
    };

    println!("📤 Sending authentication challenge request...");
    let challenge_response = client
        .create_authentication_challenge(challenge_request)
        .await
        .expect("❌ Could not request challenge from server")
        .into_inner();

    // Step 10: Extract challenge from server response
    let auth_id = challenge_response.auth_id;
    let c = BigUint::from_bytes_be(&challenge_response.c);
    
    println!("📥 Received challenge from server (auth_id: {})", auth_id);

    // Step 11: Solve the challenge
    println!("🧮 Solving the authentication challenge...");
    let s = zkp.solve(&k, &c, &login_password);
    
    // What's happening:
    // s = k - c * password mod q
    // This is our "proof" that we know the password without revealing it!
    // The server can verify this using our public commitments (y1, y2) and (r1, r2)

    // Step 12: Send our solution back to the server
    let answer_request = AuthenticationAnswerRequest {
        auth_id,
        s: s.to_bytes_be(),
    };

    println!("📤 Sending authentication solution...");
    let auth_response = client
        .verify_authentication(answer_request)
        .await
        .expect("❌ Could not verify authentication with server")
        .into_inner();

    // Step 13: Success! We're authenticated
    println!("🎉 Authentication successful!");
    println!("✅ Logged in! Session ID: {}", auth_response.session_id);
    println!("\n🔐 Zero-Knowledge Proof authentication completed!");
    println!("   → You proved you know the password without revealing it!");
    println!("   → The server verified your proof cryptographically!");
}