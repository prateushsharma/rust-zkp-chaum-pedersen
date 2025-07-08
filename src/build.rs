fn main() {
    // Configure the tonic build system
    tonic_build::configure()
        .build_server(true)           // Generate server-side code
        .out_dir("src/")             // Put generated code in src/ directory
        .compile(
            &["proto/zkp_auth.proto"], // Our proto file to compile
            &["proto/"],               // Where to look for proto files
        )
        .unwrap();
}

/*
 * WHAT THIS DOES:
 * 
 * When you run `cargo build`, this script runs FIRST and:
 * 1. Reads our zkp_auth.proto file
 * 2. Generates Rust structs for all our messages
 * 3. Generates client code to call the service
 * 4. Generates server code to implement the service
 * 5. Saves everything as src/zkp_auth.rs
 * 
 * The generated file contains:
 * - RegisterRequest, RegisterResponse structs
 * - AuthenticationChallengeRequest, AuthenticationChallengeResponse structs  
 * - AuthenticationAnswerRequest, AuthenticationAnswerResponse structs
 * - AuthClient (for making calls to server)
 * - Auth trait (for implementing server)
 */