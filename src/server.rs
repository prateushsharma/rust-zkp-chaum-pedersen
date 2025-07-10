// src/server.rs

// Standard library imports for data structures and thread safety
use std::{collections::HashMap, sync::Mutex};

// External crate imports
use num_bigint::BigUint;
use tonic::{transport::Server, Code, Request, Response, Status};

// Import our ZKP library (note: dashes in Cargo.toml become underscores in code)
use rust_zkp_chaum_pedersen::ZKP;

// Import the generated gRPC code (this file is created by build.rs from our .proto file)
pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

// Import specific message types and server traits from the generated code
use zkp_auth::{
    auth_server::{Auth, AuthServer},
    RegisterRequest, RegisterResponse,
    AuthenticationChallengeRequest, AuthenticationChallengeResponse,
    AuthenticationAnswerRequest, AuthenticationAnswerResponse,
};

// Main server struct that implements the authentication service
// Debug allows us to print the struct, Default provides default values
#[derive(Debug, Default)]
pub struct AuthImpl {
    // Thread-safe storage for user information
    // Mutex ensures only one thread can access the HashMap at a time
    pub user_info: Mutex<HashMap<String, UserInfo>>,
}

// Struct to store all information related to a user
#[derive(Debug, Default)]
pub struct UserInfo {
    // Registration data
    pub user_name: String,  // The username
    pub y1: BigUint,       // y1 = alpha^x mod p (public value derived from user's secret)
    pub y2: BigUint,       // y2 = beta^x mod p (public value derived from user's secret)
    
    // Note: Authentication fields will be added in Lecture 4
    // pub r1: BigUint,      // Challenge request values
    // pub r2: BigUint,      // Challenge request values  
    // pub c: BigUint,       // Challenge from server
    // pub s: BigUint,       // Solution to challenge
    // pub session_id: String, // Session ID for successful authentication
}

// Implementation of the Auth trait for our server
// This tells Rust that AuthImpl can handle Auth service requests
#[tonic::async_trait]
impl Auth for AuthImpl {
    
    // Handle user registration requests
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        
        // Extract the actual request data from the gRPC wrapper
        let request = request.into_inner();
        
        // Get username from the request
        let user_name = request.user;
        println!("Processing Registration for username: {:?}", user_name);
        
        // Create user info struct with the registration data
        let user_info = UserInfo {
            user_name: user_name.clone(),
            // Convert byte arrays from protobuf back to BigUint numbers
            y1: BigUint::from_bytes_be(&request.y1),
            y2: BigUint::from_bytes_be(&request.y2),
            // Use default values for other fields
            ..Default::default()
        };
        
        // Lock the user storage HashMap and insert the new user
        // The lock is automatically released when this variable goes out of scope
        let user_info_hashmap = &mut self.user_info.lock().unwrap();
        user_info_hashmap.insert(user_name.clone(), user_info);
        
        println!("Successful Registration for username: {:?}", user_name);
        
        // Return successful response (RegisterResponse is empty for now)
        Ok(Response::new(RegisterResponse {}))
    }
    
    // Placeholder method for authentication challenges
    // Will be implemented properly in Lecture 4
    async fn create_authentication_challenge(
        &self,
        _request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        println!("create_authentication_challenge called (placeholder)");
        
        // Return "not implemented" error for now
        Err(Status::new(
            Code::Unimplemented,
            "Authentication challenge not implemented yet. Coming in Lecture 4!".to_string(),
        ))
    }
    
    // Placeholder method for authentication verification
    // Will be implemented properly in Lecture 4
    async fn verify_authentication(
        &self,
        _request: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        println!("verify_authentication called (placeholder)");
        
        // Return "not implemented" error for now
        Err(Status::new(
            Code::Unimplemented,
            "Authentication verification not implemented yet. Coming in Lecture 4!".to_string(),
        ))
    }
}

// Main function - entry point for our server application
#[tokio::main]
async fn main() {
    // Define the network address our server will listen on
    let addr = "127.0.0.1:5005".to_string();
    
    println!("Starting ZKP Authentication Server on {}", addr);
    
    // Create an instance of our server implementation
    let auth_impl = AuthImpl::default();
    
    // Build and start the gRPC server
    Server::builder()
        .add_service(AuthServer::new(auth_impl))  // Wrap our implementation
        .serve(addr.parse().expect("Could not parse address"))  // Start listening
        .await  // Wait for the server (it runs forever)
        .unwrap();  // Panic if server fails to start
}