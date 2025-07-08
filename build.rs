fn main() {
    println!("cargo:warning=🚀 Build script is running!");
    
    tonic_build::configure()
        .build_server(true)
        .out_dir("src/")
        .compile(
            &["proto/zkp_auth.proto"],
            &["proto/"],
        )
        .unwrap_or_else(|e| panic!("Failed to compile protos: {}", e));
    
    println!("cargo:warning=✅ Proto compilation completed!");
}