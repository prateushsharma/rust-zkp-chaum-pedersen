# 🔐 Zero-Knowledge Proof Authentication System

A complete implementation of the **Chaum-Pedersen Zero-Knowledge Proof protocol** using Rust and gRPC for secure password-less authentication.

## 📋 Table of Contents

- [🧮 Mathematical Foundation](#-mathematical-foundation)
- [🛠️ Installation & Setup](#️-installation--setup)
- [🏗️ Project Structure](#️-project-structure)
- [🔬 How Zero-Knowledge Proofs Work](#-how-zero-knowledge-proofs-work)
- [🔄 Authentication Flow](#-authentication-flow)
- [💻 Technical Implementation](#-technical-implementation)
- [🚀 Getting Started](#-getting-started)

---

## 🧮 Mathematical Foundation

### **What is Zero-Knowledge Proof?**

A Zero-Knowledge Proof allows you to **prove you know a secret without revealing the secret itself**.

**Real-world analogy**: Imagine proving you know the password to a door by demonstrating you can unlock it, but without ever saying or showing the password.

### **The Chaum-Pedersen Protocol**

Our system uses the **Chaum-Pedersen protocol**, which works with these mathematical components:

#### **Setup Phase (Public Parameters)**
Everyone agrees on these public values:
- **`p`**: A large prime number (our "universe" of numbers)
- **`q`**: A smaller prime number (defines the group size)
- **`α` (alpha)**: First generator (like a "base" for exponentiation)
- **`β` (beta)**: Second generator (α^i mod p for some secret i)

```
Example with small numbers:
p = 23 (large prime)
q = 11 (smaller prime)  
α = 4  (first generator)
β = 9  (second generator)
```

#### **User Registration (One-time Setup)**
When you create an account:

1. **Choose secret password**: `x` (this never leaves your device!)
2. **Compute commitments**:
   - `y1 = α^x mod p`  (commitment using first generator)
   - `y2 = β^x mod p`  (commitment using second generator)
3. **Send to server**: `(username, y1, y2)` - Note: `x` is never sent!

```
Example:
Your secret: x = 6
Compute: y1 = 4^6 mod 23 = 2
Compute: y2 = 9^6 mod 23 = 3
Send to server: ("alice", 2, 3)
```

#### **Authentication Process (Every Login)**

**Step 1: Challenge Setup**
1. **Client picks random number**: `k` 
2. **Computes challenge values**:
   - `r1 = α^k mod p`
   - `r2 = β^k mod p`
3. **Sends to server**: `(username, r1, r2)`

**Step 2: Server Challenge**
1. **Server picks random challenge**: `c`
2. **Sends back**: `c`

**Step 3: Client Response**
1. **Client computes solution**: `s = k - c × x mod q`
2. **Sends to server**: `s`

**Step 4: Server Verification**
Server checks if both equations hold:
- `α^s × y1^c mod p == r1` ✓
- `β^s × y2^c mod p == r2` ✓

If both are true → Authentication successful! 🎉

```
Example with x=6, k=7, c=4:
s = (7 - 4×6) mod 11 = (7 - 24) mod 11 = 5

Verification:
α^s × y1^c = 4^5 × 2^4 mod 23 = 1024 × 16 mod 23 = 8 ✓ (equals r1)
β^s × y2^c = 9^5 × 3^4 mod 23 = 59049 × 81 mod 23 = 4 ✓ (equals r2)
```

### **Why This Works (The Magic!)**

The mathematics ensures:
- **Completeness**: If you know the secret `x`, you can always prove it
- **Soundness**: If you don't know `x`, you can't convince the verifier (except with negligible probability)
- **Zero-Knowledge**: The verifier learns nothing about `x` from the interaction

---

## 🛠️ Installation & Setup

### **Prerequisites**

#### **1. Install Rust**
```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Verify installation
rustc --version
cargo --version
```

#### **2. Install C Compiler (Required for cryptographic libraries)**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install build-essential

# macOS
xcode-select --install
# Or with Homebrew
brew install gcc

# Verify installation
gcc --version
```

**Why do we need this?**
- Many Rust cryptographic crates use C libraries for performance
- `num-bigint`, `tonic`, and crypto libraries need to compile C code
- The error `linker 'cc' not found` means this is missing

#### **3. Install Protocol Buffer Compiler**
```bash
# Ubuntu/Debian
sudo apt install protobuf-compiler

# macOS
brew install protobuf

# Windows (with Chocolatey)
choco install protoc

# Verify installation
protoc --version
```

**Why do we need this?**
- Protocol Buffers define our client-server communication format
- The `protoc` compiler converts `.proto` files to Rust code
- gRPC uses Protocol Buffers for efficient, type-safe communication

---

## 🏗️ Project Structure

```
rust-zkp-chaum-pedersen/
├── src/
│   ├── lib.rs              # ZKP mathematical implementation
│   ├── server.rs           # gRPC server (Lecture 3)
│   ├── client.rs           # gRPC client (Lecture 5) 
│   └── zkp_auth.rs         # Generated from proto (auto-created)
├── proto/
│   └── zkp_auth.proto      # gRPC service definitions
├── build.rs                # Code generation script
├── Cargo.toml              # Dependencies and project config
├── Cargo.lock              # Dependency lock file (auto-generated)
└── README.md               # This file!
```

### **Key Files Explained**

**`src/lib.rs`** - Core cryptographic implementation:
- `ZKP` struct with mathematical operations
- `compute_pair()` - Computes (α^exp mod p, β^exp mod p)
- `solve()` - Generates the proof solution s = k - c×x mod q
- `verify()` - Checks if the proof is valid
- Constant generation for secure parameters

**`proto/zkp_auth.proto`** - Communication protocol:
- Defines message formats (RegisterRequest, ChallengeRequest, etc.)
- Defines the Auth service with 3 endpoints
- Language-agnostic specification

**`build.rs`** - Code generation:
- Runs during `cargo build`
- Converts `.proto` files to Rust code
- Creates client and server boilerplate

**`Cargo.toml`** - Dependencies:
```toml
[dependencies]
rand = "0.8"                    # Random number generation
num-bigint = "0.4"              # Large integer arithmetic
hex = "0.4.3"                   # Hexadecimal encoding/decoding
tonic = "0.11"                  # gRPC framework
prost = "0.12"                  # Protocol Buffer implementation
tokio = "1.0"                   # Async runtime

[build-dependencies]
tonic-build = "0.11"            # Proto file compiler
```

---

## 🔬 How Zero-Knowledge Proofs Work

### **The Three Properties**

1. **Completeness**: If the statement is true, an honest prover can convince an honest verifier
2. **Soundness**: If the statement is false, no cheating prover can convince an honest verifier (except with negligible probability)
3. **Zero-Knowledge**: If the statement is true, the verifier learns nothing other than this fact

### **Interactive vs Non-Interactive**

Our implementation uses **Interactive ZKP**:
- Multiple rounds of communication
- Server sends fresh random challenges
- Prevents replay attacks

### **Why Chaum-Pedersen?**

- **Efficient**: Only requires modular exponentiation
- **Proven secure**: Based on discrete logarithm assumption
- **Practical**: Works well with modern computers
- **Flexible**: Can be made non-interactive with Fiat-Shamir transform

---

## 🔄 Authentication Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    
    Note over C,S: Registration (One-time)
    C->>C: Choose secret x
    C->>C: Compute y1=α^x mod p, y2=β^x mod p
    C->>S: RegisterRequest(username, y1, y2)
    S->>S: Store (username → y1, y2)
    S->>C: RegisterResponse()
    
    Note over C,S: Authentication (Every login)
    C->>C: Pick random k
    C->>C: Compute r1=α^k mod p, r2=β^k mod p
    C->>S: ChallengeRequest(username, r1, r2)
    S->>S: Pick random challenge c
    S->>C: ChallengeResponse(auth_id, c)
    C->>C: Compute s = k - c×x mod q
    C->>S: AnswerRequest(auth_id, s)
    S->>S: Verify: α^s × y1^c ?= r1 and β^s × y2^c ?= r2
    S->>C: AnswerResponse(session_id) or Error
```

---

## 💻 Technical Implementation

### **Rust Language Features Used**

1. **Async/Await**: For handling multiple concurrent connections
2. **Traits**: `Auth` trait defines server behavior
3. **Generics**: Type-safe BigUint operations
4. **Error Handling**: `Result<T, E>` for graceful error management
5. **Memory Safety**: No buffer overflows or memory leaks
6. **Concurrency**: `Mutex` for thread-safe data sharing

### **Cryptographic Libraries**

- **`num-bigint`**: Arbitrary precision arithmetic for large numbers
- **`rand`**: Cryptographically secure random number generation
- **`hex`**: Converting between binary and hexadecimal

### **Networking Libraries**

- **`tonic`**: High-performance gRPC implementation
- **`prost`**: Fast Protocol Buffer serialization
- **`tokio`**: Async runtime for handling thousands of connections

---

## 🚀 Getting Started

### **Current Progress** ✅

After completing **Lectures 1-2**, you have:

- [x] **Mathematical foundation** implemented in `src/lib.rs`
- [x] **Protocol definitions** in `proto/zkp_auth.proto`
- [x] **Code generation** working via `build.rs`
- [x] **Dependencies** properly configured
- [x] **Generated gRPC code** in `src/zkp_auth.rs`

### **Test Current Setup**

```bash
# Verify everything builds
cargo build

# Run the mathematical tests
cargo test

# Check generated file exists
ls -la src/zkp_auth.rs

# See the generated types
head -20 src/zkp_auth.rs
```

### **Next Steps** 🎯

**Lecture 3**: Build the gRPC server
- Implement user registration
- Handle concurrent users safely
- Store authentication data

**Lecture 4**: Complete authentication flow
- Challenge-response implementation
- Session management
- Security validation

**Lecture 5**: Build the client
- User interface
- Network communication
- Error handling

---

## 🤓 Fun Facts

- **RSA vs ECC vs ZKP**: ZKP doesn't rely on factoring or elliptic curves, but on discrete logarithms
- **Quantum Resistance**: Some ZKP schemes are being researched for post-quantum cryptography
- **Applications**: Used in blockchain (zk-SNARKs), privacy-preserving authentication, and anonymous credentials
- **Performance**: Modern ZKP can verify in milliseconds even for complex statements

---

## 🔗 References

- [Chaum-Pedersen Protocol Paper](https://link.springer.com/chapter/10.1007/3-540-46766-1_9)
- [Zero-Knowledge Proofs: An Introduction](https://blog.cryptographyengineering.com/2014/11/27/zero-knowledge-proofs-illustrated-primer/)
- [RFC 5114 - Discrete Log Parameters](https://tools.ietf.org/rfc/rfc5114.txt)
- [Rust gRPC Tutorial](https://github.com/hyperium/tonic)

---

**Ready for Lecture 3? Let's build the server!** 🚀