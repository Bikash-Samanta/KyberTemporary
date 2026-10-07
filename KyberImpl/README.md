# Kyber (ML-KEM) Client-Server Demonstration

This project demonstrates a real-world network handshake using Post-Quantum Cryptography (PQC). It implements a TCP-based Client and Server that establish a secure 32-byte shared symmetric key over a network using the **Kyber (ML-KEM)** Key Encapsulation Mechanism.

Everything is written in modern **C++26**.

## Prerequisites
* A modern C++ compiler supporting C++26 (e.g., GCC 14+ or Clang 17+).
* A POSIX-compliant operating system (Linux / macOS).

## Compilation

To compile the server and client... run the following commands in your terminal:

```bash
# Compile the Server
g++ -std=c++26 -O3 server.cpp -o server

# Compile the Client
g++ -std=c++26 -O3 client.cpp -o client