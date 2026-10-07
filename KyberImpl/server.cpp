/*
[akaza@akaza KyberImpl]$ ./server
[SYSTEM] Starting Kyber KEM Server...
[NETWORK] Listening for client connections on port 8080...
[NETWORK] Client connected from 127.0.0.1:46656
[CRYPTO]  Generating Kyber-768 Keypair...
          Public Key:  98A709FC...8EEF633B
          Secret Key:  2313405A...26993B32
[HANDSHAKE] -> Sending Public Key (1184 bytes)...
[HANDSHAKE] <- Waiting for Client Ciphertext...
[HANDSHAKE] <- Received Ciphertext (1088 bytes): C87AE79A...566B5508
[CRYPTO]  Decapsulating shared secret from ciphertext...
[SUCCESS] FINAL SHARED SECRET: [F2C7DD0A...A1EF3889]
*/

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <format>
#include <print>
#include <span>
#include <string>

#include "kyber_kem.hpp"
#include "params.hpp"

constexpr int PORT = 8080;


[[nodiscard]] static std::string fingerprint(std::span<const uint8_t> data) 
{
    if (data.size() < 8) return "[Too short]";
    return std::format("{:02X}{:02X}{:02X}{:02X}...{:02X}{:02X}{:02X}{:02X}",
        data[0], data[1], data[2], data[3],
        data[data.size()-4], data[data.size()-3], data[data.size()-2], data[data.size()-1]);
}

[[nodiscard]] static bool send_exact(int fd, std::span<const uint8_t> data) 
{
    size_t total_sent = 0;
    while (total_sent < data.size()) {
        ssize_t sent = ::send(fd, data.data() + total_sent, data.size() - total_sent, 0);
        if (sent <= 0) return false;
        total_sent += static_cast<size_t>(sent);
    }
    return true;
}

[[nodiscard]] static bool recv_exact(int fd, std::span<uint8_t> data) 
{
    size_t total_recv = 0;
    while (total_recv < data.size()) {
        ssize_t received = ::recv(fd, data.data() + total_recv, data.size() - total_recv, 0);
        if (received <= 0) return false;
        total_recv += static_cast<size_t>(received);
    }
    return true;
}

int main() 
{
    std::println("[SYSTEM] Starting Kyber KEM Server...");
    
    int server_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::println(stderr, "[ERROR] Failed to create socket");
        return 1;
    }

    int opt = 1;
    ::setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (::bind(server_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
        std::println(stderr, "[ERROR] Bind failed on port {}", PORT);
        ::close(server_fd);
        return 1;
    }

    if (::listen(server_fd, 1) < 0) {
        std::println(stderr, "[ERROR] Listen failed");
        ::close(server_fd);
        return 1;
    }

    std::println("[NETWORK] Listening for client connections on port {}...", PORT);

    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int client_fd = ::accept(server_fd, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
    if (client_fd < 0) {
        std::println(stderr, "[ERROR] Accept failed");
        ::close(server_fd);
        return 1;
    }

    char client_ip[INET_ADDRSTRLEN];
    ::inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    std::println("[NETWORK] Client connected from {}:{}", client_ip, ntohs(client_addr.sin_port));

    // Key Generation
    std::println("[CRYPTO]  Generating Kyber-{} Keypair...", KYBER_K * 256);
    std::array<uint8_t, KYBER_PUBLICKEYBYTES> pk{};
    std::array<uint8_t, KYBER_SECRETKEYBYTES> sk{};
    kyber_kem_keypair(pk, sk);
    std::println("          Public Key:  {}", fingerprint(pk));
    std::println("          Secret Key:  {}", fingerprint(sk));

    // Transmit Public Key
    std::println("[HANDSHAKE] -> Sending Public Key ({} bytes)...", pk.size());
    if (!send_exact(client_fd, pk)) {
        std::println(stderr, "[ERROR] Failed to send public key to client");
        ::close(client_fd);
        ::close(server_fd);
        return 1;
    }

    // Receive Ciphertext
    std::println("[HANDSHAKE] <- Waiting for Client Ciphertext...");
    std::array<uint8_t, KYBER_CIPHERTEXTBYTES> ct{};
    if (!recv_exact(client_fd, ct)) {
        std::println(stderr, "[ERROR] Failed to receive ciphertext from client");
        ::close(client_fd);
        ::close(server_fd);
        return 1;
    }
    std::println("[HANDSHAKE] <- Received Ciphertext ({} bytes): {}", ct.size(), fingerprint(ct));

    // Decapsulation
    std::println("[CRYPTO]  Decapsulating shared secret from ciphertext...");
    std::array<uint8_t, KYBER_SSBYTES> shared_secret{};
    kyber_kem_dec(shared_secret, ct, sk);

    std::println("[SUCCESS] FINAL SHARED SECRET: [{}]", fingerprint(shared_secret));

    ::close(client_fd);
    ::close(server_fd);
    return 0;
}