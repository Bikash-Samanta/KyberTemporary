/*
[akaza@akaza KyberImpl]$ ./client
[SYSTEM] Starting Kyber KEM Client...
[NETWORK] Connecting to 127.0.0.1:8080...
[NETWORK] Connected successfully.
[HANDSHAKE] <- Waiting for Server Public Key...
[HANDSHAKE] <- Received Public Key (1184 bytes): 98A709FC...8EEF633B
[CRYPTO]  Encapsulating shared secret against Server Public Key...
          Derived Secret: F2C7DD0A...A1EF3889
          Ciphertext:     C87AE79A...566B5508
[HANDSHAKE] -> Sending Ciphertext (1088 bytes)...
[SUCCESS] FINAL SHARED SECRET: [F2C7DD0A...A1EF3889]
[akaza@akaza KyberImpl]$ 
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

constexpr const char* SERVER_IP = "127.0.0.1";
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
    std::println("[SYSTEM] Starting Kyber KEM Client...");
    
    int sock_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        std::println(stderr, "[ERROR] Failed to create socket");
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if (::inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        std::println(stderr, "[ERROR] Invalid server IP address");
        ::close(sock_fd);
        return 1;
    }

    std::println("[NETWORK] Connecting to {}:{}...", SERVER_IP, PORT);
    if (::connect(sock_fd, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        std::println(stderr, "[ERROR] Connection to server failed");
        ::close(sock_fd);
        return 1;
    }
    std::println("[NETWORK] Connected successfully.");

    // Receive Public Key
    std::println("[HANDSHAKE] <- Waiting for Server Public Key...");
    std::array<uint8_t, KYBER_PUBLICKEYBYTES> pk{};
    if (!recv_exact(sock_fd, pk)) {
        std::println(stderr, "[ERROR] Failed to receive public key");
        ::close(sock_fd);
        return 1;
    }
    std::println("[HANDSHAKE] <- Received Public Key ({} bytes): {}", pk.size(), fingerprint(pk));

    // Encapsulation
    std::println("[CRYPTO]  Encapsulating shared secret against Server Public Key...");
    std::array<uint8_t, KYBER_CIPHERTEXTBYTES> ct{};
    std::array<uint8_t, KYBER_SSBYTES> shared_secret{};
    kyber_kem_enc(ct, shared_secret, pk);
    std::println("          Derived Secret: {}", fingerprint(shared_secret));
    std::println("          Ciphertext:     {}", fingerprint(ct));

    // Transmit Ciphertext
    std::println("[HANDSHAKE] -> Sending Ciphertext ({} bytes)...", ct.size());
    if (!send_exact(sock_fd, ct)) {
        std::println(stderr, "[ERROR] Failed to send ciphertext");
        ::close(sock_fd);
        return 1;
    }

    std::println("[SUCCESS] FINAL SHARED SECRET: [{}]", fingerprint(shared_secret));

    ::close(sock_fd);
    return 0;
}