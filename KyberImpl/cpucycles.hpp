#pragma once

#include <algorithm>
#include <cstdint>
#include <limits>

#if defined(USE_RDPMC)

[[nodiscard]] inline uint64_t cpucycles() noexcept {
    const uint32_t ecx = (1U << 30) + 1;
    uint64_t result;

    __asm__ volatile (
        "rdpmc\n\t"
        "shlq $32, %%rdx\n\t"
        "orq %%rdx, %%rax"
        : "=a"(result)
        : "c"(ecx)
        : "rdx"
    );

    return result;
}

#else

[[nodiscard]] inline uint64_t cpucycles() noexcept {
    uint64_t result;

    __asm__ volatile (
        "rdtsc\n\t"
        "shlq $32, %%rdx\n\t"
        "orq %%rdx, %%rax"
        : "=a"(result)
        :
        : "rdx"
    );

    return result;
}

#endif

[[nodiscard]] inline uint64_t cpucycles_overhead() noexcept 
{
    constexpr size_t iterations = 100'000;
    uint64_t overhead = std::numeric_limits<uint64_t>::max();

    for (size_t i = 0; i < iterations; ++i) {
        const uint64_t t0 = cpucycles();
        __asm__ volatile ("" ::: "memory");
        const uint64_t t1 = cpucycles();

        overhead = std::min(overhead, t1 - t0);
    }

    return overhead;
}