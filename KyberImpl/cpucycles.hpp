#ifndef CPUCYCLES_HPP
#define CPUCYCLES_HPP

#include <cstdint>

// ==========================================
// CPU Cycle Counting Functions (Header-Only)
// ==========================================

#ifdef USE_RDPMC  /* Needs echo 2 > /sys/devices/cpu/rdpmc */
static inline uint64_t cpucycles(void) {
    const uint32_t ecx = (1U << 30) + 1;
    uint64_t result;
    __asm__ volatile ("rdpmc; shlq $32,%%rdx; orq %%rdx,%%rax"
      : "=a" (result) : "c" (ecx) : "rdx");
    return result;
}
#else
static inline uint64_t cpucycles(void) {
    uint64_t result;
    __asm__ volatile ("rdtsc; shlq $32,%%rdx; orq %%rdx,%%rax"
      : "=a" (result) : : "%rdx");
    return result;
}
#endif

// Marked as inline so it can be defined entirely in the header
// without causing multiple-definition linker errors.
inline uint64_t cpucycles_overhead(void) {
    uint64_t t0, t1, overhead = -1LL; // -1LL acts as max uint64_t value
    unsigned int i;

    for(i = 0; i < 100000; i++) {
        t0 = cpucycles();
        __asm__ volatile (""); // Prevent compiler from optimizing the loop out
        t1 = cpucycles();
        if(t1 - t0 < overhead) {
            overhead = t1 - t0;
        }
    }

    return overhead;
}

#endif // CPUCYCLES_HPP