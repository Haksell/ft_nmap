#include "ft_nmap.h"

// TODO: different seeds for different threads (_Thread_local)
uint32_t random_u32(void) {
    static uint32_t x = 1053820; // TODO: Lorenzo true seed

    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return (x);
}

uint32_t random_u32_range(uint32_t a, uint32_t b) {
    return (a + random_u32() % (b - a));
}