#include "ft_nmap.h"

static uint32_t random_u32() {
    static uint32_t x = 0;
    static bool init = false;

    if (!init) {
        x = (uint32_t)time(NULL);
        init = true;
    }

    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
}

uint32_t random_u32_range(uint32_t a, uint32_t b) {
    if (a == b) return a;
    if (a > b) {
        uint32_t tmp = a;
        a = b;
        b = tmp;
    }
    return a + random_u32() % (b - a);
}
