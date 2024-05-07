
#pragma once

#include "ft_nmap.h"

#define MAX_PAYLOAD_SIZE 512

typedef struct {
    size_t rarity;
    size_t payload_start;
    size_t payload_end;
    size_t port_ranges_start;
    size_t port_ranges_end;
} t_probe;

#define SENTINEL_RARITY 10
#define SENTINEL_PROBE ((t_probe){SENTINEL_RARITY, 0, 0, 0, 0})

static const uint8_t concatenated_payloads[] = {
    114, 254, 29,  19,  0,   0,   0,   0,   0,   0,   0,   2,   0,   1,   134, 160, 0,   1,   151, 124, 0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   6,   1,   0,   0,   1,
    0,   0,   0,   0,   0,   0,   7,   118, 101, 114, 115, 105, 111, 110, 4,   98,  105, 110, 100, 0,   0,   16,  0,
    3,   0,   0,   16,  0,   0,   0,   0,   0,   0,   0,   0,   0,   128, 240, 0,   16,  0,   1,   0,   0,   0,   0,
    0,   0,   32,  67,  75,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,
    65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  0,   0,   33,  0,   1,   104, 101, 108, 112, 13,  10,
    13,  10,  48,  132, 0,   0,   0,   45,  2,   1,   7,   99,  132, 0,   0,   0,   36,  4,   0,   10,  1,   0,   10,
    1,   0,   2,   1,   0,   2,   1,   100, 1,   1,   0,   135, 11,  111, 98,  106, 101, 99,  116, 67,  108, 97,  115,
    115, 48,  132, 0,   0,   0,   0,   79,  80,  84,  73,  79,  78,  83,  32,  115, 105, 112, 58,  110, 109, 32,  83,
    73,  80,  47,  50,  46,  48,  13,  10,  86,  105, 97,  58,  32,  83,  73,  80,  47,  50,  46,  48,  47,  85,  68,
    80,  32,  110, 109, 59,  98,  114, 97,  110, 99,  104, 61,  102, 111, 111, 59,  114, 112, 111, 114, 116, 13,  10,
    70,  114, 111, 109, 58,  32,  60,  115, 105, 112, 58,  110, 109, 64,  110, 109, 62,  59,  116, 97,  103, 61,  114,
    111, 111, 116, 13,  10,  84,  111, 58,  32,  60,  115, 105, 112, 58,  110, 109, 50,  64,  110, 109, 50,  62,  13,
    10,  67,  97,  108, 108, 45,  73,  68,  58,  32,  53,  48,  48,  48,  48,  13,  10,  67,  83,  101, 113, 58,  32,
    52,  50,  32,  79,  80,  84,  73,  79,  78,  83,  13,  10,  77,  97,  120, 45,  70,  111, 114, 119, 97,  114, 100,
    115, 58,  32,  55,  48,  13,  10,  67,  111, 110, 116, 101, 110, 116, 45,  76,  101, 110, 103, 116, 104, 58,  32,
    48,  13,  10,  67,  111, 110, 116, 97,  99,  116, 58,  32,  60,  115, 105, 112, 58,  110, 109, 64,  110, 109, 62,
    13,  10,  65,  99,  99,  101, 112, 116, 58,  32,  97,  112, 112, 108, 105, 99,  97,  116, 105, 111, 110, 47,  115,
    100, 112, 13,  10,  13,  10,  227, 0,   4,   250, 0,   1,   0,   0,   0,   1,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    197, 79,  35,  75,  113, 177, 82,  243, 48,  130, 0,   47,  2,   1,   0,   4,   6,   112, 117, 98,  108, 105, 99,
    160, 130, 0,   32,  2,   4,   76,  51,  167, 86,  2,   1,   0,   2,   1,   0,   48,  130, 0,   16,  48,  130, 0,
    12,  6,   8,   43,  6,   1,   2,   1,   1,   5,   0,   5,   0,   48,  58,  2,   1,   3,   48,  15,  2,   2,   74,
    105, 2,   3,   0,   255, 227, 4,   1,   4,   2,   1,   3,   4,   16,  48,  14,  4,   0,   2,   1,   0,   2,   1,
    0,   4,   0,   4,   0,   4,   0,   48,  18,  4,   0,   4,   0,   160, 12,  2,   2,   55,  240, 2,   1,   0,   2,
    1,   0,   48,  0,   0,   1,   0,   2,   0,   1,   0,   0,   0,   3,   231, 0,   0,   0,   0,   0,   0,   0,   101,
    0,   0,   0,   0,   0,   0,   0,   0,   13,  5,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   68,  66,  50,
    71,  69,  84,  65,  68,  68,  82,  0,   83,  81,  76,  48,  56,  48,  49,  48,  0,   0,   0,   0,   0,   0,   1,
    0,   0,   0,   0,   0,   0,   9,   95,  115, 101, 114, 118, 105, 99,  101, 115, 7,   95,  100, 110, 115, 45,  115,
    100, 4,   95,  117, 100, 112, 5,   108, 111, 99,  97,  108, 0,   0,   12,  0,   1,   30,  0,   1,   48,  2,   253,
    168, 227, 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   106, 129, 110, 48,  129, 107, 161, 3,   2,   1,   5,   162, 3,   2,   1,   10,  164, 129, 94,  48,  92,  160,
    7,   3,   5,   0,   80,  128, 0,   16,  162, 4,   27,  2,   78,  77,  163, 23,  48,  21,  160, 3,   2,   1,   0,
    161, 14,  48,  12,  27,  6,   107, 114, 98,  116, 103, 116, 27,  2,   78,  77,  165, 17,  24,  15,  49,  57,  55,
    48,  48,  49,  48,  49,  48,  48,  48,  48,  48,  48,  90,  167, 6,   2,   4,   31,  30,  185, 217, 168, 23,  48,
    21,  2,   1,   18,  2,   1,   17,  2,   1,   16,  2,   1,   23,  2,   1,   1,   2,   1,   3,   2,   1,   2,   101,
    73,  80,  65,  68,  0,   78,  65,  77,  69,  0,   74,  83,  79,  78,  0,   86,  69,  82,  83,  0,   85,  85,  73,
    68,  0,   74,  86,  73,  68,  6,   18,  52,  86,  120, 18,  52,  128, 0,   0,   12,  2,   81,  85,  65,  75,  69,
    0,   3,   255, 255, 255, 255, 115, 116, 97,  116, 117, 115, 255, 255, 255, 255, 103, 101, 116, 115, 116, 97,  116,
    117, 115, 255, 255, 255, 255, 103, 101, 116, 115, 101, 114, 118, 101, 114, 115, 32,  54,  56,  32,  101, 109, 112,
    116, 121, 32,  102, 117, 108, 108, 83,  78,  81,  85,  69,  82,  89,  58,  32,  49,  50,  55,  46,  48,  46,  48,
    46,  49,  58,  65,  65,  65,  65,  65,  65,  58,  120, 115, 118, 114, 206, 99,  209, 210, 22,  231, 19,  207, 56,
    165, 165, 134, 178, 117, 75,  153, 170, 50,  88,  27,  0,   0,   61,  0,   0,   0,   0,   18,  67,  79,  78,  78,
    69,  67,  84,  73,  79,  78,  76,  69,  83,  83,  95,  84,  68,  83,  0,   0,   0,   1,   0,   0,   4,   0,   5,
    0,   5,   0,   0,   1,   2,   0,   0,   3,   1,   1,   4,   8,   0,   0,   0,   0,   0,   0,   0,   0,   7,   2,
    4,   177, 255, 240, 151, 13,  46,  96,  209, 111, 0,   0,   4,   0,   0,   85,  171, 236, 50,  0,   0,   0,   0,
    0,   50,  4,   10,  0,   200, 117, 248, 22,  0,   92,  185, 101, 0,   0,   0,   0,   78,  209, 245, 40,  78,  81,
    0,   128, 128, 8,   255, 0,   32,  144, 128, 8,   255, 0,   0,   1,   0,   0,   0,   1,   0,   0,   115, 116, 97,
    116, 115, 13,  10,  2,   1,   0,   0,   54,  32,  0,   0,   0,   0,   0,   1,   0,   2,   101, 110, 0,   0,   0,
    21,  115, 101, 114, 118, 105, 99,  101, 58,  115, 101, 114, 118, 105, 99,  101, 45,  97,  103, 101, 110, 116, 0,
    7,   100, 101, 102, 97,  117, 108, 116, 0,   0,   0,   0,   0,   0,   0,   0,   97,  98,  99,  100, 101, 102, 103,
    104, 1,   231, 229, 117, 49,  163, 23,  11,  33,  207, 191, 43,  153, 78,  221, 25,  172, 222, 8,   95,  139, 36,
    10,  17,  25,  182, 115, 111, 173, 40,  19,  210, 10,  185, 18,  117, 244, 190, 3,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   1,   0,   0,   0,   50,  120, 186, 133, 9,   84,  101, 97,  109, 83,  112, 101, 97,  107, 0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   10,  87,  105, 110, 100,
    111, 119, 115, 32,  88,  80,  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   2,   0,   0,   0,   32,  0,   60,  0,   0,   1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   8,   110, 105, 99,  107, 110, 97,  109, 101, 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   5,   202, 127, 22,  156, 17,  249, 137, 0,   0,   0,   0,   2,
    157, 116, 139, 69,  170, 123, 239, 185, 158, 254, 173, 8,   25,  186, 207, 65,  224, 22,  162, 50,  108, 243, 207,
    244, 142, 60,  68,  131, 200, 141, 81,  69,  111, 144, 149, 35,  62,  0,   151, 43,  28,  113, 178, 78,  192, 97,
    241, 215, 111, 197, 126, 246, 72,  82,  191, 130, 106, 162, 59,  101, 170, 24,  122, 23,  56,  195, 129, 39,  195,
    71,  252, 167, 53,  186, 252, 15,  157, 157, 114, 36,  157, 252, 2,   23,  109, 107, 177, 45,  114, 198, 227, 23,
    28,  149, 217, 105, 153, 87,  206, 221, 223, 5,   220, 3,   148, 86,  4,   58,  20,  229, 173, 154, 43,  20,  48,
    58,  35,  163, 37,  173, 232, 230, 57,  138, 133, 42,  198, 223, 229, 93,  45,  160, 47,  93,  156, 215, 43,  36,
    251, 176, 156, 194, 186, 137, 180, 27,  23,  162, 182, 0,   2,   241, 38,  1,   38,  240, 144, 166, 240, 38,  87,
    78,  172, 160, 236, 248, 104, 228, 141, 33,  115, 65,  77,  83,  78,  73,  70,  70,  102, 114, 111, 109, 58,  97,
    105, 114, 104, 105, 100, 0,   64,  80,  0,   0,   0,   0,   133, 93,  180, 145, 40,  0,   0,   0,   0,   0,   1,
    124, 145, 64,  0,   0,   0,   170, 57,  218, 66,  55,  101, 207, 1,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    56,  100, 193, 120, 1,   184, 155, 203, 143, 0,   0,   0,   0,   0,   6,   0,   255, 7,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   9,   32,  24,  200, 129, 0,   56,  142, 4,   181, 64,  1,   1,   206, 187, 46,  119, 101, 108,
    108, 45,  107, 110, 111, 119, 110, 4,   99,  111, 114, 101, 22,  254, 255, 0,   0,   0,   0,   0,   0,   0,   0,
    0,   54,  1,   0,   0,   42,  0,   0,   0,   0,   0,   0,   0,   42,  254, 253, 0,   0,   0,   0,   124, 119, 64,
    30,  138, 200, 34,  160, 160, 24,  255, 147, 8,   202, 172, 10,  100, 47,  201, 34,  100, 188, 8,   168, 22,  137,
    25,  48,  0,   0,   0,   2,   0,   47,  1,   0,   13,  137, 193, 156, 28,  42,  255, 252, 241, 81,  57,  57,  57,
    0,   0,   20,  0,   1,   3,   1,   0,   0,   0,   2,   8,   0,   0,   1,   1,   6,   0,   1,   35,  69,  103, 0,
    0,   0,   0,   255, 255, 255, 255, 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   14,  53,  212,
    216, 81,  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   99,  130, 83,
    99,  53,  1,   8,   255, 0,   1,   114, 55,  116, 102, 116, 112, 46,  116, 120, 116, 0,   111, 99,  116, 101, 116,
    0,   62,  236, 227, 202, 0,   0,   0,   0,   0,   0,   0,   2,   0,   188, 97,  78,  0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   217, 0,   10,  250, 0,
    0,   0,   0,   0,   1,   4,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   198, 241, 94,  219, 120, 0,   0,   0,   5,   0,   11,
    3,   16,  0,   0,   0,   72,  0,   0,   0,   1,   0,   0,   0,   184, 16,  184, 16,  0,   0,   0,   0,   1,   0,
    0,   0,   0,   0,   1,   0,   1,   35,  69,  103, 137, 171, 205, 239, 1,   35,  69,  103, 137, 171, 205, 239, 231,
    3,   0,   0,   254, 220, 186, 152, 118, 84,  50,  16,  1,   35,  69,  103, 137, 171, 205, 239, 231, 3,   0,   0,
    1,   145, 0,   0,   0,   1,   0,   0,   0,   0,   0,   0,   32,  67,  75,  65,  65,  65,  65,  65,  65,  65,  65,
    65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  0,
    0,   33,  0,   1,   1,   145, 0,   16,  0,   1,   0,   0,   0,   0,   0,   0,   32,  67,  75,  65,  65,  65,  65,
    65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,
    65,  65,  65,  0,   0,   33,  0,   1,   0,   17,  34,  51,  68,  85,  102, 119, 0,   0,   0,   0,   0,   0,   0,
    0,   1,   16,  2,   0,   0,   0,   0,   0,   0,   0,   0,   192, 0,   0,   0,   164, 0,   0,   0,   1,   0,   0,
    0,   1,   0,   0,   0,   152, 1,   1,   0,   4,   3,   0,   0,   36,  1,   1,   0,   0,   128, 1,   0,   5,   128,
    2,   0,   2,   128, 3,   0,   1,   128, 4,   0,   2,   128, 11,  0,   1,   0,   12,  0,   4,   0,   0,   0,   1,
    3,   0,   0,   36,  2,   1,   0,   0,   128, 1,   0,   5,   128, 2,   0,   1,   128, 3,   0,   1,   128, 4,   0,
    2,   128, 11,  0,   1,   0,   12,  0,   4,   0,   0,   0,   1,   3,   0,   0,   36,  3,   1,   0,   0,   128, 1,
    0,   1,   128, 2,   0,   2,   128, 3,   0,   1,   128, 4,   0,   2,   128, 11,  0,   1,   0,   12,  0,   4,   0,
    0,   0,   1,   0,   0,   0,   36,  4,   1,   0,   0,   128, 1,   0,   1,   128, 2,   0,   1,   128, 3,   0,   1,
    128, 4,   0,   2,   128, 11,  0,   1,   0,   12,  0,   4,   0,   0,   0,   1,   49,  39,  252, 176, 56,  16,  158,
    137, 0,   0,   0,   0,   0,   0,   0,   0,   1,   16,  2,   0,   0,   0,   0,   0,   0,   0,   0,   204, 13,  0,
    0,   92,  0,   0,   0,   1,   0,   0,   0,   1,   0,   0,   0,   80,  1,   1,   0,   2,   3,   0,   0,   36,  1,
    1,   0,   0,   128, 1,   0,   5,   128, 2,   0,   2,   128, 4,   0,   2,   128, 3,   0,   3,   128, 11,  0,   1,
    0,   12,  0,   4,   0,   0,   14,  16,  0,   0,   0,   36,  2,   1,   0,   0,   128, 1,   0,   5,   128, 2,   0,
    1,   128, 4,   0,   2,   128, 3,   0,   3,   128, 11,  0,   1,   0,   12,  0,   4,   0,   0,   14,  16,  13,  0,
    0,   24,  30,  43,  81,  105, 5,   153, 28,  125, 124, 150, 252, 191, 181, 135, 228, 97,  0,   0,   0,   4,   13,
    0,   0,   20,  64,  72,  183, 213, 110, 188, 232, 133, 37,  231, 222, 127, 0,   214, 194, 211, 13,  0,   0,   20,
    144, 203, 128, 145, 62,  187, 105, 110, 8,   99,  129, 181, 236, 66,  123, 31,  0,   0,   0,   20,  38,  36,  77,
    56,  237, 219, 97,  179, 23,  42,  54,  227, 208, 207, 184, 25,  1,   1,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   16,  6,   0,   255, 6,   0,   0,   17,  190, 128,
    0,   0,   0,   56,  1,   2,   3,   4,   5,   6,   7,   8,   0,   0,   0,   0,   1,   0,   0,   20,  0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   200, 2,   0,   60,  0,   0,   0,   0,   0,   0,
    0,   0,   128, 8,   0,   0,   0,   0,   0,   1,   128, 8,   0,   0,   0,   2,   1,   0,   128, 14,  0,   0,   0,
    7,   110, 120, 112, 45,  115, 99,  97,  110, 128, 10,  0,   0,   0,   3,   0,   0,   0,   3,   128, 8,   0,   0,
    0,   9,   0,   0,   77,  45,  83,  69,  65,  82,  67,  72,  32,  42,  32,  72,  84,  84,  80,  47,  49,  46,  49,
    13,  10,  72,  111, 115, 116, 58,  32,  50,  51,  57,  46,  50,  53,  53,  46,  50,  53,  53,  46,  50,  53,  48,
    58,  49,  57,  48,  48,  13,  10,  77,  97,  110, 58,  32,  34,  115, 115, 100, 112, 58,  100, 105, 115, 99,  111,
    118, 101, 114, 34,  13,  10,  77,  88,  58,  32,  53,  13,  10,  83,  84,  58,  32,  115, 115, 100, 112, 58,  97,
    108, 108, 13,  10,  13,  10,  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   2,   0,   1,   134, 163, 0,
    0,   0,   2,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    50,  1,   0,   4,   0,   0,   66,  0,   19,  55,  0,   0,   78,  1,   0,   4,   222, 254, 200, 0,   78,  1,   0,
    4,   222, 254, 200, 0,   0,   1,   0,   0,   33,  18,  164, 66,  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   91,  80,  82,  79,  66,  69,  93,  32,  48,  48,  48,  48,  0,   0,   0,   0,   0,   0,   0,   1,   0,
    0,   0,   0,   0,   0,   9,   95,  115, 101, 114, 118, 105, 99,  101, 115, 7,   95,  100, 110, 115, 45,  115, 100,
    4,   95,  117, 100, 112, 5,   108, 111, 99,  97,  108, 0,   0,   12,  128, 1,   83,  84,  78,  111, 110, 101, 0,
    65,  109, 97,  110, 100, 97,  32,  50,  46,  54,  32,  82,  69,  81,  32,  72,  65,  78,  68,  76,  69,  32,  48,
    48,  48,  45,  48,  48,  48,  48,  48,  48,  48,  48,  32,  83,  69,  81,  32,  48,  10,  83,  69,  82,  86,  73,
    67,  69,  32,  110, 111, 111, 112, 10,  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   2,   85,  85,  85,
    85,  0,   0,   0,   1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   255, 255, 85,  19,  0,   0,   0,   48,  0,   0,   0,   1,   0,   0,   0,   2,   0,   0,   0,   0,   0,
    0,   0,   0,   114, 55,  114, 55,  0,   0,   0,   0,   0,   0,   0,   2,   85,  85,  85,  85,  0,   0,   0,   1,
    0,   0,   0,   1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   255, 255, 85,
    16,  0,   0,   0,   60,  0,   0,   0,   3,   0,   0,   0,   2,   0,   0,   0,   0,   0,   0,   0,   0,   228, 96,
    84,  83,  51,  73,  78,  73,  84,  49,  0,   101, 0,   0,   136, 10,  57,  123, 15,  0,   91,  85,  114, 239, 220,
    120, 50,  107, 0,   0,   0,   0,   0,   0,   0,   0,   0,   1,   0,   0,   0,   1,   0,   0,   118, 101, 114, 115,
    105, 111, 110, 13,  10,  255, 255, 255, 255, 84,  83,  111, 117, 114, 99,  101, 69,  110, 103, 105, 110, 101, 81,
    117, 101, 114, 121, 0,   112, 110, 103, 32,  108, 52,  52,  97,  100, 115, 108, 206, 99,  209, 210, 22,  231, 19,
    207, 56,  165, 165, 134, 178, 117, 75,  153, 170, 50,  88,  112, 110, 103, 32,  91,  93,  46,  46,  75,  115, 3,
    102, 20,  113, 0,   0,   0,   0,   1,   0,   0,   0,   0,   0,   0,   0,   1,   1,   16,  39,  0,   0,   0,   0};

static const uint16_t concatenated_port_ranges[] = {
    17,    17,    88,    88,    111,   111,   407,   407,   500,   500,   517,   517,   518,   518,   1419,  1419,
    2427,  2427,  4045,  4045,  10000, 10000, 10080, 10080, 12203, 12203, 27960, 27960, 32750, 32810, 38978, 38978,
    53,    53,    1967,  1967,  2967,  2967,  26198, 26198, 53,    53,    69,    69,    135,   135,   1761,  1761,
    26198, 26198, 137,   137,   7,     7,     13,    13,    37,    37,    42,    42,    389,   389,   5060,  5060,
    123,   123,   5353,  5353,  9100,  9100,  161,   161,   260,   260,   3401,  3401,  161,   161,   260,   260,
    3401,  3401,  177,   177,   7001,  7001,  1719,  1719,  523,   523,   53,    53,    5353,  5353,  1604,  1604,
    88,    88,    3483,  3483,  26000, 26004, 27910, 27914, 26000, 26004, 27960, 27964, 30720, 30724, 44400, 44400,
    27950, 27950, 30710, 30710, 626,   626,   31337, 31337, 2638,  2638,  17555, 17555, 49152, 49156, 5632,  5632,
    1505,  1505,  2303,  2303,  11211, 11211, 427,   427,   64738, 64738, 3784,  3784,  8767,  8767,  9987,  9987,
    2302,  2302,  1258,  1258,  2126,  2126,  3123,  3123,  12444, 12444, 13200, 13200, 23196, 23196, 26000, 26000,
    27138, 27138, 27244, 27244, 27777, 27777, 28138, 28138, 8888,  8888,  13246, 13246, 5008,  5008,  1194,  1194,
    443,   443,   500,   500,   623,   623,   5683,  5683,  443,   443,   853,   853,   3391,  3391,  4433,  4433,
    4740,  4740,  5349,  5349,  5684,  5684,  5868,  5868,  6514,  6514,  6636,  6636,  8232,  8232,  10161, 10161,
    10162, 10162, 12346, 12346, 12446, 12446, 12546, 12546, 12646, 12646, 12746, 12746, 12846, 12846, 12946, 12946,
    13046, 13046, 80,    80,    443,   443,   3283,  3283,  10001, 10001, 10001, 10001, 67,    67,    69,    69,
    111,   111,   2049,  2049,  4045,  4045,  32768, 65535, 123,   123,   135,   135,   1025,  1199,  34964, 34964,
    137,   137,   137,   137,   500,   500,   500,   500,   520,   520,   623,   623,   1194,  1194,  1645,  1645,
    1812,  1812,  1701,  1701,  1900,  1900,  2049,  2049,  2123,  2123,  2152,  2152,  3386,  3386,  2123,  2123,
    2152,  2152,  3478,  3478,  6481,  6481,  5351,  5351,  5353,  5353,  5632,  5632,  7777,  7777,  10080, 10080,
    17185, 17185, 17185, 17185, 4665,  4665,  4666,  4666,  4672,  4672,  6429,  6429,  9987,  9987,  11211, 11211,
    27015, 27030, 27444, 27444, 31337, 31337, 34555, 34555, 48899, 48899};

static const t_probe udp_probes[] = {
    {1, 0,    40,   0,   16 },
    {1, 40,   70,   16,  20 },
    {5, 70,   82,   20,  25 },
    {4, 82,   132,  25,  26 },
    {3, 132,  140,  26,  30 },
    {8, 140,  191,  30,  31 },
    {5, 191,  420,  31,  32 },
    {5, 420,  468,  32,  35 },
    {4, 468,  519,  35,  38 },
    {4, 519,  579,  38,  41 },
    {6, 579,  586,  41,  42 },
    {5, 586,  618,  42,  44 },
    {8, 618,  638,  44,  45 },
    {4, 638,  684,  45,  47 },
    {5, 684,  714,  47,  48 },
    {5, 714,  827,  48,  49 },
    {8, 827,  864,  49,  50 },
    {9, 864,  876,  50,  51 },
    {8, 876,  886,  51,  52 },
    {8, 886,  899,  52,  56 },
    {9, 899,  927,  56,  58 },
    {8, 927,  957,  58,  59 },
    {9, 957,  976,  59,  60 },
    {7, 976,  1037, 60,  61 },
    {8, 1037, 1079, 61,  63 },
    {8, 1079, 1081, 63,  64 },
    {8, 1081, 1087, 64,  65 },
    {8, 1087, 1093, 65,  66 },
    {8, 1093, 1108, 66,  67 },
    {8, 1108, 1162, 67,  68 },
    {9, 1162, 1174, 68,  69 },
    {9, 1174, 1210, 69,  70 },
    {9, 1210, 1390, 70,  71 },
    {8, 1390, 1552, 71,  72 },
    {9, 1552, 1573, 72,  73 },
    {9, 1573, 1574, 73,  84 },
    {9, 1574, 1581, 84,  85 },
    {9, 1581, 1592, 85,  86 },
    {7, 1592, 1656, 86,  87 },
    {8, 1656, 1670, 87,  90 },
    {8, 1670, 1693, 90,  91 },
    {9, 1693, 1714, 91,  92 },
    {2, 1714, 1781, 92,  113},
    {6, 1781, 1795, 113, 115},
    {8, 1795, 1800, 115, 116},
    {9, 1800, 1804, 116, 117},
    {9, 1804, 1808, 117, 118},
    {8, 1808, 2052, 118, 119},
    {8, 2052, 2071, 119, 120},
    {8, 2071, 2111, 120, 124},
    {8, 2111, 2159, 124, 125},
    {8, 2159, 2231, 125, 128},
    {8, 2231, 2281, 128, 129},
    {8, 2281, 2331, 129, 130},
    {8, 2331, 2523, 130, 131},
    {8, 2523, 2727, 131, 132},
    {8, 2727, 2751, 132, 133},
    {9, 2751, 2763, 133, 134},
    {9, 2763, 2776, 134, 135},
    {8, 2776, 2796, 135, 137},
    {8, 2796, 2856, 137, 138},
    {8, 2856, 2950, 138, 139},
    {8, 2950, 2990, 139, 140},
    {9, 2990, 3002, 140, 142},
    {8, 3002, 3010, 142, 143},
    {8, 3010, 3018, 143, 145},
    {8, 3018, 3038, 145, 146},
    {8, 3038, 3050, 146, 147},
    {8, 3050, 3052, 147, 148},
    {8, 3052, 3098, 148, 149},
    {8, 3098, 3100, 149, 150},
    {8, 3100, 3105, 150, 151},
    {8, 3105, 3159, 151, 152},
    {8, 3159, 3223, 152, 153},
    {9, 3223, 3287, 153, 154},
    {8, 3287, 3289, 154, 158},
    {9, 3289, 3323, 158, 159},
    {9, 3323, 3340, 159, 160},
    {8, 3340, 3363, 160, 161},
    {9, 3363, 3374, 161, 162},
    {9, 3374, 3393, 162, 163},
    {9, 3393, 3403, 163, 164},
    {8, 3403, 3427, 164, 165},
    SENTINEL_PROBE,
};