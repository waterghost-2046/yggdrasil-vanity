// From: kernel/curve25519-constants.cu


// From: kernel/curve25519-constants2.cu


// From: kernel/curve25519.cu


// From: kernel/entry.cu


// From: kernel/sha512.cu
#include <stdint.h>

// Rotate right function for 64-bit unsigned integers.
__device__ inline uint64_t sha512_rotr(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

// Load big-endian 64-bit value from a 64-byte array.
__device__ inline uint64_t sha512_load_be(const uint8_t *base, size_t offset)
{
    return ((uint64_t)base[offset + 7]) | ((uint64_t)base[offset + 6] << 8) |
           ((uint64_t)base[offset + 5] << 16) | ((uint64_t)base[offset + 4] << 24) |
           ((uint64_t)base[offset + 3] << 32) | ((uint64_t)base[offset + 2] << 40) |
           ((uint64_t)base[offset + 1] << 48) | ((uint64_t)base[offset + 0] << 56);
}

// Load big-endian 64-bit value from a 128-byte array.
__device__ inline uint64_t sha512_load_be_128(const uint8_t *base, size_t offset)
{
    return ((uint64_t)base[offset + 7]) | ((uint64_t)base[offset + 6] << 8) |
           ((uint64_t)base[offset + 5] << 16) | ((uint64_t)base[offset + 4] << 24) |
           ((uint64_t)base[offset + 3] << 32) | ((uint64_t)base[offset + 2] << 40) |
           ((uint64_t)base[offset + 1] << 48) | ((uint64_t)base[offset + 0] << 56);
}

// Store big-endian 64-bit value to a 64-byte array.
__device__ inline void sha512_store_be(uint8_t *base, size_t offset, uint64_t x)
{
    base[offset + 7] = (uint8_t)(x & 0xFFULL);
    base[offset + 6] = (uint8_t)((x >> 8) & 0xFFULL);
    base[offset + 5] = (uint8_t)((x >> 16) & 0xFFULL);
    base[offset + 4] = (uint8_t)((x >> 24) & 0xFFULL);
    base[offset + 3] = (uint8_t)((x >> 32) & 0xFFULL);
    base[offset + 2] = (uint8_t)((x >> 40) & 0xFFULL);
    base[offset + 1] = (uint8_t)((x >> 48) & 0xFFULL);
    base[offset + 0] = (uint8_t)((x >> 56) & 0xFFULL);
}

// The 80 SHA512 round constants.
__constant__ uint64_t SHA512_ROUND_CONSTANTS[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70UL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

// The SHA512 state structure.
typedef struct
{
    uint64_t st[8];
} sha512_State;

// Initialize a SHA512 state with IV.
__device__ inline sha512_State sha512_State_new()
{
    sha512_State state;
    // IV is defined as 64 bytes
    // In CUDA, constant data that is small and used often can be put into __constant__ memory.
    // For this IV, it's small enough to be stack allocated or directly included.
    const uint8_t IV[64] = {
        0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae,
        0x85, 0x84, 0xca, 0xa7, 0x3b, 0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94,
        0xf8, 0x2b, 0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1, 0x51,
        0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05, 0x68, 0x8c,
        0x2b, 0x3e, 0x6c, 0x1f, 0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd,
        0x6b, 0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79};

    for (int i = 0; i < 8; i++)
    {
        state.st[i] = sha512_load_be(IV, i * 8);
    }
    return state;
}

// Store the SHA512 state into a 64-byte output array.
__device__ inline void sha512_State_store(const sha512_State *state,
                               uint8_t *out)
{
    for (int i = 0; i < 8; i++)
    {
        sha512_store_be(out, i * 8, state->st[i]);
    }
}

// Add two SHA512 states.
__device__ inline void sha512_State_add(sha512_State *self, const sha512_State *other)
{
    for (int i = 0; i < 8; i++)
    {
        self->st[i] += other->st[i];
    }
}

// The W structure for the message schedule.
typedef struct
{
    uint64_t w[16];
} sha512_W;

// Initialize W struct from a 128-byte input block.
__device__ inline sha512_W sha512_W_new(const uint8_t *input)
{
    sha512_W w_struct;
    for (int i = 0; i < 16; i++)
    {
        w_struct.w[i] = sha512_load_be_128(input, i * 8);
    }
    return w_struct;
}

// Functions corresponding to SHA512 bitwise functions.
__device__ inline uint64_t sha512_big_ch(uint64_t x, uint64_t y, uint64_t z)
{
    return (x & y) ^ ((~x) & z);
}

__device__ inline uint64_t sha512_big_maj(uint64_t x, uint64_t y, uint64_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

__device__ inline uint64_t sha512_big_sigma0(uint64_t x)
{
    return sha512_rotr(x, 28) ^ sha512_rotr(x, 34) ^ sha512_rotr(x, 39);
}

__device__ inline uint64_t sha512_big_sigma1(uint64_t x)
{
    return sha512_rotr(x, 14) ^ sha512_rotr(x, 18) ^ sha512_rotr(x, 41);
}

__device__ inline uint64_t sha512_sigma0(uint64_t x)
{
    return sha512_rotr(x, 1) ^ sha512_rotr(x, 8) ^ (x >> 7);
}

__device__ inline uint64_t sha512_sigma1(uint64_t x)
{
    return sha512_rotr(x, 19) ^ sha512_rotr(x, 61) ^ (x >> 6);
}

// Performs a single update on W.
__device__ inline void sha512_W_big_m(sha512_W *w, int a, int b, int c, int d)
{
    w->w[a] = w->w[a] + sha512_sigma1(w->w[b]) + w->w[c] + sha512_sigma0(w->w[d]);
}

// Expand the message schedule.
__device__ inline void sha512_W_expand(sha512_W *w)
{
    for (int i = 0; i < 16; i++)
    {
        sha512_W_big_m(w, i, (i + 14) & 15, (i + 9) & 15, (i + 1) & 15);
    }
}

// Update the state with one round (big_f).
__device__ inline void sha512_W_big_f(sha512_W *w, sha512_State *state, int i, uint64_t k)
{
    // The indices are calculated modulo 8 as in the original code.
    int idx7 = (16 - i + 7) & 7;
    int idx4 = (16 - i + 4) & 7;
    int idx5 = (16 - i + 5) & 7;
    int idx6 = (16 - i + 6) & 7;
    int idx3 = (16 - i + 3) & 7;
    int idx0 = (16 - i + 0) & 7;
    int idx1 = (16 - i + 1) & 7;
    int idx2 = (16 - i + 2) & 7;

    state->st[idx7] =
        state->st[idx7] + sha512_big_sigma1(state->st[idx4]) +
        sha512_big_ch(state->st[idx4], state->st[idx5], state->st[idx6]) + k +
        w->w[i];
    state->st[idx3] = state->st[idx3] + state->st[idx7];
    state->st[idx7] =
        state->st[idx7] + sha512_big_sigma0(state->st[idx0]) +
        sha512_big_maj(state->st[idx0], state->st[idx1], state->st[idx2]);
}

// Process 16 rounds over the state using W.
__device__ inline void sha512_W_big_g(sha512_W *w, sha512_State *state, int s)
{
    // Each s processes 16 rounds
    for (int i = 0; i < 16; i++)
    {
        sha512_W_big_f(w, state, i, SHA512_ROUND_CONSTANTS[s * 16 + i]);
    }
}

// Process a full 128-byte message block.
__device__ inline void sha512_State_blocks(sha512_State *state,
                                const uint8_t *input)
{
    sha512_State t = *state;
    sha512_W w = sha512_W_new(input);

    for (int s = 0; s < 4; s++)
    {
        sha512_W_big_g(&w, &t, s);
        sha512_W_expand(&w);
    }

    // One final group of 16 rounds without expanding
    sha512_W_big_g(&w, &t, 4);
    sha512_State_add(&t, state);
    *state = t;
}

// The main hash function.
// input: pointer to 32 bytes (in global memory)
// out: pointer to 64 bytes (in global memory) where the digest will be
// stored.
__device__ void sha512_hash(const uint8_t *input, uint8_t *out)
{
    // Initialize state.
    sha512_State state = sha512_State_new();

    // Prepare a 128-byte padded block.
    // This is a local array, so it's on the stack (private memory).
    uint8_t padded[128] = {0};
    for (int i = 0; i < 32; i++)
    {
        padded[i] = input[i];
    }
    padded[32] = 0x80; // append the '1' bit.

    // Append the length: in SHA512 the length in bits is stored in the last 8
    // bytes. For a 32-byte message, the bit-length is 256.
    uint64_t bits = 32 * 8;
    for (int i = 0; i < 8; i++)
    {
        padded[128 - 8 + i] = (uint8_t)((bits >> (56 - i * 8)) & 0xFFULL);
    }

    // Process the (single) block.
    sha512_State_blocks(&state, padded);

    // Store the final state into out.
    sha512_State_store(&state, out);
}


