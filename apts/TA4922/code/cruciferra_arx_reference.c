/*
 * Analyst reconstruction of the custom ARX transform used by the local
 * Cruciferra variants.
 *
 * This contains only the byte transform needed to reproduce static decryption; it has no PE
 * loading, process, driver, persistence, or networking functionality.
 */

#include <stddef.h>
#include <stdint.h>

struct cruciferra_arx_context {
    uint32_t schedule[24];
    uint32_t tail[4];
};

static uint32_t load32le(const uint8_t input[4]) {
    return ((uint32_t)input[0]) |
           ((uint32_t)input[1] << 8) |
           ((uint32_t)input[2] << 16) |
           ((uint32_t)input[3] << 24);
}

static void store32le(uint8_t output[4], uint32_t value) {
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
    output[2] = (uint8_t)(value >> 16);
    output[3] = (uint8_t)(value >> 24);
}

static uint32_t rol32(uint32_t value, unsigned int count) {
    return (value << count) | (value >> (32U - count));
}

void cruciferra_arx_init(
    struct cruciferra_arx_context *context,
    const uint8_t key[48]
) {
    size_t index;

    for (index = 0; index < 8; ++index) {
        context->schedule[index] = load32le(key + (index * 4));
    }
    for (index = 8; index < 24; ++index) {
        uint32_t left =
            rol32(context->schedule[index - 1], 5) ^
            context->schedule[index - 7];
        uint32_t right =
            ((uint32_t)index * UINT32_C(0x9e3779b9)) ^
            context->schedule[index - 8];
        context->schedule[index] = left + right;
    }
    for (index = 0; index < 4; ++index) {
        context->tail[index] = load32le(key + 32 + (index * 4));
    }
}

void cruciferra_arx_block(
    const struct cruciferra_arx_context *context,
    uint32_t counter,
    uint8_t output[16]
) {
    uint32_t word_a = context->tail[0] ^ counter;
    uint32_t word_b = context->tail[1] ^ ~counter;
    uint32_t word_c = context->tail[2] ^ UINT32_C(0x6a09e667);
    uint32_t word_d = context->tail[3] ^ UINT32_C(0xbb67ae85);
    size_t index;

    for (index = 0; index < 24; ++index) {
        word_a += word_b;
        word_d = rol32(word_d ^ word_a, 16);
        word_c += word_d;
        word_b = rol32(word_b ^ word_c, 12);
        word_a += word_b;
        word_d = rol32(word_d ^ word_a, 8);
        word_c += word_d;
        word_b = rol32(word_b ^ word_c, 7);
        word_a ^= context->schedule[index];
    }

    store32le(output, word_a);
    store32le(output + 4, word_b);
    store32le(output + 8, word_c);
    store32le(output + 12, word_d);
}

void cruciferra_arx_xor(
    const struct cruciferra_arx_context *context,
    const uint8_t *input,
    uint8_t *output,
    size_t length
) {
    uint32_t counter = 0;
    size_t offset = 0;

    while (offset < length) {
        uint8_t stream[16];
        size_t block_size = length - offset;
        size_t index;

        if (block_size > sizeof(stream)) {
            block_size = sizeof(stream);
        }
        cruciferra_arx_block(context, counter, stream);
        for (index = 0; index < block_size; ++index) {
            output[offset + index] = input[offset + index] ^ stream[index];
        }
        offset += block_size;
        ++counter;
    }
}
