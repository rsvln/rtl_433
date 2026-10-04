/** @file
    Nartis I100/I300/I500 electricity meter with D101 remote display (RF 433 MHz).

    Copyright (C) 2026 rsvln

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/
/**
Nartis I100/I300/I500 electricity meter with D101 remote display (RF 433 MHz).

The meter does not transmit on its own: the D101 display polls it with
DLMS/COSEM GET requests and the meter replies. This decoder passively
listens to both directions, remembers the OBIS list of the last request
and maps the values of the following reply onto it.

Radio:
- FSK, 2400 bit/s NRZ, deviation about +-6 kHz.
- Display transmits around 433.81 MHz, the meter replies on
  433.29 / 434.25 / 434.69 MHz. Use e.g. `-f 434M -s 2048k` to hear all.
- Preamble 0x55..., sync word 0xf672.

Frame (wM-Bus like, format B):
- L (frame length - 1, including CRCs), C (0x44 display request, 0x43 meter reply), ...
- Frames longer than 128 bytes carry a CRC after the first 126 bytes.
- CRC-16 poly 0x3d65, init 0, final xor 0xffff (as wM-Bus).

Security: AES-128-GCM, 12 byte tag.
- Key = ASCII(12 digit meter serial) + bd 02 9b be.
- IV  = display address (permuted) + 32 bit frame counter.
- AAD = the 4 bytes preceding the frame counter.

Usage: the decoder is disabled by default and needs the meter serial number,
e.g. `-R <num>:012345678901`. To keep all default decoders enabled as well,
first add a negative protocol, e.g. `-R -<num> -R <num>:012345678901`.

Values are output as soon as a reply is matched to its request, so each
message only carries the fields the display just asked for.

Credits: the protocol (framing, channels, key derivation, GCM nonce/AAD) was
reverse engineered by Anton Viktorov (latonita), see
https://github.com/latonita/esphome-nartis-rf-meter
*/

#include "decoder.h"

/* ---- AES-128 (encrypt only) and GCM ---- */

static uint8_t const aes_sbox[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static uint8_t aes_xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

static void aes128_expand_key(uint8_t const key[16], uint8_t rk[176])
{
    uint8_t rcon = 0x01;
    memcpy(rk, key, 16);
    for (int i = 16; i < 176; i += 4) {
        uint8_t t[4] = {rk[i - 4], rk[i - 3], rk[i - 2], rk[i - 1]};
        if (i % 16 == 0) {
            uint8_t tmp = t[0];
            t[0]        = aes_sbox[t[1]] ^ rcon;
            t[1]        = aes_sbox[t[2]];
            t[2]        = aes_sbox[t[3]];
            t[3]        = aes_sbox[tmp];
            rcon        = aes_xtime(rcon);
        }
        for (int j = 0; j < 4; ++j) {
            rk[i + j] = rk[i - 16 + j] ^ t[j];
        }
    }
}

static void aes128_encrypt(uint8_t const rk[176], uint8_t const in[16], uint8_t out[16])
{
    uint8_t s[16], t[16];
    for (int i = 0; i < 16; ++i) {
        s[i] = in[i] ^ rk[i];
    }
    for (int round = 1; round <= 10; ++round) {
        // SubBytes + ShiftRows (state is column-major: s[row + 4 * col])
        for (int c = 0; c < 4; ++c) {
            for (int r = 0; r < 4; ++r) {
                t[r + 4 * c] = aes_sbox[s[r + 4 * ((c + r) % 4)]];
            }
        }
        // MixColumns
        if (round != 10) {
            for (int c = 0; c < 4; ++c) {
                uint8_t *a  = &t[4 * c];
                uint8_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3];
                uint8_t all = a0 ^ a1 ^ a2 ^ a3;
                a[0] = a0 ^ all ^ aes_xtime(a0 ^ a1);
                a[1] = a1 ^ all ^ aes_xtime(a1 ^ a2);
                a[2] = a2 ^ all ^ aes_xtime(a2 ^ a3);
                a[3] = a3 ^ all ^ aes_xtime(a3 ^ a0);
            }
        }
        // AddRoundKey
        for (int i = 0; i < 16; ++i) {
            s[i] = t[i] ^ rk[16 * round + i];
        }
    }
    memcpy(out, s, 16);
}

static void gf128_mul(uint8_t x[16], uint8_t const h[16])
{
    uint8_t z[16] = {0};
    uint8_t v[16];
    memcpy(v, h, 16);
    for (int i = 0; i < 128; ++i) {
        if (x[i / 8] & (0x80 >> (i % 8))) {
            for (int j = 0; j < 16; ++j) {
                z[j] ^= v[j];
            }
        }
        int lsb = v[15] & 1;
        for (int j = 15; j > 0; --j) {
            v[j] = (uint8_t)((v[j] >> 1) | (v[j - 1] << 7));
        }
        v[0] >>= 1;
        if (lsb) {
            v[0] ^= 0xe1;
        }
    }
    memcpy(x, z, 16);
}

static void ghash_update(uint8_t y[16], uint8_t const h[16], uint8_t const *data, unsigned len)
{
    for (unsigned off = 0; off < len; off += 16) {
        unsigned n = len - off < 16 ? len - off : 16;
        for (unsigned j = 0; j < n; ++j) {
            y[j] ^= data[off + j];
        }
        gf128_mul(y, h);
    }
}

/// AES-128-GCM decrypt with 96 bit IV, returns 0 if the (truncated) tag matches.
static int aes128_gcm_decrypt(uint8_t const key[16], uint8_t const iv[12],
        uint8_t const *aad, unsigned aad_len,
        uint8_t const *ct, unsigned len,
        uint8_t const *tag, unsigned tag_len,
        uint8_t *pt)
{
    uint8_t rk[176];
    uint8_t h[16]  = {0};
    uint8_t cb[16] = {0};
    uint8_t ks[16];
    uint8_t y[16] = {0};

    aes128_expand_key(key, rk);
    aes128_encrypt(rk, h, h);

    // GHASH over AAD and ciphertext
    ghash_update(y, h, aad, aad_len);
    ghash_update(y, h, ct, len);
    uint8_t lens[16] = {0};
    uint64_t abits = (uint64_t)aad_len * 8, cbits = (uint64_t)len * 8;
    for (int i = 0; i < 8; ++i) {
        lens[7 - i]  = (uint8_t)(abits >> (8 * i));
        lens[15 - i] = (uint8_t)(cbits >> (8 * i));
    }
    ghash_update(y, h, lens, 16);

    // Tag = E(J0) ^ GHASH
    memcpy(cb, iv, 12);
    cb[15] = 1;
    aes128_encrypt(rk, cb, ks);
    int diff = 0;
    for (unsigned i = 0; i < tag_len; ++i) {
        diff |= (ks[i] ^ y[i]) ^ tag[i];
    }
    if (diff) {
        return -1;
    }

    // CTR starting at J0 + 1
    uint32_t ctr = 2;
    for (unsigned off = 0; off < len; off += 16) {
        cb[12] = (uint8_t)(ctr >> 24);
        cb[13] = (uint8_t)(ctr >> 16);
        cb[14] = (uint8_t)(ctr >> 8);
        cb[15] = (uint8_t)(ctr);
        aes128_encrypt(rk, cb, ks);
        unsigned n = len - off < 16 ? len - off : 16;
        for (unsigned j = 0; j < n; ++j) {
            pt[off + j] = ct[off + j] ^ ks[j];
        }
        ctr++;
    }
    return 0;
}

/* ---- OBIS mapping ---- */

struct nartis_obis {
    uint8_t a, c, d, e, f;
    char const *key;
    char const *label;
    char const *fmt;
    double scale;
};

static struct nartis_obis const nartis_obis_map[] = {
        {1, 32, 7, 0, 255, "voltage_L1_V", "Voltage L1", "%.1f V", 0.1},
        {1, 52, 7, 0, 255, "voltage_L2_V", "Voltage L2", "%.1f V", 0.1},
        {1, 72, 7, 0, 255, "voltage_L3_V", "Voltage L3", "%.1f V", 0.1},
        {1, 124, 7, 0, 255, "voltage_L1L2_V", "Voltage L1-L2", "%.1f V", 0.1},
        {1, 125, 7, 0, 255, "voltage_L2L3_V", "Voltage L2-L3", "%.1f V", 0.1},
        {1, 126, 7, 0, 255, "voltage_L3L1_V", "Voltage L3-L1", "%.1f V", 0.1},
        {1, 31, 7, 0, 255, "current_L1_A", "Current L1", "%.3f A", 0.001},
        {1, 51, 7, 0, 255, "current_L2_A", "Current L2", "%.3f A", 0.001},
        {1, 71, 7, 0, 255, "current_L3_A", "Current L3", "%.3f A", 0.001},
        {1, 91, 7, 0, 255, "current_N_A", "Current N", "%.3f A", 0.001},
        {1, 1, 7, 0, 255, "power_W", "Active power", "%.0f W", 1},
        {1, 21, 7, 0, 255, "power_L1_W", "Active power L1", "%.0f W", 1},
        {1, 41, 7, 0, 255, "power_L2_W", "Active power L2", "%.0f W", 1},
        {1, 61, 7, 0, 255, "power_L3_W", "Active power L3", "%.0f W", 1},
        {1, 3, 7, 0, 255, "reactive_power_var", "Reactive power", "%.0f var", 1},
        {1, 23, 7, 0, 255, "reactive_power_L1_var", "Reactive power L1", "%.0f var", 1},
        {1, 43, 7, 0, 255, "reactive_power_L2_var", "Reactive power L2", "%.0f var", 1},
        {1, 63, 7, 0, 255, "reactive_power_L3_var", "Reactive power L3", "%.0f var", 1},
        {1, 14, 7, 0, 255, "frequency_Hz", "Frequency", "%.2f Hz", 0.01},
        {1, 1, 8, 0, 255, "energy_kWh", "Energy import", "%.3f kWh", 0.001},
        {1, 1, 8, 1, 255, "energy_T1_kWh", "Energy import T1", "%.3f kWh", 0.001},
        {1, 1, 8, 2, 255, "energy_T2_kWh", "Energy import T2", "%.3f kWh", 0.001},
        {1, 1, 8, 3, 255, "energy_T3_kWh", "Energy import T3", "%.3f kWh", 0.001},
        {1, 1, 8, 4, 255, "energy_T4_kWh", "Energy import T4", "%.3f kWh", 0.001},
        {1, 2, 8, 0, 255, "energy_export_kWh", "Energy export", "%.3f kWh", 0.001},
        {1, 3, 8, 0, 255, "energy_reactive_import_kvarh", "Reactive energy import", "%.3f kvarh", 0.001},
        {1, 4, 8, 0, 255, "energy_reactive_export_kvarh", "Reactive energy export", "%.3f kvarh", 0.001},
        {1, 1, 8, 0, 101, "energy_last_month_kWh", "Energy import last month", "%.3f kWh", 0.001},
        {0, 96, 9, 0, 255, "temperature_C", "Temperature", "%.1f C", 0.1},
};

#define NARTIS_MAX_ITEMS 16

struct nartis_item {
    uint16_t cls;
    uint8_t obis[6];
};

struct nartis_context {
    char serial[16];
    uint8_t key[16];
    int have_key;
    int req_valid;
    uint32_t req_ctr;
    unsigned n_items;
    struct nartis_item items[NARTIS_MAX_ITEMS];
};

/// Parse one DLMS data element, returns bytes consumed or 0 on error.
static unsigned nartis_dlms_value(uint8_t const *b, unsigned len, int *is_num, double *num, char *str, unsigned str_size)
{
    if (len < 1) {
        return 0;
    }
    *is_num = 0;
    str[0]  = '\0';
    uint8_t t = b[0];
    switch (t) {
    case 0x00: // null
        return 1;
    case 0x03: // boolean
    case 0x11: // unsigned8
    case 0x16: // enum
        if (len < 2) return 0;
        *is_num = 1, *num = b[1];
        return 2;
    case 0x0f: // integer8
        if (len < 2) return 0;
        *is_num = 1, *num = (int8_t)b[1];
        return 2;
    case 0x10: // integer16
        if (len < 3) return 0;
        *is_num = 1, *num = (int16_t)((b[1] << 8) | b[2]);
        return 3;
    case 0x12: // unsigned16
        if (len < 3) return 0;
        *is_num = 1, *num = (b[1] << 8) | b[2];
        return 3;
    case 0x05: // integer32
        if (len < 5) return 0;
        *is_num = 1, *num = (int32_t)((uint32_t)b[1] << 24 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 8 | b[4]);
        return 5;
    case 0x06: // unsigned32
        if (len < 5) return 0;
        *is_num = 1, *num = (uint32_t)b[1] << 24 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 8 | b[4];
        return 5;
    case 0x14: // integer64
    case 0x15: { // unsigned64
        if (len < 9) return 0;
        uint64_t v = 0;
        for (int i = 1; i <= 8; ++i) {
            v = (v << 8) | b[i];
        }
        *is_num = 1, *num = t == 0x14 ? (double)(int64_t)v : (double)v;
        return 9;
    }
    case 0x09: { // octet-string
        if (len < 2 || len < 2u + b[1]) return 0;
        unsigned n = b[1];
        // DLMS date-time
        if (n == 12 && str_size >= 20) {
            snprintf(str, str_size, "%04d-%02d-%02d %02d:%02d:%02d",
                    (b[2] << 8) | b[3], b[4], b[5], b[7], b[8], b[9]);
        }
        return 2 + n;
    }
    case 0x01: // array
    case 0x02: { // structure
        if (len < 2) return 0;
        unsigned pos = 2;
        for (unsigned i = 0; i < b[1]; ++i) {
            int dn;
            double dv;
            char ds[24];
            unsigned n = nartis_dlms_value(b + pos, len - pos, &dn, &dv, ds, sizeof(ds));
            if (!n) return 0;
            pos += n;
        }
        return pos;
    }
    default:
        return 0;
    }
}

static int nartis_check_crc(uint8_t const *b, unsigned len)
{
    uint16_t crc = crc16(b, len - 2, 0x3d65, 0x0000) ^ 0xffff;
    return crc == ((b[len - 2] << 8) | b[len - 1]);
}

/// Display GET request: remember the requested OBIS list.
static int nartis_parse_request(r_device *decoder, struct nartis_context *ctx, uint32_t ctr, uint8_t const *pt, unsigned len)
{
    // 00 01 | 00 66 | 00 01 | len16 | c0 <type> <invoke-id> ...
    if (len < 12 || pt[8] != 0xc0) {
        return DECODE_FAIL_OTHER;
    }
    unsigned pos, n;
    if (pt[9] == 0x01) { // get-request-normal
        pos = 11, n = 1;
    }
    else if (pt[9] == 0x03) { // get-request-with-list
        pos = 12, n = pt[11];
    }
    else {
        return DECODE_FAIL_OTHER;
    }
    if (n > NARTIS_MAX_ITEMS || pos + n * 10 > len) {
        return DECODE_FAIL_SANITY;
    }
    for (unsigned i = 0; i < n; ++i, pos += 10) {
        ctx->items[i].cls = (uint16_t)((pt[pos] << 8) | pt[pos + 1]);
        memcpy(ctx->items[i].obis, &pt[pos + 2], 6);
    }
    ctx->n_items   = n;
    ctx->req_ctr   = ctr;
    ctx->req_valid = 1;
    decoder_logf(decoder, 1, __func__, "GET request ctr %u with %u items", ctr, n);
    return 1;
}

/// Meter GET response: map values onto the remembered request.
static int nartis_parse_response(r_device *decoder, struct nartis_context *ctx, uint32_t ctr, uint8_t const *pt, unsigned len)
{
    // 0d fd f8 37 | len | 00 01 | 00 01 | 00 66 | len16 | c4 <type> <invoke-id> ...
    if (len < 17 || pt[13] != 0xc4) {
        return DECODE_FAIL_OTHER;
    }
    if (!ctx->req_valid || ctr <= ctx->req_ctr || ctr - ctx->req_ctr > 4) {
        decoder_logf(decoder, 1, __func__, "GET response ctr %u without matching request", ctr);
        return DECODE_FAIL_OTHER;
    }
    unsigned pos, n;
    if (pt[14] == 0x01) { // get-response-normal: c4 01 c1 <result> data
        pos = 16, n = 1;
    }
    else if (pt[14] == 0x03) { // get-response-with-list: c4 03 c1 <n> (<result> data)*
        pos = 17, n = pt[16];
    }
    else {
        return DECODE_FAIL_OTHER;
    }
    if (n != ctx->n_items) {
        decoder_logf(decoder, 1, __func__, "GET response with %u items, request had %u", n, ctx->n_items);
        return DECODE_FAIL_SANITY;
    }
    ctx->req_valid = 0;

    /* clang-format off */
    data_t *data = data_make(
            "model",    "",     DATA_STRING, "Nartis-Meter",
            "id",       "",     DATA_STRING, ctx->serial,
            NULL);
    /* clang-format on */
    int found = 0;

    for (unsigned i = 0; i < n; ++i) {
        if (pos >= len) {
            break;
        }
        if (pt[pos++] != 0) { // data-access-result error: one byte code
            pos++;
            continue;
        }
        int is_num;
        double v;
        char s[24];
        unsigned used = nartis_dlms_value(pt + pos, len - pos, &is_num, &v, s, sizeof(s));
        if (!used) {
            decoder_logf(decoder, 1, __func__, "Unknown DLMS type 0x%02x", pt[pos]);
            break;
        }
        pos += used;

        uint8_t const *o = ctx->items[i].obis;
        if (ctx->items[i].cls == 8 && o[0] == 0 && o[2] == 1 && o[3] == 0 && s[0]) {
            data = data_str(data, "meter_time", "Meter time", NULL, s);
            found++;
            continue;
        }
        if (!is_num) {
            continue;
        }
        for (unsigned k = 0; k < sizeof(nartis_obis_map) / sizeof(nartis_obis_map[0]); ++k) {
            struct nartis_obis const *m = &nartis_obis_map[k];
            if (o[0] == m->a && o[2] == m->c && o[3] == m->d && o[4] == m->e && o[5] == m->f) {
                data = data_dbl(data, m->key, m->label, m->fmt, v * m->scale);
                found++;
                break;
            }
        }
    }
    data = data_str(data, "mic", "Integrity", NULL, "CRC");

    if (!found) {
        data_free(data);
        return DECODE_FAIL_OTHER;
    }
    decoder_output_data(decoder, data);
    return 1;
}

static int nartis_d101_decode(r_device *decoder, bitbuffer_t *bitbuffer)
{
    uint8_t const sync[] = {0x55, 0x55, 0xf6, 0x72};
    struct nartis_context *ctx = decoder_user_data(decoder);
    int ret = DECODE_ABORT_EARLY;

    for (int row = 0; row < bitbuffer->num_rows; ++row) {
        unsigned bits = bitbuffer->bits_per_row[row];
        unsigned pos  = bitbuffer_search(bitbuffer, row, 0, sync, 32);
        if (pos + 32 + 12 * 8 > bits) {
            continue;
        }
        pos += 32;

        uint8_t raw[256];
        bitbuffer_extract_bytes(bitbuffer, row, pos, raw, 8);
        unsigned total = raw[0] + 1u;
        if (total < 12 || pos + total * 8 > bits) {
            ret = DECODE_ABORT_LENGTH;
            continue;
        }
        bitbuffer_extract_bytes(bitbuffer, row, pos, raw, total * 8);

        // wM-Bus format B: block 1+2 is 126 bytes + CRC, then block 3 + CRC
        uint8_t f[256];
        unsigned flen;
        if (total > 128) {
            if (!nartis_check_crc(raw, 128) || !nartis_check_crc(raw + 128, total - 128)) {
                ret = DECODE_FAIL_MIC;
                continue;
            }
            memcpy(f, raw, 126);
            memcpy(f + 126, raw + 128, total - 128);
            flen = total - 2;
        }
        else {
            if (!nartis_check_crc(raw, total)) {
                ret = DECODE_FAIL_MIC;
                continue;
            }
            memcpy(f, raw, total);
            flen = total;
        }

        uint8_t c = f[1];
        uint8_t iv[12];
        unsigned hdr; // offset of the 4 byte AAD, followed by the frame counter
        if (c == 0x44) {
            // display -> meter: f[2..9] display address
            static uint8_t const perm[8] = {2, 3, 4, 5, 0, 1, 6, 7};
            for (int i = 0; i < 8; ++i) {
                iv[i] = f[2 + perm[i]];
            }
            hdr = 13;
        }
        else if (c == 0x43) {
            // meter -> display: f[11..18] display address (already permuted)
            if (flen < 30) {
                ret = DECODE_ABORT_LENGTH;
                continue;
            }
            memcpy(iv, &f[11], 8);
            hdr = 21;
        }
        else {
            decoder_logf(decoder, 2, __func__, "Unhandled frame type 0x%02x", c);
            ret = DECODE_FAIL_OTHER;
            continue;
        }

        unsigned enc_len = f[hdr + 2];
        unsigned ct_pos  = hdr + 8;
        if (ct_pos + enc_len + 12 + 2 > flen) {
            ret = DECODE_ABORT_LENGTH;
            continue;
        }
        memcpy(&iv[8], &f[hdr + 4], 4);
        uint32_t ctr = (uint32_t)f[hdr + 4] << 24 | (uint32_t)f[hdr + 5] << 16 | (uint32_t)f[hdr + 6] << 8 | f[hdr + 7];

        if (!ctx->have_key) {
            decoder_log(decoder, 1, __func__, "No meter serial given, can't decrypt");
            return DECODE_FAIL_OTHER;
        }
        uint8_t pt[256];
        if (aes128_gcm_decrypt(ctx->key, iv, &f[hdr], 4, &f[ct_pos], enc_len, &f[ct_pos + enc_len], 12, pt) != 0) {
            decoder_logf(decoder, 1, __func__, "Frame 0x%02x ctr %u: GCM tag mismatch (wrong serial?)", c, ctr);
            ret = DECODE_FAIL_MIC;
            continue;
        }
        decoder_logf(decoder, 2, __func__, "Frame 0x%02x ctr %u decrypted", c, ctr);
        decoder_log_bitrow(decoder, 2, __func__, pt, enc_len * 8, "plaintext");

        int r = c == 0x44 ? nartis_parse_request(decoder, ctx, ctr, pt, enc_len)
                          : nartis_parse_response(decoder, ctx, ctr, pt, enc_len);
        // a request alone produces no output, but is a valid decode
        if (r > 0 && c == 0x43) {
            return r;
        }
        ret = r > 0 ? DECODE_FAIL_OTHER : r;
    }
    return ret;
}

static char const *const output_fields[] = {
        "model",
        "id",
        "voltage_L1_V",
        "voltage_L2_V",
        "voltage_L3_V",
        "voltage_L1L2_V",
        "voltage_L2L3_V",
        "voltage_L3L1_V",
        "current_L1_A",
        "current_L2_A",
        "current_L3_A",
        "current_N_A",
        "power_W",
        "power_L1_W",
        "power_L2_W",
        "power_L3_W",
        "reactive_power_var",
        "reactive_power_L1_var",
        "reactive_power_L2_var",
        "reactive_power_L3_var",
        "frequency_Hz",
        "energy_kWh",
        "energy_T1_kWh",
        "energy_T2_kWh",
        "energy_T3_kWh",
        "energy_T4_kWh",
        "energy_export_kWh",
        "energy_reactive_import_kvarh",
        "energy_reactive_export_kvarh",
        "energy_last_month_kWh",
        "temperature_C",
        "meter_time",
        "mic",
        NULL,
};

r_device const nartis_d101;

static r_device *nartis_d101_create(char const *arg)
{
    r_device *r_dev = decoder_create(&nartis_d101, sizeof(struct nartis_context));
    if (!r_dev) {
        return NULL;
    }
    struct nartis_context *ctx = decoder_user_data(r_dev);

    if (arg && !strncmp(arg, "serial=", 7)) {
        arg += 7;
    }
    if (arg && strlen(arg) == 12 && strspn(arg, "0123456789") == 12) {
        static uint8_t const suffix[4] = {0xbd, 0x02, 0x9b, 0xbe};
        memcpy(ctx->serial, arg, 12);
        memcpy(ctx->key, arg, 12);
        memcpy(ctx->key + 12, suffix, 4);
        ctx->have_key = 1;
    }
    else {
        fprintf(stderr, "Nartis: give the 12 digit meter serial, e.g. -R %s:012345678901\n", "<num>");
    }
    return r_dev;
}

r_device const nartis_d101 = {
        .name        = "Nartis I100/I300/I500 electricity meter with D101 display (needs serial, -R <num>:<serial>)",
        .modulation  = FSK_PULSE_PCM,
        .short_width = 417,
        .long_width  = 417,
        .reset_limit = 30000, // header has 32+ zero bits in a row
        .decode_fn   = &nartis_d101_decode,
        .create_fn   = &nartis_d101_create,
        .fields      = output_fields,
        .disabled    = 1,
};
