#include "dostotp.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

void secure_clear(void *ptr, size_t size)
{
    OPENSSL_cleanse(ptr, size);
}

static int fail(char *error, const char *message)
{
    if (error) snprintf(error, ERROR_CAP, "%s", message);
    return 0;
}

const char *hash_name(Hash hash)
{
    switch (hash) {
    case HASH_SHA1: return "SHA1";
    case HASH_SHA256: return "SHA256";
    case HASH_SHA512: return "SHA512";
    }
    return "UNKNOWN";
}

int base32_decode(const char *text, unsigned char *out, size_t cap, size_t *len)
{
    uint32_t bits = 0;
    unsigned count = 0;
    size_t used = 0, symbols = 0, padding = 0;
    const unsigned char *p = (const unsigned char *)text;
    for (; *p; ++p) {
        unsigned value;
        int c = toupper(*p);
        if (isspace(*p) || c == '-') continue;
        if (c == '=') { ++padding; continue; }
        if (padding) return 0;
        if (c >= 'A' && c <= 'Z') value = (unsigned)(c - 'A');
        else if (c >= '2' && c <= '7') value = (unsigned)(c - '2' + 26);
        else return 0;
        ++symbols;
        bits = (bits << 5) | value;
        count += 5;
        if (count >= 8) {
            count -= 8;
            if (used >= cap) return 0;
            out[used++] = (unsigned char)(bits >> count);
        }
    }
    if (!used || count >= 5 || (count && (bits & ((1U << count) - 1U)))) return 0;
    if (padding && (padding > 6 || (symbols + padding) % 8)) return 0;
    *len = used;
    return 1;
}

static int safe_text(const char *s, size_t cap, int required)
{
    size_t i;
    if (required && !s[0]) return 0;
    for (i = 0; i < cap; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (!c) return 1;
        if (c < 32 || c == 127) return 0;
    }
    return 0;
}

int account_validate(const Account *a, char *error)
{
    unsigned char decoded[128];
    size_t n = 0;
    int valid;
    if (!safe_text(a->label, sizeof(a->label), 1))
        return fail(error, "Account name is required (maximum 95 bytes; no controls).");
    if (!safe_text(a->issuer, sizeof(a->issuer), 0))
        return fail(error, "Issuer is too long or contains control characters.");
    if (strchr(a->issuer, ':') || strchr(a->label, ':'))
        return fail(error, "Issuer and account name cannot contain ':' (URI separator).");
    if (!memchr(a->secret, 0, sizeof(a->secret)))
        return fail(error, "Secret is too long.");
    if (a->hash < HASH_SHA1 || a->hash > HASH_SHA512)
        return fail(error, "Algorithm must be SHA1, SHA256 or SHA512.");
    if (a->digits != 6 && a->digits != 8)
        return fail(error, "Digits must be 6 or 8.");
    if (a->period < 1 || a->period > 300)
        return fail(error, "Period must be between 1 and 300 seconds.");
    valid = base32_decode(a->secret, decoded, sizeof(decoded), &n);
    secure_clear(decoded, sizeof(decoded));
    if (!valid) return fail(error, "Invalid Base32 secret. Use letters A-Z and digits 2-7.");
    return 1;
}

int totp_code(const Account *a, uint64_t timestamp, char out[9])
{
    unsigned char secret[128], digest[EVP_MAX_MD_SIZE], counter[8];
    size_t secret_len = 0;
    unsigned digest_len = 0, offset, binary, mod;
    uint64_t step;
    const EVP_MD *md;
    int i, ok = 0;
    if (!account_validate(a, NULL)) return 0;
    if (!base32_decode(a->secret, secret, sizeof(secret), &secret_len)) goto done;
    md = a->hash == HASH_SHA256 ? EVP_sha256() : a->hash == HASH_SHA512 ? EVP_sha512() : EVP_sha1();
    step = timestamp / a->period;
    for (i = 7; i >= 0; --i) { counter[i] = (unsigned char)step; step >>= 8; }
    if (!HMAC(md, secret, (int)secret_len, counter, sizeof(counter), digest, &digest_len)) goto done;
    offset = digest[digest_len - 1] & 15U;
    binary = ((unsigned)(digest[offset] & 127U) << 24)
           | ((unsigned)digest[offset + 1] << 16)
           | ((unsigned)digest[offset + 2] << 8)
           | digest[offset + 3];
    mod = a->digits == 8 ? 100000000U : 1000000U;
    snprintf(out, 9, "%0*u", (int)a->digits, binary % mod);
    ok = 1;
done:
    secure_clear(secret, sizeof(secret));
    secure_clear(digest, sizeof(digest));
    return ok;
}

static int hex_value(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int percent_decode(const char *src, size_t n, char *dst, size_t cap, int query)
{
    size_t i, used = 0;
    for (i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)src[i];
        if (c == '%') {
            int hi, lo;
            if (i + 2 >= n) return 0;
            hi = hex_value((unsigned char)src[i + 1]);
            lo = hex_value((unsigned char)src[i + 2]);
            if (hi < 0 || lo < 0) return 0;
            c = (unsigned char)((hi << 4) | lo);
            i += 2;
        } else if (query && c == '+') c = ' ';
        if (c < 32 || c == 127 || used + 1 >= cap) return 0;
        dst[used++] = (char)c;
    }
    dst[used] = 0;
    return 1;
}

static int number(const char *s, unsigned *value)
{
    unsigned v = 0;
    if (!*s) return 0;
    for (; *s; ++s) {
        if (*s < '0' || *s > '9' || v > 300) return 0;
        v = v * 10 + (unsigned)(*s - '0');
    }
    *value = v;
    return 1;
}

int account_from_uri(const char *uri, Account *account, char *error)
{
    Account a = {{0}, {0}, {0}, HASH_SHA1, 6, 30};
    char label[TEXT_CAP * 2], field[64], value[SECRET_CAP], prefix[TEXT_CAP] = "";
    const char *q, *p;
    char *colon;
    unsigned seen = 0;
    int ok = 0;
    if (strlen(uri) >= URI_CAP || strncmp(uri, "otpauth://totp/", 15) || strchr(uri, '#'))
        return fail(error, "Expected an otpauth://totp/ URI (HOTP is not supported).");
    q = strchr(uri + 15, '?');
    if (!q || !percent_decode(uri + 15, (size_t)(q - uri - 15), label, sizeof(label), 0))
        return fail(error, "Invalid URI label or percent encoding.");
    colon = strchr(label, ':');
    if (colon) {
        *colon++ = 0;
        while (*colon == ' ') ++colon;
        if (strlen(label) >= sizeof(prefix) || strlen(colon) >= sizeof(a.label))
            return fail(error, "Issuer or account name is too long.");
        strcpy(prefix, label);
        strcpy(a.label, colon);
    } else {
        if (strlen(label) >= sizeof(a.label)) return fail(error, "Account name is too long.");
        strcpy(a.label, label);
    }
    p = q + 1;
    while (*p) {
        const char *end = strchr(p, '&'), *eq;
        unsigned bit = 0;
        if (!end) end = p + strlen(p);
        eq = memchr(p, '=', (size_t)(end - p));
        if (!eq || !percent_decode(p, (size_t)(eq - p), field, sizeof(field), 1)
            || !percent_decode(eq + 1, (size_t)(end - eq - 1), value, sizeof(value), 1)) {
            fail(error, "Invalid URI parameter or percent encoding."); goto done;
        }
        if (!strcmp(field, "secret")) { bit = 1; strcpy(a.secret, value); }
        else if (!strcmp(field, "issuer")) {
            bit = 2;
            if (strlen(value) >= sizeof(a.issuer)) { fail(error, "Issuer is too long."); goto done; }
            strcpy(a.issuer, value);
        } else if (!strcmp(field, "algorithm")) {
            size_t i;
            bit = 4;
            for (i = 0; value[i]; ++i) value[i] = (char)toupper((unsigned char)value[i]);
            if (!strcmp(value, "SHA1")) a.hash = HASH_SHA1;
            else if (!strcmp(value, "SHA256")) a.hash = HASH_SHA256;
            else if (!strcmp(value, "SHA512")) a.hash = HASH_SHA512;
            else { fail(error, "Unsupported TOTP algorithm."); goto done; }
        } else if (!strcmp(field, "digits")) {
            bit = 8;
            if (!number(value, &a.digits)) { fail(error, "Invalid digit count."); goto done; }
        } else if (!strcmp(field, "period")) {
            bit = 16;
            if (!number(value, &a.period)) { fail(error, "Invalid period."); goto done; }
        }
        if (bit & seen) { fail(error, "Duplicate URI parameter."); goto done; }
        seen |= bit;
        p = *end ? end + 1 : end;
    }
    if (!(seen & 1)) { fail(error, "The URI has no secret."); goto done; }
    if (prefix[0] && (seen & 2) && strcmp(prefix, a.issuer)) {
        fail(error, "Issuer in label and query must agree."); goto done;
    }
    if (!(seen & 2)) strcpy(a.issuer, prefix);
    if (!account_validate(&a, error)) goto done;
    *account = a;
    ok = 1;
done:
    secure_clear(&a, sizeof(a));
    secure_clear(value, sizeof(value));
    return ok;
}

static int percent_encode(const char *src, char *dst, size_t cap)
{
    const char *hex = "0123456789ABCDEF";
    size_t used = 0;
    for (; *src; ++src) {
        unsigned char c = (unsigned char)*src;
        int plain = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || strchr("-._~", c);
        size_t n = plain ? 1U : 3U;
        if (used + n >= cap) return 0;
        if (plain) dst[used++] = (char)c;
        else { dst[used++] = '%'; dst[used++] = hex[c >> 4]; dst[used++] = hex[c & 15]; }
    }
    dst[used] = 0;
    return 1;
}

int account_to_uri(const Account *a, char *uri, size_t cap)
{
    char issuer[TEXT_CAP * 3], label[TEXT_CAP * 3], secret[SECRET_CAP * 3];
    int n;
    if (!account_validate(a, NULL) || !percent_encode(a->issuer, issuer, sizeof(issuer))
        || !percent_encode(a->label, label, sizeof(label))
        || !percent_encode(a->secret, secret, sizeof(secret))) return 0;
    n = snprintf(uri, cap, "otpauth://totp/%s%s%s?secret=%s&issuer=%s&algorithm=%s&digits=%u&period=%u",
                 issuer, *issuer ? ":" : "", label, secret, issuer,
                 hash_name(a->hash), a->digits, a->period);
    secure_clear(secret, sizeof(secret));
    return n >= 0 && (size_t)n < cap;
}
