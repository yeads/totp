#include "dostotp.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned checks;
#define CHECK(expr) do { ++checks; if (!(expr)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); exit(1); } } while (0)

static Account example(void)
{
    Account a = {"Example", "alice@example.com", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", HASH_SHA1, 6, 30};
    return a;
}

static void encode(const unsigned char *data, size_t n, char *out)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    unsigned bits = 0, count = 0;
    size_t i, used = 0;
    for (i = 0; i < n; ++i) {
        bits = (bits << 8) | data[i]; count += 8;
        while (count >= 5) { count -= 5; out[used++] = alphabet[(bits >> count) & 31]; }
    }
    if (count) out[used++] = alphabet[(bits << (5 - count)) & 31];
    out[used] = 0;
}

static void test_rfc(void)
{
    const uint64_t times[] = {59, 1111111109, 1111111111, 1234567890, 2000000000, UINT64_C(20000000000)};
    const char *expected[][3] = {
        {"94287082", "46119246", "90693936"}, {"07081804", "68084774", "25091201"},
        {"14050471", "67062674", "99943326"}, {"89005924", "91819424", "93441116"},
        {"69279037", "90698825", "38618901"}, {"65353130", "77737706", "47863826"}
    };
    const unsigned char seed[] = "1234567890123456789012345678901234567890123456789012345678901234";
    const size_t lengths[] = {20, 32, 64};
    size_t i, j;
    Account a = example();
    char code[9], before[9];
    a.digits = 8;
    for (i = 0; i < 6; ++i) for (j = 0; j < 3; ++j) {
        a.hash = (Hash)(j + 1); encode(seed, lengths[j], a.secret);
        CHECK(totp_code(&a, times[i], code)); CHECK(!strcmp(code, expected[i][j]));
    }
    a = example();
    CHECK(totp_code(&a, 59, code)); CHECK(!strcmp(code, "287082"));
    CHECK(totp_code(&a, 30, before)); CHECK(!strcmp(before, code));
    CHECK(totp_code(&a, 60, before)); CHECK(strcmp(before, code));
    a.period = 60;
    CHECK(totp_code(&a, 119, before)); CHECK(!strcmp(before, code));
    a.period = 0; CHECK(!totp_code(&a, 59, code));
    a = example(); a.digits = 7; CHECK(!totp_code(&a, 59, code));
}

static void test_base32(void)
{
    const char *encoded[] = {"MY======", "MZXQ====", "MZXW6===", "MZXW6YQ=", "MZXW6YTB", "MZXW6YTBOI======"};
    const char *decoded[] = {"f", "fo", "foo", "foob", "fooba", "foobar"};
    const char *bad[] = {"", "A", "AAA", "AAAAAA", "MZ", "M1======", "MY=", "MY=======", "MY======A", "!", "01234567"};
    unsigned char buf[128];
    size_t n, i;
    for (i = 0; i < 6; ++i) {
        CHECK(base32_decode(encoded[i], buf, sizeof(buf), &n));
        CHECK(n == strlen(decoded[i]) && !memcmp(buf, decoded[i], n));
    }
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) CHECK(!base32_decode(bad[i], buf, sizeof(buf), &n));
    CHECK(base32_decode("mzxw 6y-tb oi======", buf, sizeof(buf), &n));
    CHECK(n == 6 && !memcmp(buf, "foobar", 6));
    CHECK(!base32_decode("MZXW6YTBOI======", buf, 5, &n));
}

static void test_uri(void)
{
    Account a, b;
    char error[ERROR_CAP], uri[URI_CAP];
    const char *bad[] = {
        "otpauth://hotp/A?secret=MY", "otpauth://totp/A", "otpauth://totp/A?issuer=X",
        "otpauth://totp/A?secret=MY&secret=MY", "otpauth://totp/A?secret=MZ",
        "otpauth://totp/A?secret=MY&digits=7", "otpauth://totp/A?secret=MY&period=0",
        "otpauth://totp/A?secret=MY&period=-1", "otpauth://totp/A?secret=MY&algorithm=MD5",
        "otpauth://totp/%00A?secret=MY", "otpauth://totp/%1BA?secret=MY",
        "otpauth://totp/%QQ?secret=MY", "otpauth://totp/%?secret=MY",
        "otpauth://totp/A:B?secret=MY&issuer=C", "otpauth://totp/A?secret=MY#x",
        "otpauth://totp/?secret=MY", "otpauth://totp/A?secret=MY&period=9999999999"
    };
    size_t i;
    CHECK(account_from_uri("otpauth://totp/Example%20%26%20Co:alice%2Bdev%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example+%26+Co&algorithm=sha256&digits=8&period=60", &a, error));
    CHECK(!strcmp(a.issuer, "Example & Co") && !strcmp(a.label, "alice+dev@example.com"));
    CHECK(a.hash == HASH_SHA256 && a.digits == 8 && a.period == 60);
    CHECK(account_to_uri(&a, uri, sizeof(uri))); CHECK(account_from_uri(uri, &b, error));
    CHECK(!strcmp(a.issuer, b.issuer) && !strcmp(a.label, b.label) && !strcmp(a.secret, b.secret));
    CHECK(a.hash == b.hash && a.digits == b.digits && a.period == b.period);
    CHECK(account_from_uri("otpauth://totp/alice?secret=MY", &b, error));
    CHECK(b.hash == HASH_SHA1 && b.digits == 6 && b.period == 30 && !b.issuer[0]);
    CHECK(!account_to_uri(&a, uri, 10));
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) CHECK(!account_from_uri(bad[i], &b, error));
    a = example(); strcpy(a.label, "账户"); strcpy(a.issuer, "邮件");
    CHECK(account_to_uri(&a, uri, sizeof(uri))); CHECK(account_from_uri(uri, &b, error));
    CHECK(!strcmp(a.label, b.label) && !strcmp(a.issuer, b.issuer));
    strcpy(a.issuer, "ambiguous:issuer"); CHECK(!account_to_uri(&a, uri, sizeof(uri)));
    a = example(); strcpy(a.label, "ambiguous:label"); CHECK(!account_validate(&a, error));
}

static unsigned char *read_file(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    long size;
    unsigned char *data;
    CHECK(f != NULL); CHECK(fseek(f, 0, SEEK_END) == 0);
    size = ftell(f); CHECK(size >= 0); *n = (size_t)size;
    rewind(f); data = malloc(*n); CHECK(data != NULL);
    CHECK(fread(data, 1, *n, f) == *n); CHECK(fclose(f) == 0);
    return data;
}

static void write_file(const char *path, const unsigned char *data, size_t n)
{
    FILE *f = fopen(path, "wb");
    CHECK(f != NULL); CHECK(fwrite(data, 1, n, f) == n); CHECK(fclose(f) == 0);
}

static void test_vault(void)
{
    char directory[] = "/tmp/dostotp-test-XXXXXX", path[PATH_CAP], badpath[PATH_CAP], lockpath[PATH_CAP], error[ERROR_CAP];
    Vault *v = calloc(1, sizeof(*v)), *loaded = calloc(1, sizeof(*loaded));
    VaultKey key = {{0}, {0}, 0}, loaded_key = {{0}, {0}, 0}, newkey = {{0}, {0}, 0};
    struct stat st;
    unsigned char *first, *second;
    size_t n, n2, i, tamper_offsets[] = {0, 8, 12, 28, 40, 44};
    int fd, status;
    pid_t child;
    CHECK(v && loaded); CHECK(mkdtemp(directory) != NULL);
    snprintf(path, sizeof(path), "%s/accounts.vault", directory);
    snprintf(badpath, sizeof(badpath), "%s/bad.vault", directory);
    snprintf(lockpath, sizeof(lockpath), "%s/accounts.vault.lock", directory);
    CHECK(vault_key_create("correct horse battery staple", &key, error));
    CHECK(vault_save(path, v, &key, error));
    CHECK(vault_load(path, "correct horse battery staple", loaded, &loaded_key, error));
    CHECK(loaded->count == 0);
    v->accounts[0] = example(); v->count = 1;
    CHECK(vault_save(path, v, &key, error));
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    first = read_file(path, &n);
    for (i = 0; i + strlen(v->accounts[0].secret) <= n; ++i)
        CHECK(memcmp(first + i, v->accounts[0].secret, strlen(v->accounts[0].secret)) != 0);
    CHECK(vault_save(path, v, &key, error)); second = read_file(path, &n2);
    CHECK(n == n2 && memcmp(first + 28, second + 28, 12));
    CHECK(vault_load(path, "correct horse battery staple", loaded, &loaded_key, error));
    CHECK(loaded->count == 1 && !strcmp(loaded->accounts[0].secret, v->accounts[0].secret));
    CHECK(!vault_load(path, "wrong password", loaded, &loaded_key, error));
    CHECK(loaded->count == 1 && !strcmp(loaded->accounts[0].label, "alice@example.com"));
    for (i = 0; i < sizeof(tamper_offsets) / sizeof(tamper_offsets[0]); ++i) {
        first[tamper_offsets[i]] ^= 1; write_file(badpath, first, n);
        CHECK(!vault_load(badpath, "correct horse battery staple", loaded, &loaded_key, error));
        first[tamper_offsets[i]] ^= 1;
    }
    first[n - 1] ^= 1; write_file(badpath, first, n);
    CHECK(!vault_load(badpath, "correct horse battery staple", loaded, &loaded_key, error));
    write_file(badpath, first, 20);
    CHECK(!vault_load(badpath, "correct horse battery staple", loaded, &loaded_key, error));
    CHECK(vault_key_create("new password", &newkey, error));
    CHECK(vault_save(path, v, &newkey, error));
    CHECK(!vault_load(path, "correct horse battery staple", loaded, &loaded_key, error));
    CHECK(vault_load(path, "new password", loaded, &loaded_key, error));
    CHECK(!vault_save("/no-such-dostotp-directory/vault", v, &key, error));
    CHECK(vault_load(path, "new password", loaded, &loaded_key, error));
    /* Exercise maximum-size payload and UTF-8 metadata. */
    for (i = 0; i < MAX_ACCOUNTS; ++i) {
        Account *a = &v->accounts[i];
        *a = example();
        memset(a->issuer, 'I', TEXT_CAP - 1); a->issuer[TEXT_CAP - 1] = 0;
        memset(a->label, 'L', TEXT_CAP - 1); a->label[TEXT_CAP - 1] = 0;
        memset(a->secret, 'A', SECRET_CAP - 4); a->secret[SECRET_CAP - 4] = 0;
    }
    v->count = MAX_ACCOUNTS;
    CHECK(vault_save(path, v, &newkey, error));
    CHECK(vault_load(path, "new password", loaded, &loaded_key, error));
    CHECK(loaded->count == MAX_ACCOUNTS && strlen(loaded->accounts[255].secret) == SECRET_CAP - 4);
    fd = vault_lock_file(path, error); CHECK(fd >= 0);
    child = fork(); CHECK(child >= 0);
    if (child == 0) { int other = vault_lock_file(path, error); _exit(other < 0 ? 0 : 1); }
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(fd);
    CHECK(unlink(badpath) == 0); CHECK(symlink(path, badpath) == 0);
    CHECK(!vault_load(badpath, "new password", loaded, &loaded_key, error));
    unlink(badpath); unlink(path); unlink(lockpath); rmdir(directory);
    free(first); free(second);
    secure_clear(v, sizeof(*v)); secure_clear(loaded, sizeof(*loaded)); free(v); free(loaded);
    secure_clear(&key, sizeof(key)); secure_clear(&newkey, sizeof(newkey)); secure_clear(&loaded_key, sizeof(loaded_key));
}

int main(void)
{
    test_rfc(); test_base32(); test_uri(); test_vault();
    printf("PASS: %u core checks (RFC 6238, Base32, URI, encryption, locking).\n", checks);
    return 0;
}
