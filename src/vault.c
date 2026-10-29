#include "dostotp.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define HEADER_SIZE 44U
#define TAG_SIZE 16U
#define MAX_PAYLOAD (4U + MAX_ACCOUNTS * (TEXT_CAP * 2U + SECRET_CAP + 12U))

static int fail(char *error, const char *message)
{
    snprintf(error, ERROR_CAP, "%s", message);
    return 0;
}

static int syserror(char *error, const char *action)
{
    snprintf(error, ERROR_CAP, "%s: %s", action, strerror(errno));
    return 0;
}

static void put32(unsigned char *p, uint32_t n)
{
    p[0] = (unsigned char)(n >> 24); p[1] = (unsigned char)(n >> 16);
    p[2] = (unsigned char)(n >> 8); p[3] = (unsigned char)n;
}

static uint32_t get32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static int derive(const char *password, VaultKey *key, char *error)
{
    size_t len = strlen(password);
    if (!len || len >= PASSWORD_CAP) return fail(error, "Password must be 1-255 bytes.");
    if (PKCS5_PBKDF2_HMAC(password, (int)len, key->salt, sizeof(key->salt),
                         (int)KDF_ITERATIONS, EVP_sha256(), sizeof(key->key), key->key) != 1)
        return fail(error, "OpenSSL could not derive the encryption key.");
    key->ready = 1;
    return 1;
}

int vault_key_create(const char *password, VaultKey *key, char *error)
{
    VaultKey candidate = {{0}, {0}, 0};
    int ok = 0;
    if (RAND_bytes(candidate.salt, sizeof(candidate.salt)) != 1)
        fail(error, "OpenSSL random generator failed.");
    else if (derive(password, &candidate, error)) { *key = candidate; ok = 1; }
    secure_clear(&candidate, sizeof(candidate));
    return ok;
}

static void pack_string(unsigned char **p, const char *s)
{
    size_t n = strlen(s);
    (*p)[0] = (unsigned char)(n >> 8); (*p)[1] = (unsigned char)n;
    memcpy(*p + 2, s, n);
    *p += n + 2;
}

static int unpack_string(const unsigned char **p, const unsigned char *end, char *out, size_t cap)
{
    size_t n;
    if (end - *p < 2) return 0;
    n = ((size_t)(*p)[0] << 8) | (*p)[1];
    *p += 2;
    if (n >= cap || (size_t)(end - *p) < n || memchr(*p, 0, n)) return 0;
    memcpy(out, *p, n); out[n] = 0; *p += n;
    return 1;
}

static int unpack(const unsigned char *data, size_t n, Vault *vault, char *error)
{
    const unsigned char *p = data + 4, *end = data + n;
    size_t i;
    if (n < 4 || get32(data) > MAX_ACCOUNTS) return fail(error, "Invalid vault account count.");
    vault->count = get32(data);
    for (i = 0; i < vault->count; ++i) {
        Account *a = &vault->accounts[i];
        if (!unpack_string(&p, end, a->issuer, sizeof(a->issuer))
            || !unpack_string(&p, end, a->label, sizeof(a->label))
            || !unpack_string(&p, end, a->secret, sizeof(a->secret)) || end - p < 6)
            return fail(error, "Invalid vault account data.");
        a->hash = (Hash)p[0]; a->digits = p[1]; a->period = get32(p + 2); p += 6;
        if (!account_validate(a, error)) return 0;
    }
    return p == end ? 1 : fail(error, "Unexpected trailing vault data.");
}

static int read_all(int fd, unsigned char *data, size_t n)
{
    while (n) {
        ssize_t r = read(fd, data, n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return 0;
        data += r; n -= (size_t)r;
    }
    return 1;
}

static int write_all(int fd, const unsigned char *data, size_t n)
{
    while (n) {
        ssize_t r = write(fd, data, n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return 0;
        data += r; n -= (size_t)r;
    }
    return 1;
}

int vault_load(const char *path, const char *password, Vault *vault, VaultKey *key, char *error)
{
    int fd = -1, ok = 0, n = 0, final_n = 0;
    struct stat st;
    size_t file_size = 0, payload_size = 0;
    unsigned char *file = NULL, *plain = NULL;
    Vault *candidate = NULL;
    VaultKey candidate_key = {{0}, {0}, 0};
    EVP_CIPHER_CTX *ctx = NULL;
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return syserror(error, "Cannot open vault");
    if (fstat(fd, &st) < 0) { syserror(error, "Cannot inspect vault"); goto done; }
    if (!S_ISREG(st.st_mode) || st.st_size < (off_t)(HEADER_SIZE + TAG_SIZE + 4)
        || st.st_size > (off_t)(HEADER_SIZE + TAG_SIZE + MAX_PAYLOAD)) {
        fail(error, "Not a valid TOTP vault file."); goto done;
    }
    file_size = (size_t)st.st_size;
    file = malloc(file_size);
    if (!file) { fail(error, "Out of memory."); goto done; }
    if (!read_all(fd, file, file_size)) { fail(error, "Could not read the complete vault."); goto done; }
    if (memcmp(file, "DOSOTP01", 8) || get32(file + 8) != KDF_ITERATIONS) {
        fail(error, "Unsupported or damaged vault header."); goto done;
    }
    payload_size = get32(file + 40);
    if (payload_size != file_size - HEADER_SIZE - TAG_SIZE) {
        fail(error, "Invalid vault length."); goto done;
    }
    memcpy(candidate_key.salt, file + 12, sizeof(candidate_key.salt));
    if (!derive(password, &candidate_key, error)) goto done;
    plain = malloc(payload_size);
    candidate = calloc(1, sizeof(*candidate));
    ctx = EVP_CIPHER_CTX_new();
    if (!plain || !candidate || !ctx) { fail(error, "Out of memory."); goto done; }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, candidate_key.key, file + 28) != 1
        || EVP_DecryptUpdate(ctx, NULL, &n, file, HEADER_SIZE) != 1
        || EVP_DecryptUpdate(ctx, plain, &n, file + HEADER_SIZE, (int)payload_size) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, file + HEADER_SIZE + payload_size) != 1
        || EVP_DecryptFinal_ex(ctx, plain + n, &final_n) != 1) {
        fail(error, "Wrong password or damaged vault (authentication failed)."); goto done;
    }
    if ((size_t)(n + final_n) != payload_size || !unpack(plain, payload_size, candidate, error)) goto done;
    *vault = *candidate; *key = candidate_key; ok = 1;
done:
    if (fd >= 0) close(fd);
    EVP_CIPHER_CTX_free(ctx);
    if (plain) { secure_clear(plain, payload_size); free(plain); }
    if (candidate) { secure_clear(candidate, sizeof(*candidate)); free(candidate); }
    secure_clear(&candidate_key, sizeof(candidate_key));
    free(file);
    return ok;
}

static int atomic_write(const char *path, const unsigned char *data, size_t n, char *error)
{
    char temp[PATH_CAP], directory[PATH_CAP], *slash;
    int fd, dirfd, ok = 0;
    if (snprintf(temp, sizeof(temp), "%s.tmp.XXXXXX", path) >= (int)sizeof(temp))
        return fail(error, "Vault path is too long.");
    snprintf(directory, sizeof(directory), "%s", path);
    slash = strrchr(directory, '/');
    if (!slash) strcpy(directory, ".");
    else if (slash == directory) slash[1] = 0;
    else *slash = 0;
    dirfd = open(directory, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) return syserror(error, "Cannot open vault directory");
    fd = mkstemp(temp);
    if (fd < 0) { close(dirfd); return syserror(error, "Cannot create temporary vault"); }
    if (fchmod(fd, S_IRUSR | S_IWUSR) < 0 || !write_all(fd, data, n) || fsync(fd) < 0)
        syserror(error, "Cannot write vault");
    else ok = 1;
    if (close(fd) < 0 && ok) { syserror(error, "Cannot close vault"); ok = 0; }
    if (ok && rename(temp, path) < 0) { syserror(error, "Cannot replace vault"); ok = 0; }
    if (ok) {
        /* The rename is committed. Some filesystems do not support directory fsync. */
        (void)fsync(dirfd);
    } else unlink(temp);
    close(dirfd);
    return ok;
}

int vault_save(const char *path, const Vault *vault, const VaultKey *key, char *error)
{
    unsigned char *plain = NULL, *file = NULL, *p;
    EVP_CIPHER_CTX *ctx = NULL;
    size_t i, payload_size = 0;
    int n = 0, final_n = 0, ok = 0;
    if (!key->ready || vault->count > MAX_ACCOUNTS) return fail(error, "Vault is not ready.");
    for (i = 0; i < vault->count; ++i) if (!account_validate(&vault->accounts[i], error)) return 0;
    plain = malloc(MAX_PAYLOAD);
    file = malloc(HEADER_SIZE + MAX_PAYLOAD + TAG_SIZE);
    ctx = EVP_CIPHER_CTX_new();
    if (!plain || !file || !ctx) { fail(error, "Out of memory."); goto done; }
    put32(plain, (uint32_t)vault->count); p = plain + 4;
    for (i = 0; i < vault->count; ++i) {
        const Account *a = &vault->accounts[i];
        pack_string(&p, a->issuer); pack_string(&p, a->label); pack_string(&p, a->secret);
        *p++ = (unsigned char)a->hash; *p++ = (unsigned char)a->digits;
        put32(p, a->period); p += 4;
    }
    payload_size = (size_t)(p - plain);
    memcpy(file, "DOSOTP01", 8); put32(file + 8, KDF_ITERATIONS);
    memcpy(file + 12, key->salt, sizeof(key->salt));
    put32(file + 40, (uint32_t)payload_size);
    if (RAND_bytes(file + 28, 12) != 1
        || EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key->key, file + 28) != 1
        || EVP_EncryptUpdate(ctx, NULL, &n, file, HEADER_SIZE) != 1
        || EVP_EncryptUpdate(ctx, file + HEADER_SIZE, &n, plain, (int)payload_size) != 1
        || EVP_EncryptFinal_ex(ctx, file + HEADER_SIZE + n, &final_n) != 1
        || (size_t)(n + final_n) != payload_size
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, file + HEADER_SIZE + payload_size) != 1) {
        fail(error, "OpenSSL vault encryption failed."); goto done;
    }
    ok = atomic_write(path, file, HEADER_SIZE + payload_size + TAG_SIZE, error);
done:
    EVP_CIPHER_CTX_free(ctx);
    if (plain) { secure_clear(plain, MAX_PAYLOAD); free(plain); }
    free(file);
    return ok;
}

int vault_lock_file(const char *path, char *error)
{
    char lockpath[PATH_CAP];
    struct flock lock;
    struct stat st;
    int fd;
    if (snprintf(lockpath, sizeof(lockpath), "%s.lock", path) >= (int)sizeof(lockpath)) {
        fail(error, "Vault path is too long."); return -1;
    }
    fd = open(lockpath, O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK, S_IRUSR | S_IWUSR);
    if (fd < 0) { syserror(error, "Cannot open vault lock"); return -1; }
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != getuid()) {
        fail(error, "Vault lock must be a regular file owned by you."); close(fd); return -1;
    }
    memset(&lock, 0, sizeof(lock)); lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET;
    if (fcntl(fd, F_SETLK, &lock) < 0) {
        fail(error, "Vault is already open in another process."); close(fd); return -1;
    }
    return fd;
}

int vault_default_path(char *path, size_t cap, char *error)
{
    const char *base = getenv("XDG_DATA_HOME");
    const char *home = getenv("HOME");
    char directory[PATH_CAP], *p;
    struct stat st;
    int n;
    if (base && base[0] == '/') n = snprintf(directory, sizeof(directory), "%s/dostotp", base);
    else if (home && home[0] == '/') n = snprintf(directory, sizeof(directory), "%s/.local/share/dostotp", home);
    else return fail(error, "Set HOME or XDG_DATA_HOME, or pass --vault PATH.");
    if (n < 0 || (size_t)n >= sizeof(directory)) return fail(error, "Data directory path is too long.");
    for (p = directory + 1; ; ++p) {
        char saved = *p;
        if (saved != '/' && saved != 0) continue;
        *p = 0;
        if (mkdir(directory, 0700) < 0 && errno != EEXIST) return syserror(error, "Cannot create data directory");
        if (stat(directory, &st) < 0 || !S_ISDIR(st.st_mode)) return fail(error, "Data path is not a directory.");
        *p = saved;
        if (!saved) break;
    }
    n = snprintf(path, cap, "%s/accounts.vault", directory);
    return n >= 0 && (size_t)n < cap ? 1 : fail(error, "Vault path is too long.");
}
