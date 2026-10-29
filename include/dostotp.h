#ifndef DOSTOTP_H
#define DOSTOTP_H

#include <stddef.h>
#include <stdint.h>

#define APP_VERSION "1.0.0"
#define MAX_ACCOUNTS 256
#define TEXT_CAP 96
#define SECRET_CAP 209
#define URI_CAP 2048
#define ERROR_CAP 256
#define PASSWORD_CAP 256
#define PATH_CAP 4096
#define KDF_ITERATIONS 600000U

typedef enum { HASH_SHA1 = 1, HASH_SHA256 = 2, HASH_SHA512 = 3 } Hash;

typedef struct {
    char issuer[TEXT_CAP];
    char label[TEXT_CAP];
    char secret[SECRET_CAP];
    Hash hash;
    unsigned digits;
    unsigned period;
} Account;

typedef struct {
    size_t count;
    Account accounts[MAX_ACCOUNTS];
} Vault;

typedef struct {
    unsigned char key[32];
    unsigned char salt[16];
    int ready;
} VaultKey;

const char *hash_name(Hash hash);
int base32_decode(const char *text, unsigned char *out, size_t cap, size_t *len);
int account_validate(const Account *account, char *error);
int totp_code(const Account *account, uint64_t timestamp, char out[9]);
int account_from_uri(const char *uri, Account *account, char *error);
int account_to_uri(const Account *account, char *uri, size_t cap);

int vault_key_create(const char *password, VaultKey *key, char *error);
int vault_load(const char *path, const char *password, Vault *vault, VaultKey *key, char *error);
int vault_save(const char *path, const Vault *vault, const VaultKey *key, char *error);
int vault_lock_file(const char *path, char *error);
int vault_default_path(char *path, size_t cap, char *error);
void secure_clear(void *ptr, size_t size);

int ui_run(const char *path, int demo, int ansi, unsigned timeout);

#endif
