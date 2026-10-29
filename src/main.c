#include "dostotp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

static void usage(void)
{
    puts("TOTP Utilities " APP_VERSION " -- Norton-inspired authenticator\n"
         "\nUsage: dostotp [--vault PATH] [--demo] [--ansi] [--timeout SECONDS]\n"
         "\n  --vault PATH       Open an encrypted vault at PATH\n"
         "  --demo             Explore sample accounts; nothing is saved\n"
         "  --ansi             Use the terminal's standard 16-color palette\n"
         "  --timeout SECONDS  Auto-lock after inactivity (default 300, 0 disables)\n"
         "  --help             Show this help\n"
         "  --version          Show version\n"
         "\nKeys: F1 Help, F2 Add, F3 Edit, F4 Import, F5 Reveal, F6 Lock,\n"
         "      F7 Find, F8 Delete, F9 Setup, F10 Menu. Arrows select. Q quits.\n"
         "\nRequires an interactive UTF-8 terminal, at least 76 columns x 24 rows.\n"
         "Default vault: $XDG_DATA_HOME/dostotp/accounts.vault, or\n"
         "               $HOME/.local/share/dostotp/accounts.vault");
}

int main(int argc, char **argv)
{
    char path[PATH_CAP] = "", error[ERROR_CAP];
    int i, demo = 0, ansi = 0;
    unsigned timeout = 300;
    struct rlimit core_limit = {0, 0};
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) { usage(); return 0; }
        if (!strcmp(argv[i], "--version")) { puts("dostotp " APP_VERSION); return 0; }
        if (!strcmp(argv[i], "--demo")) demo = 1;
        else if (!strcmp(argv[i], "--ansi")) ansi = 1;
        else if (!strcmp(argv[i], "--vault") && i + 1 < argc) {
            if (!argv[i + 1][0] || strlen(argv[i + 1]) >= sizeof(path) - 16) {
                fputs("Invalid or excessively long vault path.\n", stderr); return 2;
            }
            strcpy(path, argv[++i]);
        } else if (!strcmp(argv[i], "--timeout") && i + 1 < argc) {
            char *end;
            unsigned long n = strtoul(argv[++i], &end, 10);
            if (!argv[i][0] || *end || n > 86400) {
                fputs("Timeout must be 0-86400 seconds.\n", stderr); return 2;
            }
            timeout = (unsigned)n;
        } else { fprintf(stderr, "Unknown or incomplete option: %s\n", argv[i]); return 2; }
    }
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        fputs("dostotp needs an interactive terminal. Try --help.\n", stderr); return 1;
    }
    if (getenv("TERM") && !strcmp(getenv("TERM"), "dumb")) {
        fputs("A terminal with ANSI cursor and color support is required.\n", stderr); return 1;
    }
    umask(0077);
    (void)setrlimit(RLIMIT_CORE, &core_limit);
    if (!demo && !path[0] && !vault_default_path(path, sizeof(path), error)) {
        fprintf(stderr, "%s\n", error); return 1;
    }
    return ui_run(path, demo, ansi, timeout);
}
