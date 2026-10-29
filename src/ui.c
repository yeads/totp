#include "dostotp.h"

#include <ctype.h>
#include <errno.h>
#include <locale.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

enum { DESKTOP, BLUE, WHITE, SELECTED, YELLOW, INPUT, RED, BLACK, MUTED, COLOR_COUNT };
enum { K_UP = 1001, K_DOWN, K_LEFT, K_RIGHT, K_HOME, K_END, K_PGUP, K_PGDN,
       K_DELETE, K_BACKTAB, K_F1 = 1101, K_LITERAL = 2000 };

#define SCREEN_COLS 240
#define SCREEN_ROWS 80

typedef struct {
    char text[32];                 /* UTF-8 glyph and optional combining marks */
    unsigned char bytes, width, style; /* width 0 is a wide glyph's second cell */
} Cell;

static struct {
    Cell next[SCREEN_ROWS][SCREEN_COLS], previous[SCREEN_ROWS][SCREEN_COLS];
    int valid, cols, rows, ansi;
} screen;
/* Per cell: at most 31 glyph bytes, a cursor address and one color escape. */
static char frame_output[SCREEN_ROWS * SCREEN_COLS * 128];

typedef struct {
    const char *label;
    char *value;
    size_t cap;
    int secret;
} Field;

typedef struct {
    Vault vault;
    VaultKey key;
    const char *path;
    int demo, ansi, cols, rows, selected, scroll, filtered[MAX_ACCOUNTS], matches;
    int unlocked, hidden;
    unsigned timeout;
    double activity;
    char search[TEXT_CAP], status[ERROR_CAP];
} App;

static App app;
static struct termios original_termios;
static int terminal_active, pasting;
static volatile sig_atomic_t interrupted, resize_pending;
static const char *rgb[COLOR_COUNT] = {
    "\033[38;2;255;255;255;48;2;80;88;80m",     /* desktop */
    "\033[38;2;255;255;255;48;2;85;85;255m",    /* Norton blue */
    "\033[38;2;0;0;170;48;2;255;255;255m",      /* title / menus */
    "\033[38;2;255;255;85;48;2;0;0;0m",         /* selection */
    "\033[38;2;255;255;85;48;2;85;85;255m",     /* highlighted text */
    "\033[38;2;0;0;0;48;2;255;255;255m",        /* input */
    "\033[38;2;170;0;0;48;2;255;255;255m",      /* footer / errors */
    "\033[38;2;255;255;255;48;2;0;0;0m",        /* shadow */
    "\033[38;2;170;170;170;48;2;85;85;255m"     /* secondary text */
};
static const char *ansi[COLOR_COUNT] = {
    "\033[0;97;100m", "\033[0;97;104m", "\033[0;34;107m",
    "\033[0;93;40m", "\033[0;93;104m", "\033[0;30;107m",
    "\033[0;31;107m", "\033[0;97;40m", "\033[0;37;104m"
};

static double monotime(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

static void signal_handler(int sig) { interrupted = sig; }
static void resize_handler(int sig) { (void)sig; resize_pending = 1; }

static void terminal_close(void)
{
    if (!terminal_active) return;
    fputs("\033[0m\033[?25h\033[?2004l\033[?1049l", stdout);
    fflush(stdout);
    (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_termios);
    terminal_active = 0;
    secure_clear(&screen, sizeof(screen));
    secure_clear(frame_output, sizeof(frame_output));
}

static int terminal_open(void)
{
    struct termios raw;
    struct sigaction action;
    if (tcgetattr(STDIN_FILENO, &original_termios) < 0) return 0;
    raw = original_termios;
    raw.c_lflag &= (tcflag_t)~(ECHO | ICANON | IEXTEN);
    raw.c_iflag &= (tcflag_t)~(IXON | ICRNL);
    raw.c_cc[VMIN] = 0; raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) < 0) return 0;
    terminal_active = 1;
    atexit(terminal_close);
    memset(&action, 0, sizeof(action));
    action.sa_handler = signal_handler;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL); sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP, &action, NULL); sigaction(SIGTSTP, &action, NULL);
    action.sa_handler = resize_handler;
    sigaction(SIGWINCH, &action, NULL);
    fputs("\033[?1049h\033[?2004h\033[?25l\033[2J", stdout);
    fflush(stdout);
    return 1;
}

static void dimensions(void)
{
    struct winsize ws;
    app.cols = 80; app.rows = 25;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        if (ws.ws_col) app.cols = ws.ws_col;
        if (ws.ws_row) app.rows = ws.ws_row;
    }
    if (app.cols > SCREEN_COLS) app.cols = SCREEN_COLS;
    if (app.rows > SCREEN_ROWS) app.rows = SCREEN_ROWS;
    if (resize_pending) { screen.valid = 0; resize_pending = 0; }
}

static void blank_cell(Cell *cell, int style)
{
    memset(cell, 0, sizeof(*cell));
    cell->text[0] = ' '; cell->bytes = 1; cell->width = 1;
    cell->style = (unsigned char)style;
}

/* Overwriting either half of a wide glyph must also erase its other half. */
static void erase_glyph(int x, int y)
{
    Cell *cell = &screen.next[y][x];
    if (!cell->width && x > 0 && screen.next[y][x - 1].width == 2)
        blank_cell(&screen.next[y][x - 1], cell->style);
    else if (cell->width == 2 && x + 1 < app.cols)
        blank_cell(&screen.next[y][x + 1], cell->style);
}

static void put_glyph(int x, int y, int style, const char *text, size_t bytes, int width)
{
    Cell *cell = &screen.next[y][x];
    erase_glyph(x, y);
    if (width == 2) erase_glyph(x + 1, y);
    memset(cell, 0, sizeof(*cell));
    memcpy(cell->text, text, bytes);
    cell->bytes = (unsigned char)bytes; cell->width = (unsigned char)width;
    cell->style = (unsigned char)style;
    if (width == 2) {
        memset(cell + 1, 0, sizeof(*cell));
        cell[1].style = (unsigned char)style;
    }
}

/* Compose the entire scene, including overlays, before touching the terminal. */
static void present(void)
{
    int y, x, style = -1;
    int full = !screen.valid || screen.cols != app.cols || screen.rows != app.rows || screen.ansi != app.ansi;
    size_t used = 0, sent = 0;
    for (y = 0; y < app.rows; ++y) {
        for (x = 0; x < app.cols;) {
            const Cell *cell = &screen.next[y][x];
            char cursor[32];
            int n;
            if (!cell->width || (!full && !memcmp(cell, &screen.previous[y][x], sizeof(*cell)))) {
                ++x; continue;
            }
            n = snprintf(cursor, sizeof(cursor), "\033[%d;%dH", y + 1, x + 1);
            memcpy(frame_output + used, cursor, (size_t)n); used += (size_t)n;
            if (style != cell->style) {
                const char *escape = app.ansi ? ansi[cell->style] : rgb[cell->style];
                size_t len = strlen(escape);
                memcpy(frame_output + used, escape, len); used += len;
                style = cell->style;
            }
            do {
                memcpy(frame_output + used, cell->text, cell->bytes); used += cell->bytes;
                x += cell->width;
                if (x >= app.cols) break;
                cell = &screen.next[y][x];
            } while (cell->width && cell->style == style
                     && (full || memcmp(cell, &screen.previous[y][x], sizeof(*cell))));
        }
    }
    /* Unchanged frames produce no output. Changed runs are sent as one batch. */
    while (sent < used) {
        ssize_t n = write(STDOUT_FILENO, frame_output + sent, used - sent);
        if (n < 0 && errno == EINTR && !interrupted) continue;
        if (n <= 0) { interrupted = SIGHUP; break; }
        sent += (size_t)n;
    }
    memcpy(screen.previous, screen.next, sizeof(screen.previous));
    screen.cols = app.cols; screen.rows = app.rows; screen.ansi = app.ansi; screen.valid = 1;
    secure_clear(frame_output, used);
}

/* Lay out UTF-8 by cell width; control characters never reach the terminal. */
static void text_at(int x, int y, int width, int c, const char *s)
{
    int used = 0;
    mbstate_t state;
    if (x < 0 || y < 0 || x >= app.cols || y >= app.rows || width <= 0) return;
    if (width > app.cols - x) width = app.cols - x;
    memset(&state, 0, sizeof(state));
    while (*s) {
        wchar_t wc;
        size_t n = mbrtowc(&wc, s, MB_CUR_MAX, &state);
        int cells;
        if (n == (size_t)-1 || n == (size_t)-2) {
            if (used == width) break;
            memset(&state, 0, sizeof(state)); ++s;
            put_glyph(x + used++, y, c, "?", 1, 1); continue;
        }
        if (!n) break;
        cells = wcwidth(wc);
        if (cells < 0 || cells > 2) { s += n; continue; }
        if (!cells) {
            if (used) {
                Cell *previous = &screen.next[y][x + used - 1];
                if (!previous->width) --previous;
                if ((size_t)previous->bytes + n < sizeof(previous->text)) {
                    memcpy(previous->text + previous->bytes, s, n);
                    previous->bytes = (unsigned char)(previous->bytes + n);
                }
            }
            s += n; continue;
        }
        if (used + cells > width) break;
        if (n >= sizeof(screen.next[0][0].text)) break;
        put_glyph(x + used, y, c, s, n, cells); s += n; used += cells;
    }
    while (used < width) put_glyph(x + used++, y, c, " ", 1, 1);
}

static void fill(int x, int y, int width, int height, int c)
{
    int row;
    for (row = 0; row < height; ++row) text_at(x, y + row, width, c, "");
}

static void line(int x, int y, int width, const char *left, const char *mid, const char *right, int c)
{
    int i;
    text_at(x, y, 1, c, left);
    for (i = 1; i < width - 1; ++i) text_at(x + i, y, 1, c, mid);
    text_at(x + width - 1, y, 1, c, right);
}

static void box(int x, int y, int width, int height, const char *title)
{
    int row;
    line(x, y, width, "┌", "─", "┐", BLUE);
    for (row = 1; row < height - 1; ++row) {
        text_at(x, y + row, 1, BLUE, "│");
        text_at(x + width - 1, y + row, 1, BLUE, "│");
    }
    line(x, y + height - 1, width, "└", "─", "┘", BLUE);
    if (title && *title) text_at(x + 2, y, (int)strlen(title) + 2, WHITE, title);
}

static int contains(const char *s, const char *needle)
{
    size_t n = strlen(needle), i;
    if (!n) return 1;
    for (; *s; ++s) {
        for (i = 0; i < n && s[i]; ++i)
            if (tolower((unsigned char)s[i]) != tolower((unsigned char)needle[i])) break;
        if (i == n) return 1;
    }
    return 0;
}

static void filter(void)
{
    size_t i;
    app.matches = 0;
    for (i = 0; i < app.vault.count; ++i) {
        Account *a = &app.vault.accounts[i];
        if (contains(a->issuer, app.search) || contains(a->label, app.search))
            app.filtered[app.matches++] = (int)i;
    }
    if (app.selected >= app.matches) app.selected = app.matches - 1;
    if (app.selected < 0) app.selected = 0;
}

static Account *current(void)
{
    return app.matches ? &app.vault.accounts[app.filtered[app.selected]] : NULL;
}

static void message(const char *s) { snprintf(app.status, sizeof(app.status), "%s", s); }

static int too_small(void) { return app.cols < 76 || app.rows < 24; }

static void draw(void)
{
    int x = 2, y = 2, w, h, left, pane_y = 5, pane_h, visible, i, rx, rw;
    char buf[256];
    Account *a;
    time_t now = time(NULL);
    struct tm local;
    dimensions();
    secure_clear(screen.next, sizeof(screen.next));
    fill(0, 0, app.cols, app.rows, DESKTOP);
    if (too_small()) {
        text_at(1, 1, app.cols - 2, WHITE, "TOTP Utilities");
        text_at(1, 3, app.cols - 2, DESKTOP, "Resize terminal to at least 76 x 24.");
        text_at(1, 5, app.cols - 2, DESKTOP, "Ctrl-C exits safely.");
        return;
    }
    text_at(0, 0, app.cols, INPUT, "  Menu    Configuration    Advise    Quit!");
    text_at(app.cols - 11, 0, 10, INPUT, "F1=Help");
    w = app.cols - 6; h = app.rows - 5;
    fill(x + 2, y + 1, w, h, BLACK);
    fill(x, y, w, h, BLUE);
    box(x, y, w, h, "");
    text_at(x + 1, y, w - 2, WHITE, "");
    snprintf(buf, sizeof(buf), "The TOTP Utilities %s", APP_VERSION);
    text_at(x + (w - (int)strlen(buf)) / 2, y, (int)strlen(buf), WHITE, buf);
    left = w / 3;
    if (left > 36) left = 36;
    pane_h = h - 6; visible = pane_h - 3;
    box(x + 3, pane_y, left, pane_h, " Accounts ");
    rx = x + left + 5; rw = w - left - 8;
    box(rx, pane_y, rw, pane_h, " Description ");
    filter();
    if (app.selected < app.scroll) app.scroll = app.selected;
    if (app.selected >= app.scroll + visible) app.scroll = app.selected - visible + 1;
    snprintf(buf, sizeof(buf), "%s", app.demo ? "DEMONSTRATION" : "ACCOUNT VAULT");
    text_at(x + 5, pane_y + 1, left - 4, YELLOW, buf);
    for (i = 0; i < visible && i + app.scroll < app.matches; ++i) {
        int index = i + app.scroll;
        Account *entry = &app.vault.accounts[app.filtered[index]];
        snprintf(buf, sizeof(buf), " %s%s%s", entry->issuer, entry->issuer[0] ? " / " : "", entry->label);
        text_at(x + 5, pane_y + 2 + i, left - 4, index == app.selected ? SELECTED : BLUE, buf);
    }
    if (!app.matches) text_at(x + 5, pane_y + 3, left - 4, MUTED, app.search[0] ? "No matches" : "(empty)");
    if (app.scroll > 0) text_at(x + left + 2, pane_y + 1, 1, INPUT, "▲");
    if (app.scroll + visible < app.matches) text_at(x + left + 2, pane_y + pane_h - 2, 1, INPUT, "▼");
    a = app.unlocked ? current() : NULL;
    rx += 2; rw -= 4;
    if (a) {
        char code[9], display[16];
        unsigned remaining = a->period - (unsigned)((uint64_t)now % a->period);
        int bar = rw - 12, filled;
        text_at(rx, pane_y + 1, rw, YELLOW, a->issuer[0] ? a->issuer : "TOTP ACCOUNT");
        text_at(rx, pane_y + 2, rw, BLUE, a->label);
        if (app.hidden) strcpy(display, "* * * * * *");
        else if (now < 0 || !totp_code(a, (uint64_t)now, code)) strcpy(display, "UNAVAILABLE");
        else {
            unsigned half = a->digits / 2;
            snprintf(display, sizeof(display), "%.*s %s", (int)half, code, code + half);
        }
        text_at(rx, pane_y + 4, rw, BLUE, "Current one-time password:");
        text_at(rx + 1, pane_y + 5, rw - 2, SELECTED, display);
        secure_clear(code, sizeof(code)); secure_clear(display, sizeof(display));
        snprintf(buf, sizeof(buf), "Valid for %2u second%s", remaining, remaining == 1 ? "" : "s");
        text_at(rx, pane_y + 7, rw, remaining <= 5 ? YELLOW : BLUE, buf);
        filled = (int)((unsigned)bar * remaining / a->period);
        text_at(rx, pane_y + 8, 1, BLUE, "[");
        for (i = 0; i < bar; ++i)
            text_at(rx + i + 1, pane_y + 8, 1, i < filled ? YELLOW : MUTED, i < filled ? "█" : "░");
        text_at(rx + bar + 1, pane_y + 8, 1, BLUE, "]");
        snprintf(buf, sizeof(buf), "%s / %u digits / %us", hash_name(a->hash), a->digits, a->period);
        text_at(rx, pane_y + 10, rw, BLUE, buf);
        if (pane_h > 14) text_at(rx, pane_y + 12, rw, MUTED, "Enter edits the selected account.");
        if (pane_h > 16) text_at(rx, pane_y + 14, rw, MUTED, "F5 reveals the provisioning URI.");
    } else {
        text_at(rx, pane_y + 1, rw, YELLOW, app.unlocked ? "WELCOME TO TOTP" : "ENCRYPTED ACCOUNT VAULT");
        text_at(rx, pane_y + 3, rw, BLUE, app.unlocked ? "Keep your one-time passwords" : "Unlock your vault to access");
        text_at(rx, pane_y + 4, rw, BLUE, app.unlocked ? "close at hand." : "your accounts and secret keys.");
        text_at(rx, pane_y + 6, rw, BLUE, "F2  Add an account manually");
        text_at(rx, pane_y + 7, rw, BLUE, "F4  Import an otpauth:// URI");
        text_at(rx, pane_y + 9, rw, BLUE, "AES-256-GCM encrypted storage");
        text_at(rx, pane_y + 10, rw, BLUE, "F1  Keyboard guide and advice");
    }
    snprintf(buf, sizeof(buf), " %03zu accounts | %s%s%s", app.vault.count,
             app.demo ? "DEMO - memory only" : app.unlocked ? "Vault unlocked" : "Vault locked",
             app.search[0] ? " | Find: " : "", app.search);
    text_at(x + 4, y + h - 3, w - 8, BLACK, buf);
    text_at(0, app.rows - 2, app.cols, RED, app.status[0] ? app.status : "Press Enter to edit an account, or F10 to activate the menu.");
    text_at(0, app.rows - 1, app.cols, WHITE, " F1 Help  F2 Add  F3 Edit  F4 Import  F6 Lock  F7 Find  F8 Delete  F10 Menu");
    if (app.cols >= 96 && localtime_r(&now, &local)) {
        strftime(buf, sizeof(buf), "%H:%M:%S", &local);
        text_at(app.cols - 9, app.rows - 1, 8, WHITE, buf);
    }
}

static int read_byte(int timeout)
{
    struct pollfd fd = {STDIN_FILENO, POLLIN, 0};
    unsigned char c;
    int r = poll(&fd, 1, timeout);
    if (r <= 0) return -1;
    if (fd.revents & (POLLHUP | POLLERR | POLLNVAL)) { interrupted = SIGHUP; return -1; }
    return read(STDIN_FILENO, &c, 1) == 1 ? c : -1;
}

static int key_read(void)
{
    char seq[24];
    int c = read_byte(200), n = 0;
    if (c < 0) return 0;
    app.activity = monotime();
    if (c != 27) {
        if (pasting) return c >= 32 && c != 127 ? K_LITERAL + c : 0;
        return c;
    }
    c = read_byte(45);
    if (c < 0) return pasting ? 0 : 27;
    if (c != '[' && c != 'O') return 0;
    seq[n++] = (char)c;
    while (n < (int)sizeof(seq) - 1) {
        c = read_byte(45);
        if (c < 0) break;
        seq[n++] = (char)c;
        if (c >= 64 && c <= 126) break;
    }
    seq[n] = 0;
    if (!strcmp(seq, "[200~")) { pasting = 1; return 0; }
    if (!strcmp(seq, "[201~")) { pasting = 0; return 0; }
    if (pasting) return 0;
    if (!strcmp(seq, "[A") || !strcmp(seq, "OA")) return K_UP;
    if (!strcmp(seq, "[B") || !strcmp(seq, "OB")) return K_DOWN;
    if (!strcmp(seq, "[C") || !strcmp(seq, "OC")) return K_RIGHT;
    if (!strcmp(seq, "[D") || !strcmp(seq, "OD")) return K_LEFT;
    if (!strcmp(seq, "[H") || !strcmp(seq, "OH") || !strcmp(seq, "[1~")) return K_HOME;
    if (!strcmp(seq, "[F") || !strcmp(seq, "OF") || !strcmp(seq, "[4~")) return K_END;
    if (!strcmp(seq, "[5~")) return K_PGUP;
    if (!strcmp(seq, "[6~")) return K_PGDN;
    if (!strcmp(seq, "[3~")) return K_DELETE;
    if (!strcmp(seq, "[Z")) return K_BACKTAB;
    if (n == 2 && seq[0] == 'O' && seq[1] >= 'P' && seq[1] <= 'S') return K_F1 + seq[1] - 'P';
    if (seq[0] == '[') {
        static const int fn[] = {11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 23, 24};
        int i, value = atoi(seq + 1);
        for (i = 0; i < 12; ++i) if (seq[n - 1] == '~' && value == fn[i]) return K_F1 + i;
    }
    return 0;
}

static int expired(void)
{
    return app.unlocked && !app.demo && app.timeout && monotime() - app.activity >= app.timeout;
}

static void dialog(int width, int height, const char *title, int *x, int *y)
{
    *x = (app.cols - width) / 2; *y = (app.rows - height) / 2;
    fill(*x + 2, *y + 1, width, height, BLACK);
    fill(*x, *y, width, height, BLUE);
    box(*x, *y, width, height, title);
}

static void wrap_text(int x, int y, int width, int rows, const char *text)
{
    int row;
    const char *p = text;
    for (row = 0; row < rows && *p; ++row) {
        char part[512];
        size_t n = 0;
        while (p[n] && p[n] != '\n' && n < (size_t)width && n < sizeof(part) - 1) ++n;
        if (p[n] && p[n] != '\n' && n == (size_t)width) {
            size_t last = n;
            while (last > 0 && p[last] != ' ') --last;
            if (last) n = last;
        }
        memcpy(part, p, n); part[n] = 0;
        text_at(x, y + row, width, BLUE, part);
        p += n;
        if (*p == '\n' || *p == ' ') ++p;
    }
}

static int notice(const char *title, const char *body, int confirm)
{
    while (!interrupted && !expired()) {
        int x, y, key;
        draw();
        if (!too_small()) {
            dialog(68, 13, title, &x, &y);
            wrap_text(x + 3, y + 2, 62, 7, body);
            text_at(x + 3, y + 10, 62, SELECTED, confirm ? " Y = Confirm                  N / Esc = Cancel" : " Enter / Esc = Return");
        }
        present();
        key = key_read();
        if (too_small()) continue;
        if (confirm && (key == 'y' || key == 'Y')) return 1;
        if (key == 27 || key == 'n' || key == 'N' || (!confirm && (key == 13 || key == 10))) return 0;
    }
    return 0;
}

static void backspace(char *value)
{
    size_t n = strlen(value);
    if (!n) return;
    --n;
    while (n && ((unsigned char)value[n] & 0xc0) == 0x80) --n;
    secure_clear(value + n, strlen(value + n));
}

/* Input stays inside the alternate screen; secrets are never echoed by the tty. */
static int form(const char *title, const char *hint, Field *fields, int count)
{
    int active = 0, height = 8 + count * 2;
    while (!interrupted && !expired()) {
        int x, y, i, key;
        draw();
        if (!too_small()) {
            dialog(70, height, title, &x, &y);
            text_at(x + 3, y + 2, 64, BLUE, hint);
            for (i = 0; i < count; ++i) {
                Field *f = &fields[i];
                const char *view = f->value;
                char masked[43];
                size_t len = strlen(f->value);
                text_at(x + 3, y + 4 + i * 2, 16, i == active ? YELLOW : BLUE, f->label);
                if (f->secret) {
                    memset(masked, '*', len < sizeof(masked) - 1 ? len : sizeof(masked) - 1);
                    masked[len < sizeof(masked) - 1 ? len : sizeof(masked) - 1] = 0;
                    view = masked;
                } else if (len > 39) {
                    view += len - 39;
                    while (((unsigned char)*view & 0xc0) == 0x80) ++view;
                }
                text_at(x + 20, y + 4 + i * 2, 46, i == active ? INPUT : BLACK, view);
                if (i == active) text_at(x + 67, y + 4 + i * 2, 1, YELLOW, "◄");
            }
            text_at(x + 3, y + height - 2, 64, WHITE, " Tab Next  Shift-Tab Previous  Ctrl-U Clear  Enter OK  Esc Cancel");
        }
        present(); key = key_read();
        if (too_small()) continue;
        if (key == 27) return 0;
        if (key == 13 || key == 10) return 1;
        if (key == 9 || key == K_DOWN) { active = (active + 1) % count; continue; }
        if (key == K_BACKTAB || key == K_UP) { active = (active + count - 1) % count; continue; }
        if (key == 21) { secure_clear(fields[active].value, fields[active].cap); continue; }
        if (key == 127 || key == 8) { backspace(fields[active].value); continue; }
        if (key >= K_LITERAL) key -= K_LITERAL;
        if (key >= 32 && key <= 255 && key != 127) {
            Field *f = &fields[active];
            size_t len = strlen(f->value);
            if (len + 1 < f->cap) { f->value[len] = (char)key; f->value[len + 1] = 0; }
        }
    }
    return 0;
}

static int unlock(int create)
{
    char password[PASSWORD_CAP] = "", repeat[PASSWORD_CAP] = "", error[ERROR_CAP];
    int ok = 0;
    Field fields[] = {
        {"Master password", password, sizeof(password), 1},
        {"Repeat password", repeat, sizeof(repeat), 1}
    };
    app.unlocked = 0;
    while (!interrupted) {
        if (!form(create ? " Create encrypted vault " : " Unlock vault ",
                  create ? "Choose a master password (at least 8 bytes)." : "Enter your master password. Esc exits TOTP Utilities.",
                  fields, create ? 2 : 1)) break;
        if (create && (strlen(password) < 8 || strcmp(password, repeat))) {
            notice(" Password not accepted ", "Use at least 8 bytes, and enter the same password twice.", 0);
        } else {
            message(create ? "Creating encrypted vault..." : "Unlocking vault...");
            draw(); present();
            if (create) ok = vault_key_create(password, &app.key, error)
                             && vault_save(app.path, &app.vault, &app.key, error);
            else ok = vault_load(app.path, password, &app.vault, &app.key, error);
            if (ok) break;
            secure_clear(&app.key, sizeof(app.key));
            notice(" Cannot unlock vault ", error, 0);
        }
        secure_clear(password, sizeof(password)); secure_clear(repeat, sizeof(repeat));
    }
    secure_clear(password, sizeof(password)); secure_clear(repeat, sizeof(repeat));
    app.unlocked = ok; app.activity = monotime();
    if (ok) message(create ? "Vault created. Press F2 to add your first account." : "Vault unlocked. Changes are saved automatically.");
    return ok;
}

static int commit(Vault *candidate)
{
    char error[ERROR_CAP];
    if (!app.demo && !vault_save(app.path, candidate, &app.key, error)) {
        notice(" Save failed - changes discarded ", error, 0); return 0;
    }
    app.vault = *candidate;
    filter();
    message(app.demo ? "Demo updated in memory. No files are written." : "Changes saved to the encrypted vault.");
    return 1;
}

static int store_account(const Account *a, int index)
{
    Vault *candidate;
    size_t i;
    int ok;
    for (i = 0; i < app.vault.count; ++i) {
        if ((int)i != index && !strcmp(app.vault.accounts[i].issuer, a->issuer)
            && !strcmp(app.vault.accounts[i].label, a->label)) {
            notice(" Duplicate account ", "An account with this issuer and name already exists. Edit that account or choose a different name.", 0);
            return 0;
        }
    }
    if (index < 0 && app.vault.count == MAX_ACCOUNTS) {
        notice(" Vault is full ", "This vault holds up to 256 accounts.", 0); return 0;
    }
    candidate = malloc(sizeof(*candidate));
    if (!candidate) { notice(" Error ", "Out of memory.", 0); return 0; }
    *candidate = app.vault;
    if (index < 0) index = (int)candidate->count++;
    candidate->accounts[index] = *a;
    ok = commit(candidate);
    secure_clear(candidate, sizeof(*candidate)); free(candidate);
    if (ok) {
        app.search[0] = 0; app.selected = index; filter();
    }
    return ok;
}

static unsigned parse_unsigned(const char *s)
{
    unsigned long n;
    if (!s[0] || strlen(s) != strspn(s, "0123456789")) return 0;
    n = strtoul(s, NULL, 10);
    return n <= 300 ? (unsigned)n : 0;
}

static void edit_account(int edit)
{
    Account a = {{0}, {0}, {0}, HASH_SHA1, 6, 30};
    char hash[12] = "SHA1", digits[8] = "6", period[8] = "30", error[ERROR_CAP];
    int index = -1;
    Field fields[] = {
        {"Issuer", a.issuer, sizeof(a.issuer), 0},
        {"Account", a.label, sizeof(a.label), 0},
        {"Base32 secret", a.secret, sizeof(a.secret), 1},
        {"Algorithm", hash, sizeof(hash), 0},
        {"Digits", digits, sizeof(digits), 0},
        {"Period (sec)", period, sizeof(period), 0}
    };
    if (edit) {
        if (!current()) { message("Select an account first."); return; }
        index = app.filtered[app.selected]; a = *current();
        snprintf(hash, sizeof(hash), "%s", hash_name(a.hash));
        snprintf(digits, sizeof(digits), "%u", a.digits);
        snprintf(period, sizeof(period), "%u", a.period);
    }
    while (form(edit ? " Edit account " : " Add account ",
                "SHA1 / SHA256 / SHA512; 6 or 8 digits; period 1-300.", fields, 6)) {
        size_t i;
        for (i = 0; hash[i]; ++i) hash[i] = (char)toupper((unsigned char)hash[i]);
        a.hash = !strcmp(hash, "SHA1") ? HASH_SHA1 : !strcmp(hash, "SHA256") ? HASH_SHA256
                 : !strcmp(hash, "SHA512") ? HASH_SHA512 : 0;
        a.digits = parse_unsigned(digits); a.period = parse_unsigned(period);
        if (!account_validate(&a, error)) notice(" Check account details ", error, 0);
        else if (store_account(&a, index)) break;
    }
    secure_clear(&a, sizeof(a));
}

static void import_account(void)
{
    char uri[URI_CAP] = "", error[ERROR_CAP];
    Account a;
    Field field = {"otpauth URI", uri, sizeof(uri), 1};
    memset(&a, 0, sizeof(a));
    while (form(" Import TOTP account ", "Paste an otpauth://totp/ URI, then press Enter.", &field, 1)) {
        if (!account_from_uri(uri, &a, error)) notice(" Import failed ", error, 0);
        else if (store_account(&a, -1)) break;
    }
    secure_clear(uri, sizeof(uri)); secure_clear(&a, sizeof(a));
}

static void delete_account(void)
{
    Vault *candidate;
    Account *a = current();
    char body[512];
    size_t index;
    if (!a) { message("Select an account first."); return; }
    snprintf(body, sizeof(body), "Delete %s / %s?\n\nThe stored secret will be removed from this vault. You will need the original secret to add it again.", a->issuer, a->label);
    if (!notice(" Delete account ", body, 1)) return;
    candidate = malloc(sizeof(*candidate));
    if (!candidate) { notice(" Error ", "Out of memory.", 0); return; }
    *candidate = app.vault;
    index = (size_t)app.filtered[app.selected];
    memmove(&candidate->accounts[index], &candidate->accounts[index + 1],
            (candidate->count - index - 1) * sizeof(Account));
    --candidate->count;
    secure_clear(&candidate->accounts[candidate->count], sizeof(Account));
    commit(candidate);
    secure_clear(candidate, sizeof(*candidate)); free(candidate);
}

static void find_accounts(void)
{
    char query[TEXT_CAP];
    Field field = {"Find", query, sizeof(query), 0};
    snprintf(query, sizeof(query), "%s", app.search);
    if (form(" Find accounts ", "Search issuer or account name. Empty text shows all.", &field, 1)) {
        strcpy(app.search, query); app.selected = 0; app.scroll = 0; filter();
        message("Filter applied. Esc clears the filter.");
    }
}

static void reveal_account(void)
{
    char uri[URI_CAP] = "";
    Account *a = current();
    int offset = 0;
    if (!a) { message("Select an account first."); return; }
    if (!notice(" Reveal provisioning secret ", "The next screen contains the reusable secret for this account. Anyone with it can generate the same codes.\n\nReveal the provisioning URI?", 1)) return;
    if (!account_to_uri(a, uri, sizeof(uri))) { message("Could not encode the account URI."); return; }
    while (!interrupted && !expired()) {
        int x, y, row, key, width, height, lines;
        size_t len = strlen(uri);
        draw();
        width = app.cols - 12; height = app.rows - 6;
        lines = (int)((len + (size_t)(width - 7)) / (size_t)(width - 6));
        if (!too_small()) {
            dialog(width, height, " Provisioning URI - secret ", &x, &y);
            text_at(x + 3, y + 2, width - 6, YELLOW, "Select text in your terminal to copy. Never share this URI.");
            for (row = 0; row < height - 7; ++row) {
                size_t start = (size_t)(offset + row) * (size_t)(width - 6);
                if (start < len) text_at(x + 3, y + 4 + row, width - 6, BLUE, uri + start);
            }
            text_at(x + 3, y + height - 2, width - 6, WHITE, " Up/Down Scroll                  Enter / Esc Close");
        }
        present(); key = key_read();
        if (too_small()) continue;
        if (key == 27 || key == 13 || key == 10) break;
        if (key == K_DOWN && offset + height - 7 < lines) ++offset;
        if (key == K_UP && offset) --offset;
    }
    secure_clear(uri, sizeof(uri));
}

static void change_password(void)
{
    char old[PASSWORD_CAP] = "", password[PASSWORD_CAP] = "", repeat[PASSWORD_CAP] = "", error[ERROR_CAP];
    VaultKey key = {{0}, {0}, 0}, verified_key = {{0}, {0}, 0};
    Vault *verified = NULL;
    Field fields[] = {
        {"Current password", old, sizeof(old), 1},
        {"New password", password, sizeof(password), 1},
        {"Repeat password", repeat, sizeof(repeat), 1}
    };
    if (app.demo) { notice(" Demonstration ", "Demo mode has no password or saved vault.", 0); return; }
    while (form(" Change master password ", "Choose a new password of at least 8 bytes.", fields, 3)) {
        if (strlen(password) < 8 || strcmp(password, repeat)) {
            notice(" Password not accepted ", "Use at least 8 bytes, and enter the same new password twice.", 0);
            continue;
        }
        verified = calloc(1, sizeof(*verified));
        if (!verified) { notice(" Error ", "Out of memory.", 0); break; }
        if (vault_load(app.path, old, verified, &verified_key, error)
            && vault_key_create(password, &key, error)
            && vault_save(app.path, &app.vault, &key, error)) {
            secure_clear(&app.key, sizeof(app.key)); app.key = key;
            message("Master password changed. Existing backups keep their old password.");
            secure_clear(verified, sizeof(*verified)); free(verified); verified = NULL;
            break;
        }
        secure_clear(verified, sizeof(*verified)); free(verified); verified = NULL;
        notice(" Password change failed ", error, 0);
    }
    secure_clear(&key, sizeof(key)); secure_clear(&verified_key, sizeof(verified_key));
    secure_clear(old, sizeof(old)); secure_clear(password, sizeof(password)); secure_clear(repeat, sizeof(repeat));
}

static void help(void)
{
    const char *lines[] = {
        "TOTP Utilities " APP_VERSION,
        "An offline authenticator, dressed for 1991.",
        "",
        "Up/Down, J/K     Select account     Enter     Edit",
        "F2 / A           Add account        F3 / E    Edit",
        "F4 / I           Import URI         F5 / R    Reveal URI",
        "F6 / L           Lock vault         F7 / /    Find",
        "F8 / D / Delete  Delete account     F9 / S    Setup",
        "F10 / M          Main menu          Q        Quit",
        "Space            Hide/show code     Esc      Clear filter",
        "",
        "Forms: Tab switches fields; Ctrl-U clears a field.",
        "Secrets stay masked. Use terminal paste to enter a URI.",
        "Codes use your system clock; keep it synchronized.",
        "Copy the encrypted .vault file to make a backup.",
        "Use --vault /path/to/backup to open a backup.",
        "There is no password recovery. Keep your recovery codes."
    };
    while (!interrupted && !expired()) {
        int x, y, i, key;
        draw();
        if (!too_small()) {
            dialog(70, 22, " Help / Advise ", &x, &y);
            for (i = 0; i < (int)(sizeof(lines) / sizeof(lines[0])); ++i)
                text_at(x + 3, y + 2 + i, 64, i ? BLUE : YELLOW, lines[i]);
            text_at(x + 3, y + 20, 64, WHITE, " Enter / Esc Return");
        }
        present(); key = key_read();
        if (!too_small() && (key == 27 || key == 13 || key == 10 || key == K_F1)) return;
    }
}

static int menu(const char *title, const char **items, int count)
{
    int selected = 0;
    while (!interrupted && !expired()) {
        int x, y, i, key;
        draw();
        if (!too_small()) {
            dialog(54, count + 6, title, &x, &y);
            for (i = 0; i < count; ++i)
                text_at(x + 3, y + 2 + i, 48, i == selected ? SELECTED : BLUE, items[i]);
            text_at(x + 3, y + count + 4, 48, WHITE, " Up/Down Select   Enter Run   Esc Cancel");
        }
        present(); key = key_read();
        if (too_small()) continue;
        if (key == 27) return -1;
        if (key == 13 || key == 10) return selected;
        if (key == K_UP || key == 'k') selected = (selected + count - 1) % count;
        if (key == K_DOWN || key == 'j') selected = (selected + 1) % count;
        if (key >= '1' && key < '1' + count) return key - '1';
    }
    return -1;
}

static void setup(void)
{
    const char *items[] = {" 1  Change master password", " 2  Auto-lock timeout", " 3  Vault information", " 4  Switch color palette"};
    int choice = menu(" Configuration ", items, 4);
    if (choice == 0) change_password();
    else if (choice == 1) {
        char value[8];
        Field field = {"Seconds", value, sizeof(value), 0};
        snprintf(value, sizeof(value), "%u", app.timeout);
        while (form(" Auto-lock timeout ", "0 disables locking; 1-86400 seconds. Session only.", &field, 1)) {
            unsigned long n = strtoul(value, NULL, 10);
            if (*value && strlen(value) == strspn(value, "0123456789") && n <= 86400) {
                app.timeout = (unsigned)n; message("Auto-lock timeout updated for this session."); break;
            }
            notice(" Invalid timeout ", "Enter a whole number from 0 to 86400.", 0);
        }
    } else if (choice == 2) {
        char body[PATH_CAP + 256];
        snprintf(body, sizeof(body), "AES-256-GCM authenticated encryption\nPBKDF2-HMAC-SHA256 / 600,000 iterations\n%zu / 256 accounts\nAuto-lock: %u seconds (0 = off)\n\n%s",
                 app.vault.count, app.timeout, app.demo ? "DEMO: no file is opened or saved." : app.path);
        notice(" Vault information ", body, 0);
    } else if (choice == 3) app.ansi = !app.ansi;
}

static void demo_accounts(void)
{
    static const char *names[][2] = {
        {"GitHub", "octocat"}, {"Google", "alex@example.com"},
        {"Proton", "personal mail"}, {"Cloudflare", "homelab"},
        {"Fastmail", "work"}, {"NAS", "administrator"}
    };
    size_t i;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        Account *a = &app.vault.accounts[i];
        snprintf(a->issuer, sizeof(a->issuer), "%s", names[i][0]);
        snprintf(a->label, sizeof(a->label), "%s", names[i][1]);
        strcpy(a->secret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        a->hash = HASH_SHA1; a->digits = 6; a->period = 30;
    }
    app.vault.count = sizeof(names) / sizeof(names[0]); app.unlocked = 1;
    message("DEMONSTRATION - public example secrets; changes are not saved.");
}

int ui_run(const char *path, int demo, int use_ansi, unsigned timeout)
{
    int lockfd = -1, create = 0, running = 1, result = 0;
    char error[ERROR_CAP];
    struct stat st;
    memset(&app, 0, sizeof(app));
    app.path = path; app.demo = demo; app.ansi = use_ansi; app.timeout = timeout;
    app.activity = monotime();
    setlocale(LC_ALL, "");
    if (MB_CUR_MAX == 1) {
        if (!setlocale(LC_CTYPE, "C.UTF-8")) setlocale(LC_CTYPE, "en_US.UTF-8");
    }
    if (!demo) {
        lockfd = vault_lock_file(path, error);
        if (lockfd < 0) { fprintf(stderr, "%s\n", error); return 1; }
        if (lstat(path, &st) < 0) {
            if (errno == ENOENT) create = 1;
            else { fprintf(stderr, "Cannot inspect vault: %s\n", strerror(errno)); close(lockfd); return 1; }
        } else if (!S_ISREG(st.st_mode)) {
            fputs("Vault must be a regular file, not a symlink or device.\n", stderr); close(lockfd); return 1;
        }
    }
    if (!terminal_open()) {
        fputs("Could not initialize the terminal.\n", stderr);
        if (lockfd >= 0) close(lockfd);
        return 1;
    }
    if (demo) demo_accounts();
    else if (!unlock(create)) running = 0;
    while (running && !interrupted) {
        int key;
        if (expired()) {
            secure_clear(&app.vault, sizeof(app.vault)); secure_clear(&app.key, sizeof(app.key));
            app.search[0] = 0; app.selected = 0; app.scroll = 0;
            message("Vault locked after inactivity.");
            if (!unlock(0)) break;
        }
        draw(); present(); key = key_read();
        if (too_small()) continue;
        if (key == K_F1 + 9 || key == 'm' || key == 'M') {
            const char *items[] = {" 1  Add account                 F2", " 2  Edit account                F3",
                " 3  Import otpauth URI          F4", " 4  Reveal provisioning URI     F5",
                " 5  Lock vault                  F6", " 6  Find accounts               F7",
                " 7  Delete account              F8", " 8  Configuration               F9", " 9  Quit"};
            int choice = menu(" Menu ", items, 9);
            key = choice >= 0 && choice < 8 ? K_F1 + choice + 1 : choice == 8 ? 'q' : 0;
        }
        switch (key) {
        case K_UP: case 'k': case 'K': if (app.selected) --app.selected; break;
        case K_DOWN: case 'j': case 'J': if (app.selected + 1 < app.matches) ++app.selected; break;
        case K_HOME: app.selected = 0; break;
        case K_END: app.selected = app.matches - 1; break;
        case K_PGUP: app.selected -= 8; if (app.selected < 0) app.selected = 0; break;
        case K_PGDN: app.selected += 8; if (app.selected >= app.matches) app.selected = app.matches - 1; break;
        case K_F1: case '?': case 'h': case 'H': help(); break;
        case K_F1 + 1: case 'a': case 'A': edit_account(0); break;
        case K_F1 + 2: case 'e': case 'E': case 13: case 10: edit_account(1); break;
        case K_F1 + 3: case 'i': case 'I': import_account(); break;
        case K_F1 + 4: case 'r': case 'R': reveal_account(); break;
        case K_F1 + 5: case 'l': case 'L':
            if (app.demo) { message("Demo mode has no encrypted vault to lock."); break; }
            secure_clear(&app.vault, sizeof(app.vault)); secure_clear(&app.key, sizeof(app.key));
            app.search[0] = 0; app.selected = 0; app.scroll = 0;
            message("Vault locked.");
            if (!unlock(0)) running = 0;
            break;
        case K_F1 + 6: case '/': find_accounts(); break;
        case K_F1 + 7: case 'd': case 'D': case K_DELETE: delete_account(); break;
        case K_F1 + 8: case 's': case 'S': setup(); break;
        case ' ': app.hidden = !app.hidden; break;
        case 27: app.search[0] = 0; app.scroll = 0; message("Filter cleared."); break;
        case 'q': case 'Q': case K_F1 + 11: running = 0; break;
        default: break;
        }
    }
    if (interrupted) result = 128 + interrupted;
    secure_clear(&app.vault, sizeof(app.vault)); secure_clear(&app.key, sizeof(app.key));
    terminal_close();
    if (lockfd >= 0) close(lockfd);
    return result;
}
