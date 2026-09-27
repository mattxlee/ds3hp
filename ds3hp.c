#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>
#include <math.h>
#include <time.h>
#include <pthread.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ncurses.h>

#define STATE_PATH ".ds3hp_state"
#define MAGIC "DS3HP01"
#define CHUNK (1u << 20)
#define MAX_BATCH 512

typedef struct {
    char magic[8];
    int32_t pid;
    int32_t type;
    double min;
    double max;
    uint64_t count;
} __attribute__((packed)) StateHdr;

typedef struct {
    uint64_t addr;
    uint32_t bits;
} __attribute__((packed)) Cand;

typedef struct {
    int type;
    double min, max;
    int exact;
    double exact_val;
    double tol;
    Cand *c;
    size_t n, cap;
} Search;

enum { T_FLOAT = 0, T_INT = 1 };
enum { F_DEC, F_INC, F_CHG, F_UNCH, F_EQ, F_LT, F_GT };

static int g_pid = 0;
static Search g_s;
static volatile sig_atomic_t g_stop = 0;

static uint32_t read_at(uint64_t addr, int *ok);

static void die(const char *msg)
{
    fprintf(stderr, "error: %s: %s\n", msg, strerror(errno));
    exit(1);
}

static double bits_to_val(int type, uint32_t b)
{
    if (type == T_FLOAT) {
        float f;
        memcpy(&f, &b, 4);
        return (double)f;
    }
    int32_t i;
    memcpy(&i, &b, 4);
    return (double)i;
}

static int val_finite(int type, uint32_t b)
{
    if (type == T_FLOAT) {
        float f;
        memcpy(&f, &b, 4);
        return isfinite(f);
    }
    return 1;
}

static int val_in_range(const Search *s, uint32_t b)
{
    if (!val_finite(s->type, b))
        return 0;
    double v = bits_to_val(s->type, b);
    if (s->exact)
        return fabs(v - s->exact_val) <= s->tol;
    return v >= s->min && v <= s->max;
}

static uint32_t val_to_bits(int type, double v)
{
    if (type == T_FLOAT) {
        float f = (float)v;
        uint32_t b;
        memcpy(&b, &f, 4);
        return b;
    }
    int32_t i = (int32_t)v;
    uint32_t b;
    memcpy(&b, &i, 4);
    return b;
}

static int detect_pid(void)
{
    DIR *d = opendir("/proc");
    if (!d)
        die("opendir /proc");
    struct dirent *e;
    int found = 0;
    while ((e = readdir(d))) {
        if (!isdigit((unsigned char)e->d_name[0]))
            continue;
        char path[300], comm[256];
        snprintf(path, sizeof path, "/proc/%s/comm", e->d_name);
        FILE *f = fopen(path, "r");
        if (!f)
            continue;
        if (fgets(comm, sizeof comm, f) && strncmp(comm, "DarkSoulsIII", 12) == 0)
            found = atoi(e->d_name);
        fclose(f);
        if (found)
            break;
    }
    closedir(d);
    return found;
}

static void push_cand(Search *s, uint64_t addr, uint32_t bits)
{
    if (s->n == s->cap) {
        size_t ncap = s->cap ? s->cap * 2 : (1u << 20);
        Cand *p = realloc(s->c, ncap * sizeof(Cand));
        if (!p) {
            fprintf(stderr, "error: out of memory at %zu candidates\n", s->n);
            exit(1);
        }
        s->c = p;
        s->cap = ncap;
    }
    s->c[s->n].addr = addr;
    s->c[s->n].bits = bits;
    s->n++;
}

typedef struct {
    uint64_t start;
    uint64_t end;
} Region;

static size_t read_regions(int pid, int anon_only, Region **out)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        die("open maps");
    Region *rs = NULL;
    size_t n = 0, cap = 0;
    char line[1024];
    while (fgets(line, sizeof line, f)) {
        unsigned long long a, b;
        char perms[8] = {0};
        char rest[512] = {0};
        if (sscanf(line, "%llx-%llx %7s %*s %*s %*s %511[^\n]", &a, &b, perms, rest) < 3)
            continue;
        if (perms[0] != 'r' || perms[1] != 'w')
            continue;
        char *p = rest;
        while (*p && isspace((unsigned char)*p))
            p++;
        if (anon_only) {
            int skip_bracket = (*p == '[' && strncmp(p, "[heap]", 6) != 0);
            if ((*p && *p != '[') || skip_bracket)
                continue;
        }
        if (n == cap) {
            cap = cap ? cap * 2 : 256;
            Region *nr = realloc(rs, cap * sizeof(Region));
            if (!nr)
                die("realloc regions");
            rs = nr;
        }
        rs[n].start = a;
        rs[n].end = b;
        n++;
    }
    fclose(f);
    *out = rs;
    return n;
}

typedef struct {
    Search *s;
    volatile int *cancel;
    volatile uint64_t *done;
    size_t nr;
    uint64_t total;
    int verbose;
} ScanCtx;

static void scan_region(ScanCtx *ctx, uint64_t start, uint64_t end, uint8_t *buf, size_t bufsz)
{
    Search *s = ctx->s;
    uint64_t p = start, prev = start;
    while (p < end) {
        if (ctx->cancel && *ctx->cancel)
            return;
        size_t want = (size_t)(end - p);
        if (want > bufsz)
            want = bufsz;
        struct iovec li = { buf, want };
        struct iovec ri = { (void *)p, want };
        ssize_t r = process_vm_readv(g_pid, &li, 1, &ri, 1, 0);
        if (r <= 0) {
            p += 4096 - (p & 4095);
            if (ctx->done) {
                *ctx->done += p - prev;
                prev = p;
            }
            continue;
        }
        size_t words = (size_t)r / 4;
        for (size_t i = 0; i < words; i++) {
            uint32_t w;
            memcpy(&w, buf + i * 4, 4);
            if (val_in_range(s, w))
                push_cand(s, p + i * 4, w);
        }
        p += words * 4;
        if ((size_t)r < want && words * 4 == (size_t)r)
            p += 4;
        if (ctx->done) {
            *ctx->done += p - prev;
            prev = p;
        }
    }
}

static void scan_all(ScanCtx *ctx, int anon_only)
{
    Region *rs;
    size_t nr = read_regions(g_pid, anon_only, &rs);
    uint64_t total = 0;
    for (size_t i = 0; i < nr; i++)
        total += rs[i].end - rs[i].start;
    ctx->nr = nr;
    ctx->total = total;
    if (ctx->done)
        *ctx->done = 0;
    if (ctx->verbose)
        fprintf(stderr, "pid %d, %zu regions (%s), %.0f MB\n", g_pid, nr,
                anon_only ? "anon" : "all", total / 1048576.0);
    uint8_t *buf = malloc(CHUNK);
    if (!buf)
        die("malloc buffer");
    for (size_t i = 0; i < nr; i++) {
        if (ctx->cancel && *ctx->cancel)
            break;
        scan_region(ctx, rs[i].start, rs[i].end, buf, CHUNK);
    }
    free(buf);
    free(rs);
}

static void save_state(void)
{
    FILE *f = fopen(STATE_PATH, "wb");
    if (!f)
        die("write state");
    StateHdr h = {0};
    memcpy(h.magic, MAGIC, 8);
    h.pid = g_pid;
    h.type = g_s.type;
    h.min = g_s.min;
    h.max = g_s.max;
    h.count = g_s.n;
    if (fwrite(&h, sizeof h, 1, f) != 1)
        die("write header");
    if (g_s.n && fwrite(g_s.c, sizeof(Cand), g_s.n, f) != g_s.n)
        die("write candidates");
    fclose(f);
}

static void load_state(void)
{
    FILE *f = fopen(STATE_PATH, "rb");
    if (!f) {
        fprintf(stderr, "error: no scan state; run 'first' first\n");
        exit(1);
    }
    StateHdr h;
    if (fread(&h, sizeof h, 1, f) != 1 || memcmp(h.magic, MAGIC, 8) != 0) {
        fprintf(stderr, "error: bad state file\n");
        exit(1);
    }
    g_pid = h.pid;
    g_s.type = h.type;
    g_s.min = h.min;
    g_s.max = h.max;
    g_s.n = (size_t)h.count;
    g_s.cap = g_s.n ? g_s.n : 1;
    g_s.c = malloc(g_s.cap * sizeof(Cand));
    if (!g_s.c)
        die("malloc state");
    if (g_s.n && fread(g_s.c, sizeof(Cand), g_s.n, f) != g_s.n)
        die("read candidates");
    fclose(f);
}

static void cmd_first(int argc, char **argv)
{
    int anon_only = 1;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) {
            const char *t = argv[++i];
            if (strcmp(t, "float") == 0)
                g_s.type = T_FLOAT;
            else if (strcmp(t, "int") == 0)
                g_s.type = T_INT;
            else {
                fprintf(stderr, "error: --type must be float or int\n");
                exit(1);
            }
        } else if (strcmp(argv[i], "--min") == 0 && i + 1 < argc) {
            g_s.min = atof(argv[++i]);
        } else if (strcmp(argv[i], "--max") == 0 && i + 1 < argc) {
            g_s.max = atof(argv[++i]);
        } else if ((strcmp(argv[i], "--value") == 0 || strcmp(argv[i], "--eq") == 0) && i + 1 < argc) {
            g_s.exact = 1;
            g_s.exact_val = atof(argv[++i]);
        } else if (strcmp(argv[i], "--tol") == 0 && i + 1 < argc) {
            g_s.tol = atof(argv[++i]);
        } else if (strcmp(argv[i], "--maps") == 0 && i + 1 < argc) {
            const char *m = argv[++i];
            if (strcmp(m, "anon") == 0)
                anon_only = 1;
            else if (strcmp(m, "all") == 0)
                anon_only = 0;
            else {
                fprintf(stderr, "error: --maps must be anon or all\n");
                exit(1);
            }
        } else {
            fprintf(stderr, "error: unknown option %s\n", argv[i]);
            exit(1);
        }
    }
    if (!g_pid)
        g_pid = detect_pid();
    if (!g_pid) {
        fprintf(stderr, "error: Dark Souls III process not found (is it running?)\n");
        exit(1);
    }
    if (g_s.c) {
        free(g_s.c);
        g_s.c = NULL;
        g_s.cap = 0;
    }
    g_s.n = 0;
    if (g_s.exact)
        fprintf(stderr, "type=%s exact=%g tol=%g, scanning...\n",
                g_s.type == T_FLOAT ? "float" : "int", g_s.exact_val, g_s.tol);
    else
        fprintf(stderr, "type=%s range=[%g, %g], scanning...\n",
                g_s.type == T_FLOAT ? "float" : "int", g_s.min, g_s.max);
    ScanCtx ctx = { &g_s, &g_stop, NULL, 0, 0, 1 };
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    scan_all(&ctx, anon_only);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double dt = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    save_state();
    printf("first scan: %zu candidates in %.1fs\n", g_s.n, dt);
    printf("now change your HP in game, then run: ds3hp next --dec\n");
}

static int parse_filter(int argc, char **argv, int *mode, double *param, double *tol)
{
    *mode = -1;
    *param = 0;
    *tol = 0.0;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--dec") == 0 || strcmp(argv[i], "-d") == 0)
            *mode = F_DEC;
        else if (strcmp(argv[i], "--inc") == 0 || strcmp(argv[i], "-i") == 0)
            *mode = F_INC;
        else if (strcmp(argv[i], "--changed") == 0 || strcmp(argv[i], "-c") == 0)
            *mode = F_CHG;
        else if (strcmp(argv[i], "--unchanged") == 0 || strcmp(argv[i], "-u") == 0)
            *mode = F_UNCH;
        else if (strcmp(argv[i], "--eq") == 0 && i + 1 < argc) {
            *mode = F_EQ;
            *param = atof(argv[++i]);
        } else if (strcmp(argv[i], "--lt") == 0 && i + 1 < argc) {
            *mode = F_LT;
            *param = atof(argv[++i]);
        } else if (strcmp(argv[i], "--gt") == 0 && i + 1 < argc) {
            *mode = F_GT;
            *param = atof(argv[++i]);
        } else if (strcmp(argv[i], "--tol") == 0 && i + 1 < argc) {
            *tol = atof(argv[++i]);
        } else {
            fprintf(stderr, "error: bad filter option %s\n", argv[i]);
            exit(1);
        }
    }
    return *mode != -1;
}

static void search_filter(Search *s, int mode, double param, double tol, volatile int *cancel)
{
    size_t out = 0;
    size_t i = 0;
    while (i < s->n) {
        if (cancel && *cancel)
            break;
        size_t batch = s->n - i;
        if (batch > MAX_BATCH)
            batch = MAX_BATCH;
        struct iovec li[MAX_BATCH], ri[MAX_BATCH];
        uint32_t vals[MAX_BATCH];
        for (size_t k = 0; k < batch; k++) {
            li[k].iov_base = &vals[k];
            li[k].iov_len = 4;
            ri[k].iov_base = (void *)s->c[i + k].addr;
            ri[k].iov_len = 4;
        }
        ssize_t r = process_vm_readv(g_pid, li, batch, ri, batch, 0);
        size_t done = r > 0 ? (size_t)r / 4 : 0;
        for (size_t k = done; k < batch; k++) {
            int ok;
            vals[k] = read_at(s->c[i + k].addr, &ok);
            if (!ok)
                vals[k] = 0, li[k].iov_len = 0;
            else
                li[k].iov_len = 4;
        }
        for (size_t k = 0; k < batch; k++) {
            if (li[k].iov_len == 0)
                continue;
            uint32_t nb = vals[k];
            if (!val_finite(s->type, nb))
                continue;
            double ov = bits_to_val(s->type, s->c[i + k].bits);
            double nv = bits_to_val(s->type, nb);
            int keep = 0;
            switch (mode) {
            case F_DEC: keep = nv < ov - tol; break;
            case F_INC: keep = nv > ov + tol; break;
            case F_CHG: keep = fabs(nv - ov) > tol; break;
            case F_UNCH: keep = fabs(nv - ov) <= tol; break;
            case F_EQ: keep = fabs(nv - param) <= tol; break;
            case F_LT: keep = nv < param; break;
            case F_GT: keep = nv > param; break;
            }
            if (keep) {
                s->c[out].addr = s->c[i + k].addr;
                s->c[out].bits = nb;
                out++;
            }
        }
        i += batch;
    }
    s->n = out;
}

static void cmd_next(int argc, char **argv)
{
    load_state();
    int mode;
    double param, tol;
    if (!parse_filter(argc, argv, &mode, &param, &tol)) {
        fprintf(stderr, "error: give a filter: --dec --inc --changed --unchanged --eq V --lt V --gt V\n");
        exit(1);
    }
    search_filter(&g_s, mode, param, tol, NULL);
    save_state();
    printf("next scan: %zu candidates remain\n", g_s.n);
    if (g_s.n <= 30 && g_s.n > 0) {
        printf("candidates:\n");
        for (size_t k = 0; k < g_s.n; k++)
            printf("  [%zu] 0x%llx = %g\n", k, (unsigned long long)g_s.c[k].addr,
                   bits_to_val(g_s.type, g_s.c[k].bits));
        printf("be at full HP, then run: ds3hp lock <index>\n");
    }
}

static void read_many(const uint64_t *addrs, size_t n, uint32_t *out, uint8_t *ok)
{
    size_t i = 0;
    while (i < n) {
        size_t batch = n - i;
        if (batch > MAX_BATCH)
            batch = MAX_BATCH;
        struct iovec li[MAX_BATCH], ri[MAX_BATCH];
        for (size_t k = 0; k < batch; k++) {
            li[k].iov_base = &out[i + k];
            li[k].iov_len = 4;
            ri[k].iov_base = (void *)addrs[i + k];
            ri[k].iov_len = 4;
        }
        ssize_t r = process_vm_readv(g_pid, li, batch, ri, batch, 0);
        size_t done = r > 0 ? (size_t)r / 4 : 0;
        for (size_t k = 0; k < batch; k++)
            ok[i + k] = k < done ? 1 : 0;
        for (size_t k = done; k < batch; k++) {
            int o;
            out[i + k] = read_at(addrs[i + k], &o);
            ok[i + k] = o;
        }
        i += batch;
    }
}

static void cmd_list(int argc, char **argv)
{
    load_state();
    size_t limit = 50;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--limit") == 0 && i + 1 < argc)
            limit = (size_t)atol(argv[++i]);
    }
    printf("pid %d, type=%s, %zu candidates (values re-read from memory)\n", g_pid,
           g_s.type == T_FLOAT ? "float" : "int", g_s.n);
    size_t shown = g_s.n < limit ? g_s.n : limit;
    uint64_t *addrs = malloc((shown ? shown : 1) * sizeof(uint64_t));
    uint32_t *vals = malloc((shown ? shown : 1) * sizeof(uint32_t));
    uint8_t *ok = malloc(shown ? shown : 1);
    if (!addrs || !vals || !ok)
        die("malloc list");
    for (size_t k = 0; k < shown; k++)
        addrs[k] = g_s.c[k].addr;
    if (shown)
        read_many(addrs, shown, vals, ok);
    for (size_t k = 0; k < shown; k++) {
        if (ok[k])
            printf("  [%zu] 0x%llx = %g\n", k, (unsigned long long)addrs[k],
                   bits_to_val(g_s.type, vals[k]));
        else
            printf("  [%zu] 0x%llx = <unreadable>\n", k, (unsigned long long)addrs[k]);
    }
    if (shown < g_s.n)
        printf("  ... %zu more\n", g_s.n - shown);
    free(addrs);
    free(vals);
    free(ok);
}

static uint32_t read_at(uint64_t addr, int *ok)
{
    uint32_t v = 0;
    struct iovec li = { &v, 4 };
    struct iovec ri = { (void *)addr, 4 };
    *ok = process_vm_readv(g_pid, &li, 1, &ri, 1, 0) == 4;
    return v;
}

static void cmd_peek(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "error: peek <index>\n");
        exit(1);
    }
    load_state();
    size_t idx = (size_t)atol(argv[0]);
    if (idx >= g_s.n) {
        fprintf(stderr, "error: index out of range (0..%zu)\n", g_s.n ? g_s.n - 1 : 0);
        exit(1);
    }
    int ok;
    uint32_t v = read_at(g_s.c[idx].addr, &ok);
    if (!ok)
        printf("[%zu] 0x%llx = <unreadable>\n", idx, (unsigned long long)g_s.c[idx].addr);
    else
        printf("[%zu] 0x%llx = %g\n", idx, (unsigned long long)g_s.c[idx].addr,
               bits_to_val(g_s.type, v));
}

static void on_sigint(int sig)
{
    (void)sig;
    g_stop = 1;
}

#define MAX_LOCKS 8192

static void add_index(size_t idx, size_t **arr, size_t *cnt, size_t *cap)
{
    if (idx >= g_s.n) {
        fprintf(stderr, "error: index %zu out of range (0..%zu)\n", idx, g_s.n ? g_s.n - 1 : 0);
        exit(1);
    }
    if (*cnt == MAX_LOCKS) {
        fprintf(stderr, "error: too many targets (max %d); narrow the scan first\n", MAX_LOCKS);
        exit(1);
    }
    if (*cnt == *cap) {
        *cap = *cap ? *cap * 2 : 16;
        size_t *p = realloc(*arr, *cap * sizeof(size_t));
        if (!p)
            die("realloc indices");
        *arr = p;
    }
    (*arr)[(*cnt)++] = idx;
}

static void add_spec(const char *s, size_t **arr, size_t *cnt, size_t *cap)
{
    if (strcmp(s, "all") == 0) {
        for (size_t i = 0; i < g_s.n; i++)
            add_index(i, arr, cnt, cap);
        return;
    }
    const char *dash = strchr(s, '-');
    if (dash && dash != s) {
        long a = atol(s), b = atol(dash + 1);
        if (a > b) {
            long t = a;
            a = b;
            b = t;
        }
        for (long i = a; i <= b; i++)
            add_index((size_t)i, arr, cnt, cap);
        return;
    }
    add_index((size_t)atol(s), arr, cnt, cap);
}

static void cmd_lock(int argc, char **argv)
{
    load_state();
    size_t *idxs = NULL, nidx = 0, cap = 0;
    int have_val = 0;
    double val = 0;
    int interval = 5;
    int seconds = 0;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--value") == 0 && i + 1 < argc) {
            val = atof(argv[++i]);
            have_val = 1;
        } else if (strcmp(argv[i], "--interval-ms") == 0 && i + 1 < argc) {
            interval = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--seconds") == 0 && i + 1 < argc) {
            seconds = atoi(argv[++i]);
        } else if (argv[i][0] == '-' && !isdigit((unsigned char)argv[i][1])) {
            fprintf(stderr, "error: unknown option %s\n", argv[i]);
            exit(1);
        } else {
            add_spec(argv[i], &idxs, &nidx, &cap);
        }
    }
    if (nidx == 0) {
        fprintf(stderr, "error: lock <index|a-b|all> ... [--value V] [--interval-ms N] [--seconds N]\n");
        exit(1);
    }
    uint64_t *addrs = malloc(nidx * sizeof(uint64_t));
    uint32_t *bits = malloc(nidx * sizeof(uint32_t));
    if (!addrs || !bits)
        die("malloc locks");
    for (size_t i = 0; i < nidx; i++)
        addrs[i] = g_s.c[idxs[i]].addr;
    if (have_val) {
        for (size_t i = 0; i < nidx; i++)
            bits[i] = val_to_bits(g_s.type, val);
    } else {
        uint8_t *ok = malloc(nidx);
        if (!ok)
            die("malloc ok");
        read_many(addrs, nidx, bits, ok);
        for (size_t i = 0; i < nidx; i++) {
            if (!ok[i]) {
                fprintf(stderr, "error: cannot read 0x%llx (run list/peek)\n",
                        (unsigned long long)addrs[i]);
                exit(1);
            }
        }
        free(ok);
    }
    printf("locking %zu value(s), interval %dms; Ctrl-C to stop\n", nidx, interval);
    for (size_t i = 0; i < nidx; i++)
        printf("  [%zu] 0x%llx -> %g\n", idxs[i], (unsigned long long)addrs[i],
               bits_to_val(g_s.type, bits[i]));
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);
    time_t t0 = time(NULL);
    unsigned long writes = 0, fails = 0;
    while (!g_stop) {
        for (size_t off = 0; off < nidx; off += MAX_BATCH) {
            size_t batch = nidx - off;
            if (batch > MAX_BATCH)
                batch = MAX_BATCH;
            struct iovec li[MAX_BATCH], ri[MAX_BATCH];
            for (size_t k = 0; k < batch; k++) {
                li[k].iov_base = &bits[off + k];
                li[k].iov_len = 4;
                ri[k].iov_base = (void *)addrs[off + k];
                ri[k].iov_len = 4;
            }
            ssize_t w = process_vm_writev(g_pid, li, batch, ri, batch, 0);
            if (w != (ssize_t)batch * 4)
                fails++;
            writes++;
        }
        if (seconds > 0 && time(NULL) - t0 >= seconds)
            break;
        struct timespec ts = { 0, (long)interval * 1000000L };
        nanosleep(&ts, NULL);
    }
    printf("stopped after %lu write passes (%lu failed)\n", writes, fails);
    free(addrs);
    free(bits);
    free(idxs);
}

static void cmd_set(int argc, char **argv)
{
    load_state();
    size_t *idxs = NULL, nidx = 0, cap = 0;
    int have_val = 0;
    double val = 0;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--value") == 0 && i + 1 < argc) {
            val = atof(argv[++i]);
            have_val = 1;
        } else if (argv[i][0] == '-' && !isdigit((unsigned char)argv[i][1])) {
            fprintf(stderr, "error: unknown option %s\n", argv[i]);
            exit(1);
        } else {
            add_spec(argv[i], &idxs, &nidx, &cap);
        }
    }
    if (!have_val) {
        fprintf(stderr, "error: set <index|a-b|all> --value V\n");
        exit(1);
    }
    if (nidx == 0) {
        fprintf(stderr, "error: set <index|a-b|all> --value V\n");
        exit(1);
    }
    uint32_t bits = val_to_bits(g_s.type, val);
    unsigned long written = 0, fails = 0;
    for (size_t i = 0; i < nidx; i++) {
        uint64_t addr = g_s.c[idxs[i]].addr;
        struct iovec li = { &bits, 4 };
        struct iovec ri = { (void *)addr, 4 };
        if (process_vm_writev(g_pid, &li, 1, &ri, 1, 0) == 4)
            written++;
        else
            fails++;
    }
    printf("set %lu value(s) to %g (%lu failed)\n", written, val, fails);
    free(idxs);
}

static void cmd_reset(void)
{
    if (unlink(STATE_PATH) == 0)
        printf("state cleared\n");
    else
        printf("nothing to clear\n");
}

/* ======================= pointer chains ======================= */

#define CHAIN_MAGIC "DS3CHAIN"
#define CHAIN_VERSION 3
#define CHAIN_MAX 8
#define CHAIN_MAX_OFF (1u << 20)
#define CHAIN_MAX_PROBES 8000000u
#define CHAIN_COUNT_MAX 1000000u

typedef struct {
    uint64_t rva;
    uint8_t n;
    uint64_t offs[CHAIN_MAX];
} Chain;

typedef struct {
    int type;
    char module[256];
    uint32_t scans;
    uint32_t verifies;
    uint64_t token;
    Chain *c;
    uint32_t n, cap;
} ChainSet;

typedef struct {
    uint64_t start, end;
    char perms[8];
    char path[1024];
} CMap;

static int cmaps_read(int pid, CMap **out, size_t *outn)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    CMap *m = NULL;
    size_t n = 0, cap = 0;
    char line[2048];
    while (fgets(line, sizeof line, f)) {
        unsigned long long a, b;
        char perms[8] = {0};
        char rest[1024] = {0};
        if (sscanf(line, "%llx-%llx %7s %*s %*s %*s %1023[^\n]", &a, &b, perms, rest) < 3)
            continue;
        char *p = rest;
        while (*p && isspace((unsigned char)*p))
            p++;
        if (n == cap) {
            cap = cap ? cap * 2 : 256;
            CMap *nm = realloc(m, cap * sizeof(CMap));
            if (!nm) {
                free(m);
                fclose(f);
                return -1;
            }
            m = nm;
        }
        m[n].start = a;
        m[n].end = b;
        snprintf(m[n].perms, sizeof m[n].perms, "%s", perms);
        snprintf(m[n].path, sizeof m[n].path, "%s", p);
        n++;
    }
    fclose(f);
    *out = m;
    *outn = n;
    return 0;
}

static long cmap_find(const CMap *m, size_t n, uint64_t a)
{
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (a < m[mid].start)
            hi = mid;
        else if (a >= m[mid].end)
            lo = mid + 1;
        else
            return (long)mid;
    }
    return -1;
}

static int cmap_readable(const CMap *m, size_t n, uint64_t a)
{
    long r = cmap_find(m, n, a);
    return r >= 0 && m[r].perms[0] == 'r';
}

static uint64_t chain_module_base(const CMap *m, size_t n, const char *sub)
{
    uint64_t base = 0;
    for (size_t i = 0; i < n; i++)
        if (m[i].path[0] && strstr(m[i].path, sub) &&
            (base == 0 || m[i].start < base))
            base = m[i].start;
    return base;
}

/* per-process token: starttime (jiffies since boot) mixed with pid, so two
 * scans of the same game instance compare equal but a restart does not */
static uint64_t process_token(int pid)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char buf[1024];
    if (!fgets(buf, sizeof buf, f)) {
        fclose(f);
        return 0;
    }
    fclose(f);
    char *p = strrchr(buf, ')');
    if (!p)
        return 0;
    const char *q = p + 1;
    long field = 3;
    uint64_t starttime = 0;
    while (*q) {
        while (*q == ' ')
            q++;
        if (!*q)
            break;
        if (field == 22) {
            starttime = strtoull(q, NULL, 10);
            break;
        }
        while (*q && *q != ' ')
            q++;
        field++;
    }
    return starttime * 2654435761ull + (uint64_t)(uint32_t)pid;
}

static int chain_is_static(const CMap *m, size_t n, uint64_t a, const char *mod)
{
    long r = cmap_find(m, n, a);
    if (r < 0 || !m[r].path[0] || !strstr(m[r].path, mod))
        return 0;
    return m[r].perms[0] == 'r' && m[r].perms[1] == 'w';
}

static int read64_at(int pid, uint64_t addr, uint64_t *out)
{
    struct iovec li = { out, 8 };
    struct iovec ri = { (void *)addr, 8 };
    return process_vm_readv(pid, &li, 1, &ri, 1, 0) == 8;
}

static int chain_resolve(int pid, const CMap *m, size_t nm, uint64_t modbase,
                         const Chain *c, uint64_t *res)
{
    uint64_t a = modbase + c->rva;
    for (int i = 0; i < c->n; i++) {
        long r = cmap_find(m, nm, a);
        if (r < 0 || m[r].perms[0] != 'r')
            return 0;
        uint64_t p;
        if (!read64_at(pid, a, &p))
            return 0;
        a = p + c->offs[i];
    }
    *res = a;
    return 1;
}

static uint64_t chain_total_off(const Chain *c)
{
    uint64_t t = 0;
    for (int i = 0; i < c->n; i++)
        t += c->offs[i];
    return t;
}

static int chain_is_stable(const ChainSet *cs)
{
    return (cs->scans >= 2 || cs->verifies >= 1) && cs->n == 1;
}

/* keep only chains whose resolved value equals val; returns survivors or -1 */
static int chain_verify(ChainSet *cs, int pid, double val)
{
    if (cs->n == 0)
        return 0;
    CMap *m = NULL;
    size_t nm = 0;
    if (cmaps_read(pid, &m, &nm) != 0) {
        fprintf(stderr, "error: open maps\n");
        return -1;
    }
    uint64_t modbase = chain_module_base(m, nm, cs->module);
    if (!modbase) {
        const char *base = strrchr(cs->module, '/');
        base = base ? base + 1 : cs->module;
        modbase = chain_module_base(m, nm, base);
    }
    if (!modbase) {
        fprintf(stderr, "error: module '%s' not mapped now\n", cs->module);
        free(m);
        return -1;
    }
    uint32_t want = val_to_bits(cs->type, val);
    uint32_t out = 0;
    for (uint32_t i = 0; i < cs->n; i++) {
        uint64_t addr;
        if (!chain_resolve(g_pid, m, nm, modbase, &cs->c[i], &addr))
            continue;
        int ok;
        uint32_t v = read_at(addr, &ok);
        if (ok && v == want)
            cs->c[out++] = cs->c[i];
    }
    free(m);
    cs->n = out;
    cs->verifies++;
    return (int)out;
}

static void chain_format(const Chain *c, const char *mod, char *buf, size_t len)
{
    size_t off = 0;
    off += snprintf(buf + off, len - off, "%s+0x%llx", mod,
                    (unsigned long long)c->rva);
    for (int i = 0; i < c->n && off < len; i++)
        off += snprintf(buf + off, len - off, " -> 0x%llx",
                        (unsigned long long)c->offs[i]);
}

static int chain_id_cmp(const void *A, const void *B)
{
    const Chain *a = A, *b = B;
    if (a->rva != b->rva)
        return a->rva < b->rva ? -1 : 1;
    if (a->n != b->n)
        return a->n < b->n ? -1 : 1;
    for (int i = 0; i < a->n; i++)
        if (a->offs[i] != b->offs[i])
            return a->offs[i] < b->offs[i] ? -1 : 1;
    return 0;
}

/* prefer deep chains with small total offset */
static int chain_heur_cmp(const void *A, const void *B)
{
    const Chain *a = A, *b = B;
    if (a->n != b->n)
        return a->n > b->n ? -1 : 1;
    uint64_t ta = chain_total_off(a), tb = chain_total_off(b);
    if (ta != tb)
        return ta < tb ? -1 : 1;
    return chain_id_cmp(A, B);
}

static void cs_push(ChainSet *cs, const Chain *c)
{
    if (cs->n >= CHAIN_COUNT_MAX)
        return;
    if (cs->n == cs->cap) {
        uint32_t nc = cs->cap ? cs->cap * 2 : 64;
        Chain *p = realloc(cs->c, nc * sizeof(Chain));
        if (!p)
            return;
        cs->c = p;
        cs->cap = nc;
    }
    cs->c[cs->n++] = *c;
}

static void chainset_unique(ChainSet *cs)
{
    if (cs->n < 2)
        return;
    qsort(cs->c, cs->n, sizeof(Chain), chain_id_cmp);
    uint32_t w = 1;
    for (uint32_t i = 1; i < cs->n; i++)
        if (chain_id_cmp(&cs->c[i], &cs->c[w - 1]) != 0)
            cs->c[w++] = cs->c[i];
    cs->n = w;
}

/* build one chain by walking probe parents; returns 0 if too deep */
typedef struct {
    uint64_t loc, off;
    int64_t parent;
} CProbe;

static int cbuild(const CProbe *all, size_t s, uint64_t modbase, Chain *out)
{
    uint64_t offs[CHAIN_MAX];
    int n = 0;
    int64_t cur = (int64_t)s;
    while (all[cur].parent >= 0) {
        if (n >= CHAIN_MAX)
            return 0;
        offs[n++] = all[cur].off;
        cur = all[cur].parent;
    }
    out->rva = all[s].loc - modbase;
    out->n = (uint8_t)n;
    for (int i = 0; i < n; i++)
        out->offs[i] = offs[i];
    return 1;
}

static CProbe *g_cprobes;

static int cprobe_cmp(const void *pa, const void *pb)
{
    uint64_t x = g_cprobes[*(const size_t *)pa].loc;
    uint64_t y = g_cprobes[*(const size_t *)pb].loc;
    return (x > y) - (x < y);
}

static int chain_region_special(const char *path)
{
    return path[0] == '[' &&
           (strncmp(path, "[stack]", 7) == 0 ||
            strncmp(path, "[vvar]", 6) == 0 ||
            strncmp(path, "[vdso]", 6) == 0);
}

static void chain_scan(int pid, uint64_t T, int depth, uint64_t maxoff,
                       const char *mod, ChainSet *out,
                       volatile int *cancel, volatile uint64_t *done,
                       uint64_t *total_out)
{
    CMap *m = NULL;
    size_t nm = 0;
    if (cmaps_read(pid, &m, &nm) != 0) {
        fprintf(stderr, "error: open maps\n");
        return;
    }
    uint64_t modbase = chain_module_base(m, nm, mod);
    uint64_t minaddr = UINT64_MAX, maxaddr = 0, total = 0;
    for (size_t i = 0; i < nm; i++) {
        if (m[i].perms[0] != 'r' || chain_region_special(m[i].path))
            continue;
        if (m[i].start < minaddr)
            minaddr = m[i].start;
        if (m[i].end > maxaddr)
            maxaddr = m[i].end;
        total += m[i].end - m[i].start;
    }
    if (total_out)
        *total_out = total;
    if (!modbase) {
        fprintf(stderr, "error: module '%s' not mapped; use --module SUBSTR\n", mod);
        free(m);
        return;
    }

    CProbe *all = NULL;
    size_t nall = 0, call = 0;
    size_t *lvl = NULL, *next = NULL;
    size_t nlvl = 0, nnext = 0, cnext = 0;
    uint8_t *buf = NULL;
    int oom = 0, exhausted = 0;

    all = malloc(256 * sizeof(CProbe));
    lvl = malloc(sizeof(size_t));
    buf = malloc(CHUNK);
    if (!all || !lvl || !buf) {
        fprintf(stderr, "error: malloc scan\n");
        free(all);
        free(lvl);
        free(buf);
        free(m);
        return;
    }
    call = 256;
    all[nall].loc = T;
    all[nall].off = 0;
    all[nall].parent = -1;
    nall = 1;
    lvl[0] = 0;
    nlvl = 1;

    for (int d = 1; d <= depth && !(cancel && *cancel) && !exhausted && !oom; d++) {
        if (nlvl == 0)
            break;
        g_cprobes = all;
        qsort(lvl, nlvl, sizeof(size_t), cprobe_cmp);
        next = NULL;
        nnext = 0;
        cnext = 0;
        uint64_t scanned = 0;
        for (size_t ri = 0; ri < nm && !exhausted && !oom; ri++) {
            if (m[ri].perms[0] != 'r' || chain_region_special(m[ri].path))
                continue;
            uint64_t p = m[ri].start;
            while (p < m[ri].end) {
                if (cancel && *cancel)
                    break;
                size_t want = (size_t)(m[ri].end - p);
                if (want > CHUNK)
                    want = CHUNK;
                struct iovec li = { buf, want };
                struct iovec rr = { (void *)p, want };
                ssize_t rd = process_vm_readv(pid, &li, 1, &rr, 1, 0);
                if (rd <= 0) {
                    p += 4096 - (p & 4095);
                    continue;
                }
                size_t words = (size_t)rd / 8;
                for (size_t j = 0; j < words; j++) {
                    uint64_t W;
                    memcpy(&W, buf + j * 8, 8);
                    if (W < minaddr || W >= maxaddr)
                        continue;
                    if (!cmap_readable(m, nm, W))
                        continue;
                    size_t lo = 0, hi = nlvl;
                    while (lo < hi) {
                        size_t mid = (lo + hi) / 2;
                        if (all[lvl[mid]].loc < W)
                            lo = mid + 1;
                        else
                            hi = mid;
                    }
                    if (lo >= nlvl)
                        continue;
                    uint64_t A = all[lvl[lo]].loc;
                    if (A < W)
                        continue;
                    uint64_t dd = A - W;
                    if (dd > maxoff)
                        continue;
                    uint64_t loc = p + j * 8;
                    if (nall == call) {
                        call = call ? call * 2 : 256;
                        CProbe *np = realloc(all, call * sizeof(CProbe));
                        if (!np) {
                            oom = 1;
                            break;
                        }
                        all = np;
                    }
                    g_cprobes = all;
                    all[nall].loc = loc;
                    all[nall].off = dd;
                    all[nall].parent = (int64_t)lvl[lo];
                    nall++;
                    if (chain_is_static(m, nm, loc, mod)) {
                        Chain c;
                        if (cbuild(all, nall - 1, modbase, &c)) {
                            uint64_t res;
                            if (chain_resolve(pid, m, nm, modbase, &c, &res) && res == T)
                                cs_push(out, &c);
                        }
                    } else {
                        if (nnext == cnext) {
                            cnext = cnext ? cnext * 2 : 256;
                            size_t *nn = realloc(next, cnext * sizeof(size_t));
                            if (!nn) {
                                oom = 1;
                                break;
                            }
                            next = nn;
                        }
                        next[nnext++] = nall - 1;
                    }
                    if (nall >= CHAIN_MAX_PROBES) {
                        exhausted = 1;
                        break;
                    }
                }
                p += words * 8;
                if ((size_t)rd < want && words * 8 == (size_t)rd)
                    p += 8 - (p & 7);
                scanned = p - m[ri].start;
                if (done)
                    *done = scanned;
                if (exhausted)
                    break;
            }
        }
        free(lvl);
        lvl = next;
        nlvl = nnext;
        next = NULL;
    }

    if (exhausted)
        fprintf(stderr, "  warning: probe limit reached (%u); results may be incomplete\n",
                CHAIN_MAX_PROBES);
    if (oom)
        fprintf(stderr, "  warning: out of memory during scan\n");

    chainset_unique(out);
    qsort(out->c, out->n, sizeof(Chain), chain_heur_cmp);
    free(buf);
    free(all);
    free(lvl);
    free(next);
    free(m);
}

static int chainset_save(const char *file, const ChainSet *cs)
{
    FILE *f = fopen(file, "wb");
    if (!f) {
        fprintf(stderr, "error: open %s: %s\n", file, strerror(errno));
        return -1;
    }
    uint32_t ver = CHAIN_VERSION;
    uint32_t scans = cs->scans;
    uint32_t verifies = cs->verifies;
    int32_t type = cs->type;
    uint64_t token = cs->token;
    uint16_t ml = (uint16_t)strlen(cs->module);
    uint32_t cnt = cs->n;
    fwrite(CHAIN_MAGIC, 1, 8, f);
    fwrite(&ver, 4, 1, f);
    fwrite(&scans, 4, 1, f);
    fwrite(&verifies, 4, 1, f);
    fwrite(&type, 4, 1, f);
    fwrite(&token, 8, 1, f);
    fwrite(&ml, 2, 1, f);
    if (ml)
        fwrite(cs->module, 1, ml, f);
    fwrite(&cnt, 4, 1, f);
    for (uint32_t i = 0; i < cs->n; i++) {
        fwrite(&cs->c[i].rva, 8, 1, f);
        fwrite(&cs->c[i].n, 1, 1, f);
        if (cs->c[i].n)
            fwrite(cs->c[i].offs, 8, cs->c[i].n, f);
    }
    fclose(f);
    return 0;
}

static int chainset_load(const char *file, ChainSet *cs)
{
    FILE *f = fopen(file, "rb");
    if (!f)
        return -1;
    char magic[8];
    uint32_t ver = 0, scans = 0, verifies = 0, cnt = 0;
    int32_t type = 0;
    uint64_t token = 0;
    uint16_t ml = 0;
    int ok = 1;
    if (fread(magic, 1, 8, f) != 8 || memcmp(magic, CHAIN_MAGIC, 8) != 0)
        ok = 0;
    if (ok && (fread(&ver, 4, 1, f) != 1 || ver != CHAIN_VERSION))
        ok = 0;
    if (ok && (fread(&scans, 4, 1, f) != 1 || fread(&verifies, 4, 1, f) != 1 ||
               fread(&type, 4, 1, f) != 1 || fread(&token, 8, 1, f) != 1))
        ok = 0;
    if (ok && (fread(&ml, 2, 1, f) != 1 || ml >= sizeof cs->module))
        ok = 0;
    if (ok && ml && fread(cs->module, 1, ml, f) != ml)
        ok = 0;
    cs->module[ok ? ml : 0] = 0;
    if (ok && (fread(&cnt, 4, 1, f) != 1 || cnt > CHAIN_COUNT_MAX))
        ok = 0;
    if (!ok) {
        fclose(f);
        fprintf(stderr, "error: bad chain file: %s\n", file);
        return -2;
    }
    Chain *arr = calloc(cnt ? cnt : 1, sizeof(Chain));
    if (!arr) {
        fclose(f);
        fprintf(stderr, "error: malloc chain file\n");
        return -2;
    }
    cs->c = arr;
    cs->cap = cnt ? cnt : 1;
    cs->n = 0;
    cs->scans = scans;
    cs->verifies = verifies;
    cs->type = type;
    cs->token = token;
    for (uint32_t i = 0; i < cnt; i++) {
        uint8_t n;
        if (fread(&arr[i].rva, 8, 1, f) != 1 || fread(&n, 1, 1, f) != 1 ||
            n > CHAIN_MAX || (n && fread(arr[i].offs, 8, n, f) != n)) {
            fclose(f);
            free(arr);
            cs->c = NULL;
            cs->n = 0;
            cs->cap = 0;
            fprintf(stderr, "error: bad chain file: %s\n", file);
            return -2;
        }
        arr[i].n = n;
        cs->n++;
    }
    fclose(f);
    return 0;
}

static int cs_contains(const ChainSet *cs, const Chain *c)
{
    size_t lo = 0, hi = cs->n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        int r = chain_id_cmp(&cs->c[mid], c);
        if (r == 0)
            return 1;
        if (r < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return 0;
}

/* intersect a (previous scans) with b (current scan); both sorted by id */
static int chainset_intersect(ChainSet *a, ChainSet *b, ChainSet *out)
{
    qsort(a->c, a->n, sizeof(Chain), chain_id_cmp);
    qsort(b->c, b->n, sizeof(Chain), chain_id_cmp);
    out->type = a->type;
    snprintf(out->module, sizeof out->module, "%s", a->module);
    out->scans = a->scans + 1;
    out->verifies = a->verifies;
    for (uint32_t i = 0; i < a->n; i++)
        if (cs_contains(b, &a->c[i]))
            cs_push(out, &a->c[i]);
    chainset_unique(out);
    qsort(out->c, out->n, sizeof(Chain), chain_heur_cmp);
    return 0;
}

static int cmd_chain_scan(int argc, char **argv)
{
    const char *file = NULL;
    const char *mod = "DarkSoulsIII.exe";
    uint64_t addr = 0;
    int have_addr = 0, depth = 4, pid = 0, reset = 0, type = T_FLOAT;
    uint64_t maxoff = 0x1000;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--addr") == 0 && i + 1 < argc) {
            addr = strtoull(argv[++i], NULL, 0);
            have_addr = 1;
        } else if (strcmp(argv[i], "--depth") == 0 && i + 1 < argc) {
            depth = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--max-offset") == 0 && i + 1 < argc) {
            maxoff = strtoull(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--module") == 0 && i + 1 < argc) {
            mod = argv[++i];
        } else if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
            pid = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) {
            const char *t = argv[++i];
            type = strcmp(t, "int") == 0 ? T_INT : T_FLOAT;
        } else if (strcmp(argv[i], "--reset") == 0) {
            reset = 1;
        } else if (!file) {
            file = argv[i];
        } else {
            fprintf(stderr, "error: unknown option %s\n", argv[i]);
            return 1;
        }
    }
    if (!file || !have_addr) {
        fprintf(stderr, "error: chain scan <file> --addr 0xADDR [--depth N] [--max-offset M] [--module S] [--pid P] [--type float|int] [--reset]\n");
        return 1;
    }
    if (depth < 1 || depth > CHAIN_MAX)
        depth = CHAIN_MAX;
    if (maxoff > CHAIN_MAX_OFF)
        maxoff = CHAIN_MAX_OFF;
    g_pid = pid ? pid : detect_pid();
    if (!g_pid) {
        fprintf(stderr, "error: Dark Souls III process not found\n");
        return 1;
    }
    CMap *m = NULL;
    size_t nm = 0;
    if (cmaps_read(g_pid, &m, &nm) != 0) {
        fprintf(stderr, "error: open maps\n");
        return 1;
    }
    uint64_t modbase = chain_module_base(m, nm, mod);
    if (!modbase) {
        fprintf(stderr, "error: module '%s' not mapped; use --module SUBSTR\n", mod);
        free(m);
        return 1;
    }
    if (!cmap_readable(m, nm, addr)) {
        fprintf(stderr, "error: target 0x%llx is not readable\n", (unsigned long long)addr);
        free(m);
        return 1;
    }
    free(m);

    ChainSet prev;
    int have_prev = 0;
    if (!reset) {
        int r = chainset_load(file, &prev);
        if (r == 0)
            have_prev = 1;
        else if (r == -2)
            return 1;
    }

    ChainSet fresh = {0};
    fresh.type = type;
    snprintf(fresh.module, sizeof fresh.module, "%s", mod);
    fprintf(stderr, "pointer scan: target 0x%llx, module %s (base 0x%llx), depth %d, max-offset 0x%llx\n",
            (unsigned long long)addr, mod, (unsigned long long)modbase, depth,
            (unsigned long long)maxoff);
    uint64_t total = 0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    chain_scan(g_pid, addr, depth, maxoff, mod, &fresh, NULL, NULL, &total);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double dt = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    printf("scan: %u candidate chain(s) in %.1fs\n", fresh.n, dt);

    ChainSet result = {0};
    uint64_t tok = process_token(g_pid);
    if (have_prev && prev.token != 0 && prev.token == tok) {
        fprintf(stderr, "note: same process as last scan (pid %d); restart the game before scanning again\n", g_pid);
        result = prev;
    } else if (have_prev) {
        chainset_intersect(&prev, &fresh, &result);
        result.token = tok;
        printf("intersect: %u -> %u chain(s) (scan #%u)\n", prev.n, result.n, result.scans);
        free(prev.c);
    } else {
        result = fresh;
        result.type = type;
        snprintf(result.module, sizeof result.module, "%s", mod);
        result.scans = 1;
        result.token = tok;
        memset(&fresh, 0, sizeof fresh);
        printf("saved %u candidate chain(s) (scan #1)\n", result.n);
        if (result.n == 0)
            fprintf(stderr, "note: no chain found; increase --depth/--max-offset\n");
    }
    if (chainset_save(file, &result) != 0) {
        free(result.c);
        return 1;
    }
    printf("wrote %s (%u chain(s), %u scan(s), %u verify/ies)\n", file, result.n,
           result.scans, result.verifies);
    if (chain_is_stable(&result)) {
        char b[512];
        chain_format(&result.c[0], result.module, b, sizeof b);
        printf("stable chain: %s\n", b);
        printf("use: ds3hp chain load %s\n", file);
    } else if (result.n > 1) {
        printf("still %u candidate(s); re-run after a restart, or use"
               " 'chain verify <file> --value V'\n", result.n);
    }
    free(result.c);
    free(fresh.c);
    return 0;
}

static ChainSet chain_load_file(const char *file)
{
    ChainSet cs = {0};
    int r = chainset_load(file, &cs);
    if (r == -1) {
        fprintf(stderr, "error: no chain file %s; run 'chain scan' first\n", file);
        exit(1);
    }
    if (r != 0)
        exit(1);
    return cs;
}

static void cmd_chain_list(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "error: chain list <file>\n");
        exit(1);
    }
    ChainSet cs = chain_load_file(argv[0]);
    printf("%s: %u chain(s), %u scan(s), module %s, type %s\n", argv[0], cs.n,
           cs.scans, cs.module, cs.type == T_FLOAT ? "float" : "int");
    for (uint32_t i = 0; i < cs.n; i++) {
        char b[512];
        chain_format(&cs.c[i], cs.module, b, sizeof b);
        printf("  [%u] %s  (%u deref%s, total 0x%llx)\n", i, b, cs.c[i].n,
               cs.c[i].n == 1 ? "" : "s", (unsigned long long)chain_total_off(&cs.c[i]));
    }
    free(cs.c);
}

static void cmd_chain_resolve(int argc, char **argv)
{
    const char *file = NULL;
    int index = 0, pid = 0, have_val = 0;
    double val = 0;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--index") == 0 && i + 1 < argc)
            index = atoi(argv[++i]);
        else if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc)
            pid = atoi(argv[++i]);
        else if (strcmp(argv[i], "--value") == 0 && i + 1 < argc) {
            val = atof(argv[++i]);
            have_val = 1;
        } else if (!file)
            file = argv[i];
        else {
            fprintf(stderr, "error: unknown option %s\n", argv[i]);
            exit(1);
        }
    }
    if (!file) {
        fprintf(stderr, "error: chain resolve <file> [--index K] [--pid P] [--value V]\n");
        exit(1);
    }
    ChainSet cs = chain_load_file(file);
    if (cs.scans < 2)
        fprintf(stderr, "warning: only %u scan(s); chain not yet verified across restarts\n", cs.scans);
    if (index < 0 || (uint32_t)index >= cs.n) {
        fprintf(stderr, "error: index %d out of range (0..%d)\n", index,
                cs.n ? (int)cs.n - 1 : 0);
        exit(1);
    }
    g_pid = pid ? pid : detect_pid();
    if (!g_pid) {
        fprintf(stderr, "error: Dark Souls III process not found\n");
        exit(1);
    }
    CMap *m = NULL;
    size_t nm = 0;
    if (cmaps_read(g_pid, &m, &nm) != 0) {
        fprintf(stderr, "error: open maps\n");
        exit(1);
    }
    uint64_t modbase = chain_module_base(m, nm, cs.module);
    if (!modbase) {
        const char *base = strrchr(cs.module, '/');
        base = base ? base + 1 : cs.module;
        modbase = chain_module_base(m, nm, base);
    }
    if (!modbase) {
        fprintf(stderr, "error: module '%s' not mapped now\n", cs.module);
        exit(1);
    }
    uint64_t addr;
    if (!chain_resolve(g_pid, m, nm, modbase, &cs.c[index], &addr)) {
        fprintf(stderr, "error: chain %d failed to resolve\n", index);
        exit(1);
    }
    char b[512];
    chain_format(&cs.c[index], cs.module, b, sizeof b);
    printf("%s\n  resolves to 0x%llx (pid %d, module base 0x%llx)\n", b,
           (unsigned long long)addr, g_pid, (unsigned long long)modbase);
    if (have_val) {
        int ok;
        uint32_t v = read_at(addr, &ok);
        uint32_t want = val_to_bits(cs.type, val);
        if (!ok)
            printf("  warning: value unreadable at address\n");
        else if (v != want)
            printf("  warning: value %g != expected %g (address may be wrong)\n",
                   bits_to_val(cs.type, v), val);
        else
            printf("  value check ok: %g\n", val);
    }
    free(m);
    free(cs.c);
}

static void cmd_chain_load(int argc, char **argv)
{
    const char *file = NULL;
    int index = 0, pid = 0, have_val = 0;
    double val = 0;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--index") == 0 && i + 1 < argc)
            index = atoi(argv[++i]);
        else if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc)
            pid = atoi(argv[++i]);
        else if (strcmp(argv[i], "--value") == 0 && i + 1 < argc) {
            val = atof(argv[++i]);
            have_val = 1;
        } else if (!file)
            file = argv[i];
        else {
            fprintf(stderr, "error: unknown option %s\n", argv[i]);
            exit(1);
        }
    }
    if (!file) {
        fprintf(stderr, "error: chain load <file> [--index K] [--pid P] [--value V]\n");
        exit(1);
    }
    ChainSet cs = chain_load_file(file);
    if (cs.scans < 2)
        fprintf(stderr, "warning: only %u scan(s); chain not yet verified across restarts\n", cs.scans);
    if (index < 0 || (uint32_t)index >= cs.n) {
        fprintf(stderr, "error: index %d out of range (0..%d)\n", index,
                cs.n ? (int)cs.n - 1 : 0);
        exit(1);
    }
    g_pid = pid ? pid : detect_pid();
    if (!g_pid) {
        fprintf(stderr, "error: Dark Souls III process not found\n");
        exit(1);
    }
    CMap *m = NULL;
    size_t nm = 0;
    if (cmaps_read(g_pid, &m, &nm) != 0) {
        fprintf(stderr, "error: open maps\n");
        exit(1);
    }
    uint64_t modbase = chain_module_base(m, nm, cs.module);
    uint64_t addr;
    if (!modbase || !chain_resolve(g_pid, m, nm, modbase, &cs.c[index], &addr)) {
        fprintf(stderr, "error: chain %d failed to resolve (module %s)\n", index, cs.module);
        exit(1);
    }
    int ok;
    uint32_t cur = read_at(addr, &ok);
    if (!ok) {
        fprintf(stderr, "error: resolved address 0x%llx is unreadable\n",
                (unsigned long long)addr);
        exit(1);
    }
    if (have_val) {
        uint32_t want = val_to_bits(cs.type, val);
        if (cur != want)
            printf("warning: current value %g != expected %g\n",
                   bits_to_val(cs.type, cur), val);
    }
    g_s.type = cs.type;
    g_s.min = 1.0;
    g_s.max = 10000.0;
    g_s.exact = 0;
    g_s.tol = 0;
    Cand c = { addr, cur };
    g_s.c = &c;
    g_s.n = 1;
    g_s.cap = 1;
    save_state();
    g_s.c = NULL;
    g_s.n = 0;
    g_s.cap = 0;
    printf("loaded chain %d -> 0x%llx = %g (pid %d)\n", index,
           (unsigned long long)addr, bits_to_val(cs.type, cur), g_pid);
    printf("run 'ds3hp list' or 'ds3hp lock 0' to use it\n");
    free(m);
    free(cs.c);
}

static void cmd_chain_verify(int argc, char **argv)
{
    const char *file = NULL;
    int pid = 0, have_val = 0;
    double val = 0;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--value") == 0 && i + 1 < argc) {
            val = atof(argv[++i]);
            have_val = 1;
        } else if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
            pid = atoi(argv[++i]);
        } else if (!file) {
            file = argv[i];
        } else {
            fprintf(stderr, "error: unknown option %s\n", argv[i]);
            exit(1);
        }
    }
    if (!file || !have_val) {
        fprintf(stderr, "error: chain verify <file> --value V [--pid P]\n");
        exit(1);
    }
    ChainSet cs = chain_load_file(file);
    g_pid = pid ? pid : detect_pid();
    if (!g_pid) {
        fprintf(stderr, "error: Dark Souls III process not found\n");
        exit(1);
    }
    if (cs.token != 0 && cs.token == process_token(g_pid)) {
        fprintf(stderr, "same process as last scan; restart the game before verifying"
                        " (verify needs a new layout to filter)\n");
        free(cs.c);
        return;
    }
    uint32_t before = cs.n;
    int r = chain_verify(&cs, g_pid, val);
    if (r < 0) {
        free(cs.c);
        exit(1);
    }
    if (cs.n == 0) {
        fprintf(stderr, "no chain matched %g; %u candidate(s) kept (not saved)\n",
                val, before);
        free(cs.c);
        return;
    }
    if (chainset_save(file, &cs) != 0) {
        free(cs.c);
        exit(1);
    }
    printf("verify: %u -> %u chain(s) against %g (%u verify/ies)\n", before, cs.n,
           val, cs.verifies);
    if (chain_is_stable(&cs)) {
        char b[512];
        chain_format(&cs.c[0], cs.module, b, sizeof b);
        printf("stable chain: %s\n", b);
        printf("use: ds3hp chain load %s\n", file);
    } else {
        printf("still %u candidate(s); repeat with another value or restart\n", cs.n);
    }
    free(cs.c);
}

static void cmd_chain_clear(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "error: chain clear <file>\n");
        exit(1);
    }
    if (unlink(argv[0]) == 0)
        printf("removed %s\n", argv[0]);
    else
        printf("nothing to remove (%s)\n", argv[0]);
}

static void cmd_chain(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "usage: chain <scan|list|resolve|load|clear> ...\n");
        exit(1);
    }
    const char *sub = argv[0];
    if (strcmp(sub, "scan") == 0)
        cmd_chain_scan(argc - 1, argv + 1);
    else if (strcmp(sub, "list") == 0)
        cmd_chain_list(argc - 1, argv + 1);
    else if (strcmp(sub, "resolve") == 0)
        cmd_chain_resolve(argc - 1, argv + 1);
    else if (strcmp(sub, "verify") == 0)
        cmd_chain_verify(argc - 1, argv + 1);
    else if (strcmp(sub, "load") == 0)
        cmd_chain_load(argc - 1, argv + 1);
    else if (strcmp(sub, "clear") == 0)
        cmd_chain_clear(argc - 1, argv + 1);
    else {
        fprintf(stderr, "error: unknown chain subcommand '%s'\n", sub);
        exit(1);
    }
}

/* ============================ TUI ============================ */

#define MAX_WATCH 64
#define TICK_MS 20
#define SCAN_FIRST (-1)
#define SCAN_CHAIN (-2)
#define CHAIN_DEF_DEPTH 4
#define CHAIN_DEF_OFF 0x1000

typedef struct {
    char name[24];
    Search s;
    int has_addr;
    uint64_t addr;
    int lock_on;
    int has_lockval;
    uint32_t lock_bits;
    volatile int scanning;
    volatile int cancel;
    volatile uint64_t progress;
    uint64_t total;
    int scan_mode;
    pthread_t th;
    int th_valid;
    char status[80];
    int live_ok;
    uint32_t live_bits;
    char chain_file[256];
    int has_chain_file;
    ChainSet cs;
    int has_cs;
} Watch;

static Watch g_w[MAX_WATCH];
static int g_nw = 0;
static int g_cur = 0;
static long long g_t0_ms = 0;

typedef struct {
    Watch *w;
    int mode;
    double param, tol;
} ScanArgs;

static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void *scan_thread(void *p)
{
    ScanArgs *a = p;
    Watch *w = a->w;
    if (a->mode == SCAN_FIRST) {
        w->s.n = 0;
        w->progress = 0;
        w->total = 0;
        ScanCtx ctx = { &w->s, &w->cancel, &w->progress, 0, 0, 0 };
        scan_all(&ctx, 1);
        w->total = ctx.total;
        snprintf(w->status, sizeof w->status, "first: %zu cand", w->s.n);
    } else if (a->mode == SCAN_CHAIN) {
        ChainSet fresh = {0};
        fresh.type = w->s.type;
        snprintf(fresh.module, sizeof fresh.module, "%s", "DarkSoulsIII.exe");
        uint64_t total = 0;
        w->progress = 0;
        chain_scan(g_pid, w->addr, CHAIN_DEF_DEPTH, CHAIN_DEF_OFF, "DarkSoulsIII.exe",
                   &fresh, &w->cancel, &w->progress, &total);
        w->total = total;
        ChainSet result = {0};
        ChainSet prev;
        uint64_t tok = process_token(g_pid);
        int same_proc = 0;
        if (w->has_chain_file && access(w->chain_file, F_OK) == 0 &&
            chainset_load(w->chain_file, &prev) == 0) {
            if (prev.token != 0 && prev.token == tok) {
                same_proc = 1;
                result = prev;
            } else {
                chainset_intersect(&prev, &fresh, &result);
                result.token = tok;
                free(prev.c);
            }
            free(fresh.c);
            fresh.c = NULL;
        } else {
            result = fresh;
            memset(&fresh, 0, sizeof fresh);
            result.type = w->s.type;
            snprintf(result.module, sizeof result.module, "%s", "DarkSoulsIII.exe");
            result.scans = 1;
            result.token = tok;
        }
        int save_ok = 1;
        if (w->has_chain_file)
            save_ok = chainset_save(w->chain_file, &result) == 0;
        free(w->cs.c);
        w->cs = result;
        w->has_cs = 1;
        if (!save_ok)
            snprintf(w->status, sizeof w->status, "SAVE FAILED: %.55s", w->chain_file);
        else if (same_proc)
            snprintf(w->status, sizeof w->status, "no new scan; restart game [saved]");
        else
            snprintf(w->status, sizeof w->status, "chain: %u (%u scan%s) -> %.55s",
                     w->cs.n, w->cs.scans, w->cs.scans == 1 ? "" : "s", w->chain_file);
        free(fresh.c);
    } else {
        search_filter(&w->s, a->mode, a->param, a->tol, &w->cancel);
        snprintf(w->status, sizeof w->status, "next: %zu cand", w->s.n);
    }
    w->progress = 0;
    w->scanning = 0;
    free(a);
    return NULL;
}

static int tui_prompt(const char *label, char *buf, size_t buflen)
{
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    (void)cols;
    move(rows - 1, 0);
    clrtoeol();
    attron(A_BOLD);
    mvprintw(rows - 1, 0, "%s", label);
    attroff(A_BOLD);
    echo();
    curs_set(1);
    nodelay(stdscr, FALSE);
    int r = wgetnstr(stdscr, buf, (int)buflen - 1);
    noecho();
    curs_set(0);
    nodelay(stdscr, TRUE);
    timeout(TICK_MS);
    move(rows - 1, 0);
    clrtoeol();
    if (r == ERR) {
        buf[0] = 0;
        return 0;
    }
    buf[buflen - 1] = 0;
    return 1;
}

static void watch_start(Watch *w, int mode, double param, double tol)
{
    w->cancel = 0;
    w->scanning = 1;
    w->progress = 0;
    w->total = 0;
    w->scan_mode = mode;
    snprintf(w->status, sizeof w->status, "%s...",
             mode == SCAN_FIRST ? "scanning" : mode == SCAN_CHAIN ? "chain scan" : "filtering");
    ScanArgs *a = malloc(sizeof *a);
    if (!a) {
        w->scanning = 0;
        return;
    }
    a->w = w;
    a->mode = mode;
    a->param = param;
    a->tol = tol;
    if (pthread_create(&w->th, NULL, scan_thread, a) != 0) {
        free(a);
        w->scanning = 0;
        snprintf(w->status, sizeof w->status, "thread error");
        return;
    }
    w->th_valid = 1;
}

static void watch_autoload_chain(Watch *w);

static void tui_add_watch(void)
{
    if (g_nw >= MAX_WATCH) {
        return;
    }
    char name[24], ts[16];
    if (!tui_prompt("name: ", name, sizeof name) || !name[0])
        return;
    if (!tui_prompt("type [float/int] (float): ", ts, sizeof ts))
        return;
    Watch *w = &g_w[g_nw];
    memset(w, 0, sizeof *w);
    snprintf(w->name, sizeof w->name, "%s", name);
    w->s.type = strcmp(ts, "int") == 0 ? T_INT : T_FLOAT;
    w->s.min = 1.0;
    w->s.max = 10000.0;
    snprintf(w->status, sizeof w->status, "new");
    g_nw++;
    g_cur = g_nw - 1;
    watch_autoload_chain(w);
}

static void tui_first(Watch *w)
{
    if (w->scanning)
        return;
    char v[32];
    if (!tui_prompt("first value (empty=1-10000, A-B range, or V:tol): ", v, sizeof v))
        return;
    w->s.exact = 0;
    w->s.tol = 0;
    w->s.min = 1;
    w->s.max = 10000;
    if (strchr(v, '-')) {
        double a, b;
        if (sscanf(v, "%lf-%lf", &a, &b) == 2) {
            if (a > b) {
                double t = a;
                a = b;
                b = t;
            }
            w->s.min = a;
            w->s.max = b;
        }
    } else if (v[0]) {
        double a = 0, t = 0;
        if (strchr(v, ':'))
            sscanf(v, "%lf:%lf", &a, &t);
        else
            a = atof(v);
        w->s.exact = 1;
        w->s.exact_val = a;
        w->s.tol = t;
    }
    free(w->s.c);
    w->s.c = NULL;
    w->s.n = 0;
    w->s.cap = 0;
    watch_start(w, SCAN_FIRST, 0, 0);
}

static void tui_next(Watch *w, int mode, double param)
{
    if (w->scanning || w->s.n == 0)
        return;
    watch_start(w, mode, param, 0);
}

static void watch_write(Watch *w)
{
    if (!w->has_addr || !w->has_lockval)
        return;
    struct iovec li = { &w->lock_bits, 4 };
    struct iovec ri = { (void *)w->addr, 4 };
    process_vm_writev(g_pid, &li, 1, &ri, 1, 0);
}

static void tui_toggle_lock(Watch *w)
{
    if (!w->has_addr) {
        snprintf(w->status, sizeof w->status, "no address bound");
        return;
    }
    if (w->lock_on) {
        w->lock_on = 0;
        snprintf(w->status, sizeof w->status, "unlocked");
        return;
    }
    if (!w->has_lockval) {
        char v[32];
        if (!tui_prompt("lock value: ", v, sizeof v) || !v[0])
            return;
        w->lock_bits = val_to_bits(w->s.type, atof(v));
        w->has_lockval = 1;
    }
    w->lock_on = 1;
    snprintf(w->status, sizeof w->status, "locked");
}

static void tui_edit_val(Watch *w)
{
    if (!w->has_addr)
        return;
    char v[32];
    if (!tui_prompt("lock value (not written): ", v, sizeof v) || !v[0])
        return;
    w->lock_bits = val_to_bits(w->s.type, atof(v));
    w->has_lockval = 1;
    snprintf(w->status, sizeof w->status, "lock val = %g (press s to write, l to hold)",
             atof(v));
}

static void tui_set(Watch *w)
{
    if (!w->has_addr)
        return;
    if (!w->has_lockval) {
        char v[32];
        if (!tui_prompt("value: ", v, sizeof v) || !v[0])
            return;
        w->lock_bits = val_to_bits(w->s.type, atof(v));
        w->has_lockval = 1;
    }
    watch_write(w);
    snprintf(w->status, sizeof w->status, "set once");
}

static void tui_reset(Watch *w)
{
    if (w->scanning)
        return;
    free(w->s.c);
    w->s.c = NULL;
    w->s.n = 0;
    w->s.cap = 0;
    w->has_addr = 0;
    w->lock_on = 0;
    w->has_lockval = 0;
    snprintf(w->status, sizeof w->status, "reset");
}

static void tui_chain_path(Watch *w)
{
    char safe[64];
    size_t j = 0;
    for (size_t i = 0; w->name[i] && j < sizeof safe - 1; i++) {
        unsigned char ch = (unsigned char)w->name[i];
        safe[j++] = (isalnum(ch) || ch == '_' || ch == '-' || ch == '.') ? (char)ch : '_';
    }
    safe[j] = 0;
    mkdir("chains", 0755);
    snprintf(w->chain_file, sizeof w->chain_file, "chains/%s.chain", j ? safe : "watch");
    w->has_chain_file = 1;
}

/* resolve the first (best) chain in w->cs and bind it as the watch address */
static void watch_bind_chain(Watch *w)
{
    if (!w->has_cs || w->cs.n == 0 || !g_pid)
        return;
    CMap *m = NULL;
    size_t nm = 0;
    if (cmaps_read(g_pid, &m, &nm) != 0)
        return;
    uint64_t modbase = chain_module_base(m, nm, w->cs.module);
    if (!modbase) {
        const char *base = strrchr(w->cs.module, '/');
        base = base ? base + 1 : w->cs.module;
        modbase = chain_module_base(m, nm, base);
    }
    uint64_t addr;
    int ok = modbase && chain_resolve(g_pid, m, nm, modbase, &w->cs.c[0], &addr);
    free(m);
    if (!ok) {
        snprintf(w->status, sizeof w->status, "chain: %u (resolve failed)", w->cs.n);
        return;
    }
    w->addr = addr;
    w->has_addr = 1;
    if (!w->has_lockval) {
        int o;
        w->lock_bits = read_at(addr, &o);
        if (o)
            w->has_lockval = 1;
    }
    snprintf(w->status, sizeof w->status, "auto chain -> 0x%llx", (unsigned long long)addr);
}

/* on 'a': if a chain file for this name exists, load it; auto-bind only if verified */
static void watch_autoload_chain(Watch *w)
{
    if (!w->has_chain_file)
        tui_chain_path(w);
    ChainSet cs;
    if (chainset_load(w->chain_file, &cs) != 0)
        return;
    free(w->cs.c);
    w->cs = cs;
    w->has_cs = 1;
    if (!chain_is_stable(&cs)) {
        if (cs.n == 0)
            snprintf(w->status, sizeof w->status, "chain file empty");
        else
            snprintf(w->status, sizeof w->status,
                     "chain: %u cand (unverified: press C or V)", cs.n);
        return;
    }
    watch_bind_chain(w);
}

/* 'V': prune candidate chains by the current value, no address scan needed */
static void tui_verify_chain(Watch *w)
{
    if (w->scanning)
        return;
    if (!w->has_cs) {
        watch_autoload_chain(w);
        if (!w->has_cs) {
            snprintf(w->status, sizeof w->status, "no chain file");
            return;
        }
    }
    if (w->cs.n == 0) {
        snprintf(w->status, sizeof w->status, "no chains");
        return;
    }
    if (w->cs.token != 0 && w->cs.token == process_token(g_pid)) {
        snprintf(w->status, sizeof w->status, "restart game to verify (same process)");
        return;
    }
    char v[32];
    if (!tui_prompt("current value: ", v, sizeof v) || !v[0])
        return;
    uint32_t before = w->cs.n;
    int r = chain_verify(&w->cs, g_pid, atof(v));
    if (r < 0) {
        snprintf(w->status, sizeof w->status, "verify failed");
        return;
    }
    if (w->cs.n > 0) {
        if (w->has_chain_file)
            chainset_save(w->chain_file, &w->cs);
        snprintf(w->status, sizeof w->status, "verify: %u -> %u (%u verify%s)",
                 before, w->cs.n, w->cs.verifies, w->cs.verifies == 1 ? "" : "s");
        if (chain_is_stable(&w->cs))
            watch_bind_chain(w);
    } else {
        snprintf(w->status, sizeof w->status,
                 "no chain matched %g; not saved", atof(v));
    }
}

static void tui_chain_scan(Watch *w)
{
    if (w->scanning)
        return;
    if (!w->has_addr) {
        snprintf(w->status, sizeof w->status, "bind an address first");
        return;
    }
    if (!w->has_chain_file)
        tui_chain_path(w);
    watch_start(w, SCAN_CHAIN, 0, 0);
}

static void tui_load_chain(Watch *w)
{
    if (w->scanning)
        return;
    if (!w->has_chain_file)
        tui_chain_path(w);
    ChainSet cs;
    int r = chainset_load(w->chain_file, &cs);
    if (r != 0) {
        snprintf(w->status, sizeof w->status, "no chain file");
        return;
    }
    if (cs.n == 0) {
        snprintf(w->status, sizeof w->status, "chain file empty");
        free(cs.c);
        return;
    }
    CMap *m = NULL;
    size_t nm = 0;
    if (cmaps_read(g_pid, &m, &nm) != 0) {
        snprintf(w->status, sizeof w->status, "open maps failed");
        free(cs.c);
        return;
    }
    uint64_t modbase = chain_module_base(m, nm, cs.module);
    uint64_t addr;
    if (!modbase || !chain_resolve(g_pid, m, nm, modbase, &cs.c[0], &addr)) {
        snprintf(w->status, sizeof w->status, "chain failed to resolve");
        free(m);
        free(cs.c);
        return;
    }
    free(m);
    w->addr = addr;
    w->has_addr = 1;
    if (!w->has_lockval) {
        int ok;
        w->lock_bits = read_at(addr, &ok);
        if (ok)
            w->has_lockval = 1;
    }
    snprintf(w->status, sizeof w->status, "chain -> 0x%llx", (unsigned long long)addr);
    free(w->cs.c);
    w->cs = cs;
    w->has_cs = 1;
}

#define WATCH_PATH ".ds3hp_watches"

static void watch_name_sanitize(const char *in, char *out, size_t n)
{
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 1 < n; i++) {
        char c = in[i];
        out[j++] = (c == '\t' || c == '\n' || c == '\r') ? '_' : c;
    }
    out[j] = 0;
}

static void watches_save(void)
{
    FILE *f = fopen(WATCH_PATH, "w");
    if (!f)
        return;
    fprintf(f, "DS3HPW1\n");
    for (int i = 0; i < g_nw; i++) {
        Watch *w = &g_w[i];
        char nm[32];
        watch_name_sanitize(w->name, nm, sizeof nm);
        fprintf(f, "%s\t%d\t%d\t%u\t%d\n", nm, w->s.type, w->has_lockval,
                w->lock_bits, w->lock_on);
    }
    fclose(f);
}

static void watches_load(void)
{
    FILE *f = fopen(WATCH_PATH, "r");
    if (!f)
        return;
    char line[256];
    if (!fgets(line, sizeof line, f) || strncmp(line, "DS3HPW1", 7) != 0) {
        fclose(f);
        return;
    }
    while (g_nw < MAX_WATCH && fgets(line, sizeof line, f)) {
        char nm[24];
        int type = 0, hl = 0, lo = 0;
        unsigned bits = 0;
        if (sscanf(line, "%23[^\t]\t%d\t%d\t%u\t%d", nm, &type, &hl, &bits, &lo) != 5)
            continue;
        Watch *w = &g_w[g_nw];
        memset(w, 0, sizeof *w);
        snprintf(w->name, sizeof w->name, "%s", nm);
        w->s.type = type;
        w->s.min = 1.0;
        w->s.max = 10000.0;
        w->has_lockval = hl;
        w->lock_bits = bits;
        w->lock_on = lo;
        snprintf(w->status, sizeof w->status, "restored");
        g_nw++;
    }
    fclose(f);
}

/* after restart: load each watch's chain file; auto-bind only if verified */
static void watches_autoresolve(void)
{
    for (int i = 0; i < g_nw; i++)
        watch_autoload_chain(&g_w[i]);
}

static void tui_delete(int idx)
{
    if (idx < 0 || idx >= g_nw)
        return;
    Watch *w = &g_w[idx];
    if (w->th_valid) {
        w->cancel = 1;
        pthread_join(w->th, NULL);
        w->th_valid = 0;
    }
    free(w->s.c);
    free(w->cs.c);
    w->s.c = NULL;
    w->cs.c = NULL;
    memmove(&g_w[idx], &g_w[idx + 1], (g_nw - idx - 1) * sizeof(Watch));
    g_nw--;
    if (g_cur >= g_nw)
        g_cur = g_nw ? g_nw - 1 : 0;
}

static void tui_candidates(Watch *w)
{
    size_t sel = 0, top = 0;
    for (;;) {
        if (g_stop)
            return;
        erase();
        int rows, cols;
        getmaxyx(stdscr, rows, cols);
        (void)cols;
        attron(A_BOLD);
        mvprintw(0, 0, "candidates: %s (%zu)", w->name, w->s.n);
        attroff(A_BOLD);
        int listrows = rows - 3;
        if (listrows < 1)
            listrows = 1;
        if (sel < top)
            top = sel;
        if (sel >= top + (size_t)listrows)
            top = sel - listrows + 1;
        for (int i = 0; i < listrows; i++) {
            size_t idx = top + i;
            if (idx >= w->s.n)
                break;
            mvprintw(2 + i, 0, "[%zu] 0x%llx = %g", idx,
                     (unsigned long long)w->s.c[idx].addr,
                     bits_to_val(w->s.type, w->s.c[idx].bits));
            if (idx == sel)
                mvchgat(2 + i, 0, -1, A_REVERSE, 0, NULL);
        }
        mvprintw(rows - 1, 0, "j/k move  PgUp/PgDn  Enter=bind  q=back");
        refresh();
        int ch = getch();
        if (ch == ERR)
            continue;
        switch (ch) {
        case 'q':
        case 27:
            return;
        case 'j':
        case KEY_DOWN:
            if (sel + 1 < w->s.n)
                sel++;
            break;
        case 'k':
        case KEY_UP:
            if (sel)
                sel--;
            break;
        case KEY_NPAGE:
            sel += listrows;
            if (sel >= w->s.n)
                sel = w->s.n ? w->s.n - 1 : 0;
            break;
        case KEY_PPAGE:
            sel = sel > (size_t)listrows ? sel - listrows : 0;
            break;
        case '\n':
        case '\r':
        case KEY_ENTER:
            w->addr = w->s.c[sel].addr;
            w->has_addr = 1;
            if (!w->has_lockval) {
                w->lock_bits = w->s.c[sel].bits;
                w->has_lockval = 1;
            }
            snprintf(w->status, sizeof w->status, "bound 0x%llx",
                     (unsigned long long)w->addr);
            return;
        }
    }
}

static void tui_refresh_values(void)
{
    for (int i = 0; i < g_nw; i++) {
        Watch *w = &g_w[i];
        if (!w->has_addr) {
            w->live_ok = 0;
            continue;
        }
        int ok;
        uint32_t v = read_at(w->addr, &ok);
        w->live_bits = v;
        w->live_ok = ok;
    }
}

static void tui_lock_tick(void)
{
    for (int i = 0; i < g_nw; i++) {
        Watch *w = &g_w[i];
        if (w->lock_on)
            watch_write(w);
    }
}

static void tui_draw(void)
{
    erase();
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    (void)cols;
    attron(A_BOLD);
    mvprintw(0, 0, "ds3hp tui   pid=%d   %d watch(es)", g_pid, g_nw);
    attroff(A_BOLD);
    mvprintw(1, 0, "%-8s %-5s %-16s %10s %3s %10s %-7s %s",
             "NAME", "TYPE", "ADDR", "VALUE", "LCK", "LOCKVAL", "CHAIN", "STATUS");
    int listrows = rows - 4;
    if (listrows < 1)
        listrows = 1;
    if (g_nw == 0)
        mvprintw(2, 0, "(press 'a' to add a watch)");
    for (int i = 0; i < g_nw && i < listrows; i++) {
        Watch *w = &g_w[i];
        char addr[24] = "--";
        if (w->has_addr)
            snprintf(addr, sizeof addr, "0x%llx", (unsigned long long)w->addr);
        char val[24] = "--";
        if (w->has_addr && w->live_ok)
            snprintf(val, sizeof val, "%g", bits_to_val(w->s.type, w->live_bits));
        else if (w->has_addr)
            snprintf(val, sizeof val, "unreadable");
        char lv[24] = "--";
        if (w->has_lockval)
            snprintf(lv, sizeof lv, "%g", bits_to_val(w->s.type, w->lock_bits));
        char chn[16] = "-";
        if (w->has_cs) {
            if (chain_is_stable(&w->cs))
                snprintf(chn, sizeof chn, "stable");
            else
                snprintf(chn, sizeof chn, "%uc", w->cs.n);
        } else if (w->has_chain_file && access(w->chain_file, F_OK) == 0) {
            snprintf(chn, sizeof chn, "file");
        }
        char st[80];
        if (w->scanning) {
            double pct = w->total ? 100.0 * (double)w->progress / (double)w->total : 0;
            if (w->scan_mode == SCAN_CHAIN)
                snprintf(st, sizeof st, "chain %.0f%%", pct);
            else
                snprintf(st, sizeof st, "scanning %.0f%% (%zu cand)", pct, w->s.n);
        } else {
            snprintf(st, sizeof st, "%s", w->status);
        }
        mvprintw(2 + i, 0, "%-8.8s %-5s %-16.16s %10.10s %3s %10.10s %-7.7s %-.40s",
                 w->name, w->s.type == T_FLOAT ? "float" : "int", addr, val,
                 w->lock_on ? (w->has_lockval ? "ON" : "?") : "off", lv, chn, st);
        if (i == g_cur)
            mvchgat(2 + i, 0, -1, A_REVERSE, 0, NULL);
    }
    mvprintw(rows - 1, 0,
             "a add f first d/i dec/inc c/u chg/unch e eq Enter cand l lock v lval s once C chain V verify G get x del r reset p pid q quit");
    refresh();
}

static void tui_handle(int ch)
{
    switch (ch) {
    case 'q':
    case 'Q':
        g_stop = 1;
        break;
    case 'p': {
        int p = detect_pid();
        if (p)
            g_pid = p;
        break;
    }
    case KEY_UP:
    case 'k':
        if (g_cur > 0)
            g_cur--;
        break;
    case KEY_DOWN:
    case 'j':
        if (g_cur + 1 < g_nw)
            g_cur++;
        break;
    case 'a':
        tui_add_watch();
        break;
    case 'f':
        if (g_nw)
            tui_first(&g_w[g_cur]);
        break;
    case 'd':
        if (g_nw)
            tui_next(&g_w[g_cur], F_DEC, 0);
        break;
    case 'i':
        if (g_nw)
            tui_next(&g_w[g_cur], F_INC, 0);
        break;
    case 'c':
        if (g_nw)
            tui_next(&g_w[g_cur], F_CHG, 0);
        break;
    case 'u':
        if (g_nw)
            tui_next(&g_w[g_cur], F_UNCH, 0);
        break;
    case 'e':
        if (g_nw) {
            char v[32];
            if (tui_prompt("value to match: ", v, sizeof v) && v[0])
                tui_next(&g_w[g_cur], F_EQ, atof(v));
        }
        break;
    case '\n':
    case '\r':
    case KEY_ENTER:
    case 'o':
        if (g_nw && !g_w[g_cur].scanning && g_w[g_cur].s.n)
            tui_candidates(&g_w[g_cur]);
        break;
    case 'l':
        if (g_nw)
            tui_toggle_lock(&g_w[g_cur]);
        break;
    case 'v':
        if (g_nw)
            tui_edit_val(&g_w[g_cur]);
        break;
    case 's':
        if (g_nw)
            tui_set(&g_w[g_cur]);
        break;
    case 'x':
    case KEY_DC:
        tui_delete(g_cur);
        break;
    case 'r':
        if (g_nw)
            tui_reset(&g_w[g_cur]);
        break;
    case 'C':
        if (g_nw)
            tui_chain_scan(&g_w[g_cur]);
        break;
    case 'V':
        if (g_nw)
            tui_verify_chain(&g_w[g_cur]);
        break;
    case 'G':
        if (g_nw)
            tui_load_chain(&g_w[g_cur]);
        break;
    }
}

static void cmd_tui(int argc, char **argv)
{
    int pid_override = 0;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc)
            pid_override = atoi(argv[++i]);
        else {
            fprintf(stderr, "error: tui [--pid N]\n");
            exit(1);
        }
    }
    if (pid_override)
        g_pid = pid_override;
    else if (!g_pid)
        g_pid = detect_pid();
    if (!g_pid)
        fprintf(stderr, "warning: Dark Souls III not found; press 'p' to re-detect\n");
    watches_load();
    watches_autoresolve();
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    timeout(TICK_MS);
    g_stop = 0;
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);
    g_t0_ms = now_ms();
    long long last_refresh = 0;
    while (!g_stop) {
        long long now = now_ms();
        if (now - last_refresh >= 100) {
            tui_refresh_values();
            last_refresh = now;
        }
        tui_draw();
        int ch = getch();
        if (ch != ERR)
            tui_handle(ch);
        tui_lock_tick();
    }
    for (int i = 0; i < g_nw; i++) {
        Watch *w = &g_w[i];
        if (w->th_valid) {
            w->cancel = 1;
            pthread_join(w->th, NULL);
            w->th_valid = 0;
        }
        free(w->s.c);
        free(w->cs.c);
    }
    watches_save();
    endwin();
    printf("bye\n");
}

/* ========================== end TUI ========================== */

static void usage(const char *prog)
{
    printf("usage: %s <command> [options]\n\n", prog);
    printf("  tui [--pid N]             interactive multi-target manager (ncurses)\n");
    printf("  first [--type float|int] [--value V [--tol T] | --min A --max B] [--maps anon|all]\n");
    printf("        snapshot HP while at full health, or search an exact value\n");
    printf("  next  <--dec|--inc|--changed|--unchanged|--eq V|--lt V|--gt V> [--tol T]\n");
    printf("        keep candidates matching the change since last scan\n");
    printf("  list  [--limit N]         show candidates with values re-read from memory\n");
    printf("  peek  <index>             re-read one candidate\n");
    printf("  lock  <index|a-b|all> ... [--value V] [--interval-ms N] [--seconds N]\n");
    printf("        freeze one or more values at once (defaults to each value now)\n");
    printf("  set   <index|a-b|all> --value V\n");
    printf("        write V once to the chosen candidates\n");
    printf("  chain scan   <file> --addr 0xADDR [--depth N] [--max-offset M] [--module S] [--pid P] [--type float|int] [--reset]\n");
    printf("        scan for restart-stable pointer chains; re-run after a restart to intersect\n");
    printf("  chain list   <file>       show candidate chains\n");
    printf("  chain resolve <file> [--index K] [--value V]   resolve a chain to an address\n");
    printf("  chain verify <file> --value V [--pid P]         keep chains whose value == V\n");
    printf("  chain load   <file> [--index K] [--value V]    resolve and load as current target\n");
    printf("  chain clear  <file>       delete a chain file\n");
    printf("  reset                     delete saved scan state\n\n");
    printf("typical run (float HP):\n");
    printf("  %s tui               # or use the CLI steps below\n", prog);
    printf("  %s first\n", prog);
    printf("  take damage in game\n");
    printf("  %s next --dec\n", prog);
    printf("  heal / take more damage and repeat  next --inc / next --dec\n");
    printf("  %s list              # until only a few remain\n", prog);
    printf("  %s lock 0\n", prog);
    printf("  # after restarting the game, just run 'first' again\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    const char *cmd = argv[1];
    if (strcmp(cmd, "tui") == 0)
        cmd_tui(argc - 2, argv + 2);
    else if (strcmp(cmd, "first") == 0)
        cmd_first(argc - 2, argv + 2);
    else if (strcmp(cmd, "next") == 0)
        cmd_next(argc - 2, argv + 2);
    else if (strcmp(cmd, "list") == 0)
        cmd_list(argc - 2, argv + 2);
    else if (strcmp(cmd, "peek") == 0)
        cmd_peek(argc - 2, argv + 2);
    else if (strcmp(cmd, "lock") == 0)
        cmd_lock(argc - 2, argv + 2);
    else if (strcmp(cmd, "set") == 0)
        cmd_set(argc - 2, argv + 2);
    else if (strcmp(cmd, "chain") == 0)
        cmd_chain(argc - 2, argv + 2);
    else if (strcmp(cmd, "reset") == 0)
        cmd_reset();
    else if (strcmp(cmd, "pid") == 0) {
        int p = detect_pid();
        printf("%d\n", p);
        return p ? 0 : 1;
    } else {
        usage(argv[0]);
        return 1;
    }
    return 0;
}
