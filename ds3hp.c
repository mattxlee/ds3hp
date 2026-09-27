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

/* ============================ TUI ============================ */

#define MAX_WATCH 64
#define TICK_MS 20
#define SCAN_FIRST (-1)

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
    pthread_t th;
    int th_valid;
    char status[64];
    int live_ok;
    uint32_t live_bits;
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
    snprintf(w->status, sizeof w->status, "%s...", mode == SCAN_FIRST ? "scanning" : "filtering");
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
    if (!tui_prompt("value: ", v, sizeof v) || !v[0])
        return;
    w->lock_bits = val_to_bits(w->s.type, atof(v));
    w->has_lockval = 1;
    watch_write(w);
    snprintf(w->status, sizeof w->status, "set once");
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
    mvprintw(1, 0, "%-10s %-5s %-18s %12s %3s %12s  %s",
             "NAME", "TYPE", "ADDR", "VALUE", "LCK", "LOCKVAL", "STATUS");
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
        char st[64];
        if (w->scanning) {
            double pct = w->total ? 100.0 * (double)w->progress / (double)w->total : 0;
            snprintf(st, sizeof st, "scanning %.0f%% (%zu cand)", pct, w->s.n);
        } else {
            snprintf(st, sizeof st, "%s", w->status);
        }
        mvprintw(2 + i, 0, "%-10.10s %-5s %-18.18s %12.12s %3s %12.12s  %-.38s",
                 w->name, w->s.type == T_FLOAT ? "float" : "int", addr, val,
                 w->lock_on ? (w->has_lockval ? "ON" : "?") : "off", lv, st);
        if (i == g_cur)
            mvchgat(2 + i, 0, -1, A_REVERSE, 0, NULL);
    }
    mvprintw(rows - 1, 0,
             "a add  f first  d/i dec/inc  c/u chg/unch  e eq  Enter cand  l lock  v val  s set  x del  r reset  p pid  q quit");
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
    }
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
