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
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>

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

enum { T_FLOAT = 0, T_INT = 1 };
enum { F_DEC, F_INC, F_CHG, F_UNCH, F_EQ, F_LT, F_GT };

static int g_pid = 0;
static int g_type = T_FLOAT;
static double g_min = 1.0;
static double g_max = 10000.0;
static int g_exact = 0;
static double g_exact_val = 0;
static double g_tol = 0;
static Cand *g_c = NULL;
static size_t g_n = 0;
static size_t g_cap = 0;
static volatile sig_atomic_t g_stop = 0;

static uint32_t read_at(uint64_t addr, int *ok);

static void die(const char *msg)
{
    fprintf(stderr, "error: %s: %s\n", msg, strerror(errno));
    exit(1);
}

static double bits_to_val(uint32_t b)
{
    if (g_type == T_FLOAT) {
        float f;
        memcpy(&f, &b, 4);
        return (double)f;
    }
    int32_t i;
    memcpy(&i, &b, 4);
    return (double)i;
}

static int val_finite(uint32_t b)
{
    if (g_type == T_FLOAT) {
        float f;
        memcpy(&f, &b, 4);
        return isfinite(f);
    }
    return 1;
}

static int val_in_range(uint32_t b)
{
    if (!val_finite(b))
        return 0;
    double v = bits_to_val(b);
    if (g_exact)
        return fabs(v - g_exact_val) <= g_tol;
    return v >= g_min && v <= g_max;
}

static uint32_t val_to_bits(double v)
{
    if (g_type == T_FLOAT) {
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

static void push_cand(uint64_t addr, uint32_t bits)
{
    if (g_n == g_cap) {
        size_t ncap = g_cap ? g_cap * 2 : (1u << 20);
        Cand *p = realloc(g_c, ncap * sizeof(Cand));
        if (!p) {
            fprintf(stderr, "error: out of memory at %zu candidates; use a narrower --min/--max\n", g_n);
            exit(1);
        }
        g_c = p;
        g_cap = ncap;
    }
    g_c[g_n].addr = addr;
    g_c[g_n].bits = bits;
    g_n++;
    if (g_n % (8u << 20) == 0)
        fprintf(stderr, "  ... %zu candidates\n", g_n);
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

static void scan_region(uint64_t start, uint64_t end, uint8_t *buf, size_t bufsz)
{
    uint64_t p = start;
    while (p < end) {
        size_t want = (size_t)(end - p);
        if (want > bufsz)
            want = bufsz;
        struct iovec li = { buf, want };
        struct iovec ri = { (void *)p, want };
        ssize_t r = process_vm_readv(g_pid, &li, 1, &ri, 1, 0);
        if (r <= 0) {
            p += 4096 - (p & 4095);
            continue;
        }
        size_t words = (size_t)r / 4;
        for (size_t i = 0; i < words; i++) {
            uint32_t w;
            memcpy(&w, buf + i * 4, 4);
            if (val_in_range(w))
                push_cand(p + i * 4, w);
        }
        p += words * 4;
        if ((size_t)r < want && words * 4 == (size_t)r)
            p += 4;
    }
}

static void save_state(void)
{
    FILE *f = fopen(STATE_PATH, "wb");
    if (!f)
        die("write state");
    StateHdr h = {0};
    memcpy(h.magic, MAGIC, 8);
    h.pid = g_pid;
    h.type = g_type;
    h.min = g_min;
    h.max = g_max;
    h.count = g_n;
    if (fwrite(&h, sizeof h, 1, f) != 1)
        die("write header");
    if (g_n && fwrite(g_c, sizeof(Cand), g_n, f) != g_n)
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
    g_type = h.type;
    g_min = h.min;
    g_max = h.max;
    g_n = (size_t)h.count;
    g_cap = g_n ? g_n : 1;
    g_c = malloc(g_cap * sizeof(Cand));
    if (!g_c)
        die("malloc state");
    if (g_n && fread(g_c, sizeof(Cand), g_n, f) != g_n)
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
                g_type = T_FLOAT;
            else if (strcmp(t, "int") == 0)
                g_type = T_INT;
            else {
                fprintf(stderr, "error: --type must be float or int\n");
                exit(1);
            }
        } else if (strcmp(argv[i], "--min") == 0 && i + 1 < argc) {
            g_min = atof(argv[++i]);
        } else if (strcmp(argv[i], "--max") == 0 && i + 1 < argc) {
            g_max = atof(argv[++i]);
        } else if ((strcmp(argv[i], "--value") == 0 || strcmp(argv[i], "--eq") == 0) && i + 1 < argc) {
            g_exact = 1;
            g_exact_val = atof(argv[++i]);
        } else if (strcmp(argv[i], "--tol") == 0 && i + 1 < argc) {
            g_tol = atof(argv[++i]);
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
    Region *rs;
    size_t nr = read_regions(g_pid, anon_only, &rs);
    uint64_t bytes = 0;
    for (size_t i = 0; i < nr; i++)
        bytes += rs[i].end - rs[i].start;
    if (g_exact)
        fprintf(stderr, "pid %d, %zu regions (%s), %.0f MB, type=%s exact=%g tol=%g\n",
                g_pid, nr, anon_only ? "anon" : "all", bytes / 1048576.0,
                g_type == T_FLOAT ? "float" : "int", g_exact_val, g_tol);
    else
        fprintf(stderr, "pid %d, %zu regions (%s), %.0f MB, type=%s range=[%g, %g]\n",
                g_pid, nr, anon_only ? "anon" : "all", bytes / 1048576.0,
                g_type == T_FLOAT ? "float" : "int", g_min, g_max);
    uint8_t *buf = malloc(CHUNK);
    if (!buf)
        die("malloc buffer");
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (size_t i = 0; i < nr; i++)
        scan_region(rs[i].start, rs[i].end, buf, CHUNK);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double dt = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    save_state();
    printf("first scan: %zu candidates in %.1fs\n", g_n, dt);
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

static void cmd_next(int argc, char **argv)
{
    load_state();
    int mode;
    double param, tol;
    if (!parse_filter(argc, argv, &mode, &param, &tol)) {
        fprintf(stderr, "error: give a filter: --dec --inc --changed --unchanged --eq V --lt V --gt V\n");
        exit(1);
    }
    size_t out = 0;
    size_t i = 0;
    while (i < g_n) {
        size_t batch = g_n - i;
        if (batch > MAX_BATCH)
            batch = MAX_BATCH;
        struct iovec li[MAX_BATCH], ri[MAX_BATCH];
        uint32_t vals[MAX_BATCH];
        for (size_t k = 0; k < batch; k++) {
            li[k].iov_base = &vals[k];
            li[k].iov_len = 4;
            ri[k].iov_base = (void *)g_c[i + k].addr;
            ri[k].iov_len = 4;
        }
        ssize_t r = process_vm_readv(g_pid, li, batch, ri, batch, 0);
        size_t done = r > 0 ? (size_t)r / 4 : 0;
        for (size_t k = done; k < batch; k++) {
            int ok;
            vals[k] = read_at(g_c[i + k].addr, &ok);
            if (!ok)
                vals[k] = 0, li[k].iov_len = 0;
            else
                li[k].iov_len = 4;
        }
        for (size_t k = 0; k < batch; k++) {
            if (li[k].iov_len == 0)
                continue;
            uint32_t nb = vals[k];
            if (!val_finite(nb))
                continue;
            double ov = bits_to_val(g_c[i + k].bits);
            double nv = bits_to_val(nb);
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
                g_c[out].addr = g_c[i + k].addr;
                g_c[out].bits = nb;
                out++;
            }
        }
        i += batch;
    }
    g_n = out;
    save_state();
    printf("next scan: %zu candidates remain\n", g_n);
    if (g_n <= 30 && g_n > 0) {
        printf("candidates:\n");
        for (size_t k = 0; k < g_n; k++)
            printf("  [%zu] 0x%llx = %g\n", k, (unsigned long long)g_c[k].addr, bits_to_val(g_c[k].bits));
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
           g_type == T_FLOAT ? "float" : "int", g_n);
    size_t shown = g_n < limit ? g_n : limit;
    uint64_t *addrs = malloc((shown ? shown : 1) * sizeof(uint64_t));
    uint32_t *vals = malloc((shown ? shown : 1) * sizeof(uint32_t));
    uint8_t *ok = malloc(shown ? shown : 1);
    if (!addrs || !vals || !ok)
        die("malloc list");
    for (size_t k = 0; k < shown; k++)
        addrs[k] = g_c[k].addr;
    if (shown)
        read_many(addrs, shown, vals, ok);
    for (size_t k = 0; k < shown; k++) {
        if (ok[k])
            printf("  [%zu] 0x%llx = %g\n", k, (unsigned long long)addrs[k], bits_to_val(vals[k]));
        else
            printf("  [%zu] 0x%llx = <unreadable>\n", k, (unsigned long long)addrs[k]);
    }
    if (shown < g_n)
        printf("  ... %zu more\n", g_n - shown);
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
    if (idx >= g_n) {
        fprintf(stderr, "error: index out of range (0..%zu)\n", g_n ? g_n - 1 : 0);
        exit(1);
    }
    int ok;
    uint32_t v = read_at(g_c[idx].addr, &ok);
    if (!ok)
        printf("[%zu] 0x%llx = <unreadable>\n", idx, (unsigned long long)g_c[idx].addr);
    else
        printf("[%zu] 0x%llx = %g\n", idx, (unsigned long long)g_c[idx].addr, bits_to_val(v));
}

static void on_sigint(int sig)
{
    (void)sig;
    g_stop = 1;
}

#define MAX_LOCKS 8192

static void add_index(size_t idx, size_t **arr, size_t *cnt, size_t *cap)
{
    if (idx >= g_n) {
        fprintf(stderr, "error: index %zu out of range (0..%zu)\n", idx, g_n ? g_n - 1 : 0);
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
        for (size_t i = 0; i < g_n; i++)
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
        addrs[i] = g_c[idxs[i]].addr;
    if (have_val) {
        for (size_t i = 0; i < nidx; i++)
            bits[i] = val_to_bits(val);
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
               bits_to_val(bits[i]));
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
    uint32_t bits = val_to_bits(val);
    unsigned long written = 0, fails = 0;
    for (size_t i = 0; i < nidx; i++) {
        uint64_t addr = g_c[idxs[i]].addr;
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

#define SAVE_MAGIC "DS3HPSV1"

typedef struct {
    uint64_t start, end;
    char perms[8];
    char path[1024];
} MapEnt;

typedef struct {
    int kind;
    uint64_t base, size;
    char perms[8];
    char path[1024];
} Src;

static int maps_read(int pid, MapEnt **out, size_t *outn)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    MapEnt *m = NULL;
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
            MapEnt *nm = realloc(m, cap * sizeof(MapEnt));
            if (!nm)
                die("realloc maps");
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

static long find_region(const MapEnt *m, size_t n, uint64_t addr)
{
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (addr < m[mid].start)
            hi = mid;
        else if (addr >= m[mid].end)
            lo = mid + 1;
        else
            return (long)mid;
    }
    return -1;
}

static int src_equal(const Src *a, const Src *b)
{
    return a->kind == b->kind && a->base == b->base && a->size == b->size &&
           strcmp(a->perms, b->perms) == 0 && strcmp(a->path, b->path) == 0;
}

#define SAVE_MAGIC2 "DS3HPSV2"
#define MAX_CHAIN 8
#define MAX_PROBES 8000000

typedef struct {
    uint64_t loc, off;
    int64_t parent;
    int32_t root;
} Probe;

typedef struct {
    uint64_t rva;
    int n;
    uint64_t offs[MAX_CHAIN];
} Chain;

static Probe *g_probes;

static int probe_cmp(const void *pa, const void *pb)
{
    uint64_t x = g_probes[*(const size_t *)pa].loc;
    uint64_t y = g_probes[*(const size_t *)pb].loc;
    return (x > y) - (x < y);
}

static uint64_t read64_at(uint64_t addr, int *ok)
{
    uint64_t v = 0;
    struct iovec li = { &v, 8 };
    struct iovec ri = { (void *)addr, 8 };
    *ok = process_vm_readv(g_pid, &li, 1, &ri, 1, 0) == 8;
    return v;
}

static int addr_readable(const MapEnt *m, size_t nm, uint64_t a)
{
    long r = find_region(m, nm, a);
    return r >= 0 && m[r].perms[0] == 'r';
}

static uint64_t module_base_of(const MapEnt *m, size_t nm, const char *sub)
{
    uint64_t base = 0;
    for (size_t i = 0; i < nm; i++)
        if (m[i].path[0] && strstr(m[i].path, sub) &&
            (base == 0 || m[i].start < base))
            base = m[i].start;
    return base;
}

static int is_static_loc(const MapEnt *m, size_t nm, uint64_t a, const char *sub)
{
    long r = find_region(m, nm, a);
    if (r < 0 || !m[r].path[0] || !strstr(m[r].path, sub))
        return 0;
    return m[r].perms[0] == 'r' && m[r].perms[1] == 'w';
}

static int build_chain(const Probe *all, size_t s, uint64_t modbase, Chain *out)
{
    uint64_t offs[MAX_CHAIN];
    int n = 0;
    int64_t cur = (int64_t)s;
    while (all[cur].parent >= 0) {
        if (n >= MAX_CHAIN)
            return 0;
        offs[n++] = all[cur].off;
        cur = all[cur].parent;
    }
    out->rva = all[s].loc - modbase;
    out->n = n;
    memcpy(out->offs, offs, sizeof(uint64_t) * n);
    return 1;
}

static int chain_resolve(const Chain *c, uint64_t modbase, uint64_t *res)
{
    uint64_t a = modbase + c->rva;
    for (int i = 0; i < c->n; i++) {
        int ok;
        uint64_t p = read64_at(a, &ok);
        if (!ok)
            return 0;
        a = p + c->offs[i];
    }
    *res = a;
    return 1;
}

static void print_chain(const char *mod, const Chain *c, uint64_t modbase)
{
    printf("%s+0x%llx", mod, (unsigned long long)c->rva);
    for (int i = 0; i < c->n; i++)
        printf(" -> 0x%llx", (unsigned long long)c->offs[i]);
    printf("  (base 0x%llx, %d deref%s)\n", (unsigned long long)modbase, c->n,
           c->n == 1 ? "" : "s");
}

static size_t find_chains(const uint64_t *targets, size_t nt, int maxdepth,
                          uint64_t maxoff, const char *mod, MapEnt *m, size_t nm,
                          uint64_t modbase, Chain *out)
{
    memset(out, 0, sizeof(Chain) * nt);
    Probe *all = NULL;
    size_t nall = 0, call = 0;
    size_t *lvl = NULL, *next = NULL;
    size_t nlvl = 0, nnext = 0, cnext = 0;
    uint64_t minaddr = UINT64_MAX, maxaddr = 0;
    for (size_t i = 0; i < nm; i++) {
        if (m[i].perms[0] != 'r')
            continue;
        if (m[i].start < minaddr)
            minaddr = m[i].start;
        if (m[i].end > maxaddr)
            maxaddr = m[i].end;
    }
#define PUSH_PROBE(LOC, OFF, PAR, ROOT)                                          \
    do {                                                                         \
        if (nall == call) {                                                      \
            call = call ? call * 2 : 256;                                        \
            Probe *np = realloc(all, call * sizeof(Probe));                      \
            if (!np) { free(all); free(lvl); free(next); return 0; }             \
            all = np;                                                            \
        }                                                                        \
        all[nall].loc = (LOC);                                                   \
        all[nall].off = (OFF);                                                   \
        all[nall].parent = (PAR);                                                \
        all[nall].root = (ROOT);                                                 \
        nall++;                                                                  \
    } while (0)
    for (size_t i = 0; i < nt; i++)
        PUSH_PROBE(targets[i], 0, -1, (int32_t)i);
    lvl = malloc((nt ? nt : 1) * sizeof(size_t));
    if (!lvl) {
        free(all);
        return 0;
    }
    for (size_t i = 0; i < nt; i++)
        lvl[i] = i;
    nlvl = nt;
    uint8_t *buf = malloc(CHUNK);
    if (!buf) {
        free(all);
        free(lvl);
        return 0;
    }
    size_t found = 0;
    int exhausted = 0;
    for (int depth = 1; depth <= maxdepth && found < nt && !exhausted; depth++) {
        fprintf(stderr, "  depth %d: scanning...\n", depth);
        g_probes = all;
        qsort(lvl, nlvl, sizeof(size_t), probe_cmp);
        next = NULL;
        nnext = 0;
        cnext = 0;
        size_t *sols = NULL, nsol = 0, csol = 0;
        for (size_t ri = 0; ri < nm; ri++) {
            if (m[ri].perms[0] != 'r')
                continue;
            if (m[ri].path[0] == '[' &&
                (strncmp(m[ri].path, "[stack]", 7) == 0 ||
                 strncmp(m[ri].path, "[vvar]", 6) == 0 ||
                 strncmp(m[ri].path, "[vdso]", 6) == 0))
                continue;
            uint64_t p = m[ri].start;
            while (p < m[ri].end) {
                size_t want = (size_t)(m[ri].end - p);
                if (want > CHUNK)
                    want = CHUNK;
                struct iovec li = { buf, want };
                struct iovec rr = { (void *)p, want };
                ssize_t rd = process_vm_readv(g_pid, &li, 1, &rr, 1, 0);
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
                    if (!addr_readable(m, nm, W))
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
                    uint64_t d = A - W;
                    if (d > maxoff)
                        continue;
                    uint64_t loc = p + j * 8;
                    size_t idx = nall;
                    int32_t root = all[lvl[lo]].root;
                    PUSH_PROBE(loc, d, (int64_t)lvl[lo], root);
                    if (is_static_loc(m, nm, loc, mod)) {
                        if (nsol == csol) {
                            csol = csol ? csol * 2 : 8;
                            size_t *nn = realloc(sols, csol * sizeof(size_t));
                            if (nn)
                                sols = nn;
                        }
                        if (sols)
                            sols[nsol++] = idx;
                    } else {
                        if (nnext == cnext) {
                            cnext = cnext ? cnext * 2 : 256;
                            size_t *nn = realloc(next, cnext * sizeof(size_t));
                            if (nn)
                                next = nn;
                        }
                        if (next)
                            next[nnext++] = idx;
                    }
                    if (nall >= MAX_PROBES) {
                        exhausted = 1;
                        break;
                    }
                }
                p += words * 8;
                if ((size_t)rd < want && words * 8 == (size_t)rd)
                    p += 8 - (p & 7);
                if (exhausted)
                    break;
            }
            if (exhausted)
                break;
        }
        for (size_t i = 0; i < nsol; i++) {
            int32_t root = all[sols[i]].root;
            if (root < 0 || (size_t)root >= nt || out[root].n)
                continue;
            Chain c;
            if (!build_chain(all, sols[i], modbase, &c))
                continue;
            uint64_t res;
            if (chain_resolve(&c, modbase, &res) && res == targets[root]) {
                out[root] = c;
                found++;
            }
        }
        fprintf(stderr, "  depth %d: %zu/%zu chain(s) found\n", depth, found, nt);
        free(sols);
        if (exhausted)
            break;
        free(lvl);
        lvl = next;
        nlvl = nnext;
        next = NULL;
        if (nlvl == 0)
            break;
    }
    if (exhausted)
        fprintf(stderr, "  warning: probe limit reached (%d); results may be incomplete\n",
                MAX_PROBES);
    free(buf);
    free(all);
    free(lvl);
    free(next);
    return found;
#undef PUSH_PROBE
}

static void cmd_save(int argc, char **argv)
{
    const char *file = NULL;
    int use_ptr = 1;
    int depth = 4;
    uint64_t maxoff = 0x8000;
    const char *mod = "DarkSoulsIII.exe";
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--ptr") == 0)
            use_ptr = 1;
        else if (strcmp(argv[i], "--raw") == 0)
            use_ptr = 0;
        else if (strcmp(argv[i], "--depth") == 0 && i + 1 < argc)
            depth = atoi(argv[++i]);
        else if (strcmp(argv[i], "--max-offset") == 0 && i + 1 < argc)
            maxoff = strtoull(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "--module") == 0 && i + 1 < argc)
            mod = argv[++i];
        else if (!file)
            file = argv[i];
        else {
            fprintf(stderr, "error: unknown option %s\n", argv[i]);
            exit(1);
        }
    }
    if (!file) {
        fprintf(stderr, "error: save <file> [--raw | --ptr [--depth N] [--max-offset M] [--module S]]\n");
        exit(1);
    }
    load_state();
    if (!g_pid)
        g_pid = detect_pid();
    if (!g_pid) {
        fprintf(stderr, "error: Dark Souls III process not found\n");
        exit(1);
    }
    MapEnt *m;
    size_t nm;
    if (maps_read(g_pid, &m, &nm) != 0)
        die("open maps");
    if (use_ptr) {
        if (g_n == 0) {
            fprintf(stderr, "error: no candidates to save\n");
            exit(1);
        }
        uint64_t modbase = module_base_of(m, nm, mod);
        if (!modbase) {
            fprintf(stderr, "error: module '%s' not mapped; use --module SUBSTR\n", mod);
            exit(1);
        }
        fprintf(stderr, "pointer scan: %zu candidate(s), depth %d, max-offset 0x%llx, module %s\n",
                g_n, depth, (unsigned long long)maxoff, mod);
        uint64_t *tg = malloc(g_n * sizeof(uint64_t));
        Chain *ch = calloc(g_n, sizeof(Chain));
        if (!tg || !ch)
            die("malloc ptr scan");
        for (size_t i = 0; i < g_n; i++)
            tg[i] = g_c[i].addr;
        size_t got = find_chains(tg, g_n, depth, maxoff, mod, m, nm, modbase, ch);
        FILE *f = fopen(file, "wb");
        if (!f)
            die("open save file");
        fwrite(SAVE_MAGIC2, 1, 8, f);
        int32_t type = g_type;
        fwrite(&type, sizeof type, 1, f);
        const char *fullmod = mod;
        for (size_t i = 0; i < nm; i++)
            if (m[i].path[0] && strstr(m[i].path, mod)) {
                fullmod = m[i].path;
                break;
            }
        uint16_t ml = (uint16_t)strlen(fullmod);
        fwrite(&ml, sizeof ml, 1, f);
        fwrite(fullmod, 1, ml, f);
        uint32_t cnt = (uint32_t)got;
        fwrite(&cnt, sizeof cnt, 1, f);
        for (size_t i = 0; i < g_n; i++) {
            if (ch[i].n == 0)
                continue;
            uint8_t n = (uint8_t)ch[i].n;
            fwrite(&ch[i].rva, 8, 1, f);
            fwrite(&n, 1, 1, f);
            if (n)
                fwrite(ch[i].offs, sizeof(uint64_t), n, f);
            fwrite(&g_c[i].bits, 4, 1, f);
        }
        fclose(f);
        printf("saved %u/%zu pointer chain(s) to %s (module 0x%llx)\n", cnt, g_n, file,
               (unsigned long long)modbase);
        for (size_t i = 0; i < g_n; i++)
            if (ch[i].n || ch[i].rva) {
                printf("  [%zu] 0x%llx: ", i, (unsigned long long)g_c[i].addr);
                print_chain(mod, &ch[i], modbase);
            } else {
                printf("  [%zu] 0x%llx: no chain found\n", i, (unsigned long long)g_c[i].addr);
            }
        free(tg);
        free(ch);
        free(m);
        return;
    }
    uint64_t *sb = malloc((nm ? nm : 1) * sizeof(uint64_t));
    if (!sb)
        die("malloc srcbase");
    for (size_t i = 0; i < nm; i++) {
        if (!m[i].path[0]) {
            sb[i] = m[i].start;
            continue;
        }
        uint64_t base = m[i].start;
        for (size_t j = 0; j < nm; j++)
            if (strcmp(m[j].path, m[i].path) == 0 && m[j].start < base)
                base = m[j].start;
        sb[i] = base;
    }
    Src *srcs = NULL;
    size_t nsrc = 0, scap = 0;
    uint32_t *es = malloc((g_n ? g_n : 1) * sizeof(uint32_t));
    uint64_t *eo = malloc((g_n ? g_n : 1) * sizeof(uint64_t));
    uint32_t *eb = malloc((g_n ? g_n : 1) * sizeof(uint32_t));
    if (!es || !eo || !eb)
        die("malloc save");
    size_t nents = 0;
    unsigned long lost = 0;
    for (size_t k = 0; k < g_n; k++) {
        long ri = find_region(m, nm, g_c[k].addr);
        if (ri < 0) {
            lost++;
            continue;
        }
        Src s;
        memset(&s, 0, sizeof s);
        if (m[ri].path[0]) {
            s.kind = 0;
            s.base = sb[ri];
            snprintf(s.path, sizeof s.path, "%s", m[ri].path);
        } else {
            s.kind = 1;
            s.base = m[ri].start;
            s.size = m[ri].end - m[ri].start;
            snprintf(s.perms, sizeof s.perms, "%s", m[ri].perms);
        }
        size_t si;
        for (si = 0; si < nsrc; si++)
            if (src_equal(&srcs[si], &s))
                break;
        if (si == nsrc) {
            if (nsrc == scap) {
                scap = scap ? scap * 2 : 16;
                Src *ns = realloc(srcs, scap * sizeof(Src));
                if (!ns)
                    die("realloc srcs");
                srcs = ns;
            }
            srcs[nsrc++] = s;
        }
        es[nents] = (uint32_t)si;
        eo[nents] = g_c[k].addr - s.base;
        eb[nents] = g_c[k].bits;
        nents++;
    }
    FILE *f = fopen(file, "wb");
    if (!f)
        die("open save file");
    fwrite(SAVE_MAGIC, 1, 8, f);
    int32_t type = g_type;
    fwrite(&type, sizeof type, 1, f);
    uint32_t su = (uint32_t)nsrc;
    fwrite(&su, sizeof su, 1, f);
    for (size_t i = 0; i < nsrc; i++) {
        uint8_t kind = (uint8_t)srcs[i].kind;
        uint8_t perms[8] = {0};
        memcpy(perms, srcs[i].perms, strlen(srcs[i].perms));
        uint16_t pl = (uint16_t)strlen(srcs[i].path);
        fwrite(&kind, 1, 1, f);
        fwrite(&srcs[i].base, 8, 1, f);
        fwrite(&srcs[i].size, 8, 1, f);
        fwrite(perms, 8, 1, f);
        fwrite(&pl, sizeof pl, 1, f);
        if (pl)
            fwrite(srcs[i].path, 1, pl, f);
    }
    uint64_t cu = (uint64_t)nents;
    fwrite(&cu, sizeof cu, 1, f);
    for (size_t i = 0; i < nents; i++) {
        fwrite(&es[i], 4, 1, f);
        fwrite(&eo[i], 8, 1, f);
        fwrite(&eb[i], 4, 1, f);
    }
    fclose(f);
    printf("saved %zu candidate(s) to %s (%zu source mapping(s), %lu skipped)\n",
           nents, file, nsrc, lost);
    free(m);
    free(sb);
    free(srcs);
    free(es);
    free(eo);
    free(eb);
}

static void load_ptr(const char *file, int pid_override)
{
    FILE *f = fopen(file, "rb");
    if (!f)
        die("open save file");
    char magic[8];
    if (fread(magic, 1, 8, f) != 8 || memcmp(magic, SAVE_MAGIC2, 8) != 0) {
        fprintf(stderr, "error: bad save file\n");
        exit(1);
    }
    int32_t type;
    uint16_t ml;
    if (fread(&type, sizeof type, 1, f) != 1 || fread(&ml, sizeof ml, 1, f) != 1)
        die("read save header");
    char mod[512] = {0};
    if (ml >= sizeof mod)
        ml = sizeof mod - 1;
    if (ml && fread(mod, 1, ml, f) != ml)
        die("read save module");
    mod[ml] = 0;
    uint32_t cnt;
    if (fread(&cnt, sizeof cnt, 1, f) != 1)
        die("read save count");
    Chain *ch = calloc(cnt ? cnt : 1, sizeof(Chain));
    uint32_t *bits = malloc((cnt ? cnt : 1) * sizeof(uint32_t));
    if (!ch || !bits)
        die("malloc load");
    for (uint32_t i = 0; i < cnt; i++) {
        uint8_t n;
        if (fread(&ch[i].rva, 8, 1, f) != 1 || fread(&n, 1, 1, f) != 1)
            die("read chain");
        if (n > MAX_CHAIN)
            die("bad chain length");
        ch[i].n = n;
        if (n && fread(ch[i].offs, sizeof(uint64_t), n, f) != n)
            die("read chain offsets");
        if (fread(&bits[i], 4, 1, f) != 1)
            die("read chain bits");
    }
    fclose(f);
    g_pid = pid_override ? pid_override : detect_pid();
    if (!g_pid) {
        fprintf(stderr, "error: Dark Souls III process not found (is it running?)\n");
        exit(1);
    }
    MapEnt *m;
    size_t nm;
    if (maps_read(g_pid, &m, &nm) != 0)
        die("open maps");
    uint64_t modbase = module_base_of(m, nm, mod);
    if (!modbase) {
        const char *base = strrchr(mod, '/');
        base = base ? base + 1 : mod;
        modbase = module_base_of(m, nm, base);
    }
    if (!modbase) {
        fprintf(stderr, "error: base module '%s' not mapped now\n", mod);
        exit(1);
    }
    g_type = type;
    g_min = 1.0;
    g_max = 10000.0;
    g_exact = 0;
    g_tol = 0;
    g_n = 0;
    g_cap = 0;
    g_c = NULL;
    size_t ok = 0, fail = 0;
    for (uint32_t i = 0; i < cnt; i++) {
        uint64_t addr;
        if (!chain_resolve(&ch[i], modbase, &addr) || !addr_readable(m, nm, addr)) {
            fail++;
            continue;
        }
        int rok;
        uint32_t v = read_at(addr, &rok);
        push_cand(addr, rok ? v : bits[i]);
        ok++;
    }
    save_state();
    printf("resolved %zu/%u pointer chain(s) from %s (pid %d, module 0x%llx, %zu failed)\n",
           ok, cnt, file, g_pid, (unsigned long long)modbase, fail);
    printf("run 'ds3hp list' or 'ds3hp lock <index|all>' to use them\n");
    free(m);
    free(ch);
    free(bits);
}

static void cmd_ptr(int argc, char **argv)
{
    load_state();
    size_t idx = 0;
    int have = 0;
    int depth = 4;
    uint64_t maxoff = 0x8000;
    const char *mod = "DarkSoulsIII.exe";
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--depth") == 0 && i + 1 < argc)
            depth = atoi(argv[++i]);
        else if (strcmp(argv[i], "--max-offset") == 0 && i + 1 < argc)
            maxoff = strtoull(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "--module") == 0 && i + 1 < argc)
            mod = argv[++i];
        else {
            idx = (size_t)atol(argv[i]);
            have = 1;
        }
    }
    if (!have) {
        fprintf(stderr, "error: ptr <index> [--depth N] [--max-offset M] [--module S]\n");
        exit(1);
    }
    if (idx >= g_n) {
        fprintf(stderr, "error: index out of range (0..%zu)\n", g_n ? g_n - 1 : 0);
        exit(1);
    }
    if (!g_pid)
        g_pid = detect_pid();
    if (!g_pid) {
        fprintf(stderr, "error: Dark Souls III process not found\n");
        exit(1);
    }
    MapEnt *m;
    size_t nm;
    if (maps_read(g_pid, &m, &nm) != 0)
        die("open maps");
    uint64_t modbase = module_base_of(m, nm, mod);
    if (!modbase) {
        fprintf(stderr, "error: module '%s' not mapped; use --module SUBSTR\n", mod);
        exit(1);
    }
    uint64_t target = g_c[idx].addr;
    fprintf(stderr, "pointer scan for [%zu] 0x%llx (depth %d, max-offset 0x%llx, module %s)...\n",
            idx, (unsigned long long)target, depth, (unsigned long long)maxoff, mod);
    Chain c;
    size_t got = find_chains(&target, 1, depth, maxoff, mod, m, nm, modbase, &c);
    if (got) {
        uint64_t addr;
        chain_resolve(&c, modbase, &addr);
        printf("found: ");
        print_chain(mod, &c, modbase);
        printf("resolves to 0x%llx (current target 0x%llx)\n",
               (unsigned long long)addr, (unsigned long long)target);
    } else {
        printf("no pointer chain found (try increasing --depth or --max-offset)\n");
    }
    free(m);
}

static void cmd_load(int argc, char **argv)
{
    const char *file = NULL;
    int pid_override = 0;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc)
            pid_override = atoi(argv[++i]);
        else if (!file)
            file = argv[i];
        else {
            fprintf(stderr, "error: unknown option %s\n", argv[i]);
            exit(1);
        }
    }
    if (!file) {
        fprintf(stderr, "error: load <file> [--pid N]\n");
        exit(1);
    }
    FILE *f = fopen(file, "rb");
    if (!f)
        die("open save file");
    char magic[8];
    if (fread(magic, 1, 8, f) != 8) {
        fprintf(stderr, "error: bad save file\n");
        exit(1);
    }
    fclose(f);
    if (memcmp(magic, SAVE_MAGIC2, 8) == 0) {
        load_ptr(file, pid_override);
        return;
    }
    f = fopen(file, "rb");
    if (!f || fread(magic, 1, 8, f) != 8 || memcmp(magic, SAVE_MAGIC, 8) != 0) {
        fprintf(stderr, "error: bad save file\n");
        exit(1);
    }
    int32_t type;
    if (fread(&type, sizeof type, 1, f) != 1)
        die("read save header");
    uint32_t nsrc;
    if (fread(&nsrc, sizeof nsrc, 1, f) != 1)
        die("read save header");
    Src *srcs = calloc(nsrc ? nsrc : 1, sizeof(Src));
    if (!srcs)
        die("malloc srcs");
    for (uint32_t i = 0; i < nsrc; i++) {
        uint8_t kind, perms[8];
        uint16_t pl;
        if (fread(&kind, 1, 1, f) != 1 || fread(&srcs[i].base, 8, 1, f) != 1 ||
            fread(&srcs[i].size, 8, 1, f) != 1 || fread(perms, 8, 1, f) != 1 ||
            fread(&pl, sizeof pl, 1, f) != 1)
            die("read save source");
        srcs[i].kind = kind;
        snprintf(srcs[i].perms, sizeof srcs[i].perms, "%.7s", (char *)perms);
        if (pl >= sizeof srcs[i].path)
            pl = sizeof srcs[i].path - 1;
        if (pl && fread(srcs[i].path, 1, pl, f) != pl)
            die("read save source");
        srcs[i].path[pl] = 0;
    }
    uint64_t count;
    if (fread(&count, sizeof count, 1, f) != 1)
        die("read save count");
    uint32_t *es = malloc((count ? count : 1) * sizeof(uint32_t));
    uint64_t *eo = malloc((count ? count : 1) * sizeof(uint64_t));
    uint32_t *eb = malloc((count ? count : 1) * sizeof(uint32_t));
    if (!es || !eo || !eb)
        die("malloc load");
    for (uint64_t i = 0; i < count; i++) {
        if (fread(&es[i], 4, 1, f) != 1 || fread(&eo[i], 8, 1, f) != 1 ||
            fread(&eb[i], 4, 1, f) != 1)
            die("read save entry");
    }
    fclose(f);
    g_pid = pid_override ? pid_override : detect_pid();
    if (!g_pid) {
        fprintf(stderr, "error: Dark Souls III process not found (is it running?)\n");
        exit(1);
    }
    MapEnt *m;
    size_t nm;
    if (maps_read(g_pid, &m, &nm) != 0)
        die("open maps");
    uint64_t *rbase = calloc(nsrc ? nsrc : 1, sizeof(uint64_t));
    if (!rbase)
        die("malloc rbase");
    size_t unresolved = 0;
    for (uint32_t i = 0; i < nsrc; i++) {
        if (srcs[i].kind == 0) {
            uint64_t base = 0;
            for (size_t j = 0; j < nm; j++)
                if (strcmp(m[j].path, srcs[i].path) == 0 &&
                    (base == 0 || m[j].start < base))
                    base = m[j].start;
            rbase[i] = base;
        } else {
            long best = -1;
            uint64_t bestd = 0;
            for (size_t j = 0; j < nm; j++) {
                if (strcmp(m[j].perms, srcs[i].perms) != 0)
                    continue;
                if (m[j].end - m[j].start != srcs[i].size)
                    continue;
                uint64_t d = m[j].start > srcs[i].base ? m[j].start - srcs[i].base
                                                       : srcs[i].base - m[j].start;
                if (best < 0 || d < bestd) {
                    best = (long)j;
                    bestd = d;
                }
            }
            if (best >= 0)
                rbase[i] = m[best].start;
        }
        if (!rbase[i]) {
            unresolved++;
            if (srcs[i].kind == 0)
                fprintf(stderr, "warning: module not mapped now: %s\n", srcs[i].path);
            else
                fprintf(stderr, "warning: anon region not found (perms %s, size 0x%llx)\n",
                        srcs[i].perms, (unsigned long long)srcs[i].size);
        }
    }
    g_type = type;
    g_min = 1.0;
    g_max = 10000.0;
    g_exact = 0;
    g_tol = 0;
    g_n = 0;
    g_cap = 0;
    g_c = NULL;
    uint64_t skipped = 0;
    for (uint64_t k = 0; k < count; k++) {
        if (es[k] >= nsrc || rbase[es[k]] == 0) {
            skipped++;
            continue;
        }
        push_cand(rbase[es[k]] + eo[k], eb[k]);
    }
    save_state();
    printf("loaded %zu candidate(s) from %s (pid %d, %u source mapping(s), "
           "%zu unresolved, %llu skipped)\n",
           g_n, file, g_pid, nsrc, unresolved, (unsigned long long)skipped);
    printf("run 'ds3hp list' or 'ds3hp lock <index|all>' to use them\n");
    free(m);
    free(srcs);
    free(es);
    free(eo);
    free(eb);
    free(rbase);
}

static void cmd_reset(void)
{
    if (unlink(STATE_PATH) == 0)
        printf("state cleared\n");
    else
        printf("nothing to clear\n");
}

static void usage(const char *prog)
{
    printf("usage: %s <command> [options]\n\n", prog);
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
    printf("  save  <file> [--depth N] [--max-offset M] [--module S] [--raw]\n");
    printf("        save candidates as restart-stable pointer chains (--raw for offsets)\n");
    printf("  load  <file> [--pid N]    reload a save after a game restart\n");
    printf("  ptr   <index> [--depth N] [--max-offset M] [--module S]\n");
    printf("        search and print a pointer chain for one candidate\n");
    printf("  reset                     delete saved scan state\n\n");
    printf("typical run (float HP):\n");
    printf("  %s first\n", prog);
    printf("  take damage in game\n");
    printf("  %s next --dec\n", prog);
    printf("  heal / take more damage and repeat  next --inc / next --dec\n");
    printf("  %s list              # until only a few remain\n", prog);
    printf("  %s save hp.sav       # find a restart-stable pointer chain\n", prog);
    printf("  # after restarting the game:\n");
    printf("  %s load hp.sav && %s lock 0\n", prog, prog);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    const char *cmd = argv[1];
    if (strcmp(cmd, "first") == 0)
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
    else if (strcmp(cmd, "save") == 0)
        cmd_save(argc - 2, argv + 2);
    else if (strcmp(cmd, "load") == 0)
        cmd_load(argc - 2, argv + 2);
    else if (strcmp(cmd, "ptr") == 0)
        cmd_ptr(argc - 2, argv + 2);
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
