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
#include <locale.h>
#include <pthread.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ncurses.h>

#define STATE_MAGIC "CTSTATE"
#define STATE_VERSION 1
#define STATE_PATH_MAX 512
#define CHUNK (1u << 20)
#define MAX_BATCH 512

typedef enum { JNULL, JBOOL, JNUM, JSTR, JARR, JOBJ } JType;
typedef struct JVal {
    JType t;
    int b;
    long long num;
    double dbl;
    char *str;
    struct JVal **items;
    char **keys;
    size_t n, cap;
} JVal;

static JVal *json_parse(const char *text, size_t len);
static void json_free(JVal *v);
static JVal *jget(const JVal *o, const char *key);
static const char *jstr(const JVal *v);
static double jdbl(const JVal *v, double d);

typedef struct {
    char magic[8];
    uint32_t version;
    char game_id[64];
    int32_t pid;
    int32_t type;
    double min;
    double max;
    uint64_t count;
} __attribute__((packed)) StateHdr;

typedef struct {
    char id[64];
    char display_name[128];
    char process_name[64];
    char module_name[256];
    int type;
    double min, max;
    int anon_only;
} GameProfile;

static GameProfile g_profile = {
    "darksouls3", "Dark Souls III", "DarkSoulsIII", "DarkSoulsIII.exe",
    0, 1.0, 10000.0, 1
};
static GameProfile *g_profiles;
static size_t g_profile_count;
static char g_state_path[STATE_PATH_MAX];

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

static int profile_id_valid(const char *id)
{
    if (!id || !id[0] || strlen(id) >= sizeof g_profile.id)
        return 0;
    for (const unsigned char *p = (const unsigned char *)id; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '_' || *p == '-'))
            return 0;
    return strcmp(id, ".") != 0 && strcmp(id, "..") != 0;
}

static int process_matches(const char *comm)
{
    size_t n = strlen(g_profile.process_name);
    return comm && n && strncmp(comm, g_profile.process_name, n) == 0;
}

static void state_path_init(void)
{
    int n = snprintf(g_state_path, sizeof g_state_path, ".cheat-tool_state.%s", g_profile.id);
    if (n < 0 || (size_t)n >= sizeof g_state_path) {
        fprintf(stderr, "error: profile id too long for state path\n");
        exit(1);
    }
}

static void config_path(char *path, size_t len)
{
    const char *xdg = getenv("XDG_CONFIG_HOME");
    const char *home = getenv("HOME");
    int n = xdg && xdg[0]
        ? snprintf(path, len, "%s/cheat-tool/cheat-tool.json", xdg)
        : snprintf(path, len, "%s/.config/cheat-tool/cheat-tool.json", home ? home : ".");
    if (n < 0 || (size_t)n >= len) {
        fprintf(stderr, "error: config path too long\n");
        exit(1);
    }
}

static int json_has_only_keys(const JVal *obj, const char *const *keys, size_t nkeys)
{
    if (!obj || obj->t != JOBJ)
        return 0;
    for (size_t i = 0; i < obj->n; i++) {
        int found = 0;
        for (size_t j = 0; j < nkeys; j++)
            if (strcmp(obj->keys[i], keys[j]) == 0)
                found = 1;
        if (!found)
            return 0;
        for (size_t j = 0; j < i; j++)
            if (strcmp(obj->keys[i], obj->keys[j]) == 0)
                return 0;
    }
    return 1;
}

static void profiles_load(void)
{
    char path[512];
    config_path(path, sizeof path);
    FILE *f = fopen(path, "rb");
    if (!f) {
        if (errno == ENOENT) {
            g_profiles = malloc(sizeof(GameProfile));
            if (!g_profiles) die("malloc profiles");
            g_profiles[0] = g_profile;
            g_profile_count = 1;
            return;
        }
        fprintf(stderr, "error: open config %s: %s\n", path, strerror(errno));
        exit(1);
    }
    if (fseek(f, 0, SEEK_END) != 0) die("seek config");
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0 || sz > (1 << 20)) {
        fclose(f);
        fprintf(stderr, "error: invalid config size: %s\n", path);
        exit(1);
    }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) die("malloc config");
    size_t nr = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[nr] = 0;
    JVal *root = json_parse(buf, nr);
    free(buf);
    static const char *const root_keys[] = { "games" };
    static const char *const profile_keys[] = {
        "display_name", "process_name", "module_name", "default_type",
        "default_min", "default_max", "default_maps"
    };
    JVal *games = jget(root, "games");
    if (!root || root->t != JOBJ || !json_has_only_keys(root, root_keys, 1) ||
        !games || games->t != JOBJ || games->n == 0) {
        json_free(root);
        fprintf(stderr, "error: invalid config schema in %s\n", path);
        exit(1);
    }
    GameProfile *ps = calloc(games->n, sizeof *ps);
    if (!ps) die("calloc profiles");
    size_t np = 0;
    for (size_t i = 0; i < games->n; i++) {
        const char *id = games->keys[i];
        JVal *v = games->items[i];
        const char *display = jstr(jget(v, "display_name"));
        const char *process = jstr(jget(v, "process_name"));
        const char *module = jstr(jget(v, "module_name"));
        const char *type = jstr(jget(v, "default_type"));
        const char *maps = jstr(jget(v, "default_maps"));
        JVal *minv = jget(v, "default_min"), *maxv = jget(v, "default_max");
        if (!profile_id_valid(id) || !json_has_only_keys(v, profile_keys, 7) || v->n != 7 ||
            !display || !display[0] || strlen(display) >= sizeof ps[np].display_name ||
            !process || !process[0] || strlen(process) >= sizeof ps[np].process_name ||
            !module || !module[0] || strlen(module) >= sizeof ps[np].module_name ||
            !type || (strcmp(type, "float") != 0 && strcmp(type, "int") != 0) ||
            !maps || (strcmp(maps, "anon") != 0 && strcmp(maps, "all") != 0) ||
            !minv || minv->t != JNUM || !maxv || maxv->t != JNUM ||
            !isfinite(minv->dbl) || !isfinite(maxv->dbl) || minv->dbl >= maxv->dbl) {
            free(ps);
            json_free(root);
            fprintf(stderr, "error: invalid game profile '%s' in %s\n", id, path);
            exit(1);
        }
        snprintf(ps[np].id, sizeof ps[np].id, "%s", id);
        snprintf(ps[np].display_name, sizeof ps[np].display_name, "%s", display);
        snprintf(ps[np].process_name, sizeof ps[np].process_name, "%s", process);
        snprintf(ps[np].module_name, sizeof ps[np].module_name, "%s", module);
        ps[np].type = strcmp(type, "int") == 0 ? T_INT : T_FLOAT;
        ps[np].min = minv->dbl;
        ps[np].max = maxv->dbl;
        ps[np].anon_only = strcmp(maps, "anon") == 0;
        np++;
    }
    json_free(root);
    free(g_profiles);
    g_profiles = ps;
    g_profile_count = np;
}

static GameProfile *profile_find(const char *id)
{
    for (size_t i = 0; i < g_profile_count; i++)
        if (strcmp(g_profiles[i].id, id) == 0)
            return &g_profiles[i];
    return NULL;
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
        if (fgets(comm, sizeof comm, f) && process_matches(comm))
            found = atoi(e->d_name);
        fclose(f);
        if (found)
            break;
    }
    closedir(d);
    return found;
}

static int pid_ok(int pid)
{
    if (pid <= 0)
        return 0;
    char path[64], comm[256];
    snprintf(path, sizeof path, "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    int ok = fgets(comm, sizeof comm, f) && process_matches(comm);
    fclose(f);
    return ok;
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
    FILE *f = fopen(g_state_path, "wb");
    if (!f)
        die("write state");
    StateHdr h = {0};
    memcpy(h.magic, STATE_MAGIC, sizeof h.magic);
    h.version = STATE_VERSION;
    snprintf(h.game_id, sizeof h.game_id, "%s", g_profile.id);
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
    FILE *f = fopen(g_state_path, "rb");
    if (!f) {
        if (strcmp(g_profile.id, "darksouls3") == 0 && access(".ds3hp_state", F_OK) == 0)
            fprintf(stderr, "error: legacy .ds3hp_state is unsupported; run 'first' again\n");
        else
            fprintf(stderr, "error: no scan state; run 'first' first\n");
        exit(1);
    }
    StateHdr h;
    if (fread(&h, sizeof h, 1, f) != 1 || memcmp(h.magic, STATE_MAGIC, 8) != 0 ||
        h.version != STATE_VERSION || strcmp(h.game_id, g_profile.id) != 0) {
        fclose(f);
        fprintf(stderr, "error: incompatible scan state; run 'first' for game '%s'\n",
                g_profile.id);
        exit(1);
    }
    g_pid = h.pid;
    g_s.type = h.type;
    g_s.min = h.min;
    g_s.max = h.max;
    if (h.count > SIZE_MAX / sizeof(Cand)) {
        fclose(f);
        fprintf(stderr, "error: scan state candidate count is invalid\n");
        exit(1);
    }
    struct stat st;
    if (fstat(fileno(f), &st) != 0 || st.st_size < 0 ||
        (uint64_t)st.st_size != sizeof h + h.count * sizeof(Cand)) {
        fclose(f);
        fprintf(stderr, "error: truncated or invalid scan state\n");
        exit(1);
    }
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
    int anon_only = g_profile.anon_only;
    g_s.type = g_profile.type;
    g_s.min = g_profile.min;
    g_s.max = g_profile.max;
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
        fprintf(stderr, "error: %s process not found (is it running?)\n", g_profile.display_name);
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
    if (unlink(g_state_path) == 0)
        printf("state cleared\n");
    else
        printf("nothing to clear\n");
}

/* ======================= pointer chains ======================= */

#define CHAIN_MAGIC "DS3CHAIN"
#define CHAIN_VERSION 3
#define CHAIN_MAX 8
#define CHAIN_DEF_DEPTH 4
#define CHAIN_DEF_OFF 0x1000
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
    return cs->n == 1;
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

/* ===================== minimal JSON ===================== */

static void json_free(JVal *v)
{
    if (!v)
        return;
    if (v->t == JSTR)
        free(v->str);
    for (size_t i = 0; i < v->n; i++) {
        if (v->t == JOBJ)
            free(v->keys[i]);
        json_free(v->items[i]);
    }
    free(v->keys);
    free(v->items);
    free(v);
}

typedef struct {
    const char *p, *end;
    int depth, err;
} JParser;

static JVal *jnew(JType t)
{
    JVal *v = calloc(1, sizeof *v);
    if (v)
        v->t = t;
    return v;
}

static void jskip(JParser *j)
{
    while (j->p < j->end &&
           (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r'))
        j->p++;
}

static int jhex(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int jput(char **buf, size_t *len, size_t *cap, unsigned char c)
{
    if (*len + 1 >= *cap) {
        size_t nc = *cap ? *cap * 2 : 32;
        char *nb = realloc(*buf, nc);
        if (!nb)
            return 0;
        *buf = nb;
        *cap = nc;
    }
    (*buf)[(*len)++] = (char)c;
    return 1;
}

static char *jstring(JParser *j)
{
    if (j->p >= j->end || *j->p != '"') {
        j->err = 1;
        return NULL;
    }
    j->p++;
    char *s = NULL;
    size_t len = 0, cap = 0;
    while (j->p < j->end && *j->p != '"') {
        unsigned char c = (unsigned char)*j->p++;
        if (c == '\\') {
            if (j->p >= j->end) { j->err = 1; break; }
            char e = *j->p++;
            switch (e) {
            case '"': c = '"'; break;
            case '\\': c = '\\'; break;
            case '/': c = '/'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case 'u': {
                unsigned cp = 0;
                for (int k = 0; k < 4; k++) {
                    if (j->p >= j->end || jhex(*j->p) < 0) { j->err = 1; break; }
                    cp = cp * 16 + (unsigned)jhex(*j->p++);
                }
                if (cp < 0x80) {
                    c = (unsigned char)cp;
                } else if (cp < 0x800) {
                    jput(&s, &len, &cap, (unsigned char)(0xC0 | (cp >> 6)));
                    jput(&s, &len, &cap, (unsigned char)(0x80 | (cp & 0x3F)));
                    continue;
                } else {
                    jput(&s, &len, &cap, (unsigned char)(0xE0 | (cp >> 12)));
                    jput(&s, &len, &cap, (unsigned char)(0x80 | ((cp >> 6) & 0x3F)));
                    jput(&s, &len, &cap, (unsigned char)(0x80 | (cp & 0x3F)));
                    continue;
                }
                break;
            }
            default: j->err = 1; c = (unsigned char)e;
            }
        }
        jput(&s, &len, &cap, c);
    }
    if (j->p >= j->end || *j->p != '"')
        j->err = 1;
    else
        j->p++;
    if (j->err || !jput(&s, &len, &cap, 0)) {
        free(s);
        return NULL;
    }
    return s;
}

static int jpush(JVal *o, char *key, JVal *v)
{
    if (o->n == o->cap) {
        size_t nc = o->cap ? o->cap * 2 : 8;
        JVal **ni = realloc(o->items, nc * sizeof(JVal *));
        if (!ni)
            return 0;
        o->items = ni;
        if (o->t == JOBJ) {
            char **nk = realloc(o->keys, nc * sizeof(char *));
            if (!nk)
                return 0;
            o->keys = nk;
        }
        o->cap = nc;
    }
    if (o->t == JOBJ)
        o->keys[o->n] = key;
    o->items[o->n++] = v;
    return 1;
}

static JVal *jvalue(JParser *j);

static JVal *jarray(JParser *j)
{
    if (j->depth >= 32) { j->err = 1; return NULL; }
    j->depth++;
    JVal *a = jnew(JARR);
    if (!a) { j->err = 1; j->depth--; return NULL; }
    j->p++;
    jskip(j);
    if (j->p < j->end && *j->p == ']') { j->p++; j->depth--; return a; }
    for (;;) {
        JVal *v = jvalue(j);
        if (!v || !jpush(a, NULL, v)) {
            json_free(v);
            json_free(a);
            j->err = 1;
            j->depth--;
            return NULL;
        }
        jskip(j);
        if (j->p < j->end && *j->p == ',') { j->p++; continue; }
        if (j->p < j->end && *j->p == ']') { j->p++; break; }
        j->err = 1;
        json_free(a);
        j->depth--;
        return NULL;
    }
    j->depth--;
    return a;
}

static JVal *jobject(JParser *j)
{
    if (j->depth >= 32) { j->err = 1; return NULL; }
    j->depth++;
    JVal *o = jnew(JOBJ);
    if (!o) { j->err = 1; j->depth--; return NULL; }
    j->p++;
    jskip(j);
    if (j->p < j->end && *j->p == '}') { j->p++; j->depth--; return o; }
    for (;;) {
        jskip(j);
        char *k = jstring(j);
        if (!k) { json_free(o); j->depth--; return NULL; }
        jskip(j);
        if (j->p >= j->end || *j->p != ':') {
            free(k);
            json_free(o);
            j->err = 1;
            j->depth--;
            return NULL;
        }
        j->p++;
        JVal *v = jvalue(j);
        if (!v || !jpush(o, k, v)) {
            free(k);
            json_free(v);
            json_free(o);
            j->err = 1;
            j->depth--;
            return NULL;
        }
        jskip(j);
        if (j->p < j->end && *j->p == ',') { j->p++; continue; }
        if (j->p < j->end && *j->p == '}') { j->p++; break; }
        j->err = 1;
        json_free(o);
        j->depth--;
        return NULL;
    }
    j->depth--;
    return o;
}

static JVal *jvalue(JParser *j)
{
    jskip(j);
    if (j->p >= j->end) { j->err = 1; return NULL; }
    char c = *j->p;
    if (c == '{') return jobject(j);
    if (c == '[') return jarray(j);
    if (c == '"') {
        JVal *v = jnew(JSTR);
        if (!v) { j->err = 1; return NULL; }
        v->str = jstring(j);
        if (!v->str) { json_free(v); return NULL; }
        return v;
    }
    if (c == 't' && j->end - j->p >= 4 && !memcmp(j->p, "true", 4)) {
        j->p += 4;
        JVal *v = jnew(JBOOL);
        if (v) v->b = 1;
        return v;
    }
    if (c == 'f' && j->end - j->p >= 5 && !memcmp(j->p, "false", 5)) {
        j->p += 5;
        JVal *v = jnew(JBOOL);
        return v;
    }
    if (c == 'n' && j->end - j->p >= 4 && !memcmp(j->p, "null", 4)) {
        j->p += 4;
        return jnew(JNULL);
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        char *e;
        long long n = strtoll(j->p, &e, 10);
        double d = (double)n;
        if (e == j->p) { j->err = 1; return NULL; }
        if (*e == '.' || *e == 'e' || *e == 'E') {
            d = strtod(j->p, &e);
            n = (long long)d;
        }
        j->p = e;
        JVal *v = jnew(JNUM);
        if (!v) { j->err = 1; return NULL; }
        v->num = n;
        v->dbl = d;
        return v;
    }
    j->err = 1;
    return NULL;
}

static JVal *json_parse(const char *text, size_t len)
{
    JParser j = { text, text + len, 0, 0 };
    JVal *v = jvalue(&j);
    if (!v)
        return NULL;
    jskip(&j);
    if (j.err || j.p != j.end) {
        json_free(v);
        return NULL;
    }
    return v;
}

static JVal *jget(const JVal *o, const char *key)
{
    if (!o || o->t != JOBJ)
        return NULL;
    for (size_t i = 0; i < o->n; i++)
        if (strcmp(o->keys[i], key) == 0)
            return o->items[i];
    return NULL;
}

static const char *jstr(const JVal *v) { return v && v->t == JSTR ? v->str : NULL; }
static long long jll(const JVal *v, long long d) { return v && v->t == JNUM ? v->num : d; }
static double jdbl(const JVal *v, double d) { return v && v->t == JNUM ? v->dbl : d; }
static int jboolv(const JVal *v, int d) { return v && v->t == JBOOL ? v->b : d; }

static void jw_str(FILE *f, const char *s)
{
    fputc('"', f);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"': fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\n': fputs("\\n", f); break;
        case '\r': fputs("\\r", f); break;
        case '\t': fputs("\\t", f); break;
        default:
            if (c < 0x20) fprintf(f, "\\u%04x", c);
            else fputc(c, f);
        }
    }
    fputc('"', f);
}

/* ===================== watch store (JSON) ===================== */

static int legacy_watches_load(void);
static const char *watches_path(void)
{
    static char path[768];
    const char *xdg = getenv("XDG_CONFIG_HOME");
    const char *home = getenv("HOME");
    int n = xdg && xdg[0]
        ? snprintf(path, sizeof path, "%s/cheat-tool/games/%s/watches.json", xdg, g_profile.id)
        : snprintf(path, sizeof path, "%s/.config/cheat-tool/games/%s/watches.json",
                   home ? home : ".", g_profile.id);
    if (n < 0 || (size_t)n >= sizeof path) {
        fprintf(stderr, "error: watch path too long\n");
        exit(1);
    }
    return path;
}

static void mkdir_p(const char *dir)
{
    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s", dir);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') { *p = 0; mkdir(tmp, 0755); *p = '/'; }
    }
    mkdir(tmp, 0755);
}

typedef struct {
    char name[24];
    int type;
    int has_lockval;
    uint32_t lock_bits;
    int lock_on;
    int has_chain;
    ChainSet cs;
} WatchEntry;

static void entries_free(WatchEntry *e, int n)
{
    if (!e)
        return;
    for (int i = 0; i < n; i++)
        free(e[i].cs.c);
    free(e);
}

static int entries_load(WatchEntry **out, int *outn)
{
    *out = NULL;
    *outn = 0;
    const char *path = watches_path();
    FILE *f = fopen(path, "rb");
    if (!f) {
        if (errno != ENOENT)
            return -1;
        if (strcmp(g_profile.id, "darksouls3") != 0)
            return 0;
        struct stat st;
        if (strcmp(g_profile.id, "darksouls3") == 0 && stat(path, &st) != 0 && errno == ENOENT) {
            const char *legacy_json = NULL;
            char legacy_path[512];
            const char *home = getenv("HOME");
            int n = snprintf(legacy_path, sizeof legacy_path, "%s/.config/ds3hp/watches.json",
                             home ? home : ".");
            if (n >= 0 && (size_t)n < sizeof legacy_path && access(legacy_path, F_OK) == 0)
                legacy_json = legacy_path;
            if (legacy_json) {
                FILE *src = fopen(legacy_json, "rb");
            if (src) {
                FILE *dst;
                char dir[768];
                snprintf(dir, sizeof dir, "%s", path);
                char *slash = strrchr(dir, '/');
                if (slash) { *slash = 0; mkdir_p(dir); }
                dst = fopen(path, "wb");
                if (dst) {
                    char copy[8192];
                    size_t got;
                    int ok = 1;
                    while ((got = fread(copy, 1, sizeof copy, src)) > 0)
                        if (fwrite(copy, 1, got, dst) != got) { ok = 0; break; }
                    if (ferror(src)) ok = 0;
                    fclose(src);
                    if (fclose(dst) != 0) ok = 0;
                    if (!ok) {
                        unlink(path);
                        fprintf(stderr, "error: failed to migrate legacy watches from %s\n", legacy_json);
                        return -1;
                    }
                    f = fopen(path, "rb");
                } else {
                    fclose(src);
                }
                }
            }
        }
        if (!f && access(path, F_OK) != 0) {
            return 0;
        }
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || sz > (16 << 20)) {
        fclose(f);
        fprintf(stderr, "error: watches.json too large\n");
        return -1;
    }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return -1;
    }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = 0;
    JVal *root = json_parse(buf, rd);
    free(buf);
    if (!root || root->t != JOBJ) {
        json_free(root);
        fprintf(stderr, "error: bad %s\n", watches_path());
        return -1;
    }
    int cap = 0, n = 0;
    WatchEntry *arr = NULL;
    for (size_t i = 0; i < root->n; i++) {
        const char *key = root->keys[i];
        if (key[0] == '_')
            continue;
        JVal *w = root->items[i];
        if (!w || w->t != JOBJ)
            continue;
        if (n == cap) {
            int nc = cap ? cap * 2 : 8;
            WatchEntry *na = realloc(arr, (size_t)nc * sizeof *na);
            if (!na) {
                entries_free(arr, n);
                json_free(root);
                return -1;
            }
            arr = na;
            cap = nc;
        }
        WatchEntry *e = &arr[n];
        memset(e, 0, sizeof *e);
        snprintf(e->name, sizeof e->name, "%s", key);
        const char *ts = jstr(jget(w, "type"));
        e->type = (ts && strcmp(ts, "int") == 0) ? T_INT : T_FLOAT;
        JVal *lv = jget(w, "lock_value");
        if (lv && lv->t == JNUM) {
            e->has_lockval = 1;
            e->lock_bits = val_to_bits(e->type, jdbl(lv, 0));
        }
        e->lock_on = jboolv(jget(w, "lock_on"), 0);
        JVal *ch = jget(w, "chain");
        if (ch && ch->t == JOBJ) {
            ChainSet *cs = &e->cs;
            cs->type = e->type;
            const char *mod = jstr(jget(ch, "module"));
            if (mod)
                snprintf(cs->module, sizeof cs->module, "%s", mod);
            cs->scans = (uint32_t)jll(jget(ch, "scans"), 0);
            cs->verifies = (uint32_t)jll(jget(ch, "verifies"), 0);
            cs->token = (uint64_t)jll(jget(ch, "token"), 0);
            e->has_chain = 1;
            JVal *list = jget(ch, "list");
            if (list && list->t == JARR && list->n) {
                cs->cap = list->n > CHAIN_COUNT_MAX ? CHAIN_COUNT_MAX : (uint32_t)list->n;
                cs->c = calloc(cs->cap, sizeof(Chain));
                if (!cs->c) {
                    entries_free(arr, n + 1);
                    json_free(root);
                    return -1;
                }
                for (size_t k = 0; k < list->n && cs->n < cs->cap; k++) {
                    JVal *item = list->items[k];
                    if (!item || item->t != JOBJ)
                        continue;
                    Chain c;
                    memset(&c, 0, sizeof c);
                    c.rva = (uint64_t)jll(jget(item, "rva"), 0);
                    JVal *offs = jget(item, "offs");
                    if (offs && offs->t == JARR) {
                        int nn = 0;
                        for (size_t m = 0; m < offs->n && nn < CHAIN_MAX; m++)
                            c.offs[nn++] = (uint64_t)jll(offs->items[m], 0);
                        c.n = (uint8_t)nn;
                    }
                    cs->c[cs->n++] = c;
                }
            }
        }
        n++;
    }
    json_free(root);
    *out = arr;
    *outn = n;
    return 0;
}

static int entries_save(const WatchEntry *e, int n)
{
    const char *path = watches_path();
    char dir[512];
    snprintf(dir, sizeof dir, "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) { *slash = 0; mkdir_p(dir); }
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "error: open %s: %s\n", path, strerror(errno));
        return -1;
    }
    fprintf(f, "{\n  \"_version\": 1");
    for (int i = 0; i < n; i++) {
        const WatchEntry *w = &e[i];
        fprintf(f, ",\n  ");
        jw_str(f, w->name);
        fprintf(f, ": {\n    \"type\": %s", w->type == T_INT ? "\"int\"" : "\"float\"");
        if (w->has_lockval) {
            if (w->type == T_INT)
                fprintf(f, ",\n    \"lock_value\": %lld",
                        (long long)(int32_t)w->lock_bits);
            else
                fprintf(f, ",\n    \"lock_value\": %.9g",
                        bits_to_val(w->type, w->lock_bits));
        }
        fprintf(f, ",\n    \"lock_on\": %s", w->lock_on ? "true" : "false");
        if (w->has_chain) {
            fprintf(f, ",\n    \"chain\": {\n      \"module\": ");
            jw_str(f, w->cs.module);
            fprintf(f, ",\n      \"scans\": %u,\n      \"verifies\": %u,"
                       "\n      \"token\": %llu,\n      \"list\": [",
                    w->cs.scans, w->cs.verifies, (unsigned long long)w->cs.token);
            for (uint32_t k = 0; k < w->cs.n; k++) {
                fprintf(f, "%s\n        { \"rva\": %llu, \"offs\": [",
                        k ? "," : "", (unsigned long long)w->cs.c[k].rva);
                for (int m = 0; m < w->cs.c[k].n; m++)
                    fprintf(f, "%s%llu", m ? ", " : "",
                            (unsigned long long)w->cs.c[k].offs[m]);
                fprintf(f, "] }");
            }
            fprintf(f, "\n      ]\n    }");
        }
        fprintf(f, "\n  }");
    }
    fprintf(f, "\n}\n");
    fclose(f);
    return 0;
}

static WatchEntry *entries_get(WatchEntry **arr, int *n, int *cap, const char *name)
{
    for (int i = 0; i < *n; i++)
        if (strcmp((*arr)[i].name, name) == 0)
            return &(*arr)[i];
    if (*n == *cap) {
        int nc = *cap ? *cap * 2 : 8;
        WatchEntry *na = realloc(*arr, (size_t)nc * sizeof(WatchEntry));
        if (!na)
            return NULL;
        *arr = na;
        *cap = nc;
    }
    WatchEntry *e = &(*arr)[(*n)++];
    memset(e, 0, sizeof *e);
    snprintf(e->name, sizeof e->name, "%s", name);
    e->type = T_FLOAT;
    return e;
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

static WatchEntry *chain_get_entry(const char *name, WatchEntry **arr, int *n, int *cap)
{
    if (entries_load(arr, n) != 0)
        exit(1);
    *cap = *n;
    WatchEntry *e = entries_get(arr, n, cap, name);
    if (!e) {
        fprintf(stderr, "error: out of memory\n");
        exit(1);
    }
    return e;
}

static void chain_status(const WatchEntry *e, char *buf, size_t len)
{
    if (!e->has_chain) {
        snprintf(buf, len, "no chain");
    } else if (chain_is_stable(&e->cs)) {
        snprintf(buf, len, "stable (%u chain, %u scan, %u verify)",
                 e->cs.n, e->cs.scans, e->cs.verifies);
    } else {
        snprintf(buf, len, "%u candidate(s), %u scan, %u verify",
                 e->cs.n, e->cs.scans, e->cs.verifies);
    }
}

static int cmd_chain_scan(int argc, char **argv)
{
    const char *name = NULL;
    const char *mod = g_profile.module_name;
    uint64_t addr = 0;
    int have_addr = 0, depth = CHAIN_DEF_DEPTH, pid = 0, reset = 0;
    int type = g_profile.type;
    uint64_t maxoff = CHAIN_DEF_OFF;
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
            type = strcmp(argv[++i], "int") == 0 ? T_INT : T_FLOAT;
        } else if (strcmp(argv[i], "--reset") == 0) {
            reset = 1;
        } else if (!name) {
            name = argv[i];
        } else {
            fprintf(stderr, "error: unknown option %s\n", argv[i]);
            return 1;
        }
    }
    if (!name || !have_addr) {
        fprintf(stderr, "error: chain scan <watch> --addr 0xADDR"
                        " [--depth N] [--max-offset M] [--module S]"
                        " [--pid P] [--type float|int] [--reset]\n");
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

    WatchEntry *arr = NULL;
    int n = 0, cap = 0;
    WatchEntry *e = chain_get_entry(name, &arr, &n, &cap);
    if (type >= 0)
        e->type = type;

    ChainSet fresh = {0};
    fresh.type = e->type;
    snprintf(fresh.module, sizeof fresh.module, "%s", mod);
    fprintf(stderr, "scan '%s': target 0x%llx, module %s (base 0x%llx),"
                    " depth %d, max-offset 0x%llx\n",
            name, (unsigned long long)addr, mod, (unsigned long long)modbase,
            depth, (unsigned long long)maxoff);
    uint64_t total = 0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    chain_scan(g_pid, addr, depth, maxoff, mod, &fresh, NULL, NULL, &total);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double dt = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    printf("scan: %u candidate chain(s) in %.1fs\n", fresh.n, dt);

    uint64_t tok = process_token(g_pid);
    int have_prev = e->has_chain && e->cs.n > 0 && !reset;
    uint32_t prevn = have_prev ? e->cs.n : 0;
    int same = have_prev && e->cs.token != 0 && e->cs.token == tok;
    if (same) {
        fprintf(stderr, "note: same process as last scan (pid %d); restart the game"
                        " before scanning again\n", g_pid);
    } else if (have_prev) {
        ChainSet result = {0};
        chainset_intersect(&e->cs, &fresh, &result);
        result.token = tok;
        free(e->cs.c);
        e->cs = result;
        printf("intersect: %u -> %u chain(s) (scan #%u)\n", prevn, e->cs.n, e->cs.scans);
    } else {
        ChainSet result = fresh;
        memset(&fresh, 0, sizeof fresh);
        result.type = e->type;
        snprintf(result.module, sizeof result.module, "%s", mod);
        result.scans = 1;
        result.token = tok;
        free(e->cs.c);
        e->cs = result;
        printf("saved %u candidate chain(s) (scan #1)\n", e->cs.n);
    }
    free(fresh.c);
    e->has_chain = 1;
    if (entries_save(arr, n) != 0) {
        entries_free(arr, n);
        return 1;
    }
    printf("wrote %s (%u chain(s), %u scan(s), %u verify/ies)\n", watches_path(),
           e->cs.n, e->cs.scans, e->cs.verifies);
    if (chain_is_stable(&e->cs)) {
        char b[512];
        chain_format(&e->cs.c[0], e->cs.module, b, sizeof b);
        printf("stable chain: %s\n", b);
        printf("use: ds3hp chain load %s\n", name);
    } else if (e->cs.n > 1) {
        printf("still %u candidate(s); re-run after a restart, or use"
               " 'chain verify %s --value V'\n", e->cs.n, name);
    }
    entries_free(arr, n);
    return 0;
}

static void cmd_chain_list(int argc, char **argv)
{
    const char *name = NULL;
    int pid = 0;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc)
            pid = atoi(argv[++i]);
        else if (!name)
            name = argv[i];
        else {
            fprintf(stderr, "error: unknown option %s\n", argv[i]);
            exit(1);
        }
    }
    WatchEntry *arr = NULL;
    int n = 0;
    if (entries_load(&arr, &n) != 0)
        exit(1);
    printf("%s\n", watches_path());
    if (!name) {
        if (n == 0)
            printf("  (no watches)\n");
        for (int i = 0; i < n; i++) {
            char s[128], lk[32];
            chain_status(&arr[i], s, sizeof s);
            if (arr[i].has_lockval)
                snprintf(lk, sizeof lk, "%g", bits_to_val(arr[i].type, arr[i].lock_bits));
            else
                snprintf(lk, sizeof lk, "-");
            printf("  %-16s %-5s lock=%-10s%s chain: %s\n", arr[i].name,
                   arr[i].type == T_INT ? "int" : "float", lk,
                   arr[i].lock_on ? " [on]" : "", s);
        }
        entries_free(arr, n);
        return;
    }
    WatchEntry *e = NULL;
    for (int i = 0; i < n; i++)
        if (strcmp(arr[i].name, name) == 0)
            e = &arr[i];
    if (!e) {
        fprintf(stderr, "error: no watch '%s'\n", name);
        entries_free(arr, n);
        exit(1);
    }
    if (!e->has_chain) {
        printf("watch '%s' has no chain\n", name);
        entries_free(arr, n);
        return;
    }
    printf("watch '%s': %u chain(s), %u scan(s), %u verify/ies, module %s, type %s\n",
           name, e->cs.n, e->cs.scans, e->cs.verifies, e->cs.module,
           e->cs.type == T_INT ? "int" : "float");
    CMap *m = NULL;
    size_t nm = 0;
    uint64_t modbase = 0;
    if (pid) {
        g_pid = pid;
        if (cmaps_read(pid, &m, &nm) == 0)
            modbase = chain_module_base(m, nm, e->cs.module);
    }
    for (uint32_t i = 0; i < e->cs.n; i++) {
        char b[512];
        chain_format(&e->cs.c[i], e->cs.module, b, sizeof b);
        printf("  [%u] %s  (%u deref%s, total 0x%llx)", i, b, e->cs.c[i].n,
               e->cs.c[i].n == 1 ? "" : "s",
               (unsigned long long)chain_total_off(&e->cs.c[i]));
        if (pid) {
            uint64_t addr;
            if (modbase && chain_resolve(pid, m, nm, modbase, &e->cs.c[i], &addr)) {
                int ok;
                uint32_t v = read_at(addr, &ok);
                if (ok)
                    printf("  @0x%llx = %g", (unsigned long long)addr,
                           bits_to_val(e->cs.type, v));
                else
                    printf("  @0x%llx = <unreadable>", (unsigned long long)addr);
            } else {
                printf("  (unresolved)");
            }
        }
        printf("\n");
    }
    free(m);
    entries_free(arr, n);
}

static void cmd_chain_resolve(int argc, char **argv)
{
    const char *name = NULL;
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
        } else if (!name)
            name = argv[i];
        else {
            fprintf(stderr, "error: unknown option %s\n", argv[i]);
            exit(1);
        }
    }
    if (!name) {
        fprintf(stderr, "error: chain resolve <watch> [--index K] [--pid P] [--value V]\n");
        exit(1);
    }
    WatchEntry *arr = NULL;
    int n = 0;
    if (entries_load(&arr, &n) != 0)
        exit(1);
    WatchEntry *e = NULL;
    for (int i = 0; i < n; i++)
        if (strcmp(arr[i].name, name) == 0)
            e = &arr[i];
    if (!e || !e->has_chain) {
        fprintf(stderr, "error: no chain for watch '%s'\n", name);
        entries_free(arr, n);
        exit(1);
    }
    ChainSet *cs = &e->cs;
    if (!chain_is_stable(cs))
        fprintf(stderr, "warning: %u candidate chain(s); not unique yet\n", cs->n);
    if (index < 0 || (uint32_t)index >= cs->n) {
        fprintf(stderr, "error: index %d out of range (0..%d)\n", index,
                cs->n ? (int)cs->n - 1 : 0);
        entries_free(arr, n);
        exit(1);
    }
    g_pid = pid ? pid : detect_pid();
    if (!g_pid) {
        fprintf(stderr, "error: Dark Souls III process not found\n");
        entries_free(arr, n);
        exit(1);
    }
    CMap *m = NULL;
    size_t nm = 0;
    if (cmaps_read(g_pid, &m, &nm) != 0) {
        fprintf(stderr, "error: open maps\n");
        entries_free(arr, n);
        exit(1);
    }
    uint64_t modbase = chain_module_base(m, nm, cs->module);
    if (!modbase) {
        const char *base = strrchr(cs->module, '/');
        base = base ? base + 1 : cs->module;
        modbase = chain_module_base(m, nm, base);
    }
    uint64_t addr;
    if (!modbase || !chain_resolve(g_pid, m, nm, modbase, &cs->c[index], &addr)) {
        fprintf(stderr, "error: chain %d failed to resolve (module %s)\n",
                index, cs->module);
        free(m);
        entries_free(arr, n);
        exit(1);
    }
    char b[512];
    chain_format(&cs->c[index], cs->module, b, sizeof b);
    printf("%s\n  resolves to 0x%llx (pid %d, module base 0x%llx)\n", b,
           (unsigned long long)addr, g_pid, (unsigned long long)modbase);
    if (have_val) {
        int ok;
        uint32_t v = read_at(addr, &ok);
        uint32_t want = val_to_bits(cs->type, val);
        if (!ok)
            printf("  warning: value unreadable at address\n");
        else if (v != want)
            printf("  warning: value %g != expected %g (address may be wrong)\n",
                   bits_to_val(cs->type, v), val);
        else
            printf("  value check ok: %g\n", val);
    }
    free(m);
    entries_free(arr, n);
}

static void cmd_chain_verify(int argc, char **argv)
{
    const char *name = NULL;
    int pid = 0, have_val = 0;
    double val = 0;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--value") == 0 && i + 1 < argc) {
            val = atof(argv[++i]);
            have_val = 1;
        } else if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
            pid = atoi(argv[++i]);
        } else if (!name)
            name = argv[i];
        else {
            fprintf(stderr, "error: unknown option %s\n", argv[i]);
            exit(1);
        }
    }
    if (!name || !have_val) {
        fprintf(stderr, "error: chain verify <watch> --value V [--pid P]\n");
        exit(1);
    }
    WatchEntry *arr = NULL;
    int n = 0;
    if (entries_load(&arr, &n) != 0)
        exit(1);
    WatchEntry *e = NULL;
    for (int i = 0; i < n; i++)
        if (strcmp(arr[i].name, name) == 0)
            e = &arr[i];
    if (!e || !e->has_chain || e->cs.n == 0) {
        fprintf(stderr, "error: no chain for watch '%s'\n", name);
        entries_free(arr, n);
        exit(1);
    }
    g_pid = pid ? pid : detect_pid();
    if (!g_pid) {
        fprintf(stderr, "error: Dark Souls III process not found\n");
        entries_free(arr, n);
        exit(1);
    }
    uint64_t tok = process_token(g_pid);
    int same = e->cs.token != 0 && e->cs.token == tok;
    uint32_t before = e->cs.n;
    int r = chain_verify(&e->cs, g_pid, val);
    if (r < 0) {
        entries_free(arr, n);
        exit(1);
    }
    if (!same) {
        e->cs.verifies++;
        e->cs.token = tok;
    }
    if (e->cs.n == 0) {
        fprintf(stderr, "no chain matched %g; %u candidate(s) kept (not saved)\n",
                val, before);
        entries_free(arr, n);
        return;
    }
    if (entries_save(arr, n) != 0) {
        entries_free(arr, n);
        exit(1);
    }
    printf("verify '%s': %u -> %u chain(s) against %g (%u verify/ies)%s\n", name,
           before, e->cs.n, val, e->cs.verifies,
           same ? " [same process, not counted]" : "");
    if (!same && chain_is_stable(&e->cs)) {
        char b[512];
        chain_format(&e->cs.c[0], e->cs.module, b, sizeof b);
        printf("stable chain: %s\n", b);
        printf("use: ds3hp chain load %s\n", name);
    } else {
        printf("still %u candidate(s); repeat after a restart with another value\n",
               e->cs.n);
    }
    entries_free(arr, n);
}

static void cmd_chain_load(int argc, char **argv)
{
    const char *name = NULL;
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
        } else if (!name)
            name = argv[i];
        else {
            fprintf(stderr, "error: unknown option %s\n", argv[i]);
            exit(1);
        }
    }
    if (!name) {
        fprintf(stderr, "error: chain load <watch> [--index K] [--pid P] [--value V]\n");
        exit(1);
    }
    WatchEntry *arr = NULL;
    int n = 0;
    if (entries_load(&arr, &n) != 0)
        exit(1);
    WatchEntry *e = NULL;
    for (int i = 0; i < n; i++)
        if (strcmp(arr[i].name, name) == 0)
            e = &arr[i];
    if (!e || !e->has_chain) {
        fprintf(stderr, "error: no chain for watch '%s'\n", name);
        entries_free(arr, n);
        exit(1);
    }
    ChainSet *cs = &e->cs;
    if (!chain_is_stable(cs))
        fprintf(stderr, "warning: %u candidate chain(s); not unique yet\n", cs->n);
    if (index < 0 || (uint32_t)index >= cs->n) {
        fprintf(stderr, "error: index %d out of range (0..%d)\n", index,
                cs->n ? (int)cs->n - 1 : 0);
        entries_free(arr, n);
        exit(1);
    }
    g_pid = pid ? pid : detect_pid();
    if (!g_pid) {
        fprintf(stderr, "error: Dark Souls III process not found\n");
        entries_free(arr, n);
        exit(1);
    }
    CMap *m = NULL;
    size_t nm = 0;
    if (cmaps_read(g_pid, &m, &nm) != 0) {
        fprintf(stderr, "error: open maps\n");
        entries_free(arr, n);
        exit(1);
    }
    uint64_t modbase = chain_module_base(m, nm, cs->module);
    uint64_t addr;
    if (!modbase || !chain_resolve(g_pid, m, nm, modbase, &cs->c[index], &addr)) {
        fprintf(stderr, "error: chain %d failed to resolve (module %s)\n",
                index, cs->module);
        free(m);
        entries_free(arr, n);
        exit(1);
    }
    int ok;
    uint32_t cur = read_at(addr, &ok);
    if (!ok) {
        fprintf(stderr, "error: resolved address 0x%llx is unreadable\n",
                (unsigned long long)addr);
        free(m);
        entries_free(arr, n);
        exit(1);
    }
    if (have_val) {
        uint32_t want = val_to_bits(cs->type, val);
        if (cur != want)
            printf("warning: current value %g != expected %g\n",
                   bits_to_val(cs->type, cur), val);
    }
    g_s.type = cs->type;
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
    printf("loaded '%s' chain %d -> 0x%llx = %g (pid %d)\n", name, index,
           (unsigned long long)addr, bits_to_val(cs->type, cur), g_pid);
    printf("run 'ds3hp list' or 'ds3hp lock 0' to use it\n");
    free(m);
    entries_free(arr, n);
}

static void chain_remove(const char *name, int rm)
{
    WatchEntry *arr = NULL;
    int n = 0;
    if (entries_load(&arr, &n) != 0)
        exit(1);
    int idx = -1;
    for (int i = 0; i < n; i++)
        if (strcmp(arr[i].name, name) == 0)
            idx = i;
    if (idx < 0) {
        printf("nothing to remove ('%s')\n", name);
        entries_free(arr, n);
        return;
    }
    if (rm) {
        free(arr[idx].cs.c);
        memmove(&arr[idx], &arr[idx + 1], (size_t)(n - idx - 1) * sizeof(WatchEntry));
        n--;
        printf("removed watch '%s'\n", name);
    } else {
        free(arr[idx].cs.c);
        memset(&arr[idx].cs, 0, sizeof arr[idx].cs);
        arr[idx].cs.type = arr[idx].type;
        arr[idx].has_chain = 0;
        printf("cleared chain for '%s'\n", name);
    }
    entries_save(arr, n);
    entries_free(arr, n);
}

static void cmd_chain_clear(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "error: chain clear <watch>\n");
        exit(1);
    }
    chain_remove(argv[0], 0);
}

static void cmd_chain_rm(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "error: chain rm <watch>\n");
        exit(1);
    }
    chain_remove(argv[0], 1);
}

static void cmd_chain(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr,
                "usage: chain <scan|list|resolve|verify|load|clear|rm> ...\n"
                "  scan    <watch> --addr 0xADDR [--type float|int] ...\n"
                "  list    [<watch>] [--pid P]\n"
                "  resolve <watch> [--index K] [--value V] [--pid P]\n"
                "  verify  <watch> --value V [--pid P]\n"
                "  load    <watch> [--index K] [--value V] [--pid P]\n"
                "  clear   <watch>      remove the watch's chain\n"
                "  rm      <watch>      remove the watch entirely\n");
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
    else if (strcmp(sub, "rm") == 0)
        cmd_chain_rm(argc - 1, argv + 1);
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
    ChainSet cs;
    int has_cs;
} Watch;

static Watch g_w[MAX_WATCH];
static int g_nw = 0;
static int g_cur = 0;
static long long g_t0_ms = 0;
static char g_notice[64];
static long long g_notice_until = 0;

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

static void set_notice(const char *s)
{
    snprintf(g_notice, sizeof g_notice, "%s", s);
    g_notice_until = now_ms() + 4000;
}

static int watches_save(void);
static void watch_bind_chain(Watch *w);

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
        snprintf(fresh.module, sizeof fresh.module, "%s", g_profile.module_name);
        uint64_t total = 0;
        w->progress = 0;
        chain_scan(g_pid, w->addr, CHAIN_DEF_DEPTH, CHAIN_DEF_OFF, g_profile.module_name,
                   &fresh, &w->cancel, &w->progress, &total);
        w->total = total;
        uint64_t tok = process_token(g_pid);
        int same_proc = 0;
        ChainSet result = {0};
        if (w->has_cs && w->cs.n > 0) {
            if (w->cs.token != 0 && w->cs.token == tok) {
                same_proc = 1;
            } else {
                chainset_intersect(&w->cs, &fresh, &result);
                result.token = tok;
                free(w->cs.c);
                w->cs = result;
                free(fresh.c);
                fresh.c = NULL;
            }
        } else {
            result = fresh;
            memset(&fresh, 0, sizeof fresh);
            result.type = w->s.type;
            snprintf(result.module, sizeof result.module, "%s", g_profile.module_name);
            result.scans = 1;
            result.token = tok;
            free(w->cs.c);
            w->cs = result;
        }
        w->has_cs = 1;
        int save_ok = watches_save() == 0;
        if (!save_ok)
            snprintf(w->status, sizeof w->status, "SAVE FAILED: %.40s", watches_path());
        else if (same_proc)
            snprintf(w->status, sizeof w->status, "no new scan; restart game [saved]");
        else
            snprintf(w->status, sizeof w->status, "chain: %u (%u scan%s) [saved]",
                     w->cs.n, w->cs.scans, w->cs.scans == 1 ? "" : "s");
        free(fresh.c);
        if (chain_is_stable(&w->cs))
            watch_bind_chain(w);
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
    w->s.type = strcmp(ts, "int") == 0 ? T_INT : g_profile.type;
    w->s.min = g_profile.min;
    w->s.max = g_profile.max;
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

/* after load: bind the chain if verified, else report status */
static void watch_autoload_chain(Watch *w)
{
    if (!w->has_cs)
        return;
    if (!chain_is_stable(&w->cs)) {
        if (w->cs.n == 0)
            snprintf(w->status, sizeof w->status, "chain: 0 cand");
        else
            snprintf(w->status, sizeof w->status,
                     "chain: %u cand (unverified: press C or V)", w->cs.n);
        return;
    }
    watch_bind_chain(w);
}

/* 'V': prune candidate chains by the current value, no address scan needed */
static void tui_verify_chain(Watch *w)
{
    if (w->scanning)
        return;
    if (!w->has_cs || w->cs.n == 0) {
        snprintf(w->status, sizeof w->status, "no chains");
        return;
    }
    char v[32];
    if (!tui_prompt("current value: ", v, sizeof v) || !v[0])
        return;
    uint64_t tok = process_token(g_pid);
    int same = w->cs.token != 0 && w->cs.token == tok;
    uint32_t before = w->cs.n;
    int r = chain_verify(&w->cs, g_pid, atof(v));
    if (r < 0) {
        snprintf(w->status, sizeof w->status, "verify failed");
        return;
    }
    if (!same) {
        w->cs.verifies++;
        w->cs.token = tok;
    }
    if (w->cs.n > 0) {
        watches_save();
        snprintf(w->status, sizeof w->status, "verify: %u -> %u (%u verify%s)%s",
                 before, w->cs.n, w->cs.verifies, w->cs.verifies == 1 ? "" : "s",
                 same ? " same-proc" : "");
        if (!same && chain_is_stable(&w->cs))
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
    watch_start(w, SCAN_CHAIN, 0, 0);
}

static void tui_load_chain(Watch *w)
{
    if (w->scanning)
        return;
    if (!w->has_cs || w->cs.n == 0) {
        snprintf(w->status, sizeof w->status, "no chains");
        return;
    }
    watch_bind_chain(w);
}

static int watches_save(void)
{
    WatchEntry *arr = calloc(g_nw ? (size_t)g_nw : 1, sizeof(WatchEntry));
    if (!arr)
        return -1;
    for (int i = 0; i < g_nw; i++) {
        Watch *w = &g_w[i];
        WatchEntry *e = &arr[i];
        snprintf(e->name, sizeof e->name, "%.23s", w->name);
        e->type = w->s.type;
        e->has_lockval = w->has_lockval;
        e->lock_bits = w->lock_bits;
        e->lock_on = w->lock_on;
        e->has_chain = w->has_cs;
        e->cs = w->cs;   /* shallow: only read while saving */
    }
    int r = entries_save(arr, g_nw);
    free(arr);
    return r;
}

/* import the pre-JSON text watch list (".ds3hp_watches") once */
static int legacy_watches_load(void)
{
    FILE *f = fopen(".ds3hp_watches", "r");
    if (!f)
        return 0;
    char line[256];
    if (!fgets(line, sizeof line, f) || strncmp(line, "DS3HPW1", 7) != 0) {
        fclose(f);
        return 0;
    }
    int cnt = 0;
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
        snprintf(w->status, sizeof w->status, "migrated");
        g_nw++;
        cnt++;
    }
    fclose(f);
    if (cnt)
        fprintf(stderr, "note: imported %d watch(es) from .ds3hp_watches\n", cnt);
    return cnt;
}

static void watches_load(void)
{
    WatchEntry *arr = NULL;
    int n = 0;
    if (entries_load(&arr, &n) != 0)
        return;
    for (int i = 0; i < n && g_nw < MAX_WATCH; i++) {
        WatchEntry *e = &arr[i];
        Watch *w = &g_w[g_nw];
        memset(w, 0, sizeof *w);
        snprintf(w->name, sizeof w->name, "%s", e->name);
        w->s.type = e->type;
        w->s.min = 1.0;
        w->s.max = 10000.0;
        w->has_lockval = e->has_lockval;
        w->lock_bits = e->lock_bits;
        w->lock_on = e->lock_on;
        if (e->has_chain) {
            w->cs = e->cs;
            w->has_cs = 1;
            e->cs.c = NULL;   /* ownership transferred to the watch */
        }
        snprintf(w->status, sizeof w->status, "restored");
        g_nw++;
    }
    entries_free(arr, n);
    if (g_nw == 0 && legacy_watches_load() > 0)
        watches_save();
}

/* after restart: bind verified chains, report the rest */
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

static void tui_chains(Watch *w)
{
    if (!w->has_cs || w->cs.n == 0) {
        snprintf(w->status, sizeof w->status, "no chains");
        return;
    }
    uint32_t n = w->cs.n;
    uint64_t *addrs = malloc((n ? n : 1) * sizeof(uint64_t));
    uint32_t *vals = malloc((n ? n : 1) * sizeof(uint32_t));
    uint8_t *ok = malloc(n ? n : 1);
    CMap *m = NULL;
    size_t nm = 0;
    uint64_t modbase = 0;
    if (cmaps_read(g_pid, &m, &nm) == 0)
        modbase = chain_module_base(m, nm, w->cs.module);
    for (uint32_t i = 0; i < n; i++) {
        addrs[i] = 0;
        ok[i] = 0;
        if (modbase && chain_resolve(g_pid, m, nm, modbase, &w->cs.c[i], &addrs[i])) {
            int o;
            vals[i] = read_at(addrs[i], &o);
            ok[i] = o;
        }
    }
    free(m);
    if (!addrs || !vals || !ok) {
        free(addrs);
        free(vals);
        free(ok);
        return;
    }

    size_t sel = 0, top = 0;
    for (;;) {
        if (g_stop)
            break;
        erase();
        int rows, cols;
        getmaxyx(stdscr, rows, cols);
        (void)cols;
        attron(A_BOLD);
        mvprintw(0, 0, "chains: %s (%u candidate%s, ranked)", w->name, n,
                 n == 1 ? "" : "s");
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
            if (idx >= n)
                break;
            char b[256];
            chain_format(&w->cs.c[idx], w->cs.module, b, sizeof b);
            if (ok[idx])
                mvprintw(2 + i, 0, "[%zu] %-40.40s @0x%llx = %g", idx, b,
                         (unsigned long long)addrs[idx],
                         bits_to_val(w->cs.type, vals[idx]));
            else
                mvprintw(2 + i, 0, "[%zu] %-40.40s (unresolved)", idx, b);
            if (idx == sel)
                mvchgat(2 + i, 0, -1, A_REVERSE, 0, NULL);
        }
        mvprintw(rows - 1, 0, "j/k move  PgUp/PgDn  Enter=bind selected  q=back");
        refresh();
        int ch = getch();
        if (ch == ERR)
            continue;
        switch (ch) {
        case 'q':
        case 27:
            goto done;
        case 'j':
        case KEY_DOWN:
            if (sel + 1 < n)
                sel++;
            break;
        case 'k':
        case KEY_UP:
            if (sel)
                sel--;
            break;
        case KEY_NPAGE:
            sel += listrows;
            if (sel >= n)
                sel = n ? n - 1 : 0;
            break;
        case KEY_PPAGE:
            sel = sel > (size_t)listrows ? sel - listrows : 0;
            break;
        case '\n':
        case '\r':
        case KEY_ENTER:
            if (ok[sel]) {
                w->addr = addrs[sel];
                w->has_addr = 1;
                if (!w->has_lockval) {
                    w->lock_bits = vals[sel];
                    w->has_lockval = 1;
                }
                snprintf(w->status, sizeof w->status, "bound [%zu] 0x%llx", sel,
                         (unsigned long long)w->addr);
            } else {
                snprintf(w->status, sizeof w->status, "[%zu] unresolved", sel);
            }
            goto done;
        }
    }
done:
    free(addrs);
    free(vals);
    free(ok);
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
        if (!ok) {
            /* address no longer maps; drop it and stop writing the lock value */
            w->has_addr = 0;
            w->lock_on = 0;
            snprintf(w->status, sizeof w->status, "address lost; unlocked");
        }
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

static void tui_hline(int row, int innerw, const char *l, const char *r)
{
    move(row, 0);
    addstr(l);
    for (int j = 0; j < innerw; j++)
        addstr("─");
    addstr(r);
}

static void tui_trow(int row, const char *const *cells, int ncols, const int *w)
{
    move(row, 0);
    addstr("│");
    for (int k = 0; k < ncols; k++) {
        printw("%-*.*s", w[k], w[k], cells[k]);
        if (k < ncols - 1)
            addstr(" ");
    }
    addstr("│");
}

static void tui_draw(void)
{
    erase();
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    (void)cols;
    attron(A_BOLD);
    if (now_ms() < g_notice_until)
        mvprintw(0, 0, "cheat-tool tui [%s]   pid=%d   %d watch(es)   [%s]", g_profile.id, g_pid, g_nw, g_notice);
    else
        mvprintw(0, 0, "cheat-tool tui [%s]   pid=%d   %d watch(es)", g_profile.id, g_pid, g_nw);
    attroff(A_BOLD);

    int cw[8] = { 8, 5, 16, 10, 3, 10, 7, 0 };
    int statusw = cols - 69;
    if (statusw < 6)
        statusw = 6;
    cw[7] = statusw;
    int innerw = 0;
    for (int k = 0; k < 8; k++)
        innerw += cw[k] + (k < 7 ? 1 : 0);
    const char *hdr[8] = { "NAME", "TYPE", "ADDR", "VALUE", "LCK", "LOCKVAL", "CHAIN", "STATUS" };
    tui_hline(1, innerw, "╭", "╮");
    tui_trow(2, hdr, 8, cw);
    tui_hline(3, innerw, "├", "┤");
    int datarows = (rows - 6) - 4 + 1;
    if (datarows < 0)
        datarows = 0;
    for (int i = 0; i < g_nw && i < datarows; i++) {
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
        const char *cells[8] = {
            w->name, w->s.type == T_FLOAT ? "float" : "int", addr, val,
            w->has_addr && w->lock_on ? (w->has_lockval ? "ON" : "?") : "off", lv, chn, st
        };
        tui_trow(4 + i, cells, 8, cw);
        if (i == g_cur)
            mvchgat(4 + i, 1, innerw, A_REVERSE, 0, NULL);
    }
    const char *empty[8] = { "", "", "", "", "", "", "", "" };
    for (int i = g_nw; i < datarows; i++)
        tui_trow(4 + i, empty, 8, cw);
    if (g_nw == 0 && datarows > 0)
        mvprintw(4, 2, "(press 'a' to add a watch)");
    tui_hline(rows - 5, innerw, "╰", "╯");
    mvprintw(rows - 4, 0, "addr : a add  x del  f first  d/i dec/inc  c/u changed/unchanged  e eq  Enter cand  r reset");
    mvprintw(rows - 3, 0, "value: v lockval  s once  l hold");
    mvprintw(rows - 2, 0, "chain: C scan/intersect  V verify  L list  G load/bind");
    mvprintw(rows - 1, 0, "misc : j/k move  p pid  q quit");
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
        if (p) {
            g_pid = p;
            for (int i = 0; i < g_nw; i++)
                g_w[i].has_addr = 0;
            watches_autoresolve();
            set_notice("pid updated");
        }
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
    case 'L':
        if (g_nw)
            tui_chains(&g_w[g_cur]);
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
    if (pid_override && !pid_ok(pid_override)) {
        fprintf(stderr, "error: pid %d does not match profile '%s'\n", pid_override, g_profile.id);
        exit(1);
    }
    if (!g_pid)
        fprintf(stderr, "warning: game process not found; press 'p' to re-detect\n");
    watches_load();
    watches_autoresolve();
    setlocale(LC_ALL, "");
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
    long long last_pidcheck = 0;
    while (!g_stop) {
        long long now = now_ms();
        if (!pid_ok(g_pid) && now - last_pidcheck >= 500) {
            last_pidcheck = now;
            int p = detect_pid();
            if (p && p != g_pid) {
                g_pid = p;
                for (int i = 0; i < g_nw; i++)
                    g_w[i].has_addr = 0;   /* addresses are stale in the new process */
                watches_autoresolve();
                set_notice("reconnected to new pid");
            }
        }
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
    }
    watches_save();
    for (int i = 0; i < g_nw; i++) {
        free(g_w[i].s.c);
        free(g_w[i].cs.c);
    }
    endwin();
    printf("bye\n");
}

/* ========================== end TUI ========================== */

static void usage(const char *prog)
{
    printf("usage: %s [--game ID] <command> [options]\n\n", prog);
    printf("  --game ID                 select game profile (default: darksouls3)\n");
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
    printf("  chain scan   <watch> --addr 0xADDR [--depth N] [--max-offset M] [--module S] [--pid P] [--type float|int] [--reset]\n");
    printf("        scan for restart-stable pointer chains; re-run after a restart to intersect\n");
    printf("  chain list   [<watch>] [--pid P]  list watches, or one watch's chains\n");
    printf("  chain resolve <watch> [--index K] [--value V] [--pid P]   resolve a chain\n");
    printf("  chain verify <watch> --value V [--pid P]        keep chains whose value == V\n");
    printf("  chain load   <watch> [--index K] [--value V]    resolve and load as current target\n");
    printf("  chain clear  <watch>      remove the watch's chain\n");
    printf("  chain rm     <watch>      remove the watch entirely\n");
    printf("  watches are stored in %s\n", watches_path());
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
    profiles_load();
    const char *game_id = "darksouls3";
    int cmd_index = 1;
    if (cmd_index < argc && strcmp(argv[cmd_index], "--game") == 0) {
        if (cmd_index + 1 >= argc) {
            fprintf(stderr, "error: --game requires an id\n");
            return 1;
        }
        game_id = argv[cmd_index + 1];
        cmd_index += 2;
    }
    GameProfile *selected = profile_find(game_id);
    if (!selected) {
        fprintf(stderr, "error: unknown game profile '%s'\n", game_id);
        return 1;
    }
    g_profile = *selected;
    state_path_init();
    if (cmd_index >= argc) {
        usage(argv[0]);
        return 1;
    }
    const char *cmd = argv[cmd_index];
    if (strcmp(cmd, "tui") == 0)
        cmd_tui(argc - cmd_index - 1, argv + cmd_index + 1);
    else if (strcmp(cmd, "first") == 0)
        cmd_first(argc - cmd_index - 1, argv + cmd_index + 1);
    else if (strcmp(cmd, "next") == 0)
        cmd_next(argc - cmd_index - 1, argv + cmd_index + 1);
    else if (strcmp(cmd, "list") == 0)
        cmd_list(argc - cmd_index - 1, argv + cmd_index + 1);
    else if (strcmp(cmd, "peek") == 0)
        cmd_peek(argc - cmd_index - 1, argv + cmd_index + 1);
    else if (strcmp(cmd, "lock") == 0)
        cmd_lock(argc - cmd_index - 1, argv + cmd_index + 1);
    else if (strcmp(cmd, "set") == 0)
        cmd_set(argc - cmd_index - 1, argv + cmd_index + 1);
    else if (strcmp(cmd, "chain") == 0)
        cmd_chain(argc - cmd_index - 1, argv + cmd_index + 1);
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
