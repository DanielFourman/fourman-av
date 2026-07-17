/*
 * scanner.c  --  Minimal signature-based file scanner (engine)
 *
 * Loads a set of known-bad SHA-256 hashes (MalwareBazaar "recent.csv" export
 * from abuse.ch), walks a target folder, hashes every file, and moves any
 * file whose SHA-256 matches a known-bad hash into a quarantine folder.
 *
 * It is designed to be driven by the Python GUI: it prints simple, one-line,
 * machine-readable records to stdout (flushed immediately) so the GUI can
 * update a progress bar and a live log.
 *
 * Output protocol (one record per line):
 *   TOTAL <n>                 -> total files that will be scanned
 *   HASHES <n>                -> number of signatures loaded
 *   SCAN <path>               -> currently scanning this file
 *   PROGRESS <i>              -> i files processed so far
 *   CLEAN <path>              -> file is clean
 *   DETECT <path>|<sha256>    -> MATCH; file identified as malicious
 *   QUARANTINE <newpath>      -> detected file was moved here
 *   ERROR <message>           -> non-fatal problem
 *   DONE <scanned> <detected> -> scan finished
 *
 * Usage:
 *   scanner.exe <hashdb.csv> <scan_folder> <quarantine_folder>
 *
 * Build (MinGW-w64):  gcc -O2 -o scanner.exe scanner.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/stat.h>
#include <dirent.h>
#ifdef _WIN32
#include <direct.h>
#endif

/* ----------------------------------------------------------------------------
 * SHA-256 (public-domain style implementation)
 * -------------------------------------------------------------------------- */

typedef struct {
    uint8_t  data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

#define ROTR(a,b) (((a) >> (b)) | ((a) << (32 - (b))))
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)  (ROTR(x,2)  ^ ROTR(x,13) ^ ROTR(x,22))
#define EP1(x)  (ROTR(x,6)  ^ ROTR(x,11) ^ ROTR(x,25))
#define SIG0(x) (ROTR(x,7)  ^ ROTR(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | (data[j+3]);
    for (; i < 64; ++i)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen  = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += (uint64_t)ctx->datalen * 8;
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0xff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0xff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0xff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xff;
    }
}

/* Compute lowercase hex SHA-256 of a file. Returns 0 on success. */
static int sha256_file(const char *path, char out_hex[65]) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    SHA256_CTX ctx;
    sha256_init(&ctx);

    static uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        sha256_update(&ctx, buf, n);

    if (ferror(f)) { fclose(f); return -1; }
    fclose(f);

    uint8_t digest[32];
    sha256_final(&ctx, digest);

    static const char hexch[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        out_hex[i * 2]     = hexch[digest[i] >> 4];
        out_hex[i * 2 + 1] = hexch[digest[i] & 0x0f];
    }
    out_hex[64] = '\0';
    return 0;
}

/* ----------------------------------------------------------------------------
 * Signature database: sorted array of 64-char hex strings + binary search
 * -------------------------------------------------------------------------- */

typedef char Hash[65];

typedef struct {
    Hash   *items;
    size_t  count;
    size_t  cap;
} HashDB;

static int hash_cmp(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

static void db_add(HashDB *db, const char *hex) {
    if (db->count == db->cap) {
        db->cap = db->cap ? db->cap * 2 : 1024;
        db->items = realloc(db->items, db->cap * sizeof(Hash));
        if (!db->items) { fprintf(stderr, "out of memory\n"); exit(2); }
    }
    strncpy(db->items[db->count], hex, 64);
    db->items[db->count][64] = '\0';
    db->count++;
}

static int db_contains(const HashDB *db, const char *hex) {
    return bsearch(hex, db->items, db->count, sizeof(Hash), hash_cmp) != NULL;
}

/*
 * Load SHA-256 hashes from a MalwareBazaar CSV export.
 *
 * The abuse.ch "recent.csv" format is comment lines starting with '#', then
 * quoted rows where the 2nd column is the sha256_hash, e.g.:
 *   "2021-01-01 00:00:00","<sha256>","<md5>","<sha1>",...
 *
 * To be robust we also accept a plain-text file with one hash per line, and
 * we scan every field of every row for anything that looks like a 64-char
 * hex string (a SHA-256).
 */
static void db_load_csv(HashDB *db, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        printf("ERROR could not open hash database: %s\n", path);
        fflush(stdout);
        return;
    }

    char line[8192];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#') continue;          /* comment / header */

        /* Walk the line looking for runs of exactly-64 hex chars. */
        size_t i = 0, len = strlen(line);
        while (i < len) {
            if (isxdigit((unsigned char)line[i])) {
                size_t start = i;
                while (i < len && isxdigit((unsigned char)line[i])) i++;
                size_t run = i - start;
                if (run == 64) {
                    char hex[65];
                    for (size_t j = 0; j < 64; ++j)
                        hex[j] = (char)tolower((unsigned char)line[start + j]);
                    hex[64] = '\0';
                    db_add(db, hex);
                }
            } else {
                i++;
            }
        }
    }
    fclose(f);

    qsort(db->items, db->count, sizeof(Hash), hash_cmp);

    /* de-duplicate (in place) */
    size_t w = 0;
    for (size_t r = 0; r < db->count; ++r) {
        if (w == 0 || strcmp(db->items[r], db->items[w - 1]) != 0) {
            if (w != r) {
                strncpy(db->items[w], db->items[r], 64);
                db->items[w][64] = '\0';
            }
            w++;
        }
    }
    db->count = w;
}

/* ----------------------------------------------------------------------------
 * Filesystem walk
 * -------------------------------------------------------------------------- */

static int is_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return (st.st_mode & S_IFDIR) != 0;
}

/* True if `path` is inside (or equal to) `base` -- used to skip quarantine. */
static int path_is_within(const char *path, const char *base) {
    size_t bl = strlen(base);
    if (bl == 0) return 0;
#ifdef _WIN32
    if (_strnicmp(path, base, bl) != 0) return 0;
#else
    if (strncmp(path, base, bl) != 0) return 0;
#endif
    return path[bl] == '\0' || path[bl] == '/' || path[bl] == '\\';
}

/* Recursively count regular files, skipping the quarantine folder. */
static long count_files(const char *dir, const char *quarantine) {
    DIR *d = opendir(dir);
    if (!d) return 0;

    long total = 0;
    struct dirent *e;
    char child[4096];

    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        snprintf(child, sizeof(child), "%s\\%s", dir, e->d_name);

        if (is_dir(child)) {
            if (path_is_within(child, quarantine)) continue;
            total += count_files(child, quarantine);
        } else {
            total += 1;
        }
    }
    closedir(d);
    return total;
}

/* Move a detected file into quarantine. Returns 0 on success. */
static int quarantine_file(const char *src, const char *hash,
                           const char *quarantine, char *dst, size_t dstlen) {
    /* base name */
    const char *base = src;
    for (const char *p = src; *p; ++p)
        if (*p == '\\' || *p == '/') base = p + 1;

    /* prefix with first 12 hash chars to avoid collisions */
    char shorth[13];
    strncpy(shorth, hash, 12);
    shorth[12] = '\0';
    snprintf(dst, dstlen, "%s\\%s__%s.quarantine", quarantine, shorth, base);

    /* Try a fast rename first (same volume). */
    if (rename(src, dst) == 0) return 0;

    /* Fallback: copy then delete (handles cross-volume moves). */
    FILE *in = fopen(src, "rb");
    if (!in) return -1;
    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); return -1; }

    static uint8_t buf[65536];
    size_t n;
    int ok = 1;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) { ok = 0; break; }
    }
    fclose(in);
    fclose(out);

    if (!ok) { remove(dst); return -1; }
    if (remove(src) != 0) return -1;   /* copied but couldn't delete original */
    return 0;
}

/* ----------------------------------------------------------------------------
 * Scan
 * -------------------------------------------------------------------------- */

typedef struct {
    const HashDB *db;
    const char   *quarantine;
    long          scanned;
    long          detected;
} ScanState;

static void scan_dir(const char *dir, ScanState *st) {
    DIR *d = opendir(dir);
    if (!d) {
        printf("ERROR cannot open folder: %s\n", dir);
        fflush(stdout);
        return;
    }

    struct dirent *e;
    char child[4096];

    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        snprintf(child, sizeof(child), "%s\\%s", dir, e->d_name);

        if (is_dir(child)) {
            if (path_is_within(child, st->quarantine)) continue;
            scan_dir(child, st);
            continue;
        }

        printf("SCAN %s\n", child);
        fflush(stdout);

        char hex[65];
        if (sha256_file(child, hex) != 0) {
            printf("ERROR could not read file: %s\n", child);
        } else if (db_contains(st->db, hex)) {
            st->detected++;
            printf("DETECT %s|%s\n", child, hex);
            char dst[4096];
            if (quarantine_file(child, hex, st->quarantine, dst, sizeof(dst)) == 0)
                printf("QUARANTINE %s\n", dst);
            else
                printf("ERROR could not quarantine: %s\n", child);
        } else {
            printf("CLEAN %s\n", child);
        }

        st->scanned++;
        printf("PROGRESS %ld\n", st->scanned);
        fflush(stdout);
    }
    closedir(d);
}

/* ----------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------- */

int main(int argc, char **argv) {
    /* line-buffer stdout so the GUI sees records immediately */
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < 4) {
        fprintf(stderr,
            "Usage: %s <hashdb.csv> <scan_folder> <quarantine_folder>\n", argv[0]);
        return 1;
    }

    const char *dbpath     = argv[1];
    const char *scandir    = argv[2];
    const char *quarantine = argv[3];

    /* ensure quarantine folder exists */
#ifdef _WIN32
    _mkdir(quarantine);
#else
    mkdir(quarantine, 0700);
#endif

    HashDB db = {0};
    db_load_csv(&db, dbpath);
    printf("HASHES %zu\n", db.count);
    fflush(stdout);

    if (db.count == 0) {
        printf("ERROR no signatures loaded -- update the database first\n");
        printf("DONE 0 0\n");
        fflush(stdout);
        return 1;
    }

    if (!is_dir(scandir)) {
        printf("ERROR scan target is not a folder: %s\n", scandir);
        printf("DONE 0 0\n");
        fflush(stdout);
        return 1;
    }

    long total = count_files(scandir, quarantine);
    printf("TOTAL %ld\n", total);
    fflush(stdout);

    ScanState st = { .db = &db, .quarantine = quarantine, .scanned = 0, .detected = 0 };
    scan_dir(scandir, &st);

    printf("DONE %ld %ld\n", st.scanned, st.detected);
    fflush(stdout);

    free(db.items);
    return 0;
}
