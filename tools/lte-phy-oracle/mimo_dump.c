/* Oracle driver: runs srsRAN_4G release_23_11's own layer-mapping and
 * precoding code, compiled unmodified from the upstream tarball.
 * Sources: lib/src/phy/mimo/layermap.c (srsran_layermap_single,
 * srsran_layermap_diversity) and lib/src/phy/mimo/precoding.c
 * (srsran_precoding_single, srsran_precoding_diversity). Only this driver
 * is ours.
 *
 * Chain used, matching the real PDSCH/PBCH call pattern:
 *   codeword d has M symbols; layer mapping to v layers gives M/v symbols per
 *   layer; precoding is then called with nof_symbols = M/v and emits
 *   P*(M/v) = M samples per port for transmit diversity (each port transmits
 *   on every one of the M resource elements).
 */
#include <stdio.h>
#include <stdint.h>
#include <complex.h>
#include "srsran/phy/mimo/layermap.h"
#include "srsran/phy/mimo/precoding.h"

#define M 16
#define MAXOUT (4 * M)

static cf_t d[M];
static cf_t xb[SRSRAN_MAX_LAYERS][M];
static cf_t yb[SRSRAN_MAX_PORTS][MAXOUT];
static cf_t* x[SRSRAN_MAX_LAYERS];
static cf_t* y[SRSRAN_MAX_PORTS];

static void init_d(void)
{
    for (int i = 0; i < M; i++) {
        float re = 0.1f * (float)(i % 17) - 0.8f;
        float im = 0.05f * (float)(i % 13) - 0.3f;
        d[i] = re + im * _Complex_I;
    }
}
static void clear(void)
{
    for (int l = 0; l < SRSRAN_MAX_LAYERS; l++)
        for (int i = 0; i < M; i++) x[l][i] = 0;
    for (int p = 0; p < SRSRAN_MAX_PORTS; p++)
        for (int i = 0; i < MAXOUT; i++) y[p][i] = 0;
}
static void pdump(const char* tag, cf_t* v, int n)
{
    printf("%s", tag);
    for (int i = 0; i < n; i++) printf(" %.9g %.9g", (double)crealf(v[i]), (double)cimagf(v[i]));
    printf("\n");
}

int main(void)
{
    for (int i = 0; i < SRSRAN_MAX_LAYERS; i++) x[i] = xb[i];
    for (int i = 0; i < SRSRAN_MAX_PORTS; i++) y[i] = yb[i];

    init_d();
    pdump("DIN", d, M);

    /* --- 6.3.3.1 layer mapping, one codeword -> one layer ------------- */
    clear();
    srsran_layermap_single(d, x[0], M);
    pdump("LAYERMAP_SINGLE_1", x[0], M);

    /* --- 6.3.3.3 layer mapping, transmit diversity ------------------- */
    for (int nl = 2; nl <= 4; nl *= 2) {
        clear();
        srsran_layermap_diversity(d, x, nl, M);
        for (int l = 0; l < nl; l++) {
            char tag[64];
            snprintf(tag, sizeof tag, "LAYERMAP_DIV_%d_L%d", nl, l);
            pdump(tag, x[l], M / nl);
        }
    }

    /* --- 6.3.4.1 precoding, single antenna port ---------------------- */
    clear();
    srsran_layermap_single(d, x[0], M);
    for (float sc = 0.5f; sc <= 2.0f; sc += 0.5f) {
        char tag[64];
        for (int i = 0; i < MAXOUT; i++) y[0][i] = 0;
        srsran_precoding_single(x[0], y[0], M, sc);
        snprintf(tag, sizeof tag, "PRECODE_SINGLE_sc%.1f", (double)sc);
        pdump(tag, y[0], M);
    }

    /* --- 6.3.4.3 precoding, transmit diversity ----------------------- */
    for (int np = 2; np <= 4; np *= 2) {
        int nsl = M / np;                /* symbols per layer */
        int outlen = np * nsl;           /* == M per port */
        clear();
        srsran_layermap_diversity(d, x, np, M);
        int rc = srsran_precoding_diversity(x, y, np, nsl, 1.0f);
        for (int p = 0; p < np; p++) {
            char tag[96];
            snprintf(tag, sizeof tag, "PRECODE_DIV_%d_P%d_rc%d_nsl%d", np, p, rc, nsl);
            pdump(tag, y[p], outlen);
        }
    }
    return 0;
}
