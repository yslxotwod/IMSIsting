/* Oracle driver: runs srsRAN_4G release_23_11's own reference-signal
 * generators and dumps every reference resource element of one subframe.
 * Source functions: lib/src/phy/ch_estimation/refsignal_dl.c --
 * srsran_refsignal_cs_set_cell(), srsran_refsignal_cs_put_sf(),
 * srsran_refsignal_mbsfn_gen_seq() and srsran_refsignal_mbsfn_put_sf().
 * Compiled unmodified from the upstream tarball; only this driver is ours.
 *
 * Two decisions worth recording, because they decide whether the dump is
 * evidence or a restatement:
 *
 *  - The values are read back out of a ZEROED subframe buffer after put_sf(),
 *    not out of srsRAN's internal pilots array. The buffer is what an eNB
 *    hands to the OFDM modulator, so the dump carries the frequency mapping
 *    (k = 6m + (v + v_shift) mod 6) as well as the sequence. Reading the
 *    pilots array would test the sequence while assuming the mapping.
 *  - Every subframe of the radio frame is dumped, not just subframe 0. The
 *    v of CRS ports 2 and 3 is 3*(n_s mod 2) -- a function of the SLOT -- so
 *    a dump of one subframe cannot tell a correct implementation from one
 *    that hard-codes either staggering.
 *
 * Output, one line per RE:
 *   CRS   <n_rb> <cell_id> <cp> <sf> <port> <l> <k> <re> <im>
 *   MBSFN <n_rb> <area_id> <cp> <sf> <l> <k> <re> <im>
 * with l the OFDM symbol within the SUBFRAME.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <complex.h>
#include "srsran/phy/ch_estimation/refsignal_dl.h"
#include "srsran/phy/common/phy_common.h"

#define MAX_RE (2 * SRSRAN_CP_NORM_NSYMB * SRSRAN_MAX_PRB * SRSRAN_NRE)

static cf_t buf[MAX_RE];
static cf_t zero[MAX_RE * 24];

static const uint32_t PRBS[] = {6, 15, 25, 50, 75, 100, 110};
static const uint32_t CIDS[] = {0, 1, 2, 3, 4, 5, 6, 42, 503};
static const uint32_t SFS[] = {0, 1, 2, 9};
static const uint16_t AREAS[] = {0, 1, 7, 255};

static void cell_set(srsran_cell_t* cell, uint32_t nof_prb, uint32_t id, srsran_cp_t cp)
{
    memset(cell, 0, sizeof(*cell));
    cell->nof_prb         = nof_prb;
    cell->nof_ports       = 4;
    cell->id              = id;
    cell->cp              = cp;
    cell->phich_length    = SRSRAN_PHICH_NORM;
    cell->phich_resources = SRSRAN_PHICH_R_1;
    cell->frame_type      = SRSRAN_FDD;
    if (!srsran_cell_isvalid(cell)) {
        fprintf(stderr, "invalid cell: n_rb=%u id=%u cp=%d\n", nof_prb, id, (int)cp);
        exit(2);
    }
}

/* Dumps the nonzero REs of the buffer: a QPSK reference symbol is never
 * zero, so "nonzero" is exactly the set of REs put_sf wrote. */
static void dump_buf(const char* tag, uint32_t n_rb, uint32_t ident, srsran_cp_t cp,
                     uint32_t sf, int port, uint32_t only_l0, uint32_t only_l1)
{
    uint32_t nsymb = SRSRAN_CP_NSYMB(cp) * 2;
    for (uint32_t l = 0; l < nsymb; l++) {
        if (only_l1 && (l < only_l0 || l > only_l1)) continue;
        for (uint32_t k = 0; k < n_rb * SRSRAN_NRE; k++) {
            cf_t v = buf[SRSRAN_RE_IDX(n_rb, l, k)];
            if (crealf(v) == 0.0f && cimagf(v) == 0.0f) continue;
            if (port < 0) {
                printf("%s %u %u %d %u %u %u %.9g %.9g\n", tag, n_rb, ident, (int)cp, sf, l, k,
                       (double)crealf(v), (double)cimagf(v));
            } else {
                printf("%s %u %u %d %u %d %u %u %.9g %.9g\n", tag, n_rb, ident, (int)cp, sf, port, l, k,
                       (double)crealf(v), (double)cimagf(v));
            }
        }
    }
}

int main(void)
{
    srsran_cell_t     cell;
    srsran_refsignal_t csr, mbsfn;
    srsran_dl_sf_cfg_t sf_cfg;
    size_t             n;

    for (size_t ip = 0; ip < sizeof(PRBS) / sizeof(PRBS[0]); ip++) {
        uint32_t nof_prb = PRBS[ip];
        for (size_t ic = 0; ic < sizeof(CIDS) / sizeof(CIDS[0]); ic++) {
            for (int cp = 0; cp <= 1; cp++) {
                cell_set(&cell, nof_prb, CIDS[ic], (srsran_cp_t)cp);
                memset(&csr, 0, sizeof(csr));
                if (srsran_refsignal_cs_init(&csr, SRSRAN_MAX_PRB)) { fprintf(stderr, "cs_init\n"); return 2; }
                if (srsran_refsignal_cs_set_cell(&csr, cell)) { fprintf(stderr, "cs_set_cell\n"); return 2; }
                for (size_t is = 0; is < sizeof(SFS) / sizeof(SFS[0]); is++) {
                    memset(&sf_cfg, 0, sizeof(sf_cfg));
                    sf_cfg.cfi     = 1;
                    sf_cfg.sf_type = SRSRAN_SF_NORM;
                    sf_cfg.tti     = SFS[is];
                    for (int port = 0; port < 4; port++) {
                        n = (size_t)nof_prb * SRSRAN_NRE * SRSRAN_CP_NSYMB((srsran_cp_t)cp) * 2;
                        memset(buf, 0, n * sizeof(cf_t));
                        if (srsran_refsignal_cs_put_sf(&csr, &sf_cfg, (uint32_t)port, buf)) {
                            fprintf(stderr, "cs_put_sf\n");
                            return 2;
                        }
                        dump_buf("CRS", nof_prb, CIDS[ic], (srsran_cp_t)cp, SFS[is], port, 0, 0);
                    }
                }
                srsran_refsignal_free(&csr);
            }
        }
    }

    /* MBSFN reference signals, TS 36.211 6.10.2: port 4, extended cyclic
     * prefix only. put_sf() also writes the cell-specific references of the
     * non-MBSFN region from the cs_pilots argument, so a zeroed cs_pilots
     * array leaves only the MBSFN symbols (2, 6 and 10) in the buffer. */
    for (size_t ip = 0; ip < sizeof(PRBS) / sizeof(PRBS[0]); ip++) {
        uint32_t nof_prb = PRBS[ip];
        for (size_t ia = 0; ia < sizeof(AREAS) / sizeof(AREAS[0]); ia++) {
            cell_set(&cell, nof_prb, 0, SRSRAN_CP_EXT);
            memset(&mbsfn, 0, sizeof(mbsfn));
            if (srsran_refsignal_mbsfn_init(&mbsfn, SRSRAN_MAX_PRB)) { fprintf(stderr, "mbsfn_init\n"); return 2; }
            if (srsran_refsignal_mbsfn_set_cell(&mbsfn, cell, AREAS[ia])) { fprintf(stderr, "mbsfn_set_cell\n"); return 2; }
            for (size_t is = 0; is < sizeof(SFS) / sizeof(SFS[0]); is++) {
                n = (size_t)nof_prb * SRSRAN_NRE * SRSRAN_CP_NSYMB(SRSRAN_CP_EXT) * 2;
                memset(buf, 0, n * sizeof(cf_t));
                if (srsran_refsignal_mbsfn_put_sf(cell, 0, zero, mbsfn.pilots[0][SFS[is]], buf)) {
                    fprintf(stderr, "mbsfn_put_sf\n");
                    return 2;
                }
                /* 2, 6 and 10 are the MBSFN symbols of a 12-symbol subframe. */
                for (uint32_t l = 0; l < 12; l++) {
                    if (l != 2 && l != 6 && l != 10) continue;
                    for (uint32_t k = 0; k < nof_prb * SRSRAN_NRE; k++) {
                        cf_t v = buf[SRSRAN_RE_IDX(nof_prb, l, k)];
                        if (crealf(v) == 0.0f && cimagf(v) == 0.0f) continue;
                        printf("MBSFN %u %u %d %u %u %u %.9g %.9g\n", nof_prb, AREAS[ia], (int)SRSRAN_CP_EXT,
                               SFS[is], l, k, (double)crealf(v), (double)cimagf(v));
                    }
                }
            }
            srsran_refsignal_free(&mbsfn);
        }
    }

    /* Ports 0 and 1 share pilots[0], ports 2 and 3 share pilots[1]; the count
     * of reference symbols per subframe is stated by the standard (4 and 2)
     * and is dumped here so a reader can see the two port groups differ. */
    printf("PORTSYMS %u %u\n", srsran_refsignal_cs_nof_pilots_x_slot(2),
           srsran_refsignal_cs_nof_pilots_x_slot(4));
    return 0;
}
