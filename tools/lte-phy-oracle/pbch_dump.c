/* Oracle driver: runs srsRAN_4G release_23_11's own PBCH transmitter.
 *
 * srsran_pbch_encode() (lib/src/phy/phch/pbch.c) does the whole chain:
 *   srsran_crc_attach      -> 40 bits  (TS 36.212 5.3.1.1)
 *   srsran_crc_set_mask                (Table 5.3.1.1-1, row nof_ports-1)
 *   srsran_convcoder_encode -> 120     (tail biting, 5.3.1.2)
 *   srsran_rm_conv_tx      -> 1920     (5.3.1.3, four frames in one buffer)
 *   srsran_scrambling_b_offset         (6.6.1, 480-bit slice of the period)
 *   srsran_mod_modulate + layermap/precoding + srsran_pbch_put (6.6.4)
 * q->data, q->data_enc and q->rm_b are struct fields, so every stage is
 * observable. Only this driver is ours. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <complex.h>
#include "srsran/phy/phch/pbch.h"
#include "srsran/phy/common/phy_common.h"

#define NSLOTRE (7 * 6 * 12)          /* SRSRAN_SLOT_LEN_RE(6, SRSRAN_CP_NORM) */
#define NRE_SF  (2 * NSLOTRE)
static cf_t  grid[SRSRAN_MAX_PORTS][NRE_SF];
static cf_t* gridp[SRSRAN_MAX_PORTS];

static void bits(const char* tag, const uint8_t* b, int n)
{
    printf("%s ", tag);
    for (int i = 0; i < n; i++) putchar(b[i] ? '1' : '0');
    putchar('\n');
}

int main(void)
{
    static const uint32_t cids[] = {0, 1, 2, 42, 503};
    static const uint32_t portsv[] = {1, 2, 4};
    uint8_t mib[5][24];

    for (int i = 0; i < 24; i++) mib[0][i] = 0;
    for (int i = 0; i < 24; i++) mib[1][i] = 1;
    for (int i = 0; i < 24; i++) mib[2][i] = (i * 7 + 3) % 2;
    for (int i = 0; i < 24; i++) mib[3][i] = i % 2;
    for (int i = 0; i < 24; i++) mib[4][i] = (i / 3) % 2;

    for (unsigned ci = 0; ci < sizeof(cids) / sizeof(cids[0]); ci++) {
        for (unsigned pi = 0; pi < 3; pi++) {
            for (int mi = 0; mi < 5; mi++) {
                srsran_cell_t cell;
                memset(&cell, 0, sizeof cell);
                cell.nof_prb         = 6;
                cell.nof_ports       = portsv[pi];
                cell.id              = cids[ci];
                cell.cp              = SRSRAN_CP_NORM;
                cell.phich_length    = SRSRAN_PHICH_NORM;
                cell.phich_resources = SRSRAN_PHICH_R_1;
                cell.frame_type      = SRSRAN_FDD;

                for (int f = 0; f < 4; f++) {
                    srsran_pbch_t q;
                    uint8_t       payload[SRSRAN_BCH_PAYLOAD_LEN];
                    char          tag[160];

                    memset(&q, 0, sizeof q);
                    memcpy(payload, mib[mi], SRSRAN_BCH_PAYLOAD_LEN);
                    if (srsran_pbch_init(&q)) { fprintf(stderr, "init fail\n"); return 1; }
                    if (srsran_pbch_set_cell(&q, cell)) { fprintf(stderr, "set_cell fail\n"); return 1; }
                    for (int i = 0; i < SRSRAN_MAX_PORTS; i++) {
                        gridp[i] = grid[i];
                        memset(grid[i], 0, sizeof grid[i]);
                    }
                    if (srsran_pbch_encode(&q, payload, gridp, f)) { fprintf(stderr, "encode fail\n"); return 1; }

                    if (f == 0) {
                        snprintf(tag, sizeof tag, "MIBIN_%u_%u_%d", cids[ci], portsv[pi], mi);
                        bits(tag, mib[mi], 24);
                        snprintf(tag, sizeof tag, "PAYLOAD40_%u_%u_%d", cids[ci], portsv[pi], mi);
                        bits(tag, q.data, SRSRAN_BCH_PAYLOADCRC_LEN);
                        snprintf(tag, sizeof tag, "ENC120_%u_%u_%d", cids[ci], portsv[pi], mi);
                        bits(tag, q.data_enc, SRSRAN_BCH_ENCODED_LEN);
                        snprintf(tag, sizeof tag, "RAW1920TAIL_%u_%u_%d", cids[ci], portsv[pi], mi);
                        bits(tag, &q.rm_b[480], 1920 - 480);
                        for (int pp = 0; pp < (int)cell.nof_ports; pp++) {
                            snprintf(tag, sizeof tag, "RE_%u_%u_%d_P%d",
                                     cids[ci], portsv[pi], mi, pp);
                            printf("%s", tag);
                            for (int s = 0; s < 7; s++)
                                for (int k = 0; k < 72; k++) {
                                    cf_t v = grid[pp][NSLOTRE + s * 72 + k];
                                    if (crealf(v) != 0.0f || cimagf(v) != 0.0f)
                                        printf(" %d:%d", s, k);
                                }
                            printf("\n");
                        }
                    }
                    snprintf(tag, sizeof tag, "SCRAM_%u_%u_%d_F%d", cids[ci], portsv[pi], mi, f);
                    bits(tag, &q.rm_b[f * 480], 480);
                    srsran_pbch_free(&q);
                }
            }
        }
    }
    return 0;
}
