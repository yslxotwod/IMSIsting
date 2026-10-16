/**
 * pdsch_dump.c -- srsRAN oracle dump for the LTE downlink shared channel
 * transmit chain (TS 36.212 5.1/5.2/5.3 and TS 36.211 6.3/6.4).
 *
 * This file is OURS (MIT, like the rest of the tree). It is compiled against
 * an unmodified srsRAN 4G release 23.11 tree fetched into a temporary
 * directory outside the repository, so srsRAN stays a build-time oracle and
 * its AGPL source is never vendored here.
 *
 * What is driven, and why at this level rather than through the top:
 *
 *   srsran_dlsch_encode2()  gives the rate-matched codeword BEFORE the PDSCH
 *                           scrambler touches it, so the code block
 *                           segmentation, the turbo coding and the E_r split
 *                           are compared on their own. srsran_pdsch_encode()
 *                           scrambles in place, so the pre-scramble bits are
 *                           not recoverable afterwards.
 *   srsran_pdsch_encode()   the whole chain: scrambling, modulation, layer
 *                           mapping, precoding, RE mapping. Its output grid is
 *                           dumped as the REs it CHANGED, with the buffer
 *                           pre-filled with a sentinel, so a PDSCH symbol that
 *                           happens to be exactly zero is still counted.
 *   srsran_ra_dl_compute_nof_re()  the grant's own RE count and symbol lengths,
 *                           which is what makes the comparison of the PDSCH RE
 *                           set independent: neither side takes its grant
 *                           arithmetic from the other.
 *
 * The transport block is generated here with a plain LCG (not with srsRAN's
 * random generator) and dumped as a bit string, so the Python side compares
 * against the exact bits the oracle was fed and no generator has to be
 * reproduced.
 *
 * Both slots of a subframe get the same PRB set: a per-slot hopping pattern is
 * expressible in a DCI but not in the model under test, and a dump that used
 * one would be comparing two different allocations.
 *
 * Three things this driver is careful about, all of them places where a
 * dump that looks fine is not evidence:
 *
 *   * srsran_rm_turbo_tx() fills its circular buffer ONLY when rv_idx == 0
 *     (fec/turbo/rm_turbo.c, "calling this function with rv_idx!=0 without
 *     having called it first with rv_idx=0 will produce unwanted results"),
 *     and srsran_softbuffer_tx_reset() ZEROES the buffer rather than marking
 *     it empty. A lone rv!=0 encode therefore dumps a stream of zeros and
 *     compares the rate matcher under test against nothing, so an rv=0
 *     transmission of the same code blocks is primed first -- exactly what
 *     srsRAN's own fec/turbo/test/rm_turbo_test.c does.
 *   * q->x is written by srsran_pdsch_encode() only in the branch
 *     `nof_ports > 1 && nof_layers != nof_tb` (phch/pdsch.c); in the other
 *     branches x[] is either aliased onto q->d or never touched, and q->x
 *     comes from srsran_vec_cf_malloc(), i.e. it is uninitialised. Those X
 *     lines are not dumped, because a comparator handed heap contents is
 *     comparing against nothing.
 *   * the RE-availability sweep at the bottom drives the same configurations
 *     as the selftest's pdsch-re-digest through srsRAN's own mapper, so that
 *     the digest the selftest freezes is derived from the oracle and not
 *     from the implementation under test.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <complex.h>

#include "srsran/phy/phch/pdsch.h"
#include "srsran/phy/phch/ra_dl.h"
#include "srsran/phy/fec/crc.h"
#include "srsran/phy/fec/softbuffer.h"
#include "srsran/phy/utils/bit.h"
#include "srsran/phy/utils/vector.h"

#define MAX_CASES 64
#define MAX_DUMP_BITS (400000)

/* srsRAN's per-PRB RE accounting for one slot, from phch/ra_dl.c. Declared
 * here rather than included: it has no public header, and using the oracle's
 * own function is the whole point of dumping it. */
extern uint32_t ra_re_x_prb(const srsran_cell_t* cell, srsran_dl_sf_cfg_t* sf, uint32_t slot, uint32_t prb_idx);

typedef struct {
  int         n_rb;
  int         cell_id;
  int         sf;
  int         cfi;
  int         ports;
  int         layers;
  int         tbs;
  int         rv;
  int         rnti;
  int         ext_cp;
  int         tdd_cfg; /* -1 = FDD */
  int         partial; /* 1 = a scattered PRB allocation */
  srsran_mod_t mod;
  const char* mod_name;
} tcase_t;

/* TBS values are chosen so that TS 36.212 5.1.2 produces no filler bits
 * (F = 0): srsRAN 23.11 refuses F != 0 ("Error filler bits are not
 * supported. Use standard TBS"), and a transport block size it will not
 * encode cannot be compared against it. The 6136/12256/50000 entries are the
 * interesting ones: C > 1 with K1 != K2, i.e. the cases where the ORDER of the
 * code blocks and the E_r split both matter, and 12256 has C2 = 2 (two short
 * blocks first) while 50000 has C = 9, C1 = 2, C2 = 7. */
static const tcase_t cases[] = {
    {6, 0, 0, 1, 1, 1, 1000, 0, 0xFFFF, 0, -1, 0, SRSRAN_MOD_QPSK, "qpsk"},
    {6, 0, 0, 1, 1, 1, 1000, 0, 0xFFFF, 0, -1, 0, SRSRAN_MOD_16QAM, "16qam"},
    {6, 0, 0, 1, 1, 1, 1000, 0, 0xFFFF, 0, -1, 0, SRSRAN_MOD_64QAM, "64qam"},
    {6, 0, 0, 1, 1, 1, 16, 0, 0x0001, 0, -1, 0, SRSRAN_MOD_QPSK, "qpsk"},
    {25, 0, 0, 1, 1, 1, 1000, 0, 0xFFFF, 0, -1, 0, SRSRAN_MOD_QPSK, "qpsk"},
    {25, 0, 0, 1, 1, 1, 1000, 1, 0xFFFF, 0, -1, 0, SRSRAN_MOD_QPSK, "qpsk"},
    {25, 0, 0, 1, 1, 1, 1000, 2, 0xFFFF, 0, -1, 0, SRSRAN_MOD_QPSK, "qpsk"},
    {25, 0, 0, 1, 1, 1, 1000, 3, 0xFFFF, 0, -1, 0, SRSRAN_MOD_QPSK, "qpsk"},
    {25, 0, 0, 1, 1, 1, 6120, 0, 0xFFFF, 0, -1, 0, SRSRAN_MOD_16QAM, "16qam"},
    {25, 0, 2, 1, 1, 1, 1000, 0, 0x3C3C, 0, -1, 0, SRSRAN_MOD_QPSK, "qpsk"},
    {50, 0, 0, 1, 1, 1, 6136, 0, 0xFFFF, 0, -1, 0, SRSRAN_MOD_64QAM, "64qam"},
    {100, 0, 0, 1, 1, 1, 12256, 0, 0xFFFF, 0, -1, 0, SRSRAN_MOD_64QAM, "64qam"},
    {100, 0, 0, 1, 1, 1, 50000, 0, 0xFFFF, 0, -1, 0, SRSRAN_MOD_64QAM, "64qam"},
    {15, 0, 0, 1, 2, 2, 1000, 0, 0xFFFF, 0, -1, 0, SRSRAN_MOD_QPSK, "qpsk"},
    {15, 0, 0, 1, 4, 4, 1000, 0, 0xFFFF, 0, -1, 0, SRSRAN_MOD_QPSK, "qpsk"},
    {25, 3, 0, 1, 2, 2, 6120, 2, 0xFFFF, 0, -1, 0, SRSRAN_MOD_16QAM, "16qam"},
    {25, 5, 0, 1, 4, 4, 6136, 0, 0x1234, 0, -1, 0, SRSRAN_MOD_64QAM, "64qam"},
    {6, 1, 0, 2, 1, 1, 1000, 0, 0xFFFF, 0, -1, 0, SRSRAN_MOD_QPSK, "qpsk"},
    {6, 2, 1, 2, 2, 2, 1000, 0, 0xFFFF, 0, -1, 0, SRSRAN_MOD_16QAM, "16qam"},
    {6, 503, 5, 1, 1, 1, 1000, 0, 0xFFFF, 0, -1, 0, SRSRAN_MOD_QPSK, "qpsk"},
    {6, 0, 0, 3, 1, 1, 1000, 0, 0xFFFF, 0, -1, 0, SRSRAN_MOD_QPSK, "qpsk"},
    {25, 0, 0, 1, 1, 1, 1000, 0, 0xFFFF, 1, -1, 0, SRSRAN_MOD_QPSK, "qpsk"},
    {25, 4, 0, 1, 2, 2, 1000, 0, 0xFFFF, 0, -1, 1, SRSRAN_MOD_QPSK, "qpsk"},
    {25, 0, 0, 1, 1, 1, 1000, 0, 0xFFFF, 0, 1, 0, SRSRAN_MOD_QPSK, "qpsk"},
    {25, 0, 5, 1, 2, 2, 1000, 0, 0xFFFF, 0, 1, 0, SRSRAN_MOD_QPSK, "qpsk"},
};

static uint32_t rng_state;

static int next_bit(void)
{
  rng_state = rng_state * 1103515245u + 12345u;
  return (int)((rng_state >> 16) & 1u);
}

static void print_bits(const char* tag, const uint8_t* packed, int nof_bits)
{
  uint8_t* b = (uint8_t*)malloc(nof_bits ? nof_bits : 1);
  if (!b) {
    fprintf(stderr, "out of memory\n");
    exit(2);
  }
  /* Unpack with srsRAN's own helper rather than by hand: the bit order of a
   * packed array is srsRAN's convention, not ours to assume. */
  srsran_bit_unpack_vector((void*)packed, b, nof_bits);
  printf("%s ", tag);
  for (int i = 0; i < nof_bits; i++) {
    putchar('0' + (b[i] & 1));
  }
  putchar('\n');
  free(b);
}

static void print_cf(const char* tag, const cf_t* v, int n)
{
  printf("%s", tag);
  for (int i = 0; i < n; i++) {
    printf(" %.9g %.9g", crealf(v[i]), cimagf(v[i]));
  }
  putchar('\n');
}

static void set_cell(srsran_cell_t* cell, const tcase_t* c)
{
  memset(cell, 0, sizeof(*cell));
  cell->nof_prb          = c->n_rb;
  cell->nof_ports        = c->ports;
  cell->id               = c->cell_id;
  cell->cp               = c->ext_cp ? SRSRAN_CP_EXT : SRSRAN_CP_NORM;
  cell->phich_length     = SRSRAN_PHICH_NORM;
  cell->phich_resources  = SRSRAN_PHICH_R_1;
  cell->frame_type       = (c->tdd_cfg >= 0) ? SRSRAN_TDD : SRSRAN_FDD;
  if (!srsran_cell_isvalid(cell)) {
    fprintf(stderr, "invalid cell\n");
    exit(2);
  }
}

/* Prime the transmit soft buffer with the rv=0 transmission of the same code
 * blocks, so that the redundancy version asked for is read out of the
 * circular buffer srsRAN actually filled instead of out of the zeros
 * srsran_softbuffer_tx_reset() leaves behind. Does nothing when rv == 0,
 * which is the call that fills the buffer in the first place. */
static int prime_softbuffer(srsran_sch_t*          sch,
                            srsran_pdsch_cfg_t*    cfg,
                            uint8_t*               data,
                            uint8_t*               scratch,
                            uint32_t               nof_layers)
{
  uint32_t saved = cfg->grant.tb[0].rv;
  int      ret   = 0;
  if (saved != 0) {
    cfg->grant.tb[0].rv = 0;
    ret = srsran_dlsch_encode2(sch, cfg, data, scratch, 0, nof_layers);
    cfg->grant.tb[0].rv = saved;
  }
  return ret;
}

static int run_case(int idx)
{
  const tcase_t* c = &cases[idx];
  srsran_cell_t  cell;
  srsran_dl_sf_cfg_t sf;
  srsran_pdsch_cfg_t cfg;
  srsran_pdsch_t  q;
  srsran_crc_t    crc;
  srsran_softbuffer_tx_t* sb;
  srsran_mod_t    mod = c->mod;
  int             ret = 0;
  int             prb_set[SRSRAN_MAX_PRB];
  int             nof_prb_alloc = 0;
  uint8_t*        bits          = NULL;
  uint8_t*        data          = NULL;
  uint8_t*        e             = NULL;
  uint8_t*        data_ptrs[SRSRAN_MAX_CODEWORDS];
  cf_t*           grid[SRSRAN_MAX_PORTS];
  const cf_t      sentinel = 1234.5f + 6789.25f * I;
  int             nof_re_total;

  set_cell(&cell, c);
  memset(&sf, 0, sizeof(sf));
  sf.tti               = c->sf;
  sf.cfi               = c->cfi;
  sf.sf_type           = SRSRAN_SF_NORM;
  sf.non_mbsfn_region  = 1;
  if (c->tdd_cfg >= 0) {
    sf.tdd_config.sf_config  = c->tdd_cfg;
    sf.tdd_config.ss_config  = 0;
    sf.tdd_config.configured = true;
  }

  /* The PRB set, identical in both slots. A scattered set exercises the
   * per-PRB RE accounting; a contiguous one only exercises its sum. */
  for (int j = 0; j < c->n_rb; j++) {
    prb_set[j] = c->partial ? ((j % 3) == 0 || (j % 7) == 1) : 1;
    nof_prb_alloc += prb_set[j];
  }

  memset(&cfg, 0, sizeof(cfg));
  cfg.rnti     = (uint16_t)c->rnti;
  cfg.p_a      = 0.0f; /* TS 36.213 5.2: rho_A = 10^(p_a/20) * (ports==1 ? 1 : sqrt2) */
  cfg.p_b      = 0;    /* rho_B = 1, so no per-symbol power scaling */
  cfg.grant.tx_scheme = (c->ports == 1) ? SRSRAN_TXSCHEME_PORT0 : SRSRAN_TXSCHEME_DIVERSITY;
  cfg.grant.pmi       = 0;
  cfg.grant.nof_prb   = c->n_rb;
  cfg.grant.nof_tb    = 1;
  cfg.grant.nof_layers = c->layers;
  for (int s = 0; s < 2; s++) {
    for (int j = 0; j < c->n_rb; j++) {
      cfg.grant.prb_idx[s][j] = prb_set[j];
    }
  }
  cfg.grant.tb[0].enabled = true;
  cfg.grant.tb[0].tbs     = c->tbs;
  cfg.grant.tb[0].mod     = mod;
  cfg.grant.tb[0].rv      = c->rv;
  cfg.grant.tb[0].cw_idx  = 0;

  /* srsRAN's own RE accounting for this grant. */
  srsran_ra_dl_compute_nof_re(&cell, &sf, &cfg.grant);

  printf("CASE %d %d %d %d %d %d %d %d %s %d %d %d %s %d %d\n", idx, c->n_rb, c->cell_id,
         c->sf, c->cfi, c->ports, c->layers, c->tbs, c->mod_name, c->rv, c->rnti, c->ext_cp,
         c->tdd_cfg >= 0 ? "tdd" : "fdd", c->tdd_cfg, nof_prb_alloc);
  printf("GRANT %u %u %u %u\n", cfg.grant.nof_re, cfg.grant.tb[0].nof_bits,
         cfg.grant.nof_symb_slot[0], cfg.grant.nof_symb_slot[1]);
  /* Per-PRB RE counts, straight out of srsRAN's own ra_re_x_prb(). A total
   * can agree while individual PRBs are wrong -- the centre six PRBs of a
   * subframe 0/5 are the ones that carry PSS, SSS and the PBCH, and with an
   * odd N_RB two of them are half-reserved -- so the comparison is done per
   * PRB and per slot, not on the sum. */
  for (int s = 0; s < 2; s++) {
    for (int j = 0; j < c->n_rb; j++) {
      if (cfg.grant.prb_idx[s][j]) {
        printf("PRB %d %d %u\n", s, j, ra_re_x_prb(&cell, &sf, (uint32_t)s, (uint32_t)j));
      }
    }
  }
  fflush(stdout);

  if (cfg.grant.tb[0].nof_bits > MAX_DUMP_BITS) {
    printf("SKIP too-many-bits\n");
    return 0;
  }

  if (srsran_pdsch_init_enb(&q, cell.nof_prb)) {
    fprintf(stderr, "pdsch_init_enb failed\n");
    return 2;
  }
  if (srsran_pdsch_set_cell(&q, cell)) {
    fprintf(stderr, "pdsch_set_cell failed\n");
    return 2;
  }

  sb = (srsran_softbuffer_tx_t*)calloc(1, sizeof(srsran_softbuffer_tx_t));
  if (!sb || srsran_softbuffer_tx_init(sb, cell.nof_prb)) {
    fprintf(stderr, "softbuffer init failed\n");
    return 2;
  }
  cfg.softbuffers.tx[0] = sb;

  if (srsran_crc_init(&crc, SRSRAN_LTE_CRC24A, 24)) {
    fprintf(stderr, "crc init failed\n");
    return 2;
  }

  /* Transport block: generated here, packed with srsRAN's own bit packer,
   * then CRC-attached with srsRAN's own CRC, so the only thing compared is
   * this tree's implementation of the same two steps. */
  bits = (uint8_t*)calloc(1, c->tbs + 8);
  data = (uint8_t*)calloc(1, (c->tbs + 24) / 8 + 8);
  if (!bits || !data) {
    fprintf(stderr, "out of memory\n");
    return 2;
  }
  rng_state = 0x5EED0000u + (uint32_t)idx;
  for (int i = 0; i < c->tbs; i++) {
    bits[i] = (uint8_t)next_bit();
  }
  srsran_bit_pack_vector(bits, data, c->tbs);
  print_bits("TB", data, c->tbs);
  srsran_crc_attach_byte(&crc, data, c->tbs);
  print_bits("TBCRC", data, c->tbs + 24);

  e = (uint8_t*)calloc(1, cfg.grant.tb[0].nof_bits / 8 + 8);
  if (!e) {
    fprintf(stderr, "out of memory\n");
    return 2;
  }

  /* The rate-matched codeword, before the PDSCH scrambler (which pdsch_encode
   * applies IN PLACE to its own q->e buffer, not to ours). For rv != 0 the
   * circular buffer has to hold the rv=0 transmission of these code blocks
   * first -- see prime_softbuffer() -- otherwise srsRAN emits no bits at all
   * and this line would read "000...0" for a correct rate matcher too. */
  srsran_softbuffer_tx_reset(sb);
  if (prime_softbuffer(&q.dl_sch, &cfg, data, e, c->layers)) {
    fprintf(stderr, "priming rv=0 failed\n");
    return 2;
  }
  if (srsran_dlsch_encode2(&q.dl_sch, &cfg, data, e, 0, c->layers)) {
    fprintf(stderr, "dlsch_encode2 failed\n");
    return 2;
  }
  print_bits("E", e, cfg.grant.tb[0].nof_bits);

  nof_re_total = SRSRAN_NOF_RE(cell);
  for (int p = 0; p < SRSRAN_MAX_PORTS; p++) {
    grid[p] = NULL;
  }
  for (int p = 0; p < c->ports; p++) {
    grid[p] = (cf_t*)malloc(sizeof(cf_t) * nof_re_total);
    if (!grid[p]) {
      fprintf(stderr, "out of memory\n");
      return 2;
    }
    for (int i = 0; i < nof_re_total; i++) {
      grid[p][i] = sentinel;
    }
  }
  data_ptrs[0] = data;
  data_ptrs[1] = NULL;

  srsran_softbuffer_tx_reset(sb);
  if (prime_softbuffer(&q.dl_sch, &cfg, data, e, c->layers)) {
    fprintf(stderr, "priming rv=0 failed\n");
    return 2;
  }
  if (srsran_pdsch_encode(&q, &sf, &cfg, data_ptrs, grid)) {
    fprintf(stderr, "pdsch_encode failed\n");
    return 2;
  }

  print_bits("SCR", (uint8_t*)q.e[0], cfg.grant.tb[0].nof_bits);
  print_cf("D", q.d[0], cfg.grant.tb[0].nof_bits / srsran_mod_bits_x_symbol(mod));
  /* srsran_pdsch_encode() writes q->x only when it layer-maps AND precodes
   * (phch/pdsch.c: nof_ports > 1 && nof_layers != nof_tb). With one port it
   * scales q->d[0] straight into q->symbols[0], and with nof_layers == nof_tb
   * it points x[] at q->d instead; in both branches q->x keeps whatever
   * srsran_vec_cf_malloc() handed back, so dumping it would compare the
   * model against uninitialised heap and report failures that mean nothing.
   * The layer mapping is still compared -- for the layers srsRAN does
   * compute, and through q->symbols otherwise. */
  if (q.cell.nof_ports > 1 && c->layers != cfg.grant.nof_tb) {
    /* srsran_layermap_diversity() de-interleaves the modulated sequence: layer
     * l receives every nof_layers-th symbol, so q->x[l] holds
     * len(q->d)/nof_layers symbols and not the whole sequence (the mimo
     * comparison in cmp_mimo.py pins that: 16 in, 2 layers of 8; and 16 in, 4
     * layers of 4).  q->x[l] is max_re long, so printing nsym of it would dump
     * nof_re - nof_re/nof_layers entries of heap past everything srsRAN wrote
     * -- an X line that looks plausible and is half noise.  Print exactly the
     * region the layer mapper filled. */
    int nsym = cfg.grant.tb[0].nof_bits / srsran_mod_bits_x_symbol(mod);
    for (int l = 0; l < c->layers; l++) {
      printf("X %d", l);
      for (int i = 0; i < nsym / c->layers; i++) {
        printf(" %.9g %.9g", crealf(q.x[l][i]), cimagf(q.x[l][i]));
      }
      putchar('\n');
    }
  }
  {
    int nsym = cfg.grant.tb[0].nof_bits / srsran_mod_bits_x_symbol(mod);
    for (int p = 0; p < c->ports; p++) {
      printf("SY %d", p);
      for (int i = 0; i < nsym; i++) {
        printf(" %.9g %.9g", crealf(q.symbols[p][i]), cimagf(q.symbols[p][i]));
      }
      putchar('\n');
    }
  }

  /* The REs pdsch_encode actually wrote, as (symbol, subcarrier, value). The
   * sentinel makes this a change-set, so a symbol that is exactly zero is
   * still reported. */
  for (int p = 0; p < c->ports; p++) {
    for (int i = 0; i < nof_re_total; i++) {
      if (grid[p][i] != sentinel) {
        printf("RE %d %d %d %.9g %.9g\n", p, i / (c->n_rb * SRSRAN_NRE), i % (c->n_rb * SRSRAN_NRE),
               crealf(grid[p][i]), cimagf(grid[p][i]));
      }
    }
  }
  printf("END\n");
  fflush(stdout);

  for (int p = 0; p < c->ports; p++) {
    free(grid[p]);
  }
  free(e);
  free(data);
  free(bits);
  srsran_softbuffer_tx_free(sb);
  free(sb);
  srsran_pdsch_free(&q);
  return ret;
}

/* ---------------------------------------------------------------------------
 * The RE-availability sweep.
 *
 * The selftest of tools/lte_phy.py hashes the PDSCH RE positions it computes
 * over a sweep of 504 configurations. A hash of one's own output is not
 * evidence of anything -- it pins the answer without ever having been
 * checked -- so the same configurations are driven through srsRAN's mapper
 * here and dumped as raw positions. The comparator rebuilds the (symbol,
 * subcarrier) list from this and compares it with tools/lte_phy.py's, and the
 * digest the selftest freezes is the one computed from THESE lines.
 *
 * One line per (slot, symbol): three hex digits per PRB, bit k set when
 * subcarrier k of that PRB was written. Three hex digits and not a list of
 * subcarriers because an odd N_RB gives half a PRB to two of the centre
 * PRBs, so the shape of the reservation has to be visible per subcarrier.
 * A PRB outside the allocation, and a symbol whose whole PRB is reserved
 * (PSS/SSS/PBCH), are both "000" and that is not a distinction the
 * comparison needs: both sides enumerate the same available set.
 * ------------------------------------------------------------------------- */

typedef struct {
  int n_rb;
  int cell_id;
  int sf;
  int cfi;
  int ports;
  int tdd;
  int partial;
} re_sweep_t;

/* One configuration. `q` and `sb` are initialised once by run_sweep() and
 * re-targeted here: srsran_pdsch_init_enb() calls srsran_sch_init(), which
 * builds the turbo decoder's interleavers, the rate-matcher's table and a
 * 190 kB scratch buffer -- measurable, and there is no reason to pay it 504
 * times. The soft buffer is initialised for the widest bandwidth of the
 * sweep, which is the one that sizes it. */
static int re_sweep_entry(srsran_pdsch_t* q, srsran_softbuffer_tx_t* sb, const re_sweep_t* c)
{
  srsran_cell_t           cell;
  srsran_dl_sf_cfg_t      sf;
  srsran_pdsch_cfg_t      cfg;
  uint8_t*                data = NULL;
  uint8_t*                data_ptrs[SRSRAN_MAX_CODEWORDS];
  cf_t*                   grid[SRSRAN_MAX_PORTS];
  const cf_t              sentinel = 1234.5f + 6789.25f * I;
  int                     nof_re_total;
  uint8_t                 spare[1008];

  memset(&cell, 0, sizeof(cell));
  cell.nof_prb         = c->n_rb;
  cell.nof_ports       = c->ports;
  cell.id              = c->cell_id;
  cell.cp              = SRSRAN_CP_NORM;
  cell.phich_length    = SRSRAN_PHICH_NORM;
  cell.phich_resources = SRSRAN_PHICH_R_1;
  cell.frame_type      = c->tdd ? SRSRAN_TDD : SRSRAN_FDD;
  if (!srsran_cell_isvalid(&cell)) {
    fprintf(stderr, "sweep: invalid cell\n");
    return 2;
  }

  memset(&sf, 0, sizeof(sf));
  sf.tti              = c->sf;
  sf.cfi              = c->cfi;
  sf.sf_type          = SRSRAN_SF_NORM;
  sf.non_mbsfn_region = 1;
  if (c->tdd) {
    sf.tdd_config.sf_config  = 1;
    sf.tdd_config.ss_config  = 0;
    sf.tdd_config.configured = true;
  }

  memset(&cfg, 0, sizeof(cfg));
  cfg.rnti             = 0xFFFF;
  cfg.p_a              = 0.0f;
  cfg.p_b              = 0;
  cfg.grant.tx_scheme  = (c->ports == 1) ? SRSRAN_TXSCHEME_PORT0 : SRSRAN_TXSCHEME_DIVERSITY;
  cfg.grant.pmi        = 0;
  cfg.grant.nof_prb    = c->n_rb;
  cfg.grant.nof_tb     = 1;
  cfg.grant.nof_layers = c->ports;
  for (int s = 0; s < 2; s++) {
    for (int j = 0; j < c->n_rb; j++) {
      cfg.grant.prb_idx[s][j] = c->partial ? ((j % 3) == 0) : 1;
    }
  }
  cfg.grant.tb[0].enabled = true;
  cfg.grant.tb[0].tbs     = 1000;
  cfg.grant.tb[0].mod     = SRSRAN_MOD_QPSK;
  cfg.grant.tb[0].rv      = 0;
  cfg.grant.tb[0].cw_idx  = 0;

  srsran_ra_dl_compute_nof_re(&cell, &sf, &cfg.grant);

  /* RECFG <n_rb> <cell_id> <ports> <subframe> <cfi> <tdd> <partial>
   *       <srsRAN's nof_re> <symbols slot 0> <symbols slot 1> */
  printf("RECFG %d %d %d %d %d %d %d %u %u %u\n", c->n_rb, c->cell_id, c->ports, c->sf,
         c->cfi, c->tdd, c->partial, cfg.grant.nof_re, cfg.grant.nof_symb_slot[0],
         cfg.grant.nof_symb_slot[1]);

  if (srsran_pdsch_set_cell(q, cell)) {
    fprintf(stderr, "sweep: pdsch_set_cell failed\n");
    return 2;
  }
  cfg.softbuffers.tx[0] = sb;

  data = (uint8_t*)calloc(1, (1000 + 24) / 8 + 8);
  if (!data) {
    fprintf(stderr, "sweep: out of memory\n");
    return 2;
  }
  rng_state = 0x5EED0000u + (uint32_t)(c->n_rb * 31 + c->cell_id * 7 + c->sf);
  for (int i = 0; i < 1000; i++) {
    spare[i] = (uint8_t)next_bit();
  }
  srsran_bit_pack_vector(spare, data, 1000);

  nof_re_total = SRSRAN_NOF_RE(cell);
  for (int p = 0; p < SRSRAN_MAX_PORTS; p++) {
    grid[p] = NULL;
  }
  for (int p = 0; p < c->ports; p++) {
    grid[p] = (cf_t*)malloc(sizeof(cf_t) * nof_re_total);
    if (!grid[p]) {
      fprintf(stderr, "sweep: out of memory\n");
      return 2;
    }
    for (int i = 0; i < nof_re_total; i++) {
      grid[p][i] = sentinel;
    }
  }
  data_ptrs[0] = data;
  data_ptrs[1] = NULL;

  if (srsran_pdsch_encode(q, &sf, &cfg, data_ptrs, grid)) {
    fprintf(stderr, "sweep: pdsch_encode failed (n_rb %d ports %d sf %d cfi %d tdd %d)\n",
            c->n_rb, c->ports, c->sf, c->cfi, c->tdd);
    return 2;
  }

  /* How many REs each port got. They must all be the same set; the masks
   * below are port 0's. */
  printf("REPORTS");
  for (int p = 0; p < SRSRAN_MAX_PORTS; p++) {
    uint32_t n = 0;
    if (p < c->ports) {
      for (int i = 0; i < nof_re_total; i++) {
        if (grid[p][i] != sentinel) {
          n++;
        }
      }
    }
    printf(" %u", n);
  }
  putchar('\n');

  for (uint32_t s = 0; s < SRSRAN_NOF_SLOTS_PER_SF; s++) {
    for (uint32_t l = 0; l < cfg.grant.nof_symb_slot[s]; l++) {
      uint32_t lp = l + s * cfg.grant.nof_symb_slot[0];
      printf("REMAP %u %u", s, l);
      for (int n = 0; n < c->n_rb; n++) {
        uint32_t mask = 0;
        if (cfg.grant.prb_idx[s][n]) {
          for (int k = 0; k < SRSRAN_NRE; k++) {
            if (grid[0][(lp * c->n_rb + n) * SRSRAN_NRE + k] != sentinel) {
              mask |= 1u << k;
            }
          }
        }
        printf(" %03x", mask);
      }
      putchar('\n');
    }
  }
  fflush(stdout);

  for (int p = 0; p < c->ports; p++) {
    free(grid[p]);
  }
  free(data);
  return 0;
}

/* The sweep, generated rather than tabulated so that it is visibly the same
 * one the selftest walks: every bandwidth a real cell uses, every cell id
 * (the reference-signal shift is cell_id mod 6, plus one above the range to
 * show the modulo), every port count, subframes 0, 1 and 5 (PSS/SSS in 0 and
 * 5, and for TDD the special subframe 1 is deliberately included so that a
 * disagreement about it is reported rather than skipped), and for the
 * narrower bandwidths a scattered allocation and a CFI of 3. */
static int run_sweep(void)
{
  static const int prbs[]  = {6, 15, 25, 50, 100};
  static const int cids[]  = {0, 1, 2, 3, 4, 5, 501};
  static const int ports[] = {1, 2, 4};
  static const int sfs[]   = {0, 1, 5};
  srsran_pdsch_t          q;
  srsran_softbuffer_tx_t* sb;
  int                     ret = 0;

  /* Widest bandwidth of the sweep, so that every narrower configuration
   * fits the buffers pdsch_set_cell() will re-size downwards. */
  if (srsran_pdsch_init_enb(&q, 100)) {
    fprintf(stderr, "sweep: pdsch_init_enb failed\n");
    return 2;
  }
  sb = (srsran_softbuffer_tx_t*)calloc(1, sizeof(srsran_softbuffer_tx_t));
  if (!sb || srsran_softbuffer_tx_init(sb, 100)) {
    fprintf(stderr, "sweep: softbuffer init failed\n");
    return 2;
  }
  for (size_t a = 0; a < sizeof(prbs) / sizeof(prbs[0]); a++) {
    for (size_t b = 0; b < sizeof(cids) / sizeof(cids[0]); b++) {
      for (size_t d = 0; d < sizeof(ports) / sizeof(ports[0]); d++) {
        for (size_t e = 0; e < sizeof(sfs) / sizeof(sfs[0]); e++) {
          re_sweep_t c = {prbs[a], cids[b], sfs[e], 1, ports[d], 0, 0};
          if (re_sweep_entry(&q, sb, &c)) {
            ret = 2;
            goto done;
          }
          if (prbs[a] == 25 || prbs[a] == 15) {
            re_sweep_t p = {prbs[a], cids[b], sfs[e], 3, ports[d], 0, 1};
            if (re_sweep_entry(&q, sb, &p)) {
              ret = 2;
              goto done;
            }
          }
          if (prbs[a] == 25) {
            re_sweep_t t = {prbs[a], cids[b], sfs[e], 1, ports[d], 1, 0};
            if (re_sweep_entry(&q, sb, &t)) {
              ret = 2;
              goto done;
            }
          }
        }
      }
    }
  }
done:
  srsran_softbuffer_tx_free(sb);
  free(sb);
  srsran_pdsch_free(&q);
  return ret;
}

int main(int argc, char** argv)
{
  if (argc > 1 && strcmp(argv[1], "sweep") == 0) {
    return run_sweep();
  }
  int first = 0;
  int last  = (int)(sizeof(cases) / sizeof(cases[0])) - 1;
  bool named = false;
  if (argc > 1) {
    first = atoi(argv[1]);
    last  = first;
    named = true;
  }
  for (int i = first; i <= last; i++) {
    if (run_case(i)) {
      return 2;
    }
  }
  return named ? 0 : run_sweep();
}
