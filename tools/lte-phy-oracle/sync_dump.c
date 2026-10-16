/* Oracle driver: runs srsRAN_4G release_23_11's own PSS/SSS generators.
 * Source functions: lib/src/phy/sync/pss.c:srsran_pss_generate() and
 * lib/src/phy/sync/gen_sss.c:srsran_sss_generate(). Compiled unmodified from
 * the upstream tarball; only this driver is ours. */
#include <stdio.h>
#include <stdint.h>
#include <complex.h>
#include "srsran/phy/sync/pss.h"
#include "srsran/phy/sync/sss.h"

extern void srsran_sss_generate(float* signal0, float* signal5, uint32_t cell_id);

int main(void)
{
    cf_t  pss[62];
    float s0[62], s5[62];
    int   n2, cid, i;

    for (n2 = 0; n2 < 3; n2++) {
        srsran_pss_generate(pss, n2);
        printf("PSS %d", n2);
        for (i = 0; i < 62; i++) printf(" %.9g %.9g", (double)crealf(pss[i]), (double)cimagf(pss[i]));
        printf("\n");
    }
    for (cid = 0; cid < 504; cid++) {
        srsran_sss_generate(s0, s5, cid);
        printf("SSS %d", cid);
        for (i = 0; i < 62; i++) printf(" %.9g", (double)s0[i]);
        for (i = 0; i < 62; i++) printf(" %.9g", (double)s5[i]);
        printf("\n");
    }
    return 0;
}
