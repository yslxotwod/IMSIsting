/* Logging stubs so the srsRAN objects link without the full library.
 * Declarations taken from srsran/phy/utils/debug.h and
 * srsran/phy/utils/phy_logger.h. */
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/time.h>
#include "srsran/phy/utils/phy_logger.h"

bool is_handler_registered(void) { return false; }

void srsran_phy_log_print(phy_logger_level_t log_level, const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}


int get_srsran_verbose_level(void) { return 0; }

/* srsran_pdsch_encode() calls this for its optional timing measurement
 * (cfg->meas_time_en, off in the oracle dump). It lives in utils/debug.c,
 * which cannot be linked here -- it defines the logging symbols above and
 * that is a multiple definition, not a stub to be shadowed. srsran_phy_*_log
 * in debug.c uses it for timestamps, and nothing in this dump path does. */
void get_time_interval(struct timeval* tdata)
{
    (void)tdata;
}

