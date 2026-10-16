/* Logging stubs so the srsRAN objects link without the full library.
 * Declarations taken from srsran/phy/utils/debug.h and
 * srsran/phy/utils/phy_logger.h. */
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
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
