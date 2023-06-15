#include <bolos_target.h>
#include <inttypes.h>
#include <stddef.h>

void cx_rng_no_throw(uint8_t *buffer, size_t len);

unsigned char *cx_rng(uint8_t *buffer, size_t len)
{
    cx_rng_no_throw(buffer, len);
    return buffer;
}
