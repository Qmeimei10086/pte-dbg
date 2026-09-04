#pragma once
#include <stdint.h>
#include <intrin.h>
#include <ntifs.h>

// Clear CR0.WP (raise IRQL to DPC level first so no other thread races the
// write). Returns the previous IRQL to be passed back to wp_bit_on().
KIRQL wp_bit_off();

void wp_bit_on(KIRQL irql);
