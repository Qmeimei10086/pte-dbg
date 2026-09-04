#include "inline_hook.h"

KIRQL wp_bit_off() {
    auto irql = KeRaiseIrqlToDpcLevel();
    UINT64 Cr0 = __readcr0();
    Cr0 &= 0xfffffffffffeffff;
    __writecr0(Cr0);
    _disable();
    return irql;
}

void wp_bit_on(KIRQL irql) {
    UINT64 Cr0 = __readcr0();
    Cr0 |= 0x10000;
    __writecr0(Cr0);
    _enable();
    KeLowerIrql(irql);
}
