/* CPUID feature detection; every fast path is gated on these. */
#include "edgeclip.h"

#include <cpuid.h>

void cpu_detect(struct cpu_features *f)
{
    unsigned int eax, ebx, ecx, edx;

    f->aesni = f->sse41 = f->sha = f->rdrand = f->rdseed = 0;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        f->sse41 = (ecx >> 19) & 1;
        f->aesni = (ecx >> 25) & 1;
        f->rdrand = (ecx >> 30) & 1;
    }
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        f->rdseed = (ebx >> 18) & 1;
        f->sha = (ebx >> 29) & 1;
    }
}
