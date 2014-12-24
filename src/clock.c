#include "clock.h"

extern inline uint64_t cpu_tsc();
extern inline void CLOCK_RECORD_START();
extern inline void CLOCK_RECORD_END();
extern inline void CLOCK_START(char*);
extern inline void CLOCK_END(char*);

