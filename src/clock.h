#ifndef __CLOCK_H__
#define __CLOCK_H__

#include <stdint.h>
#include <stdio.h>

#define MAX_FUNC_CNT 	100

int func_cnt;
char* func_name[MAX_FUNC_CNT];
uint64_t time_mem[MAX_FUNC_CNT][2];
uint64_t total_time[MAX_FUNC_CNT];

inline uint64_t cpu_tsc()
{
	uint64_t time;
	uint32_t* p = (uint32_t*)&time;
	
	asm volatile("rdtsc" : "=a"(p[0]), "=d"(p[1]));

	return time;
}

inline void CLOCK_RECORD_START()
{
	func_cnt = 0;
}

inline void CLOCK_RECORD_END()
{
	int i;
	
	for(i = 0; i < func_cnt; i++)
		total_time[func_cnt] += (time_mem[func_cnt][0] - time_mem[func_cnt][1]);
}

inline void CLOCK_START(char* func)
{
	time_mem[func_cnt][0] = cpu_tsc();

	func_name[func_cnt] = func;
}

inline void CLOCK_END(char* func)
{
	time_mem[func_cnt][1] = cpu_tsc();

	func_cnt++;
}

inline void PRINT_TIME()
{
	int i;
	
	printf("=== Time consumed by each function ===\n");

	for(i = 0; i < func_cnt; i++)
		printf("%10s : %lld\n", func_name[func_cnt], total_time[func_cnt]);


}

#endif /* __CLOCK_H__ */
