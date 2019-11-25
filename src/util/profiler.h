/* Simple Profiler 
 * 
 * Authors:     Emanuel Regnath (emanuel.regnath@tum.de)
 *
 * Description:
 * Allows time and call measurments with little overhead. 
 * Can be deactivated to avoid any compilation.
 * Requires <stdio.h> and <time.h>
 */

#ifndef _PROFILER_H
#define _PROFILER_H

// number of samples analyzed for the moving average
#define PROF_AVG_WINDOW 10.0f

#ifndef CFG_PROFILER_ENABLED
#define CFG_PROFILER_ENABLED 1  /* 1: enabled, 0: disable profiling and remove any function call */
#endif

typedef unsigned long Profiler_Time_Type;

typedef struct {
    Profiler_Time_Type t_start;
    Profiler_Time_Type t_min;
    Profiler_Time_Type t_max;
    Profiler_Time_Type t_avg;
    Profiler_Time_Type t_total;
    unsigned int samples;   
} profile_s;

#if CFG_PROFILER_ENABLED == 1

void PROFILER_start(profile_s* profile);

void PROFILER_stop(profile_s* profile);

void PROFILER_reset(profile_s* profile);

Profiler_Time_Type PROFILER_time(profile_s* profile);

void PROFILER_print(char* name, profile_s* profile);

#else
#define PROFILER_start(p)
#define PROFILER_stop(x)
#define PROFILER_reset(x)
#define PROFILER_time(x) (0)
#define PROFILER_print(x, y)
#endif

#endif // _PROFILER_H
