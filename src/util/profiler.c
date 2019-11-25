#include "profiler.h"
#if CFG_PROFILER_ENABLED == 1 /* otherwise skip compilation */

#define CFG_UNIT_PREFIX 'u'   // m = millisecond; u = microsecond


#ifdef Arduino_h
extern myprintf(char *fmt, ... );

unsigned int systime(void){
    #if CFG_UNIT_PREFIX == 'm'
    return millis();
    #elif CFG_UNIT_PREFIX == 'u'
    return micros();
    #endif
}
#else
#include <stdio.h>
#include <sys/time.h>

#define myprintf printf

unsigned long systime(void){
    struct timeval  tv;
    gettimeofday(&tv, 0);

    #if CFG_UNIT_PREFIX=='m'
    unsigned long time_in_mill = (tv.tv_sec) * 1000L + (tv.tv_usec) / 1000;
    return time_in_mill;
    #elif CFG_UNIT_PREFIX=='u'
    unsigned long time_in_usec = (tv.tv_sec) * 1000000L + (tv.tv_usec);
    return time_in_usec;
    #endif
}

#endif


Profiler_Time_Type PROFILER_time(profile_s* profile){
    return systime() - profile->t_start;
}


void PROFILER_start(profile_s* profile){
    profile->t_start = systime();
}

void PROFILER_stop(profile_s* profile){
    Profiler_Time_Type dt = systime() - profile->t_start; // arduino
    profile->t_total += dt;

    if(dt > profile->t_max){ profile->t_max = dt; }
    if(dt < profile->t_min){ profile->t_min = dt; }
    if(profile->samples == 0) profile->t_avg = dt; // initial value
    profile->samples++;
    profile->t_avg = profile->t_avg * ((PROF_AVG_WINDOW-1.0)/PROF_AVG_WINDOW) + (float)(dt)/PROF_AVG_WINDOW;
}

void PROFILER_reset(profile_s* profile){
    profile->samples = 0;
    profile->t_min = 1000000000;  // fits 32 bit signed
    profile->t_avg = 0;
    profile->t_max = 0;
    profile->t_total = 0;
}

void PROFILER_print(char* name, profile_s* profile){
    if (profile->samples == 0) myprintf("TIME_PROFILE %s: No samples!", name);
    Profiler_Time_Type t_avg = profile->t_total / profile->samples;
	myprintf("TIME_PROFILE %s: calls=%d, min,avg,max=%ld < %ld < %ld us, total: %ld us\n", \
        name, profile->samples, profile->t_min, t_avg, profile->t_max, profile->t_total);
}

#endif