// system includes (<> searches only include paths)
#include <stdio.h>
#include <stdlib.h>

// own includes
#include "../hash.h"
#include "../util/logger.h"
#include "../util/profiler.h"



int main(){
	LOG_setLevel(LOG_LVL_DEBUG);
	LOG_setLogFile("./main.log");

	const int VECTOR_NUM = 2; 
	char* testvectors[2] = { "", "abc" };
	hash_t output[32];
	profile_s prof_hash;


	printf("\nRunning Testvectors\n");
	printf("=====================================================\n\n");


	for(int i = 0; i < VECTOR_NUM; i++){
		LOG_info("Testvector: \"%s\":", testvectors[i]);

		HASH_config(HASH_SHA2_256);
		HASH_hash(output, (unsigned char*)testvectors[i], strlen(testvectors[i]) );
		LOG_info("SHA-256  : %s -> %s", testvectors[i], HASH_hexstr( output) );   // e3b0c442... and 

		HASH_config(HASH_SHAKE_128);
		HASH_hash(output, (unsigned char*)testvectors[i], strlen(testvectors[i]) );
		LOG_info("SHAKE-128: %s -> %s", testvectors[i], HASH_hexstr( output) );


		HASH_config(HASH_BLAKE2B_256);
		HASH_hash(output, (unsigned char*)testvectors[i], strlen(testvectors[i]) );
		LOG_info("Blake 256: %s -> %s\n", testvectors[i], HASH_hexstr( output) );  // 10ebb6770... and  bddd813c6

	}



	printf("\nRunning Performance Test\n");
	printf("=====================================================\n\n");


	int rounds = 1000;
	printf("Calibrating Profiler over %d calls:\n", rounds);
	PROFILER_reset( &prof_hash);
	for(int i = 0; i < rounds; i++){
		PROFILER_start( &prof_hash);
		PROFILER_stop( &prof_hash);
	}
	PROFILER_print( "Calibration", &prof_hash);


	printf("Profiling each hash function over %d calls:\n\n", rounds);

	// SHA-256
	PROFILER_reset( &prof_hash);
	HASH_config(HASH_SHA2_256);

	for(int i = 0; i < rounds; i++){
		PROFILER_start( &prof_hash);
		HASH_hash(output, output, 32);
		PROFILER_stop( &prof_hash);
	}
	PROFILER_print( "SHA256", &prof_hash);

	// SHAKE-256
	PROFILER_reset( &prof_hash);
	HASH_config(HASH_SHAKE_128);

	for(int i = 0; i < rounds; i++){
		PROFILER_start( &prof_hash);
		HASH_hash(output, output, 32);
		PROFILER_stop( &prof_hash);
	}
	PROFILER_print( "SHAKE128", &prof_hash);


	// BLAKE2B_256
	PROFILER_reset( &prof_hash);
	HASH_config(HASH_BLAKE2B_256);

	for(int i = 0; i < rounds; i++){
		PROFILER_start( &prof_hash);
		HASH_hash(output, output, 32);
		PROFILER_stop( &prof_hash);
	}
	PROFILER_print( "BLAKE2B_256", &prof_hash);

}

