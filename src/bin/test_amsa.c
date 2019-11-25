// system includes (<> searches only include paths)
#include <stdint.h>
#include <string.h>
#include <stdio.h>

// own includes
#include "../hash.h"
#include "../wots.h"
#include "../merkle.h"
#include "../amss.h"
#include "../util/logger.h"
#include "../util/profiler.h"
#include "../util/cli.h"


void average_amss(const AMSA_Config config){

	AMSA_Amss amss = AMSA_Amss_init( config );
	AMSA_Sig   sig = AMSA_Sig_init( config );
	AMSA_Pubkey pubkey;
	byte_t seed[AMSA_SEED_SIZE] = { 'x' };
	HASH_config( config.cfg_wots.cfg_hash );


	// generate test digest
	unsigned char avg_hash[ config.cfg_wots.cfg_hash.size ];
	unsigned c1 = 0xAA;
	unsigned c2 = 0x55;
	if (config.cfg_wots.code_base ==  16) { c1 = 0x88; c2 = 0x77; }
	if (config.cfg_wots.code_base == 256) { c1 = 0x88; c2 = 0x77; }
	memset(avg_hash, c1, config.cfg_wots.cfg_hash.size);
	memset(avg_hash+config.cfg_wots.cfg_hash.size/2, c2, config.cfg_wots.cfg_hash.size/2);


	printf("\n\n.:: Testing AMSA\n"); 
	printf("=====================================================\n");
	HASH_reset_stats();

	printf("Signing the average hash 0x8888888.... \n");
	AMSA_generate( &amss, seed, &pubkey);
	printf("=> gen:    "); HASH_print_stats(); HASH_reset_stats();

	AMSA_sign(&amss, avg_hash, &sig);
	printf("=> sign:   "); HASH_print_stats(); HASH_reset_stats();

	AMSA_verify(&pubkey, avg_hash, &sig);
	printf("=> verify: "); HASH_print_stats(); HASH_reset_stats();
	printf("\n");

	CLI_print_amss( &amss );
	// clean up
	AMSA_Amss_free( &amss );
	AMSA_Sig_free( &sig );
}




void benchmark_amss(const AMSA_Config config, unsigned rounds){

	AMSA_Amss amss = AMSA_Amss_init( config );
	AMSA_Sig   sig = AMSA_Sig_init( config );
	AMSA_Pubkey pubkey;

	byte_t seed[AMSA_SEED_SIZE] = { 'x' };
	hash_t msg_digest[config.cfg_wots.cfg_hash.size];
	HASH_config( config.cfg_wots.cfg_hash );

	// profiling
	profile_s prof_gen;
	profile_s prof_sign;
	profile_s prof_verify;
	PROFILER_reset(&prof_gen);
	PROFILER_reset(&prof_sign);
	PROFILER_reset(&prof_verify);


	printf("\n\nBenchmark AMSA-H%d-%s test:\n", config.cfg_tree.height, "SHA256");
	printf("=====================================================\n");

	// benchmark generating
	for (int idx = 0; idx < rounds; idx++){
		PROFILER_start( &prof_gen);
		AMSA_generate( &amss, seed, &pubkey);
		PROFILER_stop( &prof_gen);
	}


	CLI_print_amss( &amss );

	// benchmark signing and verification
	HASH_reset_stats();
	bool succ;
	for (int idx = 0; idx < (1 << amss.tree.config.height); idx++){
		HASH_hash(msg_digest, (unsigned char*)&idx, 4);  // message

		PROFILER_start( &prof_sign);
		AMSA_sign(&amss, msg_digest, &sig);
		PROFILER_stop( &prof_sign);


		PROFILER_start( &prof_verify);
		succ = AMSA_verify(&pubkey, msg_digest, &sig);
		PROFILER_stop( &prof_verify);
		if (succ == false) LOG_error("Signature invalid!");

	}	

	printf("\nStatistics:\n================\n");
	printf(" => gen+sign ");HASH_print_stats();
	PROFILER_print("AMSA_Generate", &prof_gen);
	PROFILER_print("AMSA_Sign", &prof_sign);
	PROFILER_print("AMSA_Verify", &prof_verify);

	// clean up
	AMSA_Amss_free( &amss );
	AMSA_Sig_free( &sig );
}



// ============================================================================
// public function implementations
// ============================================================================
int main(){
	LOG_setLevel(LOG_LVL_INFO);
	LOG_setLogFile("./test_amsa.log");
	HASH_reset_stats();

	//AMSA_Config cfg = AMSA_BLAKE2B_128_W256_H4;
	//AMSA_Config cfg = AMSA_BLAKE2B_160_H10;
	//AMSA_Config cfg = AMSA_SHA256_H4;
	AMSA_Config cfg = AMSA_SHA256_H10;
	average_amss(cfg);

	benchmark_amss(cfg, 1);

	return 0;
}