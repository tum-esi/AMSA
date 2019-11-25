// system includes (<> searches only include paths)
#include <stdint.h>
#include <string.h>
#include <stdio.h>

// own includes
#include "../hash.h"
#include "../wots.h"
#include "../merkle.h"
#include "../amss.h"
#include "../util/cli.h"
#include "../util/logger.h"
#include "../util/profiler.h"


typedef struct {
	profile_s prof_gen; // or just final value?
    int hashcalls_gen;
    int hashcalls_sign;
    int hashcalls_verify;
    int hashdata_gen;
    int hashdata_sign;
    int hashdata_verify;
    int t_gen_us;
    int t_sign_us;
    int t_verify_us;
} Stats_s;


Stats_s G_stats[sizeof(HASH_Algo_t)];


void average_wots(const WOTS_Config config){

	// generate WOTS
	HASH_config(config.cfg_hash);
	WOTS_Wots wots = WOTS_init( &config);
	hash_t seed[CFG_WOTS_SEED_SIZE] = { 'x' };
	key_s hashkey = {0};
	WOTS_chains_t signature[config.cfg_hash.size*(wots.num_chains)];

	// generate test digest
	unsigned char avg_hash[ config.cfg_hash.size ];
	unsigned c1 = 0xAA;
	unsigned c2 = 0x55;
	if (config.code_base ==  16) { c1 = 0x88; c2 = 0x77; }
	if (config.code_base == 256) { c1 = 0x88; c2 = 0x77; }
	memset(avg_hash, c1, config.cfg_hash.size);
	memset(avg_hash+config.cfg_hash.size/2, c2, config.cfg_hash.size/2);

	// get stats

	printf("\n\n.:: Testing 1 avg. "); CLI_print_wots_config( wots.config );
	printf("\n=====================================================\n");
	printf("Statistics for signing %.8s:\n", HASH_hexstr( avg_hash ) ); HASH_reset_stats();

	WOTS_import_seckey( &wots, seed, hashkey);
	WOTS_generate_pubkey( &wots );
	printf(" => gen:    "); HASH_print_stats(); HASH_reset_stats();

	WOTS_sign( &wots, avg_hash, signature);
	printf(" => sign:   "); HASH_print_stats(); HASH_reset_stats();

	WOTS_verify( &wots, avg_hash, signature);
	printf(" => verify: "); HASH_print_stats(); HASH_reset_stats();


}


void benchmark_wots(const WOTS_Config config, unsigned rounds){

	// generate WOTS
	HASH_config(config.cfg_hash);
	WOTS_Wots wots = WOTS_init( &config);
	hash_t seed[CFG_WOTS_SEED_SIZE] = { 'x' };
	key_s hashkey = { "hashkeyshashkeys" };
	WOTS_import_seckey( &wots, seed, hashkey);
	WOTS_generate_pubkey( &wots );
	WOTS_chains_t signature[config.cfg_hash.size*(wots.num_chains)];

	hash_t msg_digest[config.cfg_hash.size];
	memset(msg_digest, 0x88, config.cfg_hash.size);

	// profilers
	profile_s prof_gen;
	profile_s prof_sign;
	profile_s prof_verify;
	PROFILER_reset(&prof_gen);
	PROFILER_reset(&prof_sign);
	PROFILER_reset(&prof_verify);


	printf("\n\n.:: Perofmance Testing of "); CLI_print_wots_params( &wots );
	printf("=====================================================\n");

	bool succ;
	HASH_reset_stats();	
	for(int idx = 0; idx < rounds; idx++){
		HASH_hash( seed, msg_digest, wots.config.cfg_hash.size );

			PROFILER_start( &prof_gen);
		WOTS_import_seckey( &wots, seed, hashkey);
		WOTS_generate_pubkey( &wots );
			PROFILER_stop( &prof_gen);

			PROFILER_start( &prof_sign);
		WOTS_sign( &wots, msg_digest, signature);
			PROFILER_stop( &prof_sign); //HASH_print_stats();
	
			PROFILER_start( &prof_verify);
		succ = WOTS_verify( &wots, msg_digest, signature );
			PROFILER_stop( &prof_verify); //HASH_print_stats();

		if (succ == false) LOG_error("WOTS Signature invalid!");

		HASH_hash( msg_digest, msg_digest, wots.config.cfg_hash.size );
	}

	printf("\n\nStats:\n");
	HASH_print_stats();

	PROFILER_print("WOTS_gen", &prof_gen);
	PROFILER_print("WOTS_sign", &prof_sign);
	PROFILER_print("WOTS_verify", &prof_verify);

}


// ============================================================================
// public function implementations
// ============================================================================
int main(){
	LOG_setLevel(LOG_LVL_DEBUG);
	LOG_setLogFile("./wots_test.log");


	average_wots(WOTS_SHA2_256_W16);

	average_wots(WOTS_BLAKE2B_160_W16);


	const int ROUNDS = 100;
	benchmark_wots(WOTS_SHA2_256_W16, ROUNDS);


	return 0;

}