// system includes (<> searches only include paths)
#include <stdint.h>
#include <string.h>
#include <stdio.h>

// own includes
#include "../hash.h"
#include "../wots.h"
#include "../merkle.h"
#include "../util/cli.h"
#include "../util/logger.h"
#include "../util/profiler.h"


typedef struct {
	profile_s prof_gen; // or just final value?
    int hashcalls_add;
    int hashcalls_path;
    int hashcalls_verify;
    int hashdata_add;
    int hashdata_path;
    int hashdata_verify;
    int t_add_us;
    int t_path_us;
    int t_verify_us;
} Stats_s;

Stats_s G_stats[sizeof(HASH_Algo_t)];




void benchmark_merkle(const MT_Config config){

	// generate tree
	HASH_config(config.cfg_hash);
	MT_Tree tree;
	MT_Path path = MT_init_path( &(config) );

	// aux data
	hash_t digest[config.cfg_hash.size];
	hash_t desire[config.cfg_hash.size];
	hash_t path_root[config.cfg_hash.size];
	memset(digest, 0x88, config.cfg_hash.size);
	bool is_valid;

	// profilers
	profile_s prof_add;
	profile_s prof_path;
	profile_s prof_verify;
	PROFILER_reset(&prof_add);
	PROFILER_reset(&prof_path);
	PROFILER_reset(&prof_verify);


	printf("\n\n.:: Testing all fractal modes\n");
	printf("=====================================================\n");

	for(int mode = MT_FRACTAL_ZERO; mode <= MT_FRACTAL_HALF; mode++){
		tree = MT_init( &(config), mode );
		memset(digest, 0x88, config.cfg_hash.size);
		for(int idx = 0; idx < (1 << config.height); idx++){
			MT_add( &tree, digest);
			HASH_hash( digest, digest, config.cfg_hash.size );
		}
		printf("\nmode %d: root=%s", mode, HASH_hexstr(tree.root) );
		MT_free( &tree );
	}

	tree = MT_init( &(config), MT_FRACTAL_HALF );
	memset(digest, 0x88, config.cfg_hash.size);

	printf("\n\n.:: Perofmance Testing of MT in mode 2\n");
	printf("=====================================================\n");

	HASH_reset_stats();	
	for(int idx = 0; idx < (1 << config.height); idx++){
			PROFILER_start( &prof_add);
		MT_add( &tree, digest);
			PROFILER_stop( &prof_add);

		HASH_hash( digest, digest, config.cfg_hash.size );
	}

	CLI_print_merkle( &tree );  // print Merkle tree
	memset(digest, 0x88, config.cfg_hash.size);

	// fast forward desire seed
	memcpy(desire, digest, config.cfg_hash.size);
	for(int idx = 0; idx < (1 << (tree.exist.height)); idx++){
		HASH_hash( desire, desire, config.cfg_hash.size );
	}

	for(int idx = 0; idx < (1 << config.height); idx++){

		// generate path
			PROFILER_start( &prof_path);
		MT_generate_path( &tree, digest, &path);
			PROFILER_stop( &prof_path);

		// grow desire
		MT_grow_dtree( &tree, desire);


		// root from path
			PROFILER_start( &prof_path);
		MT_root_from_path( &path, digest, idx, (hash_t*)&path_root);
			PROFILER_stop( &prof_path);

		// validate:
		is_valid =(bool)(memcmp(path_root, tree.root, tree.config.cfg_hash.size) == 0);
		LOG_debug("digest=%.8s, mt_root=%.8s, path_root=%.8s", HASH_hexstr( digest ), HASH_hexstr( tree.root ), HASH_hexstr( path_root ) );
		if (!is_valid) LOG_error("Invalid path_root! ");


		// update digest and desire
		HASH_hash( digest, digest, config.cfg_hash.size );
		HASH_hash( desire, desire, config.cfg_hash.size );
	}



	printf("\n\nStats:\n");
	HASH_print_stats();

	PROFILER_print("MT_add", &prof_add);
	PROFILER_print("MT_path", &prof_path);
	//PROFILER_print("MT_verify", &prof_verify);

	// clean after yourself
	MT_free( &tree );
	MT_free_path( &path );
}


// ============================================================================
// public function implementations
// ============================================================================
int main(){
	LOG_setLevel(LOG_LVL_INFO);
	LOG_setLogFile("./merkle_test.log");


	MT_Config config;
	config.cfg_hash = HASH_SHA2_256;
	config.height = 8;

	benchmark_merkle(config);

	return 0;
}