#include <stdlib.h>

#include "hash.h"
#include "hashes/fips202.h"
#include "hashes/blake2.h"
#include "hashes/sha256.h"


#define HASH_VERBOSE 0    // 1: dump intermediate state, only use for debugging 
#if HASH_VERBOSE
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#endif


#if CFG_HASH_PROFILING
#include <stdio.h>
unsigned int G_profile_calls = 0;
unsigned int G_profile_processed_bytes = 0;
#endif


/* global hash config */
HASH_Config G_cfg = {HASH_SHA2, 32};

const HASH_Config HASH_SHA2_256    = {HASH_SHA2, 32};    
const HASH_Config HASH_SHAKE_128   = {HASH_SHAKE128, 32};
const HASH_Config HASH_SHAKE_256   = {HASH_SHAKE256, 64};
const HASH_Config HASH_BLAKE2B_128 = {HASH_BLAKE2B, 16}; 
const HASH_Config HASH_BLAKE2B_160 = {HASH_BLAKE2B, 20}; 
const HASH_Config HASH_BLAKE2B_192 = {HASH_BLAKE2B, 24}; 
const HASH_Config HASH_BLAKE2B_224 = {HASH_BLAKE2B, 28}; 
const HASH_Config HASH_BLAKE2B_256 = {HASH_BLAKE2B, 32}; 


static void SHA256_full(byte_t *output, const byte_t *input, const size_t input_length, const key_s *key){
        SHA256_CTX ctx_sha256;
        SHA256_Init(&(ctx_sha256));
        if (key != 0) SHA256_Update(&(ctx_sha256), key->bytes, CFG_HASH_KEY_SIZE);
        SHA256_Update(&(ctx_sha256), input, input_length);
        SHA256_Final(output, &(ctx_sha256));    
}


hash_t* HASH_init(const HASH_Config config){
    return malloc(config.size);
}


void HASH_config(const HASH_Config config){
    G_cfg = config;
}

HASH_Config HASH_getconfig(){
    return G_cfg;
}


void HASH_keyhash(byte_t *output, const byte_t *input, size_t input_length, const key_s* key){
#if HASH_VERBOSE
    printf("hash: "); int i; for (i=0; i< input_length; i++) printf( " %02x", ((unsigned char*)input)[i] );
#endif
#if CFG_HASH_PROFILING
    G_profile_calls++;
    G_profile_processed_bytes += (unsigned int)input_length;
#endif

    int key_len = CFG_HASH_KEY_SIZE;
    if (key == 0){ key_len = 0;}
    switch (G_cfg.algo) {
        case HASH_SHA2: SHA256_full(output, input, input_length, key); break;  
        case HASH_SHA3: SHA256_full(output, input, input_length, key); break;  
        case HASH_SHAKE128: shake128(output, 16, input, input_length); break;  
        case HASH_SHAKE256: shake256(output, 32, input, input_length); break;  
        case HASH_BLAKE2B: blake2b(output, G_cfg.size, input, input_length, (char*)key, key_len); break;
        default: printf("hash.c: algorithm unknown!");
    }

#if HASH_VERBOSE
        printf( " ->" );
        for (i=0; i<32; i++) printf( " %02x", ((unsigned char *)output)[i] ); printf( "\n" );
#endif
}


// simplified interface
void HASH_hash(byte_t *output, const byte_t *input, size_t input_length) {
    HASH_keyhash(output, input, input_length, 0);
}




/*
 * Print functions for debugging. Prints the hash in 2 hexadecimal values per output byte to stdout
 */
const char* HASH_hexstr(const byte_t *hash){
    static char str[64*8 + 4] = {0};   // buffers 3 hashes of max 64 byte
    static unsigned int call_idx = 0;
    ++call_idx; if(call_idx == 4) call_idx = 0;

    for (int i=0; i<G_cfg.size; i++){ sprintf( str+(call_idx*(G_cfg.size+1))+(i*2), "%02x", ((unsigned char *)hash)[i] ); }
    return str+(call_idx* (G_cfg.size+1) );
}



#if CFG_HASH_PROFILING
void HASH_print_stats() { printf("HASH_PROFILE: Calls: %d,  Processed: %d B\n", G_profile_calls, G_profile_processed_bytes); }
void HASH_reset_stats() { G_profile_calls = 0; G_profile_processed_bytes = 0;}
#else
void HASH_print_stats() { }  // let compiler remove this
void HASH_reset_stats() { }  // let compiler remove this
#endif

