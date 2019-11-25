#include <stdlib.h>

#include "wots.h"
#include "hash.h"
#include "util/logger.h"



#define IDX_HASHKEY_BYTE_CHAIN_IDX 0  // first byte set to chain idx
#define IDX_HASHKEY_BYTE_HASH_IDX 1   // second byte set to hash idx within chain


// ============================================================================
// Configurations
// ============================================================================

const WOTS_Config WOTS_SHA2_256_W4      = {{HASH_SHA2, 32},   4};
const WOTS_Config WOTS_SHA2_256_W16     = {{HASH_SHA2, 32},  16};
const WOTS_Config WOTS_SHA2_256_W256    = {{HASH_SHA2, 32}, 256};

const WOTS_Config WOTS_BLAKE2B_128_W4   = {{HASH_BLAKE2B, 16},   4};
const WOTS_Config WOTS_BLAKE2B_128_W16  = {{HASH_BLAKE2B, 16},  16}; // 4352 b
const WOTS_Config WOTS_BLAKE2B_128_W256 = {{HASH_BLAKE2B, 16}, 256}; //2304 b

const WOTS_Config WOTS_BLAKE2B_160_W4   = {{HASH_BLAKE2B, 20},   4};
const WOTS_Config WOTS_BLAKE2B_160_W16  = {{HASH_BLAKE2B, 20},  16};
const WOTS_Config WOTS_BLAKE2B_160_W32  = {{HASH_BLAKE2B, 20},  32};
const WOTS_Config WOTS_BLAKE2B_160_W256 = {{HASH_BLAKE2B, 20}, 256};

// const WOTS_Config WOTS_BLAKE2B_192_W4   = {{HASH_BLAKE2B, 24},   4};
// const WOTS_Config WOTS_BLAKE2B_192_W16  = {{HASH_BLAKE2B, 24},  16};
// const WOTS_Config WOTS_BLAKE2B_192_W256 = {{HASH_BLAKE2B, 24}, 256};

const WOTS_Config WOTS_BLAKE2B_256_W4   = {{HASH_BLAKE2B, 32}, 4};
const WOTS_Config WOTS_BLAKE2B_256_W16  = {{HASH_BLAKE2B, 32}, 16};
const WOTS_Config WOTS_BLAKE2B_256_W256 = {{HASH_BLAKE2B, 32}, 256};



// LUT for equation $ sqrt( ( 8n ) / ( log_2(w) ) * (w-1) ) $
const unsigned csum_base(unsigned int n, unsigned int w){
    if (n == 16 && w ==   4){ return 14; }
    if (n == 16 && w ==  16){ return 22; }
    if (n == 16 && w == 256){ return 64; }
    if (n == 20 && w ==   4){ return 16; }
    if (n == 20 && w ==  16){ return 25; }
    if (n == 20 && w ==  32){ return 32; }
    if (n == 20 && w == 256){ return 72; }
    if (n == 32 && w ==   4){ return 20; }
    if (n == 32 && w ==  16){ return 31; }
    if (n == 32 && w == 256){ return 91; }
    return -1;
}



// ============================================================================
// Private Functions
// ============================================================================



/**
 * Sets the first byte of the hashkey to the index of the chain.
 */
void update_hashkey(key_s* hashkey, uint8_t idx_chain){
    hashkey->bytes[IDX_HASHKEY_BYTE_CHAIN_IDX] = idx_chain;
}


/**
 * Helper method for pseudorandom key generation.
 * Expands the n-byte wots-seed into a len*n byte chain seeds.
 */
static void expand_seed(const WOTS_Wots* wots, hash_t* chains)
{
    update_hashkey( (key_s*) &(wots->hashkey), 255); // reset hashkey
    int num_chains = wots->code_digits+wots->csum_digits;
    HASH_keyhash(chains, wots->seed, CFG_WOTS_SEED_SIZE, &(wots->hashkey) );  // first seed
    hash_t preimage[CFG_WOTS_SEED_SIZE];


    for (int i = 1; i < num_chains; i++) {
        // 1. XOR previous seed with initial wots-seed
        for (int j = 0; j < wots->config.cfg_hash.size; j++){
            preimage[j] = chains[(i-1)*wots->config.cfg_hash.size + j] ^ wots->seed[j];
        }
        // 2. rehash
        HASH_keyhash(chains+(i*wots->config.cfg_hash.size), (const hash_t*)&preimage, wots->config.cfg_hash.size, &(wots->hashkey));
    }
}

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays.
 *
 * Interprets in as start-th value of the chain.
 * addr has to contain the address of the chain.
 */
static void gen_chain(hash_t* out, const hash_t* in, const key_s* hashkey, const size_t hash_bytes,
                      unsigned int start, unsigned int steps)
{
    /* Initialize out with the value at position 'start'. */
    if (in != out) memcpy(out, in, hash_bytes);
    key_s copykey = *(hashkey);

    /* Iterate 'steps' calls to the hash function. */
    // LOG_trace("gen_chain: %2d -> %2d, in=%.8s, hkey=%.8s", start, start+steps, HASH_hexstr( (const hash_t*)in), HASH_hexstr( (const hash_t*)hashkey ) );
    for (int i = start; i < (start+steps); i++) {
        copykey.bytes[IDX_HASHKEY_BYTE_HASH_IDX] = i;
        //hashkey->bytes[IDX_HASHKEY_BYTE_HASH_IDX] = i;
        HASH_keyhash(out, out, hash_bytes, &copykey);
    }
}


static void gen_chains(hash_t* chains_out, const WOTS_Wots* wots, int* starts, int* stops){
    int val_base = wots->config.code_base;
    for (int i = 0; i < wots->num_chains; i++) {
        update_hashkey( (key_s*) &(wots->hashkey), i);
        if(i >= wots->code_digits) val_base = wots->csum_base;
        if (starts == NULL){
            if (stops == NULL){  // run from 0 to end
                gen_chain( chains_out+i*wots->config.cfg_hash.size, chains_out+i*wots->config.cfg_hash.size, &(wots->hashkey), wots->config.cfg_hash.size, 0, val_base-1);
            } else {  // run from 0 to stops
                gen_chain( chains_out+i*wots->config.cfg_hash.size, chains_out+i*wots->config.cfg_hash.size, &(wots->hashkey), wots->config.cfg_hash.size, 0, stops[i]);
            }
        } else {  // run from start to end
            gen_chain( chains_out+i*wots->config.cfg_hash.size, chains_out+i*wots->config.cfg_hash.size, &(wots->hashkey), wots->config.cfg_hash.size, starts[i], val_base - 1 - starts[i]);
        }
    }    
}



int log2pow2(int x){
    int ret = 0;
    while(x > 1){
        x = x >> 1;
        ret++;
    }
    return ret;
}


/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
static void base_w(const WOTS_Wots* wots, const unsigned char *input, int *output)
{
    int in = 0;
    int out = 0;
    unsigned char total;
    int bits = 0;
    int code_bits = log2pow2(wots->config.code_base);
    int consumed;

   for (consumed = 0; consumed < wots->code_digits; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= code_bits;
        output[out] = (total >> bits) & (wots->config.code_base - 1);
        out++;
    }
}

// computes the MinWOTS checksum
static void base_w_cs(const WOTS_Wots* wots, const int input, int *output)
{
    int cs_remainder = input;
    int divisor = 1;
    int digit_val;

    // highest divisor
    for (int i = 0; i < wots->csum_digits-1; i++) {
        divisor *= wots->csum_base;
    }

    for (int digit = 0; digit < wots->csum_digits-1; digit++) {
        digit_val = (cs_remainder / divisor);
        output[digit] = digit_val;
        cs_remainder -= digit_val*divisor;
        divisor = divisor / wots->csum_base;
    }
    output[wots->csum_digits-1] = cs_remainder;
}





/* Computes the WOTS+ checksum over a message (in base_w). */
static int checksum(const WOTS_Wots* wots, const int *msg_base_w)
{
    int csum = 0;
    for (int i = 0; i < wots->code_digits; i++) {
        csum += wots->config.code_base - 1 - msg_base_w[i];
    }
    LOG_trace("csum=%d", csum);
    return csum;
}




/* Takes a message and derives the matching chain lengths. */
static void chain_lengths(const WOTS_Wots* wots, int *lengths, const hash_t* msg)
{
    base_w(wots, msg, lengths);
    int csum = checksum(wots, lengths);
    base_w_cs(wots, csum, lengths + wots->code_digits);
    LOG_trace("lengths: %d, %d, %d, ... | %d, %d, ...", lengths[0], lengths[1], lengths[2], lengths[wots->code_digits], lengths[wots->code_digits+1]);
}







WOTS_Wots WOTS_init(const WOTS_Config* config){
    WOTS_Wots wots;
    wots.config = *config;
    wots.csum_base = csum_base(config->cfg_hash.size, config->code_base);
    wots.code_digits = (8*config->cfg_hash.size) / log2pow2(config->code_base);
    wots.csum_digits = 2;
    wots.has_seckey = 0;
    wots.has_pubkey = 0;
    wots.num_chains = wots.code_digits+wots.csum_digits;
    wots.root = malloc(config->cfg_hash.size);
    return wots;
}


void WOTS_free(WOTS_Wots* wots){
    free(wots->root);
}




unsigned WOTS_num_chains(const WOTS_Config* config){
    return (8*config->cfg_hash.size) / log2pow2(config->code_base) + 2;
}




void WOTS_import_seckey(WOTS_Wots* wots, const hash_t* seckey, const key_s hashkey){
    /* check init */
    memcpy(wots->seed, seckey, CFG_WOTS_SEED_SIZE);
    wots->hashkey = hashkey; 

    wots->has_seckey = 1; 
    wots->has_pubkey = 0;  // set pubkey to zero
}


void WOTS_import_pubkey(WOTS_Wots* wots, const hash_t* pubkey, const key_s hashkey){
    memcpy(wots->root, pubkey, wots->config.cfg_hash.size);
    wots->hashkey = hashkey; 

    wots->has_seckey = 0; 
    wots->has_pubkey = 1;  // set pubkey to zero
}



void WOTS_generate_pubkey(WOTS_Wots* wots){
    const size_t size_hash = wots->config.cfg_hash.size;
    hash_t chains[wots->num_chains*size_hash];

    /* check init */
    if (wots->has_seckey == 0) LOG_error("WOTS_gen: no seckey. Import seckey first.");

    /* The WOTS private key is derived from the seed. */
    HASH_config(wots->config.cfg_hash);
    expand_seed(wots, chains);
    gen_chains(chains, wots, NULL, NULL);
    HASH_keyhash(wots->root, (unsigned char*)chains, wots->num_chains*size_hash, &(wots->hashkey));   // hash all chains together
    LOG_debug("Generating WOTS: %3d chains, seed=%.8s, root=%.8s, hkey=%.8s", wots->num_chains, HASH_hexstr( wots->seed ), HASH_hexstr( wots->root ), HASH_hexstr( (const hash_t*)&(wots->hashkey) ) );
    wots->has_pubkey = 1;
}



/**
 * Takes a n-byte message and the 32-byte seed for the private key to compute a
 * signature that is placed at 'sig'.
 */
void WOTS_sign(const WOTS_Wots* wots, const hash_t* msg, WOTS_chains_t* sig_out){

    if (wots->has_seckey == 0) LOG_error("WOTS_sign: no seckey. Import seckey first.");  
    int lengths[wots->num_chains];

    chain_lengths(wots, lengths, msg);

    /* The WOTS+ private key is derived from the seed. */
    HASH_config(wots->config.cfg_hash);
    expand_seed(wots, sig_out);

    gen_chains(sig_out, wots, NULL, lengths);
    LOG_trace("Signed: seed=%.8s, root=%.8s, sig=%.8s", HASH_hexstr( wots->seed ), HASH_hexstr( wots->root ), HASH_hexstr( sig_out ) );

}


bool WOTS_verify(const WOTS_Wots* wots, const hash_t* msg, const WOTS_chains_t* sig){
    if (wots->has_pubkey == 0) LOG_error("WOTS_verify: no pubkey. Generate or import pubkey first.");

    hash_t msg_root[wots->config.cfg_hash.size];
    WOTS_root_from_sig(wots, msg, sig, msg_root);

    bool isvalid = (bool)(memcmp(&msg_root, wots->root, wots->config.cfg_hash.size) == 0);  // 0 means equal
    if (!isvalid){
        LOG_warn("Verify failed: sig=%.8s, msg_root=%.8s, wots_root=%.8s", HASH_hexstr( sig ), HASH_hexstr(msg_root), HASH_hexstr(wots->root) );
    } 
    return isvalid;
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void WOTS_root_from_sig(const WOTS_Wots* wots, const hash_t* msg, const WOTS_chains_t* sig, hash_t* root_out)
{
    int lengths[wots->num_chains];
    WOTS_chains_t chains[wots->num_chains*wots->config.cfg_hash.size];

    HASH_config(wots->config.cfg_hash);
    chain_lengths(wots, lengths, msg);
    memcpy(chains, sig, wots->num_chains*wots->config.cfg_hash.size);

    gen_chains(chains, wots, lengths, NULL);
    HASH_keyhash(root_out, (unsigned char*)chains, wots->num_chains*wots->config.cfg_hash.size, &(wots->hashkey) );   // hash all chains together
}




