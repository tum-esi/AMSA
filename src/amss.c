

#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#include "amss.h"
#include "util/logger.h"



void gen_next_key(hash_t* sk, key_s* hashkey){
    HASH_keyhash(sk, sk, CFG_WOTS_SEED_SIZE, hashkey);   // ensures forward security
}


void gen_grow_key(hash_t* growk, hash_t* sk, key_s* hashkey){
    HASH_keyhash(growk, sk, CFG_WOTS_SEED_SIZE, hashkey);   // ensures forward security
}


AMSA_Sig AMSA_Sig_init(const AMSA_Config config){
    const int num_chains = WOTS_num_chains( &(config.cfg_wots) );
    const size_t size_hash = config.cfg_wots.cfg_hash.size;
    AMSA_Sig sig;
    WOTS_chains_t* wots = (WOTS_chains_t*) malloc( num_chains*size_hash );
    sig.wots = wots;
    sig.auth_path = MT_init_path( &(config.cfg_tree) );
    //sig.leaf_idx = 0;
    return sig;
}


void AMSA_Sig_free(AMSA_Sig* sig){
    free(sig->wots);
    free(sig->auth_path.hashes);
}



AMSA_Amss AMSA_Amss_init(const AMSA_Config config){
    AMSA_Amss amss;
    amss.wots = WOTS_init( &(config.cfg_wots) );

    // todo: determine best fractal height based on available memory
    amss.tree = MT_init( &(config.cfg_tree), MT_FRACTAL_HALF );
    return amss;   
}


void AMSA_Amss_free(AMSA_Amss* amss){
    WOTS_free( &(amss->wots) );
	MT_free( &(amss->tree) );    
}



void AMSA_generate(AMSA_Amss* amss, const byte_t* seed, AMSA_Pubkey* pubkey_out){
    
    AMSA_Config config = { amss->tree.config, amss->wots.config };

    // init hash
    const size_t size_hash = config.cfg_wots.cfg_hash.size;
    HASH_config( config.cfg_wots.cfg_hash );


    // store secret key and hashkey from random seed
    memcpy(amss->secret_key, seed, size_hash);
    memcpy(amss->hashkey.bytes, seed + CFG_WOTS_SEED_SIZE, CFG_HASH_KEY_SIZE);


    // create first seed from secret key
	hash_t wots_seed[size_hash];
    hash_t seed_first[size_hash];
    memcpy(wots_seed, amss->secret_key, size_hash);
    memcpy(seed_first, amss->secret_key, size_hash);


	for (unsigned int idx = 0; idx < (1 << config.cfg_tree.height); idx++){
        // todo: update hashkey
        //memcpy(&hashkey + 2, &idx, 3);
        WOTS_import_seckey( &(amss->wots), (const hash_t*) &wots_seed, amss->hashkey);
        WOTS_generate_pubkey( &(amss->wots) );    // gen wots pubkey
		MT_add(&(amss->tree), amss->wots.root);    // add wots
        //LOG_debug("Gen: seed=%.8s, leaf=%.8s, hashkey=%.8s", HASH_hexstr( wots_seed ), HASH_hexstr( amss->wots.root ), HASH_hexstr( (const byte_t*)&(hashkey) ) );

		gen_next_key(wots_seed, &(amss->hashkey));   // gen wots seed
	}

    // AMSA internal:
    WOTS_import_seckey( &amss->wots, seed_first, amss->hashkey );  // regenerate first wots

    // public key
    AMSA_export_pubkey(amss, pubkey_out);

    LOG_debug("AMSA_generate: Done. pk=%.8s, lidx=%d", HASH_hexstr( pubkey_out->root), amss->tree.leaf_idx );
}


void AMSA_sign(AMSA_Amss* amss, const hash_t* msg_digest, AMSA_Sig* sig_out){

    // Safety Check
    if (amss->tree.leaf_idx >= (1 << amss->tree.config.height)){
        LOG_error("AMSA_sign: All %d signatures exhausted!", (1 << amss->tree.config.height));
        return;
    }

    const size_t size_hash = amss->tree.config.cfg_hash.size;
    hash_t growkey[CFG_WOTS_SEED_SIZE];

    // set index
    sig_out->auth_path.leaf_idx = (uint16_t)amss->tree.leaf_idx;

    // WOTS signature
    WOTS_import_seckey( &(amss->wots), amss->secret_key, amss->hashkey);
    WOTS_sign( &(amss->wots), msg_digest, sig_out->wots );
	gen_next_key( amss->secret_key, &(amss->hashkey) );   // forward secure: iterate key and discard previous key

    // authentication path
    if (amss->tree.leaf_idx % 2 == 0){
        if (amss->tree.exist.leaf_idx == 0){ // first left is stored
            WOTS_import_pubkey( &(amss->wots), amss->tree.exist.left_nodes, amss->hashkey);
        } else {
            WOTS_root_from_sig( &(amss->wots), msg_digest, sig_out->wots, amss->wots.root);
        }
    } else {
        //LOG_debug("AMSA right. leaf_idx=%d, rhash=%.8s", amss->tree.exist.leaf_idx, HASH_hexstr( amss->tree.exist.right_nodes + (amss->tree.exist.leaf_idx-1)*size_hash ) );
        WOTS_import_pubkey( &(amss->wots), amss->tree.exist.right_nodes + (amss->tree.exist.leaf_idx-1)*size_hash, amss->hashkey);
    }
    MT_generate_path( &(amss->tree), amss->wots.root, &(sig_out->auth_path) );
    LOG_debug("Signing m=%.8s, leaf_idx=%d, hashkey=%.8s. leaf hash=%.8s", HASH_hexstr( msg_digest ), amss->tree.leaf_idx-1, HASH_hexstr( (const byte_t*)&(amss->wots.hashkey) ), HASH_hexstr( amss->wots.root ) );


    // grow Merkle tree if necessary
    memcpy(growkey, amss->secret_key, CFG_WOTS_SEED_SIZE);
    MT_index_t grow_idx = MT_get_grow_leaf_idx( &(amss->tree) );
    if (grow_idx != 0){
        for(int idx = amss->tree.leaf_idx; idx < grow_idx; idx++){
            HASH_keyhash(growkey, growkey, CFG_WOTS_SEED_SIZE, &(amss->hashkey));
        }
        WOTS_import_seckey( &(amss->wots), growkey, amss->hashkey ); 
        WOTS_generate_pubkey( &(amss->wots) );  // this is expensive
        MT_grow_dtree( &(amss->tree), amss->wots.root );
    }
}



void AMSA_export_pubkey(AMSA_Amss* amss, AMSA_Pubkey* pubkey_out){
    pubkey_out->config.cfg_wots = amss->wots.config;
    pubkey_out->config.cfg_tree = amss->tree.config;
    pubkey_out->hashkey = amss->hashkey;
    pubkey_out->root = amss->tree.root;
}

   


bool AMSA_verify(const AMSA_Pubkey* pubkey, const hash_t* msg_digest, const AMSA_Sig* sig){
    hash_t wots_root[pubkey->config.cfg_wots.cfg_hash.size];
    hash_t tree_root[pubkey->config.cfg_wots.cfg_hash.size];


    WOTS_Wots wots_leaf = WOTS_init( &(pubkey->config.cfg_wots) ); 
    wots_leaf.hashkey = pubkey->hashkey; // todo: move to import_pubkey
    WOTS_root_from_sig( &wots_leaf, msg_digest, sig->wots, wots_root);


	MT_root_from_path( &(sig->auth_path), wots_root, sig->auth_path.leaf_idx, tree_root);

    bool is_valid =(bool)(memcmp(tree_root, pubkey->root, pubkey->config.cfg_wots.cfg_hash.size) == 0);

    LOG_debug("Verify: wots_root=%.8s, tree_root=%.8s, pubkey=%.8s", HASH_hexstr( wots_root ), HASH_hexstr( tree_root ), HASH_hexstr( pubkey->root ) );

    if(!is_valid){
        LOG_warn("Signature is INVALID!" );
        for(int idx = 0; idx < pubkey->config.cfg_tree.height; idx++){
            LOG_debug("Path Hash %d: %.8s", idx, HASH_hexstr( sig->auth_path.hashes + idx*pubkey->config.cfg_wots.cfg_hash.size ) );
        }
    }
    WOTS_free(&wots_leaf);
    return is_valid;
}