
#include "cli.h"
#include <stdio.h>



#define CFG_HASH_SIZE_OUT 8



int cli_num_rights(const int height){
	return (1 << (height)) -1;
}

void hex_bytes(const unsigned char* buf, int len){
	printf("\nAddress Range: "); printf("%p - %p\n",(void*)buf, (void*)&(buf[len-1]));
	for (int i = 0; i < len; i++)
	{
		if (i > 0) printf(" ");
		printf("%02X", buf[i]);
		if (i % 32 == 31) printf("\n");
	}
    fflush(stdout);
}

size_t sizeof_wots_sig(const WOTS_Wots* wots){ return wots->num_chains * wots->config.cfg_hash.size; }
size_t sizeof_tree_aux(const MT_Tree* tree){ return (cli_num_rights(tree->config.height) + tree->config.height) * tree->config.cfg_hash.size; }
size_t sizeof_tree_auth(const MT_Tree* tree){ return tree->config.height * tree->config.cfg_hash.size; }




const char* CLI_hexstr(const unsigned char *hash){
    static char str[CFG_HASH_SIZE_OUT*8 + 4];   // buffers 3 hashes
    static unsigned int call_idx = 0;
    ++call_idx; if(call_idx == 4) call_idx = 0;

    for (int i=0; i < CFG_HASH_SIZE_OUT; i++){ sprintf( str+(call_idx*(CFG_HASH_SIZE_OUT+1))+(i*2), "%02x", ((unsigned char *)hash)[i] ); }
    return str+(call_idx* (CFG_HASH_SIZE_OUT+1) );
}


void CLI_print_hashname(const HASH_Config config){
	int num_bits = config.size * 8;
	if (config.algo == HASH_SHA2 ) printf("SHA2_%d", num_bits );
	if (config.algo == HASH_SHA3 ) printf("SHA3_%d", num_bits );
	if (config.algo == HASH_BLAKE2B ) printf("BLAKE2B_%d", num_bits );
	if (config.algo == HASH_SHAKE128 ) printf("SHAKE128_%d", num_bits );
}

void CLI_print_wots_config(const WOTS_Config config){
	printf("WOTS_");
	CLI_print_hashname(config.cfg_hash);
	printf("_W%d", config.code_base);
}



void CLI_print_merkle(const MT_Tree* tree){
	int idx;
	const size_t size_hash = tree->config.cfg_hash.size; 
	int n_rights = cli_num_rights(tree->top.height) + 2*cli_num_rights(tree->exist.height);
	int n_lefts = tree->top.height + 2*tree->exist.height;
	size_t total_size = MT_sizeof_tree(tree->config);
	printf("\nMerkleTree"); 
	printf("\n  - height: %d", (tree->top.height + tree->exist.height));
	printf("\n  - size: %ld byte,  (%d lefts + %d rights + 3 roots) hashes + 3 int", total_size, n_lefts, n_rights);
	printf("\n  - Root hash: %s ", CLI_hexstr( tree->root ));	

	printf("\n  - Top Tree: (root= %s )", CLI_hexstr( tree->top.root ) );
	for (idx = 0; idx < tree->top.height; idx++){
		printf("\n    - Left %d hash: %s", idx, CLI_hexstr( tree->top.left_nodes + idx*size_hash ) );
	}
	n_rights = cli_num_rights(tree->top.height);
	for (idx = 0; idx < n_rights; idx++){
		printf("\n    - Right %d hash: %s", idx, CLI_hexstr( tree->top.right_nodes + idx*size_hash ) );
	}
	printf("\n  - Bottom Tree: (root= %s )", CLI_hexstr( tree->exist.root ) );
	for (idx = 0; idx < tree->exist.height; idx++){
		printf("\n    - Left %d hash: %s", idx, CLI_hexstr( tree->exist.left_nodes + idx*size_hash ) );
	}
	n_rights = cli_num_rights(tree->exist.height);
	for (idx = 0; idx < n_rights; idx++){
		printf("\n    - Right %d hash: %s", idx, CLI_hexstr( tree->exist.right_nodes + idx*size_hash ) );
	}
	printf("\n");
}





void CLI_print_wots_params(const WOTS_Wots* wots){
	printf("WOTS=(n=%dB, l1=%d, w1=%d, l2=%d, w2=%d)\n", wots->config.cfg_hash.size, wots->code_digits, \
        wots->config.code_base, wots->csum_digits, wots->csum_base);
}

void CLI_print_wots(const WOTS_Wots* wots){
	CLI_print_wots_params( wots );
	printf("  -root: %s\n", CLI_hexstr( wots->root ) );
	printf("  -seed: %s\n", CLI_hexstr( wots->seed ) );
	printf("  -hkey: %s\n", CLI_hexstr( (hash_t*)&(wots->hashkey) ) );
}


void CLI_print_wots_sig(const WOTS_Wots* wots, const WOTS_chains_t* sig){
	key_s hashkey = wots->hashkey;
	hashkey.bytes[0] = 0xFF;
	CLI_print_wots(wots);
    for (int i = 0; i < (wots->code_digits+wots->csum_digits); i++) {
		hashkey.bytes[0] = i;
        printf("  -chain %2d: Hash: %s\n", i, CLI_hexstr(sig + i*wots->config.cfg_hash.size) );
    	printf("             Hkey: %s\n", CLI_hexstr( (hash_t*)&(hashkey) ) );
    }
}


void CLI_print_amss(const AMSA_Amss* amss){
	int size_pubkey = amss->tree.config.cfg_hash.size + 2 + CFG_HASH_KEY_SIZE;  // root + config + hashkey (16)
	int size_seckey = sizeof(amss->secret_key) + CFG_HASH_KEY_SIZE;
    int size_auth = sizeof_tree_auth( &(amss->tree) );
	int size_aux = ( MT_sizeof_tree(amss->tree.config) + sizeof_wots_sig( &(amss->wots) ) );
    int size_wots_sig = sizeof_wots_sig( &(amss->wots) );
    printf("AMSA: sizes: pk=%d B, sk=%d B, sig=(%d+%d)= %d B, aux=%d B\n", size_pubkey, size_seckey, size_wots_sig, size_auth, size_auth+size_wots_sig, size_aux);
	printf(" +TREE=(n=%dB, h=%d)\n", amss->tree.config.cfg_hash.size, amss->tree.config.height);
	printf(" +"); CLI_print_wots_params( &(amss->wots) );
}


void CLI_print_pubkey(const AMSA_Pubkey* pubkey){
    printf("=== AMSA Public Key ===\n");
    printf("Hash bytes: %d \n", pubkey->config.cfg_wots.cfg_hash.size );
    printf("Tree Height: %d \n", pubkey->config.cfg_tree.height );
    printf("Public key (hex): %s \n", HASH_hexstr( pubkey->root ) );
    printf("=== END Public Key ===\n");
}







