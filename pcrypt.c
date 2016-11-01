#include "pcrypt.h"
void shuffle2(uint32_t* vector);
void unshuffle(uint32_t* vector);
void unshuffle2(uint32_t* vector);

uint8_t rotl8(uint8_t val, uint8_t bits) {
	return ((val << bits) | (val >> (8 - bits))) & 0xff;
}

uint8_t gen_rand(uint32_t* rand) {
	*rand = *rand * 0x41c64e6d + 12345;
	return (*rand >> 16) & 0xff;
}

typedef struct cipher8_t {
	uint8_t cipher[256];
} cipher8_t;

cipher8_t cipher8_from_iv(uint8_t* iv) {
	cipher8_t cipher8;
	for (size_t ii = 0; ii < 8; ++ii) {
		for (size_t jj = 0; jj < 32; ++jj) {
			cipher8.cipher[32 * ii + jj] = rotl8(iv[jj], ii);
		}
	}
	return cipher8;
}

cipher8_t cipher8_from_rand(uint32_t* rand) {
	cipher8_t cipher8;
	for (size_t ii = 0; ii < 256; ++ii) {
		cipher8.cipher[ii] = gen_rand(rand);
	}
	return cipher8;
}

uint8_t make_integrity_byte(byte) {
	uint8_t tmp = (byte ^ 0x0c) & byte;
	return ((~tmp & 0x67) | (tmp & 0x98)) ^ 0x6f | (tmp & 0x08);
}

/**
 * input:    cleartext
 * len:      length of `input`
 * ms:       seed for iv
 * output:   location to store encrypted payload
 * returns:  length of `output`
 *
 * note: This is "version 3". Encryption of previous versions is no longer supported.
 * note: This function will allocate memory for you, you must manually call `free` on `output` when
 *       you are done with it.
 */
int encrypt(const char* input, size_t len, uint32_t ms, char** output) {

	// Sanity checks
	if (len == 0) {
		return 0;
	}

	// Allocate output space
	size_t rounded_size = len + (256 - (len % 256));
	size_t total_size = rounded_size + 5;
	*output = (char*)malloc(total_size + 3);
	uint8_t* output8 = (uint8_t*)*output;
	uint32_t* output32 = (uint32_t*)*output;

	// Write out seed
	output32[0] = htonl(ms);
	memcpy(output8 + 4, input, len);

	// Fill zeros + mark length
	if (rounded_size > len) {
		memset(output8 + 4 + len, 0, rounded_size - len);
	}
	output8[total_size - 2] = 256 - (len % 256);

	// Generate cipher and integrity byte
	cipher8_t cipher8_tmp = cipher8_from_rand(&ms);
	uint8_t* cipher8 = cipher8_tmp.cipher;
	uint32_t* cipher32 = (uint32_t*)cipher8;
	output8[total_size - 1] = make_integrity_byte(gen_rand(&ms));

	// Encrypt in chunks of 256 bytes
	for (size_t offset = 4; offset < total_size - 1; offset += 256) {
		for (size_t ii = 0; ii < 64; ++ii) {
			output32[offset / 4 + ii] ^= cipher32[ii];
		}
		shuffle2((uint32_t*)(output8 + offset));
		memcpy(cipher8, output8 + offset, 256);
	}
	return total_size;
}

/**
 * input:    encrypted payload
 * len:      length of `input`
 * output:   location to store cleartext payload
 * returns:  length of `output`, negative on error
 */
int decrypt(const char* input, size_t len, char** output) {

	// Sanity checks
	int version;
	if (len < 261) {
		return -1;
	} else {
		int mod_size = len % 256;
		if (mod_size == 32) {
			version = 1;
		} else if (mod_size == 33) {
			version = 2;
		} else if (mod_size == 5) {
			version = 3;
		} else {
			return -2;
		}
	}

	// Get cipher and encrypted blocks
	cipher8_t cipher8_tmp;
	int output_len;
	if (version == 1) {
		output_len = len - 32;
		*output = (char*)malloc(output_len);
		memcpy(*output, input + 32, output_len);
		cipher8_tmp = cipher8_from_iv((uint8_t*)input);
	} else if (version == 2) {
		output_len = len - 33;
		*output = (char*)malloc(output_len);
		memcpy(*output, input + 32, output_len);
		cipher8_tmp = cipher8_from_iv((uint8_t*)input);
		// input[len - 1] is unchecked integrity byte
	} else {
		output_len = len - 5;
		*output = (char*)malloc(output_len);
		memcpy(*output, input + 4, output_len);
		uint32_t ms = ntohl(((uint32_t*)input)[0]);
		cipher8_tmp = cipher8_from_rand(&ms);
		if (input[len - 1] != make_integrity_byte(gen_rand(&ms))) {
			return -3;
		}
	}
	uint32_t cipher32[64];
	memcpy(cipher32, cipher8_tmp.cipher, 256);
	uint8_t* output8 = (uint8_t*)*output;
	uint32_t* output32 = (uint32_t*)*output;
	
	// Decrypt in chunks of 256 bytes
	for (size_t offset = 0; offset < output_len; offset += 256) {
		uint8_t tmp[256];
		memcpy(tmp, output8 + offset, 256);
		if (version == 1) {
			unshuffle(output32 + offset);
		} else {
			unshuffle2(output32 + offset);
		}
		for (size_t ii = 0; ii < 64; ++ii) {
			output32[offset / 4 + ii] ^= cipher32[ii];
		}
		memcpy(cipher32, tmp, 256);
	}
	return output_len - output8[output_len - 1];
}
