/*

Copyright (c) 2017 Brendan Rius. All rights reserved

Configurable HMAC hash functions implemented in 2021 by Maxim Masiutin,
see the "README.md" file for more details.

*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdatomic.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdbool.h>
#include <pthread.h>
#include "base64.h"

char *g_header_b64 = NULL; // Holds the Base64 header of the original JWT
char *g_payload_b64 = NULL; // Holds the Base64 payload of the original JWT
char *g_signature_b64 = NULL; // Holds the Base64 signature of the original JWT
unsigned char *g_to_encrypt = NULL; // Holds the part of the JWT that needs to be hashed
unsigned char *g_signature = NULL; // Holds the Base64 *decoded* signature of the original JWT

// Some lengths of buffers. Useful to avoid computing it multiple times.
// Also, not all strings used finish with a '\0' for optimization purposes.
// In that case, we need to have the length
size_t g_header_b64_len = 0;
size_t g_payload_b64_len = 0;
size_t g_signature_b64_len = 0;
size_t g_signature_len = 0;
size_t g_to_encrypt_len = 0;

// The alphabet to use when brute-forcing
char *g_alphabet = NULL;
size_t g_alphabet_len = 0;

// Use atomic pointer to prevent race condition (CWE-362)
_Atomic(char *) g_found_secret = NULL;

/**
 * Constant-time memory comparison to prevent timing side-channel attacks (CWE-208).
 * Returns 0 if equal, non-zero otherwise.
 */
static int constant_time_compare(const unsigned char *a, const unsigned char *b, size_t len) {
    unsigned char result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result;
}

struct s_thread_data {
    const EVP_MD *g_evp_md; // The hash function to apply the HMAC to

    // Holds the computed signature at each iteration to compare it with the original
    // signature
    unsigned char *g_result;
    unsigned int g_result_len;

    char *g_buffer; // Holds the secret being constructed

    char starting_letter; // Each thread is assigned a first letter
    size_t max_len; // And tries combinations up to a certain length
};

/**
 * Initialize thread data. Returns 0 on success, -1 on memory allocation failure.
 */
int init_thread_data(struct s_thread_data *data, char starting_letter, size_t max_len, const EVP_MD *evp_md) {
    data->max_len = max_len;
    data->starting_letter = starting_letter;
    data->g_evp_md = evp_md;
    data->g_result = NULL;
    data->g_buffer = NULL;

    // Allocate the buffer used to hold the calculated signature
    data->g_result = malloc(EVP_MAX_MD_SIZE);
    if (data->g_result == NULL) {
        return -1;
    }
    // Allocate the buffer used to hold the generated key
    data->g_buffer = malloc(max_len + 1);
    if (data->g_buffer == NULL) {
        free(data->g_result);
        data->g_result = NULL;
        return -1;
    }
    return 0;
}

void destroy_thread_data(struct s_thread_data *data) {
    free(data->g_result);
    free(data->g_buffer);
}

/**
 * Check if the signature produced with "secret"
 * of size "secret_len" (without the '\0') matches the original
 * signature.
 * Return true if it matches, false otherwise
 */
bool check(struct s_thread_data *data, const char *secret, size_t secret_len) {
    // If the secret was found by another thread, stop this thread
    // Use atomic load to prevent race condition (CWE-362)
    if (atomic_load_explicit(&g_found_secret, memory_order_relaxed) != NULL) {
        destroy_thread_data(data);
        pthread_exit(NULL);
    }

	// Hash the "to_encrypt" buffer using HMAC into the "result" buffer
	HMAC(
		data->g_evp_md,
		(const unsigned char *) secret, secret_len,
		(const unsigned char *) g_to_encrypt, g_to_encrypt_len,
		data->g_result, &(data->g_result_len)
	);

	// Compare the computed hash to the given decoded base64 signature.
	// Use constant-time comparison to prevent timing side-channel attacks (CWE-208).
	return constant_time_compare(data->g_result, g_signature, g_signature_len) == 0;
}

bool brute_impl(struct s_thread_data *data, char* str, int index, int max_depth)
{
    for (int i = 0; i < g_alphabet_len; ++i)
    {
        // The character at "index" in "str" successively takes the value
        // of each symbol in the alphabet
        str[index] = g_alphabet[i];

        // If just changed the last letter, that means we generated a
        // permutation, so we check it
        if (index == max_depth - 1) {
            // If we found the key, we return, otherwise we continue.
            // By continuing, the current letter (at index "index")
            // will be changed to the next symbol in the alphabet
            if (check(data, (const char *) str, max_depth)) return true;
        }
        // If the letter we just changed was not the last letter of
        // the permutation we are generating, recurse to change the
        // letter at the next index.
        else {
            // If this condition is met, that means we found the key.
            // Otherwise the loop will continue and change the current
            // character to the next letter in the alphabet.
			if (brute_impl(data, str, index + 1, max_depth)) return true;
        }
    }

    // If we are here, we tried all the permutations without finding a match
	return false;
}

/**
 * Atomically set g_found_secret if not already set.
 * Returns true if this thread won the race, false otherwise.
 * Uses atomic compare-and-swap to prevent race condition (CWE-362).
 */
static bool set_found_secret(const char *buffer, size_t len) {
    char *secret = strndup(buffer, len);
    if (secret == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return false;
    }
    char *expected = NULL;
    if (atomic_compare_exchange_strong(&g_found_secret, &expected, secret)) {
        return true;  // This thread won the race
    }
    // Another thread already set it, free our copy
    free(secret);
    return false;
}

/**
 * Try all the combinations of secret starting with letter "starting_letter"
 * and stopping at a maximum length of "max_len"
 * Returns the key when there is a match, otherwise returns NULL
 */
void *brute_sequential(void *arg)
{
    struct s_thread_data *data = (struct s_thread_data *)arg;

    // We set the starting letter
    data->g_buffer[0] = data->starting_letter;
    // Special case for len = 1, we check in this function
    if (check(data, data->g_buffer, 1)) {
        // If this thread found the solution, set the shared global variable
        // so other threads stop, and stop the current thread.
        set_found_secret(data->g_buffer, 1);
        destroy_thread_data(data);
        return NULL;
    }

    // We start from length 2 (we handled the special case of length 1
    // above.
    for (size_t i = 2; i <= data->max_len; ++i) {
      	if (brute_impl(data, data->g_buffer, 1, i)) {
            // If this thread found the solution, set the shared global variable
            // so other threads stop, and stop the current thread.
            set_found_secret(data->g_buffer, i);
            destroy_thread_data(data);
            return NULL;
        }
    }

    destroy_thread_data(data);
    return NULL;
}

void usage(const char *cmd, const char *alphabet, const size_t max_len, const char *hmac_alg) {
	printf("%s <token> [alphabet] [max_len] [hmac_alg]\n"
				   "Defaults: "
				   "alphabet=%s, "
				   "max_len=%zd, "
				   "hmac_alg=%s\n", cmd, alphabet, max_len, hmac_alg);
}

int main(int argc, char **argv) {

	if (argc > 1 && strcmp(argv[1], "--version") == 0) {
		printf("jwtcrack version 1.0.0\n");
		return 0;
	}

	const EVP_MD *evp_md;
	size_t max_len = 6;
	
	// by default, use OpenSSL EVP_sha256 which corresponds to JSON HS256 (HMAC-SHA256)
	const char *default_hmac_alg = "sha256";

	g_alphabet = "eariotnslcudpmhgbfywkvxzjqEARIOTNSLCUDPMHGBFYWKVXZJQ0123456789";

	if (argc < 2) {
		usage(argv[0], g_alphabet, max_len, default_hmac_alg);
		return 1;
	}

	// Get the token
	char *jwt = argv[1];

	if (argc > 2)
		g_alphabet = argv[2];

	if (argc > 3)
	{
		char *endptr;
		errno = 0;
		long i3 = strtol(argv[3], &endptr, 10);
		if (errno != 0 || endptr == argv[3] || *endptr != '\0' || i3 <= 0 || i3 > 1000) {
			printf("Invalid max_len value %s, defaults to %zd (valid range: 1-1000)\n", argv[3], max_len);
		} else {
			max_len = (size_t)i3;
		}
	}

	if (argc > 4)
	{
		evp_md = EVP_get_digestbyname(argv[4]);
		if (evp_md == NULL) 
			printf("Unknown message digest %s, will use default %s\n", argv[4], default_hmac_alg);
	} else
	{
	   evp_md = NULL; 
	}

	if (evp_md == NULL) 
	{
		evp_md = EVP_get_digestbyname(default_hmac_alg);
		if (evp_md == NULL) 
		{
			printf("Cannot initialize the default message digest %s, aborting\n", default_hmac_alg);
			return 1;
		}
	}

	g_alphabet_len = strlen(g_alphabet);

	// Split the JWT into header, payload and signature
	// Validate each part to prevent NULL dereference (CWE-476)
	g_header_b64 = strtok(jwt, ".");
	if (g_header_b64 == NULL) {
		fprintf(stderr, "Error: Invalid JWT format - missing header\n");
		return 1;
	}

	g_payload_b64 = strtok(NULL, ".");
	if (g_payload_b64 == NULL) {
		fprintf(stderr, "Error: Invalid JWT format - missing payload\n");
		return 1;
	}

	g_signature_b64 = strtok(NULL, ".");
	if (g_signature_b64 == NULL) {
		fprintf(stderr, "Error: Invalid JWT format - missing signature\n");
		return 1;
	}

	g_header_b64_len = strlen(g_header_b64);
	g_payload_b64_len = strlen(g_payload_b64);
	g_signature_b64_len = strlen(g_signature_b64);

	// Validate minimum lengths
	if (g_header_b64_len == 0 || g_payload_b64_len == 0 || g_signature_b64_len == 0) {
		fprintf(stderr, "Error: Invalid JWT format - empty component\n");
		return 1;
	}

	// Recreate the part that is used to create the signature
	// Since it will always be the same
	g_to_encrypt_len = g_header_b64_len + 1 + g_payload_b64_len;
	g_to_encrypt = (unsigned char *) malloc(g_to_encrypt_len + 1);
	if (g_to_encrypt == NULL) {
		fprintf(stderr, "Error: Memory allocation failed for g_to_encrypt\n");
		return 1;
	}
	sprintf((char *) g_to_encrypt, "%s.%s", g_header_b64, g_payload_b64);

	// Decode the signature
	g_signature_len = Base64decode_len((const char *) g_signature_b64);
	g_signature = malloc(g_signature_len);
	if (g_signature == NULL) {
		fprintf(stderr, "Error: Memory allocation failed for g_signature\n");
		free(g_to_encrypt);
		return 1;
	}
	// We re-assign the length, because Base64decode_len returned us an approximation
	// of the size so we could malloc safely. But we need the real decoded size, which
	// is returned by this function
	g_signature_len = Base64decode((char *) g_signature, (const char *) g_signature_b64);

	// Heap allocate thread data array (fix CWE-121 VLA stack overflow)
	struct s_thread_data **pointers_data = malloc(g_alphabet_len * sizeof(struct s_thread_data *));
	if (pointers_data == NULL) {
		fprintf(stderr, "Error: Memory allocation failed for pointers_data\n");
		free(g_to_encrypt);
		free(g_signature);
		return 1;
	}

	pthread_t *tid = malloc(g_alphabet_len * sizeof(pthread_t));
	if (tid == NULL) {
		fprintf(stderr, "Error: Memory allocation failed for tid\n");
		free(pointers_data);
		free(g_to_encrypt);
		free(g_signature);
		return 1;
	}

	size_t threads_created = 0;
	for (size_t i = 0; i < g_alphabet_len; i++) {
		pointers_data[i] = malloc(sizeof(struct s_thread_data));
		if (pointers_data[i] == NULL) {
			fprintf(stderr, "Error: Memory allocation failed for thread data %zu\n", i);
			// Clean up already allocated thread data
			for (size_t j = 0; j < i; j++) {
				free(pointers_data[j]);
			}
			free(pointers_data);
			free(tid);
			free(g_to_encrypt);
			free(g_signature);
			return 1;
		}
		if (init_thread_data(pointers_data[i], g_alphabet[i], max_len, evp_md) != 0) {
			fprintf(stderr, "Error: Failed to initialize thread data %zu\n", i);
			free(pointers_data[i]);
			for (size_t j = 0; j < i; j++) {
				free(pointers_data[j]);
			}
			free(pointers_data);
			free(tid);
			free(g_to_encrypt);
			free(g_signature);
			return 1;
		}
		pthread_create(&tid[i], NULL, brute_sequential, pointers_data[i]);
		threads_created++;
	}

	for (size_t i = 0; i < threads_created; i++)
		pthread_join(tid[i], NULL);

	if (g_found_secret == NULL)
		printf("No solution found :-(\n");
	else
		/*
		 * SECURITY NOTE: Outputting the discovered secret is the explicit
		 * purpose of this security testing tool. Static analyzers may flag
		 * this as "sensitive information logging" (CWE-200, CWE-312), but
		 * this is intentional - the tool exists to find weak JWT secrets
		 * so they can be identified and replaced with stronger ones.
		 */
		printf("Secret is \"%s\"\n", g_found_secret);

	for (size_t i = 0; i < g_alphabet_len; i++)
		free(pointers_data[i]);
	free(pointers_data);
	free(g_found_secret);
	free(tid);
	free(g_to_encrypt);
	free(g_signature);

	return 0;
}
