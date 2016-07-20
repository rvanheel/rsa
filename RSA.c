//
//  RSA.c
//  
// Example file how to encrypt, sign, decrypt and verify a message using RSA encryption
// with private and key files
//
// requirements for compiling: OpenSSL (apt-get install libssl-dev)
// LIBS = -lcrypto
//

#define _GNU_SOURCE

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "base64.h"

#define free_variable(p) { free(p);  p = 0; }

int decrypt_message(RSA * rsa, char * msg, int padding, unsigned char ** encoded_message);
int encrypt_message(RSA * rsa, char * msg, int padding, char ** encoded_message);
int randomize();
RSA * read_privatekeyfile (char * filename);
RSA * read_publickeyfile (char * filename);
int sign(RSA * rsa, char * msg, char * algorithm, char ** encoded_message);
int simpleSHA256(void* input, unsigned long length, unsigned char* md);
int verify(RSA * rsa, char * msg, char * signature, char * algorithm);

int main(int argc, char **argv)
{
	unsigned char * decrypted_message;
	char * encrypted_message;
	char * encrypted_signature;
	char msg [] = "IT\'S A SECRET TO EVERYBODY.";
	// read the keyfiles
	RSA * alice_public_key = read_publickeyfile("alice.publickey.pub");
	RSA * alice_private_key = read_privatekeyfile("alice.privatekey.pem");
	RSA * bob_public_key = read_publickeyfile("bob.publickey.pub");
	RSA * bob_private_key = read_privatekeyfile("bob.privatekey.pem");	
	// ALICE'S PART
	// Encrypt the message with the public key from BOB
	if (!encrypt_message(bob_public_key, msg, RSA_PKCS1_OAEP_PADDING, &encrypted_message))
	{
		return EXIT_FAILURE;
	}
	// sign it with the private key from ALICE
	if (!sign(alice_private_key, msg, "SHA256", &encrypted_signature))
	{
		return EXIT_FAILURE;
	}
	// Output the results to the console
	printf("\n");
	printf("ALICE'S PART\n");
	printf("\n");
	printf("Encrypted message: %s\n", encrypted_message);
	printf("Signature message: %s\n", encrypted_signature);
	printf("\n");

	// Decrypt the message with the privatekey from BOB
	if (!decrypt_message(bob_private_key, encrypted_message, RSA_PKCS1_OAEP_PADDING, &decrypted_message))
	{
		return EXIT_FAILURE;
	}
	// Output the results to the console
	printf("\n");
	printf("BOB'S PART\n");
	printf("\n");
	printf("Decrypted message: %s\n", decrypted_message);
	// Verify the signature with the publickey from ALICE
	int v = verify(alice_public_key, (char *)decrypted_message, encrypted_signature, "SHA256");
	printf("Verified  message: %s\n", v == 1 ? "Yes" : "No");
	// clean up
	RSA_free(alice_public_key); 
	RSA_free(alice_private_key); 
	RSA_free(bob_public_key); 
	RSA_free(bob_private_key); 
	//
	return EXIT_SUCCESS;
}
int decrypt_message(RSA * rsa, char * msg, int padding, unsigned char ** encoded_message)
{

	int b64len = Base64decode_len(msg);
	char * tmp = (char *) malloc(b64len);
	b64len = Base64decode(tmp, msg);

	unsigned char * enc = (unsigned char *) malloc(b64len);
	int res = RSA_private_decrypt(b64len, (unsigned char *)tmp, enc, rsa, padding);		
	if (res == -1)
	{
		char err [256];
		ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), err);
		fprintf(stderr, "%s\n", err);
		return 0;
	}

	* encoded_message = (unsigned char *) malloc(res);
	memcpy(* encoded_message, enc, res);
	// free variables
	free_variable(enc);
	free_variable(tmp);
	return 1;
}
int encrypt_message(RSA * rsa, char * msg, int padding, char ** encoded_message)
{
	// randomize by calling the RAND_seed
	if (!randomize()) { return 0; }
	// encrypt the message
	unsigned char * buf = (unsigned char *) malloc(RSA_size(rsa));	
	int len = RSA_public_encrypt(strlen(msg), (unsigned char *)msg, buf, rsa, padding);
	if (len != RSA_size(rsa))
	{
		char err [256];
		ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), err);
		fprintf(stderr, "%s\n", err);
		return 0;
	}
	// encode the message into base64	
	int b64len = Base64encode_len(len);
	* encoded_message = (char *) malloc(b64len);
	Base64encode(* encoded_message, (char *)buf, len);

	// free variables
	free_variable(buf);
	return 1;
}
int randomize()
{
	unsigned char * buf = (unsigned char *) malloc(32);
	int res = RAND_bytes(buf, 32);
	free_variable(buf);
	return res;
}
RSA * read_privatekeyfile (char * filename)
{
	FILE *fp = fopen(filename, "r");
	RSA * rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	return rsa;
}
RSA * read_publickeyfile (char * filename)
{

	FILE *fp = fopen(filename, "r");
	RSA* rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
	fclose(fp);
	return rsa;
}
int simpleSHA256(void* input, unsigned long length, unsigned char* md)
{
    SHA256_CTX context;
    if(!SHA256_Init(&context))
    {
        return 0;
    }
    if(!SHA256_Update(&context, (unsigned char*)input, length))
    {
        return 0;
    }
    if(!SHA256_Final(md, &context))
    {
        return 0;
    }
    return 1;
}
int sign(RSA * rsa, char * msg, char * algorithm, char ** encoded_message)
{
	unsigned char * signature = (unsigned char *) malloc(RSA_size(rsa));
	// compute the hash for the SHA256 algorithm
	unsigned char digest[SHA256_DIGEST_LENGTH];
	simpleSHA256(msg, strlen(msg), digest);	
	// get the NID id for hashing algorithm
	int n_id = OBJ_sn2nid(algorithm);
	unsigned int siglng;
	// now sign the hashed message
	if (!RSA_sign(n_id, digest, SHA256_DIGEST_LENGTH, signature, &siglng, rsa))
	{
		char err [256];
		ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), err);
		fprintf(stderr, "%s\n", err);
		return 0;
	}
	// encode the message into base64

	int b64len = Base64encode_len(siglng);
	* encoded_message = (char *) malloc(b64len);
	Base64encode(* encoded_message, (char *)signature, siglng);
	// free variables
	free_variable(signature);
	return 1;
}
int verify(RSA * rsa, char * msg, char * signature, char * algorithm)
{
	// get the NID id for hashing algorithm
	int n_id = OBJ_sn2nid(algorithm);
	// compute the hash for the SHA256 algorithm
	unsigned char md[SHA256_DIGEST_LENGTH];
	simpleSHA256(msg, strlen(msg), md);	
	// now verify the signature
	if (RSA_verify(n_id, md, strlen((char *)md), (unsigned char *)signature, strlen(signature), rsa) == 0)
	{		
		return 1;
	}	
	char err [256];
	ERR_load_crypto_strings();
	ERR_error_string(ERR_get_error(), err);
	fprintf(stderr, "%s\n", err);
	return 0;
}
