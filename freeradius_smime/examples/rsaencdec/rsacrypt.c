/* rsacrypt, v.1.1
 * Written 3 Jan 2008 by John T. Wodder II
 * Last edited 21 Jan 2008 by John Wodder
 *
 * This program uses the OpenSSL libcrypto cryptographic library to perform RSA
 * encryption & decryption on files of arbitrary length.  It was written mainly
 * because I couldn't find a program that already did this.
 */

/* Things that need to be addressed:
 - This program assumes PKCS #1 v1.5 padding; support for other padding schemes
   needs to be added.
 - The return value of fwrite() should probably be checked.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define checkMem(p)  if (!p) {fprintf(stderr, "rsacrypt: %s: l.%d: failure to allocate memory: ", __FILE__, __LINE__); perror(NULL); exit(1); }

#define pathToStd(s) (s[0] == '-' && s[1] == '\0')

typedef int (*rsaFunc)(int, const unsigned char*, unsigned char*, RSA*, int);

int main(int argc, char** argv) {
 ERR_load_crypto_strings();
 OpenSSL_add_all_ciphers();
 _Bool encrypt=1, private=1;
 char *outf = NULL, *keyf = NULL;
 int ch;
 while ((ch = getopt(argc, argv, "o:dek:pPhV")) != -1) {
  switch (ch) {
   case 'o': outf = optarg; break;
   case 'd': encrypt = 0; break;
   case 'e': encrypt = 1; break;
   case 'k': keyf = optarg; break;
   case 'p': private = 1; break;
   case 'P': private = 0; break;
   case 'h': 
    printf("Usage: rsacrypt [-e | -d] -k keyfile [-o outfile] [-p | -P] "
     "[infile]\n       rsacrypt [-h | -V]\n\nOptions:\n"
     "  -e - encrypt the input file (default)\n"
     "  -d - decrypt the input file\n"
     "  -h - display this help message & exit\n"
     "  -k keyfile - specifies the input key file (required)\n"
     "  -o outfile - write output to `outfile'\n"
     "  -p - encrypt/decrypt using a private key (default)\n"
     "  -P - encrypt/decrypt using a public key\n"
     "  -V - display version information & exit\n");
    return 0;
   case 'V':
    printf("rsacrypt, v.1.1, a wrapper around OpenSSL for RSA file encryption\n"
     "Written by John T. Wodder II <minimiscience@users.sourceforge.net>\n"
     "Compiled %s, %s\n\n", __DATE__, __TIME__);
    return 0;
   default: fprintf(stderr, "Usage: rsacrypt [-e | -d] -k keyfile [-o outfile]"
    " [-p | -P] [infile]\n       rsacrypt [-h | -V]\n");
    return 2;
  }
 }
 FILE *infile, *outfile, *keyfile;
 if (optind < argc && !pathToStd(argv[optind])) {
  infile = fopen(argv[optind], "rb");
  if (!infile) {
   fprintf(stderr, "rsacrypt: could not read file `%s': ", argv[optind]);
   perror(NULL); exit(1);
  }
 } else {infile = stdin; }
 if (!outf || pathToStd(outf)) {outfile = stdout; }
 else {
  outfile = fopen(outf, "wb");
  if (!outfile) {
   fprintf(stderr, "rsacrypt: could not write to file `%s': ", outf);
   perror(NULL); exit(1);
  }
 }
 if (!keyf) {
  fprintf(stderr, "rsacrypt: input key file not specified\n"); exit(1);
 } else if (pathToStd(keyf)) {keyfile = stdin; }
 else {
  keyfile = fopen(keyf, "r");
  if (!keyfile) {
   fprintf(stderr, "rsacrypt: could not read from input key file `%s': ", keyf);
   perror(NULL); exit(1);
  }
 }
 RSA* key;
 if (private) key = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
 else key = PEM_read_RSA_PUBKEY(keyfile, NULL, NULL, NULL);
  /* PEM_read_RSAPublicKey() was apparently the wrong function. */
 if (!key) {ERR_print_errors_fp(stderr); exit(1); }
 if (keyfile != stdin) fclose(keyfile);
 rsaFunc cryptFunc = encrypt ?
  (private ? RSA_private_encrypt : RSA_public_encrypt)
  : (private ? RSA_private_decrypt : RSA_public_decrypt);
 int keySize = RSA_size(key);
 int insize = keySize - (encrypt ? 12 : 0);
 unsigned char* instr = calloc(insize, sizeof(char));
 checkMem(instr);
 unsigned char* outstr = calloc(keySize-(encrypt ? 0 : 12), sizeof(char));
 checkMem(outstr);
 for (;;) {
  size_t len = fread(instr, sizeof(char), insize, infile);
  if (len==0) {
   if (feof(infile)) break;
   else {
    fprintf(stderr, "rsacrypt: error reading from input: ");
    perror(NULL); exit(1);
   }
  } else if (!encrypt && len != keySize) {
   fprintf(stderr, "rsacrypt: input incorrectly sized for decryption: "
    "trailing characters ignored\n");
   exit(1);
  }
  size_t outlen = cryptFunc(len, instr, outstr, key, RSA_PKCS1_PADDING);
  if (outlen == -1) {ERR_print_errors_fp(stderr); exit(1); }
  fwrite(outstr, sizeof(char), outlen, outfile);
  /* Should the return value of fwrite() be checked? */
 }
 free(instr); free(outstr);
 if (infile != stdin) fclose(infile);
 if (outfile != stdout) fclose(outfile);
 RSA_free(key);
 EVP_cleanup();
 ERR_free_strings();
 return 0;
}
