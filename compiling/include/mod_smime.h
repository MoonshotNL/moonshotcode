#ifndef MOD_SMIME_H
#define MOD_SMIME_H

extern int pack_mime_text(char *input, int len, char **output);
extern int unpack_mime_text(char *input, int len, char **output);

extern int pack_mime_cert(X509 *input, char **output);
extern void unpack_mime_cert(char *input, int len, X509 **output);

extern int pack_smime_text(char *input, int len, RSA *pubkey, char **output);
extern int unpack_smime_text(char *input, int len, RSA *privkey, char **output);

#endif
