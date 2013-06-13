#ifndef COMMON_H
#define COMMON_H

#define ATTR_MOONSHOT_CERTIFICATE 245
#define ATTR_MOONSHOT_REQUEST 246
#define ATTR_MOONSHOT_IDPREPLY	247
#define ATTR_MOONSHOT_PROXYREPLY	248

typedef struct rlm_moonshot_t {
	char		*pub_key;
    char        *priv_key;
    char        *priv_key_password;
} rlm_moonshot_t;


#endif
