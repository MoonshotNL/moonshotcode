#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/radius.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/libradius.h>

#include "common.h"
#include "mod_mime.h"

#define STR_MAXLEN					1024
#define ATTR_MAXLEN					16

#define STATE_TIMESTAMP				0
#define STATE_DN					1
#define STATE_REQUIRED_ATTR_LEN		2
#define STATE_REQUIRED_ATTR			3
#define STATE_REQUESTED_ATTR_LEN	4
#define STATE_REQUESTED_ATTR		5

#ifndef PKCSCERT
typedef struct pkcs
{
	int pubkey;
} PKCSCERT;
#endif

typedef struct attr_req
{
	unsigned long timestamp;
	char *dn;
	char *service;
	int required_attr_len;
	char *required_attr[ATTR_MAXLEN];
	int requested_attr_len;
	char *requested_attr[ATTR_MAXLEN];
} ATTR_REQ;

ATTR_REQ *parse_attr_req(char *input, int len)
{
	ATTR_REQ *tmp_attr_req = rad_malloc(sizeof(ATTR_REQ));
	int input_cur = 0;
	
	char item_tmp[STR_MAXLEN];
	int item_len = 0;
	int attr_p = 0;
	
	int state = STATE_TIMESTAMP;
	
	while(input_cur < len)
	{
		switch (state)
		{
			case STATE_TIMESTAMP:
				if (input[input_cur] == ':')
				{
					item_tmp[item_cur] = '\0';
					tmp_attr_req->timestamp = strtol(item_tmp, NULL, 10);
					state++;
					input_cur++;
					bzero(item_tmp, sizeof(char) * STR_MAXLEN);
					tmp_cur = 0;
					break;
				}
				item_tmp[item_cur] = input[input_cur];
				item_cur++;
				input_cur++;
				break;
			case STATE_DN:
				if (input[input_cur] == ":")
				{
					item_tmp[item_cur] = '\0';
					tmp_attr_req->dn = rad_malloc(sizeof(char) * (item_cur + 1));
					memcpy(tmp_attr_req->dn, item_tmp, sizeof(char) * (item_cur + 1));
					state++;
					input_cur++;
					bzero(item_tmp, sizeof(char) * STR_MAXLEN);
					tmp_cur = 0;
					break;
				}
				item_tmp[item_cur] = input[input_cur];
				item_cur++;
				input_cur++;
				break;
			case STATE_REQUIRED_ATTR_LEN:
				if (input[input_cur] == ":")
				{
					item_tmp[item_cur] = '\0';
					tmp_attr_req->required_attr_len = (int) strtol(item_tmp, NULL, 10);
					state++;
					input_cur++;
					bzero(item_tmp, sizeof(char) * STR_MAXLEN);
					tmp_cur = 0;
					break;
				}
				item_tmp[item_cur] = input[input_cur];
				item_cur++;
				input_cur++;
				break;
			case STATE_REQUIRED_ATTR:
				if (input[input_cur] == ":")
				{
					item_tmp[item_cur] = '\0';
					
					tmp_attr_req.required_attr[attr_p] = rad_malloc(sizeof(char) * (item_cur + 1));
					memcpy(tmp_attr_req.required_attr[attr_p], item_tmp, sizeof(char) * (item_cur + 1));
					attr_p++;
					
					if (attr_p >= tmp_attr_req->required_attr_len)
					{
						state++;
						attr_p = 0;
					}
					input_cur++;
					bzero(item_tmp, sizeof(char) * STR_MAXLEN);
					tmp_cur = 0;
					break;
				}
				item_tmp[item_cur] = input[input_cur];
				item_cur++;
				input_cur++;
				break;
			case STATE_REQUESTED_ATTR_LEN:
				if (input[input_cur] == ":")
				{
					item_tmp[item_cur] = '\0';
					tmp_attr_req->requested_attr_len = (int) strtol(item_tmp, NULL, 10);
					state++;
					input_cur++;
					bzero(item_tmp, sizeof(char) * STR_MAXLEN);
					tmp_cur = 0;
					break;
				}
				item_tmp[item_cur] = input[input_cur];
				item_cur++;
				input_cur++;
				break;
			case STATE_REQUESTED_ATTR:
				if (input[input_cur] == ":")
				{
					item_tmp[item_cur] = '\0';
					
					tmp_attr_req.requested_attr[attr_p] = rad_malloc(sizeof(char) * (item_cur + 1));
					memcpy(tmp_attr_req.requested_attr[attr_p], item_tmp, sizeof(char) * (item_cur + 1));
					attr_p++;
					
					if (attr_p >= tmp_attr_req->requested_attr_len)
					{
						state++;
						attr_p = 0;
					}
					input_cur++;
					bzero(item_tmp, sizeof(char) * STR_MAXLEN);
					tmp_cur = 0;
					break;
				}
				item_tmp[item_cur] = input[input_cur];
				item_cur++;
				input_cur++;
				break;
		}
	}

	return tmp_attr_req;
}

int create_output_data(char *input, int input_len, char *output)
{
	output = malloc(5);
	strcpy(output, "abcd");
	return 0;
}

void idp_handle_requests(REQUEST *request)
{
	VALUE_PAIR *vp = request->packet->vps;
	do
	{
		if (vp->attribute == ATTR_SMIME_REQUEST)
		{
			handle_request(request, vp);
		}
	} while ((vp = vp->next) != 0)
}

void handle_request(REQUEST *request, VALUE_PAIR *vp)
{
	char *input_data;
	int input_len;
	char *output_data;
	int output_len;
	
	input_len = mime_unpack_attrrequest(vp->data.octets, vp->length, &input_data);
	ATTR_REQ *attr_request = parse_attr_req(data, len);
	if (!attr_request)
	{
		return;
	}

	PKCSCERT *cert = get_matching_certificate(request, attr_request->dn);
	if (!cert)
	{
		return;
	}
	
	output_len = create_output_request(input_data, input_len, &output_data);
}