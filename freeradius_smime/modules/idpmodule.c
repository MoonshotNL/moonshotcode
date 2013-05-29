#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/radius.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/libradius.h>

#include "common.h"
#include "mod_mime.h"

#define STR_MAXLEN					1024

#define STATE_TIMESTAMP				0
#define STATE_PROXYDN				1
#define STATE_SERVICEDN				2
#define STATE_REQUIRED_ATTR_LEN		3
#define STATE_REQUIRED_ATTR			4
#define STATE_REQUESTED_ATTR_LEN	5
#define STATE_REQUESTED_ATTR		6

typedef struct avp_struct
{
	int attr_len;
	char *attribute;
	int val_len;
	char *value;
} AVP;

typedef struct attr_req_in
{
	unsigned long timestamp;
	char *proxydn;
	char *servicedn;
	int required_attr_len;
	char **required_attr;
	int requested_attr_len;
	char **requested_attr;
} ATTR_REQ_IN;

typedef struct attr_req_out
{
	unsigned long timestamp;
	char *servicedn;
	int provided_attr_len;
	AVP *provided_attr;
	int requested_attr_len;
	char **requested_attr;
} ATTR_REQ_OUT;

ATTR_REQ_IN *parse_attr_req(char *input, int len)
{
	ATTR_REQ_IN *tmp_attr_req = rad_malloc(sizeof(ATTR_REQ_IN));
	int input_cur = 0;
	
	char item_tmp[STR_MAXLEN];
	int item_len = 0;
	int item_cur = 0;
	
	int attr_p = 0;
	
	int state = STATE_TIMESTAMP;
	
	while(input_cur <= len)
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
					item_cur = 0;
					break;
				}
				item_tmp[item_cur] = input[input_cur];
				item_cur++;
				input_cur++;
				break;
			case STATE_PROXYDN:
				if (input[input_cur] == ':')
				{
					item_tmp[item_cur] = '\0';
					tmp_attr_req->proxydn = rad_malloc(sizeof(char) * (item_cur + 1));
					memcpy(tmp_attr_req->proxydn, item_tmp, sizeof(char) * (item_cur + 1));
					state++;
					input_cur++;
					bzero(item_tmp, sizeof(char) * STR_MAXLEN);
					item_cur = 0;
					break;
				}
				item_tmp[item_cur] = input[input_cur];
				item_cur++;
				input_cur++;
				break;
			case STATE_SERVICEDN:
				if (input[input_cur] == ':')
				{
					item_tmp[item_cur] = '\0';
					tmp_attr_req->servicedn = rad_malloc(sizeof(char) * (item_cur + 1));
					memcpy(tmp_attr_req->servicedn, item_tmp, sizeof(char) * (item_cur + 1));
					state++;
					input_cur++;
					bzero(item_tmp, sizeof(char) * STR_MAXLEN);
					item_cur = 0;
					break;
				}
				item_tmp[item_cur] = input[input_cur];
				item_cur++;
				input_cur++;
				break;
			case STATE_REQUIRED_ATTR_LEN:
				if (input[input_cur] == ':')
				{
					item_tmp[item_cur] = '\0';
					tmp_attr_req->required_attr_len = (int) strtol(item_tmp, NULL, 10);

					if (tmp_attr_req->required_attr_len == 0)
					{
						state += 2;
					}
					else
					{
						state++;
					}

					input_cur++;
					bzero(item_tmp, sizeof(char) * STR_MAXLEN);
					item_cur = 0;
					break;
				}
				item_tmp[item_cur] = input[input_cur];
				item_cur++;
				input_cur++;
				break;
			case STATE_REQUIRED_ATTR:
				if (input[input_cur] == ':')
				{
					item_tmp[item_cur] = '\0';
					
					if (attr_p == 0)
					{
						tmp_attr_req->required_attr = rad_malloc(sizeof(char *));
						tmp_attr_req->required_attr[attr_p] = rad_malloc(sizeof(char) * (item_cur + 1));
					}
					else
					{
						tmp_attr_req->required_attr = realloc(tmp_attr_req->required_attr, sizeof(char *) * (attr_p + 1));
						tmp_attr_req->required_attr[attr_p] = rad_malloc(sizeof(char) * (item_cur + 1));
					}

					memcpy(tmp_attr_req->required_attr[attr_p], item_tmp, sizeof(char) * (item_cur + 1));
					attr_p++;
					
					if (attr_p >= tmp_attr_req->required_attr_len)
					{
						state++;
						attr_p = 0;
					}
					input_cur++;
					bzero(item_tmp, sizeof(char) * STR_MAXLEN);
					item_cur = 0;
					break;
				}
				item_tmp[item_cur] = input[input_cur];
				item_cur++;
				input_cur++;
				break;
			case STATE_REQUESTED_ATTR_LEN:
				if (input[input_cur] == ':')
				{
					item_tmp[item_cur] = '\0';
					tmp_attr_req->requested_attr_len = (int) strtol(item_tmp, NULL, 10);
					
					if (tmp_attr_req->required_attr_len == 0)
					{
						state += 2;
					}
					else
					{
						state++;
					}

					input_cur++;
					bzero(item_tmp, sizeof(char) * STR_MAXLEN);
					item_cur = 0;
					break;
				}
				item_tmp[item_cur] = input[input_cur];
				item_cur++;
				input_cur++;
				break;
			case STATE_REQUESTED_ATTR:
				if (input_cur == len)
				{
					item_tmp[item_cur] = '\0';
					
					if (attr_p == 0)
					{
						tmp_attr_req->requested_attr = rad_malloc(sizeof(char *));
						tmp_attr_req->requested_attr[attr_p] = rad_malloc(sizeof(char) * (item_cur + 1));
					}
					else
					{
						tmp_attr_req->requested_attr = realloc(tmp_attr_req->required_attr, sizeof(char *) * (attr_p + 1));
						tmp_attr_req->requested_attr[attr_p] = rad_malloc(sizeof(char) * (item_cur + 1));
					}

					
					memcpy(tmp_attr_req->requested_attr[attr_p], item_tmp, sizeof(char) * (item_cur + 1));
					attr_p++;
					
					if (attr_p >= tmp_attr_req->requested_attr_len)
					{
						state++;
						attr_p = 0;
					}
					input_cur++;
					bzero(item_tmp, sizeof(char) * STR_MAXLEN);
					item_cur = 0;
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

ATTR_REQ_OUT *get_attr_req_out(ATTR_REQ_IN *input)
{
	ATTR_REQ_OUT *outstruct;
	outstruct = rad_malloc(sizeof(ATTR_REQ_OUT));
	memset(outstruct, 0, sizeof(ATTR_REQ_OUT));
	
	outstruct->servicedn = input->servicedn;
	outstruct->provided_attr_len = input->required_attr_len;
	outstruct->provided_attr = get_avps_by_attributes(input->required_attr, input->required_attr_len);
	outstruct->requested_attr_len = input->requested_attr_len;
	outstruct->requested_attr = input->requested_attr;
	outstruct->timestamp = (long) time(0);

	return outstruct;
}

int attr_req_out_to_string(ATTR_REQ_OUT *input, char **output)
{
	int i;
	char *tpm_string; //= rad_malloc(sizeof(char) * STR_MAXLEN);
	int total_length = 0;
	int timestamp_strlen = 0;
	int servicedn_strlen = 0;
	int provided_attr_len_strlen = 0;
	int provided_attr_strlen[input->provided_attr_len];
	int requested_attr_len_strlen = 0;
	int requested_attr_strlen[input->requested_attr_len];
	
	//Calculate the total length of the resulting string
	
	//input->timestamp
	digittest = input->timestamp;
	while (digittest != 0) { digittest /= 10; timestamp_strlen++; }
	length += timestamp_strlen;
	length++; //The ':' delimiter
	
	//input->servicedn
	servicedn_strlen += strlen(input->servicedn);
	length += servicedn_strlen;
	length++;
	
	//input->provided_attr_len
	digittest = (long) input->provided_attr_len;
	while (digittest != 0) { digittest /= 10; provided_attr_len_strlen++; }
	length += provided_attr_len_strlen;
	length++;
	
	//input->provided_attr
	for (i = 0; i < input->provided_attr_len; i++)
	{
		provided_attr_strlen[i] = 0;
		provided_attr_strlen[i] = strlen(input->provided_attr[i].attribute);
		length += provided_attr_strlen[i];
		length++; //'='
		length += strlen(input->provided_attr[i].value);
		length++;
	}
	
	//input->requested_attr_len
	digittest = (long) input->requested_attr_len;
	while (digittest != 0) { digittest /= 10; length++; }
	length++:
	
	//input->requested_attr
	for (i = 0; i < input->requested_attr_len; i++)
	{
		length += strlen(input->requested_attr[i]);
		length++;
	}
	length++ //'\0'

	sprintf(tmp_string, "%ld:", input->timestamp);
	sprintf(tmp_string, "%s:", input->servicedn);
	sprintf(tmp_string, "%i", input->provided_attr_len);
	for (i = 0; i < input->provided_attr_len)
	{
		sprintf(tmp_string, "%s=%s:", input->provided_attr[i].attribute, input->provided_attr[i].value);
	}
	sprintf(tmp_string, "i", input->requested_attr_len);
	for (i = 0; i < input->requested_attr_len; i++)
	{
		sprintf(
	}
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
	ATTR_REQ_OUT *outstruct;
	
	input_len = mime_unpack_attrrequest(vp->data.octets, vp->length, &input_data);
	ATTR_REQ *attr_request = parse_attr_req(input_data, input_len);
	if (!attr_request)
	{
		return;
	}

	PKCSCERT *cert = get_matching_certificate(request, attr_request->dn);
	if (!cert)
	{
		return;
	}
	
	outstruct = get_attr_req_out(attr_request);
	output_len = attr_req_out_to_string(outstruct, &output_data);
}