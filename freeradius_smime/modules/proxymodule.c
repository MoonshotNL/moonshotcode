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

typedef struct avp_struct
{
	int attr_len;
	char *attribute;
	int val_len;
	char *value;
} AVP;

typedef struct attr_req_in //In this context, references are mode to both requirements and requests. Using "req" makes the struct just that much harder to read
{
	unsigned long timestamp;
	char *dn;
	char *service;
	int required_attr_len; //Amount of attribute/value pairs required. This _len is NOT the same definition as in the AVP struct!
	AVP **required_attr; //Pointer to an array of AVPs to save them all in. Maybe discuss about this in case the struct or things I changed had to be used elsewhere
	int requested_attr_len;
	char **requested_attr; //I have not mingled with the requested attributes, but I may later in order to preserve consistency
} ATTR_REQ_IN;

typedef struct attr_req_out //I did not yet manipulate this struct. I did not take it out because it's easier to delete that it is to re-insert
{
	unsigned long timestamp;
	char *dn;
	char *service;
	int provided_attr_len;
	AVP *provided_attr;
	int requested_attr_len;
	char **requested_attr;
} ATTR_REQ_OUT\;

ATTR_REQ_IN *parse_attr_req(char *input, int len) //Input is a pointer to our URN (a pointer to a char array) and the length of this URN
{
	ATTR_REQ_IN *tmp_attr_req = rad_malloc(sizeof(ATTR_REQ_IN)); //Temporary attribute request gets allocated the right amount of size
	int input_cur = 0; //We start at the beginning, at posizion zero

	char item_tmp[STR_MAXLEN]; //Here we place the output while we are still working on it
	int item_len = 0; //
	int attr_p = 0; //Dont know what the P stands for exactly. But this value only shows up when parsing the required and requested attributes. So "attributes parsed"?

    int item_cur = 0; //Added this to initialize it, but ask Sebastiaan about it. I expect some wonky naming conventions and such, but not like this

	int state = STATE_TIMESTAMP; //We start at the first data in our URN, the timestamp

	while(input_cur < len) //We will input a new character in this loop until we have done so with all of them
	{
		switch (state) //A switch for every (attribute? data? What is the correct term?) in our URN.
		{
			case STATE_TIMESTAMP: //If we are still at the timestamp...
				if (input[input_cur] == ':') //If the current character is a seperator...
				{
					item_tmp[item_cur] = '\0'; //The seperator is forgotten, and we insurt a null terminator in our temporary storage
					tmp_attr_req->timestamp = strtol(item_tmp, NULL, 10); //strtol = string to long. Our written time is converted into a long value and inserted into the temporary struct
					state++; //The state is shifted by one, so in the next loop the switch will shown us the next datapoint
					input_cur++; //We worked with a character, so the current input shifts by one
					bzero(item_tmp, sizeof(char) * STR_MAXLEN); //Our temporary item is cleared to accept a new value
					item_cur = 0; //I do not see tmp_cur defined anywhere, nor does it ever seem to have a value other than 0. Should be item_cur probably?
					break;
				}
				item_tmp[item_cur] = input[input_cur]; //We do not have a seperator yet, so the character is added to the current temporary item
				item_cur++; //Current positon in the temporary item shifts up (basically just keeping the input and its goal synched)
				input_cur++; //See above
				break;
			case STATE_DN:
				if (input[input_cur] == ':')
				{
					item_tmp[item_cur] = '\0';
					tmp_attr_req->dn = rad_malloc(sizeof(char) * (item_cur + 1)); //The temporary request gets a size equal to the amount of characters we currently have, plus one spot for the null terminator
					memcpy(tmp_attr_req->dn, item_tmp, sizeof(char) * (item_cur + 1)); //Memoryblock is copied from temporary tp our temporary struct
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
				if (input[input_cur] == ':')
				{
					item_tmp[item_cur] = '\0';
					tmp_attr_req->required_attr_len = (int) strtol(item_tmp, NULL, 10); //The string gets converted to a long, and then parsed to an int
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
			case STATE_REQUIRED_ATTR: //We perform this, but what if the attribute_length (of this and the requested as well) is zero?
				if (input[input_cur] == ':')
				{ //In this part, the data is inserted in our struct
					item_tmp[item_cur] = '\0';

					if (attr_p == 0) //If we did not parse any attributes yet...
					{
						tmp_attr_req->required_attr = rad_malloc(sizeof(char *)); //Size is allocated for the attributes we are going to parse
						tmp_attr_req.required_attr[attr_p] = rad_malloc(sizeof(char) * (item_cur + 1));
					}
					else
					{
						tmp_attr_req->required_attr = realloc(tmp_attr_req->required_attr, sizeof(char *) * (attr_p + 1)); //Size is allocated, taking into account the size we already have
						tmp_attr_req.required_attr[attr_p] = rad_malloc(sizeof(char) * (item_cur + 1));
					}

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
				//Here we are out of the separator zone. Basically, parsing code goes in this block*****

				if(parsing_attributename){ //We perform a check to see if we are still parsing an attributename, or a value
                    if (input[input_cur] == '='){ //If we have arrived at a seperation for the attribute to the value...
                        //We take the temporary item (tmp_attr_req), and place our current 'findings' in it. We forget about the "=", but we DO insert a null terminator. Basically treat this as if we found a separator
                        //We set the parsing_attributename value to false so during the next loop we are parsing the value
                        //We REset the item_cur and shift up the input_cur by one
                        //We will also clear our current temporary storage so we can start storing the value instead
                        //We then break off the loop, since we did what we wanted with the current character
                    } else {
                        //We take the temporary string (item_temp) and place our current character in it.
                        //Item_cur and input_cur shift up by one, and a break. Pretty standard stuff.
                    }
				} else { //We are not parsinbg an attributename, so we will work on a value isntead
                    //We once again take the temporary string (item_temp) and place our character in it
                    //item_cur etc.etc. shifts. Keep in mind that the attributename is currently stored in tmp_attr_req, and this one isn't.
                    //So during the finding of the seperator, we must first place this value in the temporary item. We then have to make sure BOTH values arrive in the AVP struct we defined
				}


                item_tmp[item_cur] = input[input_cur];


				item_cur++;
				input_cur++;
				break;
				//End of the line, no code past here. HUr hur hur***************************************

			case STATE_REQUESTED_ATTR_LEN:
				if (input[input_cur] == ':')
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
				if (input[input_cur] == ':')
				{
					item_tmp[item_cur] = '\0';

					if (attr_p == 0)
					{
						tmp_attr_req->requested_attr = rad_malloc(sizeof(char *));
						tmp_attr_req.requested_attr[attr_p] = rad_malloc(sizeof(char) * (item_cur + 1));
					}
					else
					{
						tmp_attr_req->requested_attr = realloc(tmp_attr_req->required_attr, sizeof(char *) * (attr_p + 1));
						tmp_attr_req.requested_attr[attr_p] = rad_malloc(sizeof(char) * (item_cur + 1));
					}


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

int create_output_request(ATTR_REQ_IN *input, char *output)
{
	ATTR_REQ_OUT outstruct;
	outstruct.timestamp = (long) time(0);
	outstruct.dn =
	output = malloc(5);
	strcpy(output, "abcd");
	return 0;
}

void handle_client_request(){
    VALUE_PAIR *vp = request->packet->vps;
	do
	{
		if (vp->attribute == ATTR_SMIME_REQUEST)
		{
			handle_request(request, vp);
		}
	} while ((vp = vp->next) != 0)
}

void idp_handle_requests(REQUEST *request)
{
	VALUE_PAIR *vp = request->packet->vps;
	do
	{
		if (vp->attribute == ATTR_SMIME_REQUEST)
		{
			handle_request(request, vp);
		} else if (vp->attribute == ATTR_SMIME_REQUEST){

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

	output_len = create_output_request(attr_request, &output_data);
}
