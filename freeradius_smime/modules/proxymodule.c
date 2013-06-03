#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/radius.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/libradius.h>

#include "common.h"
#include "mod_mime.h"

#define STR_MAXLEN					1024

#define STATE_TIMESTAMP				0 //These are the different points of data present in our URN.
#define STATE_PROXYDN               1 //We use these states to keep track of our position.
#define STATE_SERVICEDN				2
#define STATE_REQUIRED_ATTR_LEN		3
#define STATE_REQUIRED_ATTR			4
#define STATE_REQUESTED_ATTR_LEN	5
#define STATE_REQUESTED_ATTR		6

#ifndef PKCSCERT
typedef struct pkcs
{
	int pubkey;
} PKCSCERT;
#endif

typedef struct avp_struct //This is a structure for an AttributeValue Pair
{
	int attr_len; //This is the length of the attribute string. Can be used for safety, but this is not currently done or saved.
	char *attribute; //The Attributename of this pair
	int val_len;
	char *value; //The Value of this pair
} AVP;

typedef struct attr_req_in //This is a structure for an Incoming Attribute Request.
{
	unsigned long timestamp; //We keep track of the timestamp
	char *proxydn; //The Domain Name of the targeted proxy
	char *servicedn; //The Domain Name of the targeted service
	int required_attr_len; //Amount of required attribute/value pairs we can expect
	AVP **required_attr; //An array of AVPs. See above Struct for details on what is included in here
	int requested_attr_len; //Amount of requested attributed we can expect
	char **requested_attr; //Since these AVPs are not yet known at this position, we simply save the data here as a char-array rather than an AVP struct
} ATTR_REQ_IN;

typedef struct attr_req_out
{
	unsigned long timestamp;
	char *proxydn;
	char *servicedn;
	int provided_attr_len;
	AVP **provided_attr;
	int requested_attr_len;
	char **requested_attr;
} ATTR_REQ_OUT;

ATTR_REQ_IN *parse_attr_req(char *input, int len) //Input is our URN and it's length
{
	ATTR_REQ_IN *tmp_attr_req = rad_malloc(sizeof(ATTR_REQ_IN)); //Temporary Attribute Request gets allocated some size. We use this temporary one to keep our data while we are still parsing the rest of the URN

	int input_cur = 0; //We start at the beginning of the URN, at posizion zero
    int item_len = 0; //The length of the string we found
	int attr_p = 0; //Dont know what the P stands for exactly. But this value only shows up when parsing the required and requested attributes. So "attributes parsed"?
    int item_cur = 0; //Added this to initialize it, but ask Sebastiaan about it. I expect some wonky naming conventions and such, but not like this

    bool parsing_attributename = true;

    char item_tmp[STR_MAXLEN]; //Here we place the output while we are still working on it

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
			case STATE_PROXYDN:
				if (input[input_cur] == ':')
				{
					item_tmp[item_cur] = '\0';
					tmp_attr_req->dn = rad_malloc(sizeof(char) * (item_cur + 1)); //The temporary request gets a size equal to the amount of characters we currently have, plus one spot for the null terminator
					memcpy(tmp_attr_req->dn, item_tmp, sizeof(char) * (item_cur + 1)); //Memoryblock is copied from temporary tp our temporary struct
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
					tmp_attr_req->required_attr_len = (int) strtol(item_tmp, NULL, 10); //The string gets converted to a long, and then parsed to an int
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
			case STATE_REQUIRED_ATTR: //We perform this, but what if the attribute_length (of this and the requested as well) is zero?
				if(tmp_attr_req->required_attr_len <= 0){
                    state ++;
                    break;
				}
				if (input[input_cur] == ':') //A separator means we should have seen both our attributename and value by now
				{ //So in this part, the data is inserted in our struct
					item_tmp[item_cur] = '\0'; //The value still needs to be saved in our temporary file first, so we add a null terminator here as well
                    tmp_attr_req->required_attr[attr_p]->value = rad_malloc(sizeof(char) * (item_cur + 1)); //The temporary request gets a size equal to the amount of characters we currently have, plus one spot for the null terminator
                    memcpy(tmp_attr_req->required_attr[attr_p]->value, item_tmp, sizeof(char) * (item_cur + 1)); //Memoryblock is copied from temporary tp our temporary struct
                    input_cur++;
                    bzero(item_tmp, sizeof(char) * STR_MAXLEN); //We will also clear our current temporary storage so we can start storing an attributename again
                    item_cur = 0; //We REset the item_cur and shift up the input_cur by one
                    parsing_attributename != parsing_attributename; //We set the parsing_attributename value to true so during the next loop we are parsing an attributename again

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
				//Here we are out of the separator zone. Basically, parsing code goes in this block*****

				if(parsing_attributename){ //We perform a check to see if we are still parsing an attributename, or a value
                    if (input[input_cur] == '='){ //If we have arrived at a seperation for the attribute to the value...
                        item_tmp[item_cur] = '\0'; //We take the temporary item (tmp_attr_req), and place our current 'findings' in it. We forget about the "=", but we DO insert a null terminator. Basically treat this as if we found a separator
                        tmp_attr_req->required_attr[attr_p]->attribute = rad_malloc(sizeof(char) * (item_cur + 1)); //The temporary request gets a size equal to the amount of characters we currently have, plus one spot for the null terminator
                        memcpy(tmp_attr_req->required_attr[attr_p]->attribute, item_tmp, sizeof(char) * (item_cur + 1)); //Memoryblock is copied from temporary tp our temporary struct
                        //The AVP struct currently does not use the string lengths, so they are not set. If you would like to set them, THIS is the place.
                        input_cur++;
                        bzero(item_tmp, sizeof(char) * STR_MAXLEN); //We will also clear our current temporary storage so we can start storing the value instead
                        item_cur = 0; //We REset the item_cur and shift up the input_cur by one
                        parsing_attributename != parsing_attributename; //We set the parsing_attributename value to false so during the next loop we are parsing the value
                        break; //We then break off the loop, since we did what we wanted with the current character
                     } else {
                        item_tmp[item_cur] = input[input_cur];//We take the temporary string and place our current character in it.
                        item_cur++; //Item_cur and input_cur shift up by one, and a break. Pretty standard stuff.
                        input_cur++;
                        break;
                    }
				} else {
				    item_tmp[item_cur] = input[input_cur];//We take the temporary string and place our current character in it.
                    item_cur++; //Item_cur and input_cur shift up by one, and a break. Pretty standard stuff.
                    input_cur++;
                    break;
                }

                //item_tmp[item_cur] = input[input_cur];
				//item_cur++;
				//input_cur++;

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
					item_cur = 0;
					break;
				}
				item_tmp[item_cur] = input[input_cur];
				item_cur++;
				input_cur++;
				break;
			case STATE_REQUESTED_ATTR:
			    if(tmp_attr_req->requested_attr_len <= 0){
                    state ++;
                    break;
				}
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

/*
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
*/
void handle_requests_idp(REQUEST *request)
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
