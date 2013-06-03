/*
*The Attribute_Finder is used to find and/or extract Attribute/Value Pairs from a custom URN.
*The structure of the URN = TIME:DN:SERVICE:REQUIRED-ATTRIBUTE-LENGTH:REQUIRED-ATTRIBUTE#1:REQUIRED-ATRIBUTE#N:REQUESTED-ATTRIBUTE-LENGTH:REQUESTED-ATTRIBUTE#1:REQUESTED-ATTRIBUTE#N
*The idea is to cycle through all of this and then take out the amount of attributes (ATTRIBUTE_LENGTH) and the attributes themselves (ATTRIBUTE).
*This goes for both requested and required. Pay attention to attributes we do not yet know, and attributes we can expect zero of.
*Extracted attributes should then be saved in such a way they can later be requested from the VOMS server, or included in a function that will make a URN for us.
*/
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/radius.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/libradius.h>

#include "common.h"
#include "mod_mime.h"

#define STATE_IRRELEVANT			0 //These are the different points of data present in our URN.
#define STATE_LENGTH                1 //When we are finding the amount of attributes we can expect (both required and requested)
#define STATE_REQUIREDATTRIBUTEVALUEPAIR    2 //Working with a required AVP
#define STATE_REQUESTEDATTRIBUTEVALUEPAIR   3 //Working with a requested AVP

#define URN_OFFSET                  3 //The offset tells us how at what part of the URN we should look. The data starts to become relevant after the third point of data, which is the amount off attribute we can expect.

typedef struct generic_attribute_value_pair {
    char *attribute;
	char *value;
} GENERIC_AVP;

//Function returns an 'array' of all attribute/value pairs. Basically cycle through the URN, extract each AVP, and add it to the array.
AVP **find_all_attributevalue_pairs(char *urn){
    //Create an array of AVPs of both types.
    GENERIC_AVP *attribute_value_pair;
    *attribute_value_pair = cycle_urn();
    return attribute_value_pair;
}

//required zijn er, requested niet
//required parse je gewoon
//requested sla je de attributenames van op
//dan gebeurt er magic en worden de values erbij gezet

GENERIC_AVP *cycle_urn(char *urn){
    //Scroll through URN until you find the required data point (REQUIRED-ATTRIBUTE-LENGTH, the fourth one, so after three separators).

    GENERIC_AVP *gen_avp = rad_malloc(sizeof(GENERIC_AVP)); //An array of AVPs. We will fill this and return this as output.

	int input_cur = 0; //We start at the beginning of the URN, at posizion zero
	int item_cur = 0; //The current position ('cursor') of the temporary item we are writing to.
    //int item_len = 0; //The length of the string we found
	int item_p = 0; //Amount of items we parsed. We use this to track whether or not we have arrived at the relevant parts yet.
	int required_attr_p = 0; //Required attributes we parsed so far
	int requested_attr_p = 0; //Requested attributes we parsed so far

    int required_length = 0; //The amount of required attributes we can expect.
    int requested_length = 0; //The amount of requested attributes we can expect.

    char item_tmp[STR_MAXLEN]; //Here we place the output while we are still working on it

	int state = STATE_IRRELEVANT; //When we first start working our way through the URN, the first points of data are all irrelevant to us.

	while(input_cur < sizeof(urn)) //Do not know if this works yet, my itnernet is gone. Check when I have access again.
	{
		switch (state) //A switch for every (attribute? data? What is the correct term?) in our URN.
		{
        case STATE_IRRELEVANT:
            if(urn[input_cur] != ':'){ //As long as we do not find a seperator, we move on in this stage.
                input_cur++; //We shift the input ahead by one.
            } else {
                input_cur++; //In the event of finding a seperator, we must still move the input by one...
                item_p++; //But the amount of items we parsed goes up by one as well.
                if(item_p == URN_OFFSET){ //If the amount of items we parsed is equal to the offset, it means we (should have) went through all items that are irrelevant.
                    state = STATE_LENGTH; //We will now arrive at the part that is relevant: the amount of attributes we must parse.
                }
            }
            break;
        case STATE_LENGTH:
            if(urn[input_cur] != ':'){
                item_tmp[item_cur] = input[input_cur];
                item_cur++;
                input_cur++;
                break;
            } else {
                item_tmp[item_cur] = '\0'; //We insert a null-terminator since we're at the end of the string
            if(item_p == URN_OFFSET){ //If the amount of items parsed is still only as big as the offset, it means we are at REQUIRED_ATTRIBUTE_LENGTH
                    required_length = (int) strtol(item_tmp, NULL, 10); //The string gets converted to a long, and then parsed to an int
					state = STATE_REQUIREDATTRIBUTEVALUEPAIR; //In the next loop, we will parse the required AVPs
				} else { //If the amount of items parsed is bigger, we have arrived at REQUESTED_ATTRIBUTE_LENGTH
                    requested_length = (int) strtol(item_tmp, NULL, 10); //The string gets converted to a long, and then parsed to an int
					state = STATE_REQUESTEDATTRIBUTEVALUEPAIR; //In the next loop, we will parse the requested AVPs
                }
                input_cur++; //After we parsed our value, we shift the input cursor by one
                item_cur = 0; //We reset the item cursor
                bzero(item_tmp, sizeof(char) * STR_MAXLEN); //Clear the temporary item
                item_p++; //And the amount of items we parsed goes up by one.
                break;
            }
        case STATE_REQUIREDATTRIBUTEVALUEPAIR:
            //We must now extract an AVP. To do this, we take the entire string up until the next seperator, and feed it to extract_AVP. extract_AVP takes cares of the AVP itself, so we do not bother with that here.
            if(urn[input_cur] != ':'){
                item_tmp[item_cur] = input[input_cur];
                item_cur++;
                input_cur++;
            } else {
                gen_avp[required_attr_p] = extract_valuepair(item_tmp, true);
                bzero(item_tmp, sizeof(char) * STR_MAXLEN); //We clear the temporary item so it is ready to accept a new value.
                item_p++;
                item_cur = 0;
                required_attr_p++;
                attr_len;
                if(required_attr_p >= required_length){ //If we parsed all the attributes we were told to...
                    state = STATE_LENGTH; //We are once again ready to receive a length, this time the REQUESTED one.
                }
            }
            break;
        case STATE_REQUESTEDATTRIBUTEVALUEPAIR:
            //We must now extract an AVP. To do this, we take the entire string up until the next seperator, and feed it to extract_AVP. extract_AVP takes cares of the AVP itself, so we do not bother with that here.
            if(urn[input_cur] != ':'){
                item_tmp[item_cur] = input[input_cur];
                item_cur++;
                input_cur++;
            } else {
                gen_avp[required_attr_p+requested_attr_p+1] = extract_valuepair(item_tmp, false); //This avp is inserted one value after the previous one, adjusting for the required attributes we already inserted.
                bzero(item_tmp, sizeof(char) * STR_MAXLEN); //We clear the temporary item so it is ready to accept a new value.
                item_p++;
                item_cur = 0;
                requested_attr_p++;
                if(requested_attr_p >= requested_length){ //If we parsed all the attributes we were told to...
                    break; //We should now be done with this URN.
                }
            }
            break;
        case default:
            //Something must have gone terribly wrong to arrive here.
            //Do some error-handling here if there is time left.
            break;
		}
	}
    return gen_avp;
}

AVP extract_valuepair(char *raw_valuepair, bool is_required){
    GENERIC_AVP tmp_avp; //Temporary AVP

    bool parsing_attributename = true; //We always start with the parsing of an attributename
    int input_cur = 0; //Input cursor
    char item_tmp[STR_MAXLEN]; //Temporary item
    int item_cur = 0; //Item cursor

    if(is_required){ //If our AVP is required, it means both the attributename and vlaue are in there already
        if (raw_valuepair[input_cur] >= sizeof(raw_valuepair)) //A separator means we should have seen both our attributename and value by now
				{ //So in this part, the data is inserted in our struct
					item_tmp[item_cur] = '\0'; //The value still needs to be saved in our temporary file first, so we add a null terminator here as well
                    tmp_avp->value = rad_malloc(sizeof(char) * (item_cur + 1)); //The temporary request gets a size equal to the amount of characters we currently have, plus one spot for the null terminator
                    memcpy(tmp_avp->value, item_tmp, sizeof(char) * (item_cur + 1)); //Memoryblock is copied from temporary tp our temporary struct
                    input_cur++;
                    bzero(item_tmp, sizeof(char) * STR_MAXLEN); //We will also clear our current temporary storage so we can start storing an attributename again
                    item_cur = 0; //We REset the item_cur and shift up the input_cur by one
                    parsing_attributename != parsing_attributename; //We set the parsing_attributename value to true so during the next loop we are parsing an attributename again
					bzero(item_tmp, sizeof(char) * STR_MAXLEN);
					break;
				}
				//Here we are out of the separator zone. Basically, parsing code goes in this block*****

				if(parsing_attributename){ //We perform a check to see if we are still parsing an attributename, or a value
                    if (raw_valuepair[input_cur] == '='){ //If we have arrived at a seperation for the attribute to the value...
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
                        item_tmp[item_cur] = raw_valuepair[input_cur];//We take the temporary string and place our current character in it.
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
				break;
    } else { //If it is not required, it is requested. This means we DO have the attributename, but not the value. That value is found here.
        //!MAGIC!
    }
    return tmp_avp; //It should not get to this part, but checking for null-returns where this function is used should make it less prone to break.
}
