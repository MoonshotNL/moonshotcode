moonshotcode
============

MoonshotCode

Quick code overview:

common.h
	RSA *private_key;
	RSA *public_key;
	X509 *certificate_chain;
	int certificate_chain_len;
	
moonshot_init
	char *privkeyfile = parse_config_for_privkey_location;
	char *pkcs7certfile = parse_config_for_pkcs7_location;
	(common.h)private_key = load_private_key(privkeyfile);
	(common.h)certificate_chain_len = load_certificates(pkcs7certfile, &certificate_chain)

moonshot_preproxy
	if ACCESS_REQUEST
		handle_request(request, ACCESS_REQUEST)
	else if ACCESS_ACCEPT
		handle_request(request, ACCESS_ACCEPT)


moonshot_postauth
	if ACCESS_ACCEPT
		idp_handle_request(request)

handle_request
	if ACCESS_REQUEST
		char *cert_string = get_certificate_as_string(&certificate_chain, certificate_chain_len);
		char *output;
		int output_len = pack_mime_cert(cert_string, strlen(cert_string), &output)
		AVP *vp = new_avp("RADIUS_CERT_MESSAGE", output)
		add_avp(request, vp)
	else if ACCESS_ACCEPT
		foreach avp in idp_to_proxy_attr_request_avps:
			char *urn = unpack_smime(avp);
			char *returnstring = get_attributes(urn);
			char *output;
			int output_len = pack_smime(returnstring, strlen(returnstring), &output, &public_key);
			AVP *vp = new_avp("RADIUS_PROXY_ATTRIBUTES", output)
			add_avp(request, vp)

idp_handle_request
	foreach avp in client_to_idp_attr_request_avps:
		char *input_data
		int input_data_len = mime_unpack_text(vp->data.octets, vp->length, &input_data)
		ATTR_REQ *attr_request = parse_attr_data(input_data, input_data_len)
		