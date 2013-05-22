//
//  x509_check.c
//  
//
//  Created by W.A. Miltenburg on 17-05-13.
//
//

#include <stdio.h>
#include <stdlib.h>

/* Step 1. Obtain CA certificate.
 * This example assumes the CA certificate is a DER encode X.509
 * certificate that is available in memory.
 * Use R_CERT_from_binary() to create a certificate object from
 * the binary data.
 * The CA certificate can now be manipulated programmatically.
 */
ret = R_CERT_from_binary(cert_ctx, R_FLAG_SHARE_DATA,
                         R_CERT_TYPE_X509, ca_cert_len, ca_cert_data, NULL,
                         &ca_cert);
if (ret != R_ERROR_NONE)
goto err;

/* Step 2. Extract public key from CA certificate.
 * The public key is used to verify the entity’s certificate.
 * Use R_CERT_public_key_to_R_PKEY() to create a public key
 * object from the certificate object.
 * The public key can now be used in the verification operation.
 */
ret = R_CERT_public_key_to_R_PKEY(ca_cert, R_FLAG_SHAR_DATA,
                                  &ca_pkey);
if (ret != R_ERROR_NONE)
goto err;

/* Step 3. Obtain entity’s certificate.
 * This example assumes the entity’s certificate is a DER encode
 * X.509 certificate that is available in memory.
 * Use R_CERT_from_binary() to create a certificate object from
 * the binary data.
 * The entity’s certificate can now be manipulated programmatically.
 */
ret = R_CERT_from_binary(cert_ctx,
                         R_FLAG_SHARE_DATA, R_CERT_TYPE_X509,
                         cert_len, cert_data, NULL, &cert);
if (ret != R_ERROR_NONE)
goto err;

/* Step 4. Verify signature in entity’s certificate with the public
 *         key.
 * Perform a verification operation on the entity’s certificate
 * object with the public key object.
 * Use R_CERT_verify() to perform the verification.
 * An error is returned if the inputs are invalid. For example the
 * public key is a DSA key and the signature was created with an RSA
 * key.
 * Whether the certificate data is cryptographically valid is
 * returned through the third parameter - verified.
 * A value of 1 indicates the certificate’s signature was valid and a
 * value of 0 indicates that the certificate’s signature was not
 * valid.
 */
ret = R_CERT_verify(cert, ca_pkey, &verified);
If (ret != R_ERROR_NONE)
goto err;
if (verified)
printf(“Entity certificate verified\n”);
else
printf(“Entity certificate not verified\n”);