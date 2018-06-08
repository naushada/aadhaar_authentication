#ifndef __UTIL_C__
#define __UTIL_C__

#include "common.h"
#include "util.h"

util_ctx_t util_ctx_g;

int32_t util_init(uint8_t *public_key, uint8_t *private_key, uint8_t *password) {

  util_ctx_t *pUtilCtx = &util_ctx_g;

  memset((void *)pUtilCtx->public_key_file, 0, sizeof(pUtilCtx->public_key_file));
  memset((void *)pUtilCtx->private_key_file, 0, sizeof(pUtilCtx->private_key_file));
  memset((void *)pUtilCtx->password, 0, sizeof(pUtilCtx->password));

  strncpy(pUtilCtx->public_key_file, public_key, sizeof(pUtilCtx->public_key_file));
  strncpy(pUtilCtx->private_key_file, private_key, sizeof(pUtilCtx->private_key_file));
  strncpy(pUtilCtx->password, password, sizeof(pUtilCtx->password));

  return(0); 
}/*util_init*/

int32_t util_delete_newline(uint8_t *in, 
                            uint32_t inl, 
                            uint8_t *out, 
                            uint32_t *outl) {

  uint32_t offset = 0;
  uint32_t idx = 0;
  fprintf(stderr, "inl %d\n", inl);
  while(offset < inl) {

    if(in[offset] == '\n') {
      offset++;
      continue;
    }

    out[idx++] = in[offset++];
  }

  *outl = idx;
  return(0);
}/*util_delete_newline*/

int32_t util_insert_newline(uint8_t *in, 
                            uint32_t inl, 
                            uint8_t *out, 
                            uint16_t *outl) {

  uint32_t offset = 0;
  uint32_t idx = 0;

  /*do not insert new line*/
  memcpy((void *)out, in, inl);
  *outl = inl;
  return(0);

  while(inl >= 64) {
    memcpy((char *)&out[idx], (char *)&in[offset], 64);
    idx += 64;
    out[idx] = '\n';
    idx += 1;
    inl -= 64;
    offset += 64;
  }

  if(inl > 0) {
    memcpy((char *)&out[idx], (char *)&in[offset], inl);
    idx += inl;
  }

  *outl = idx;
  return(0);
}/*util_insert_newline*/

int32_t util_base64_decode(uint8_t *data,
                           uint32_t data_len,
                           uint8_t *out,
                           uint32_t *out_len) {
  uint32_t offset = 0;
  uint8_t value;
  uint32_t idx = 0;
  uint32_t tmp_len = 0;
  uint8_t *tmp_data;
  uint32_t tmp;
  uint8_t b64_index[255]; 

  memset((void *)b64_index, 0, sizeof(b64_index));
  /*populate array for base64 decode*/
  for(idx = 'A', value = 0; idx < ('A' + 26); idx++, value++) {
    b64_index[idx] = value;
  }

  /*populate array for base64 decode*/
  for(idx = 'a'; idx < ('a' + 26); idx++, value++) {
    b64_index[idx] = value;
  }
  
  /*populate array for base64 decode*/
  for(idx = '0'; idx < ('0' + 10); idx++, value++) {
    b64_index[idx]  = value;
  }
  
  b64_index[43] = '+';
  b64_index[47] = '/';
 
  tmp_data = (uint8_t *)malloc(data_len);

  if(!tmp_data) {
    fprintf(stderr, "\%s:%d memory allocation failed", __FILE__, __LINE__);
    return(-1);
  }
  
  memset((void *)tmp_data, 0, data_len);
   
  util_delete_newline(data, data_len, tmp_data, &tmp_len);
  /*calculate the pad bytes number*/
  tmp_len -= ((3 - (tmp_len % 3)) % 3);

  for(offset = 0; offset < tmp_len;) {

    if((tmp_len - offset) >= 4) {
      /*24bits number*/
      tmp = b64_index[tmp_data[offset + 0]] << 18 |
            b64_index[tmp_data[offset + 1]] << 12 |
            b64_index[tmp_data[offset + 2]] <<  6 |
            b64_index[tmp_data[offset + 3]];

      out[idx++] = (tmp >> 16) & 0xFF;
      out[idx++] = (tmp >> 8)  & 0xFF;
      out[idx++] = tmp  & 0xFF;
      offset += 4;
    } else if((tmp_len - offset) >= 3) {
      /*18-bits number*/
      tmp = b64_index[tmp_data[offset + 0]] << 12 |
            b64_index[tmp_data[offset + 1]] <<  6 |
            b64_index[tmp_data[offset + 2]];

      out[idx++] = (tmp >> 10) & 0xFF;
      out[idx++] = ((tmp >> 2) & 0xFF);
      offset += 3;

    } else if((tmp_len - offset) >= 2) {
      /*12bits number*/
      tmp = b64_index[tmp_data[offset + 0]] << 6 |
            b64_index[tmp_data[offset + 1]];

      out[idx++] = (tmp >> 4)  & 0xFF;
      offset += 2;
    }
  }

  out[idx] = '\0';
  *out_len = idx;
  free(tmp_data);

  return(0);
}/*util_base64_decode*/

int32_t util_base64(uint8_t *data,
                    uint16_t data_len,
                    uint8_t *b64,
                    uint16_t *b64_len) {
  uint32_t offset = 0;
  uint32_t idx = 0;
  int32_t tmp = 0;
  uint8_t tmp_b64[2048];

  uint8_t base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

  for(; offset < data_len; offset +=3) {

    if((data_len - offset) >= 3) {

      tmp = (data[offset] << 16 |
             data[offset + 1] << 8 |
             data[offset + 2]) & 0xFFFFFF;

      tmp_b64[idx++] = base64[(tmp >> 18)  & 0x3F];
      tmp_b64[idx++] = base64[(tmp >> 12)  & 0x3F];
      tmp_b64[idx++] = base64[(tmp >> 6 )  & 0x3F];
      tmp_b64[idx++] = base64[(tmp >> 0 )  & 0x3F];

    } else if((data_len - offset) >= 2) {
      tmp = (data[offset] << 8 |
             data[offset + 1]) & 0xFFFF;

      tmp_b64[idx++] = base64[(tmp >> 10)  & 0x3F];
      tmp_b64[idx++] = base64[(tmp >> 4)   & 0x3F];
      tmp_b64[idx++] = base64[(tmp & 0xF) << 2];
      tmp_b64[idx++] = '=';

    } else if((data_len - offset) >= 1) {
      tmp = data[offset] & 0xFF;

      tmp_b64[idx++] = base64[(tmp >> 2)  & 0x3F];
      tmp_b64[idx++] = base64[(tmp & 0x3) << 4];
      tmp_b64[idx++] = '=';
      tmp_b64[idx++] = '=';

    }
  }

  util_insert_newline(tmp_b64, idx, b64, b64_len);

  return(0);
}/*util_base64*/

int32_t util_base64_decode_ex(uint8_t *input, 
                    uint16_t length, 
                    uint8_t *out_b64, 
                    uint32_t *b64_len) {

  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new_mem_buf((void *)input, length);
  b64 = BIO_push(b64, bmem);
  BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
  BIO_set_close(bmem, BIO_CLOSE);

  *b64_len = BIO_read(b64, out_b64, strlen(input) /4 *3 + 1);
  out_b64[*b64_len] = '\0';
  BIO_free_all(b64);

  return (0);
}/*util_base64_decode_ex*/


int32_t util_base64_ex(uint8_t *input, 
                    uint16_t length, 
                    uint8_t *out_b64, 
                    uint16_t *b64_len) {

  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
  BIO_set_close(bmem, BIO_CLOSE);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  memcpy(out_b64, bptr->data, bptr->length);
  *b64_len = bptr->length;
  out_b64[*b64_len] = '\0';
  BIO_free_all(b64);

  return (0);
}/*util_base64_ex*/


int32_t util_compute_digest(uint8_t *xml, 
                            uint16_t xml_len, 
                            uint8_t *digest,
                            uint32_t *digest_len) {

  EVP_MD_CTX *ctx;

  if((ctx = EVP_MD_CTX_new()) == NULL) {
    fprintf(stderr, "\n%s:%d Context creation failed\n", __FILE__, __LINE__);
    return(-1);
  }

  if(1 != EVP_DigestInit_ex(ctx, EVP_sha1(), NULL)){
    fprintf(stderr, "\n%s:%d Init Failed\n", __FILE__, __LINE__);
    return(-2);
  }

  if(1 != EVP_DigestUpdate(ctx, xml, xml_len)) {
    fprintf(stderr, "\n%s:%d Update Failed\n", __FILE__, __LINE__);
    return(-3);
  }

  if(1 != EVP_DigestFinal_ex(ctx, digest, digest_len)) {
    fprintf(stderr, "\n%s:%d Final Failed\n", __FILE__, __LINE__);
    return(-5);
  }

  EVP_MD_CTX_free(ctx);
  ctx = NULL;

  return(0);
}/*util_compute_digest*/ 


int32_t util_subject_certificate(uint8_t **subject,
                                 uint16_t *subject_len,
                                 uint8_t **certificate,
                                 uint16_t *certificate_len) {

  util_ctx_t *pUtilCtx = &util_ctx_g;
  uint8_t *tmp_str = NULL;
  uint8_t *token = NULL;
  uint8_t buffer[2048];
  uint8_t tmp_buffer[2048];
  uint8_t subject_name[512];
  uint16_t offset = 0;
  char *save_ptr = NULL;
  int32_t rc = -1;
  FILE *fp = NULL;
  int32_t tmp_len = -1; 
  X509 *x509;

  memset((void *)buffer, 0, sizeof(buffer));
  /*Private certificate has two parts in it, 1) x509 certificate 2) Private Key
   * Private Key is used to digital signature and x509 certificate along with subject info
   * is embeded into X509 info into xml. 
   */
  fp = fopen(".dsign_cert.pem", "r"); 
  assert(fp != NULL);

  if(!(x509 = PEM_read_X509(fp, NULL, 0, NULL))) {
    fprintf(stderr, "\n%s:%d Reading of X509 failed\n", __FILE__, __LINE__);
    return(-2);
  }

  /*storing subject key for later use*/
  X509_NAME_oneline(X509_get_subject_name(x509), 
                    subject_name, 
                    sizeof(subject_name));

  /*Make subject field with , seperated instead of / */
  tmp_str = subject_name;

  token = strtok_r(tmp_str, (const char *)"/", &save_ptr);
  //token = strtok_r(subject_name, (const char *)"/", &save_ptr);
 
  while(token) {
   rc += snprintf((char *)&buffer[offset],
                  sizeof(buffer),
                  "%s,",
                  token);
   /*+1 for comma as a delimeter*/               
   offset += strlen((const char *)token) + 1;
   token = strtok_r(NULL, "/", &save_ptr);
  }
 
  *subject = (uint8_t *)malloc(rc);

  memset((*subject), 0, rc);
  strncpy((*subject), buffer, rc);
  *subject_len = rc;

  (*certificate) = (uint8_t *) malloc(sizeof(buffer));
  memset((void *)(*certificate), 0, sizeof(buffer));

  memset((void *)buffer, 0, sizeof(buffer));
  /*move file pointer to the begining*/
  rewind(fp);
  rc = fread(buffer, 1, sizeof(buffer), fp);

  if(rc <= 0) {
    fprintf(stderr, "\nReading of public certificate failed\n");
    fclose(fp);
    X509_free(x509);
    return(-1);
  }

  fclose(fp);
  X509_free(x509);

  uint16_t tmp_rc = 0;
  offset = 0;

  memset((void *)tmp_buffer, 0, sizeof(tmp_buffer));
  /*eliminate the \n from buffer and store them into tmp_buffer*/
  while(rc > 0) {
    if(!strncmp((const char *)&buffer[tmp_rc], "-----BEGIN CERTIFICATE-----", 27)) {
      tmp_rc += 27 + 1;
      rc -= 27 + 1;
    } else if(!strncmp((const char *)&buffer[tmp_rc], "-----END CERTIFICATE-----", 25)) {
      tmp_rc+= 25;
      rc -= 25;
    } else {
      tmp_buffer[offset++] = buffer[tmp_rc];
      tmp_rc++;
      rc--;
    }
  }

  /*-2 is to remove the \n from the end of the certificate*/
  strncpy((*certificate), tmp_buffer, (offset -2));
  *certificate_len = offset - 2;
 
  return(0); 
}/*util_subject_certificate*/

int32_t util_decrypt_skey(uint8_t *in, uint32_t inl, uint8_t *out, uint32_t *outl) {

  RSA *rsa = NULL;
  /*pkey - Private Key*/
  EVP_PKEY *pkey;
  PKCS12 *p12;
  FILE *fp = NULL;
  int32_t ret = -1;
  /*Pointer to plain text*/
  uint8_t *p_text = NULL;
  /*Plain text len*/
  int32_t p_len;
  util_ctx_t *pUtilCtx = &util_ctx_g;

  fp = fopen(pUtilCtx->private_key_file, "r");

  if(!fp) {
    fprintf(stderr, "\n%s:%d Opening of private key file failed\n", __FILE__, __LINE__);
    return(-1);
  }

  p12 = d2i_PKCS12_fp(fp, NULL);
  PKCS12_parse(p12, "public", &pkey, NULL, NULL);

  PKCS12_free(p12);
  fclose(fp);

  rsa = EVP_PKEY_get1_RSA(pkey);

  if(!rsa) {
    fprintf(stderr, "\n%s:%d the RSA is NULL\n", __FILE__, __LINE__);
    return(-3);
  }

  p_text = (uint8_t *)malloc(RSA_size(rsa));

  if(!p_text) {
    fprintf(stderr, "\n%s:%d memory Allocation failed for ciphered session key\n",
           __FILE__,
           __LINE__);
    return(-4);
  }

  memset((void *)p_text, 0, RSA_size(rsa));
  /*decrypt Session key (2048-bits) with private key*/
  p_len = RSA_private_decrypt(inl, 
                              in,
                              p_text, 
                              rsa,
                              RSA_PKCS1_PADDING);
  if(p_len < 0) {
    fprintf(stderr, "\n%s:%d Decryption of session key with private key failed %s\n",
            __FILE__,
            __LINE__,
            ERR_error_string(ERR_get_error(), NULL));
    free(p_text);
    p_text = NULL;
    RSA_free(rsa);
    return(-5);
  }

  memcpy((void *)out, p_text, p_len);
  *outl = p_len;

  free(p_text);
  p_text = NULL;
  RSA_free(rsa);
  EVP_PKEY_free(pkey);

  return(0);
}/*util_decrypt_skey*/

/**
 * @brief This function receives the plain xml document and its length
 *        and creates the SHA1 and then signs the SHA1 (digest) 
 *        to make the signature of XML digitally signed.
 *
 * @param signed_info xml buffer
 * @param signed_info_len is the length of xml buffer
 * @param signature_value is the computed RSA-SHA1 signature
 * @param signature_len is the length of the computed signature
 *
 * @return upon success, it returns 0 else < 0.
 */
int32_t util_compute_rsa_signature(uint8_t *signed_info, 
                                   uint16_t signed_info_len, 
                                   uint8_t **signature_value, 
                                   uint16_t *signature_len) {
  RSA *rsa = NULL;
  /*public certificate*/
  X509 *x509 = NULL;
  /*pkey - Private Key*/
  EVP_PKEY *pkey;
  EVP_MD_CTX *ctx;
  PKCS12 *p12;
  STACK_OF(X509) *ca = NULL;
  FILE *fp = NULL;
  int32_t ret = -1;
  util_ctx_t *pUtilCtx = &util_ctx_g;

  fp = fopen(pUtilCtx->private_key_file, "r");
  assert(fp != NULL);

  x509 = X509_new();

  p12 = d2i_PKCS12_fp(fp, NULL);

  PKCS12_parse(p12, pUtilCtx->password, &pkey, &x509, &ca);
  PKCS12_free(p12);

  fclose(fp);
  /*XML is digitally signed by certificate provided in Private Key*/
  fp = fopen(".dsign_cert.pem", "w");
  PEM_write_X509(fp, x509);
  fclose(fp);

  /*Initialize the message digest context*/
  ctx = EVP_MD_CTX_new();
  EVP_SignInit_ex(ctx, EVP_sha1(), NULL);
  /*signed_info is plain text*/
  EVP_SignUpdate(ctx, signed_info, signed_info_len);

  *signature_value = (uint8_t *)malloc(2048);
  assert(*signature_value != NULL);
  
  memset((void *)*signature_value, 0, 2048);
  EVP_SignFinal(ctx, 
                *signature_value, 
                (uint32_t *)signature_len, 
                pkey);

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  X509_free(x509);

 return(0); 
}/*util_compute_rsa_signature*/

/**
 * @brief This function creates the canonicalise form of signedInfo
 *        xml in which every blank spaces does matter.
 *        https://www.di-mgt.com.au/xmldsig2.html#exampleofenveloped
 *
 * @param c14n is to store the canonicalized xml
 * @param c14_max_len is the max buffer size of c14n
 * @param c14n_len is the length of canonicalised xml
 * @param sha1_digest is the SHA1(digest) of otp xml
 *
 * @param upon success returns 0 else < 0
 */
int32_t util_c14n_signedinfo(uint8_t *c14n,
                             uint16_t c14n_max_size,
                             uint16_t *c14n_len,
                             uint8_t *sha1_digest) {
  int32_t ret = -1;

  ret = snprintf(c14n,
                 c14n_max_size,
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s",
                 "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n",
                 "      <CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"></CanonicalizationMethod>\n",
                 "      <SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></SignatureMethod>\n",
                 "      <Reference URI=\"\">\n",
                 "        <Transforms>\n",
                 "          <Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></Transform>\n",
                 "        </Transforms>\n",
                 "        <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod>\n",
                 "        <DigestValue>",sha1_digest,"</DigestValue>\n",
                 "      </Reference>\n",
                 "    </SignedInfo>");

  *c14n_len = ret;

  return(0);
}/*util_c14n_signedinfo*/

/**
 * @brief https://www.di-mgt.com.au/xmldsig.html
 */  
int32_t util_compose_final_xml(uint8_t *out_xml, 
                               uint16_t out_xml_max_size, 
                               uint16_t *out_xml_len,
                               uint8_t *digest_b64,
                               uint8_t *signature_b64,
                               uint8_t *subject,
                               uint8_t *certificate) {

  int32_t ret = -1;
  ret = snprintf(out_xml,
                 out_xml_max_size,
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s",
                 "  <Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n",
                 "    <SignedInfo>\n",
                 "      <CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>\n",
                 "      <SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n",
                 "      <Reference URI=\"\">\n",
                 "        <Transforms>\n",
                 "          <Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n",
                 "        </Transforms>\n",
                 "        <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n",
                 "        <DigestValue>",
                 digest_b64,
                 "</DigestValue>\n",
                 "      </Reference>\n",
                 "    </SignedInfo>\n",
                 "    <SignatureValue>",
                 signature_b64,
                 "</SignatureValue>\n",
                 "    <KeyInfo>\n",
                 "      <X509Data>\n",
                 "        <X509SubjectName>",
                 subject,
                 "</X509SubjectName>\n",
                 "        <X509Certificate>",
                 certificate,
                 "</X509Certificate>\n",
                 "      </X509Data>\n",
                 "    </KeyInfo>\n",
                 "  </Signature>\n");
                 
  *out_xml_len = ret;

  return(0);
}/*util_compose_final_xml*/


#endif /* __UTIL_C__ */
