#ifndef __OTP_C__
#define __OTP_C__

#include "common.h"
#include "util.h"
#include "uidai.h"
#include "otp.h"

int32_t otp_compute_utf8(uint8_t *xml_in, 
                         uint16_t xml_in_len, 
                         uint8_t *utf8_set_out, 
                         uint16_t *utf8_set_len) {
  uint16_t idx;
  uint16_t utf8_idx;

  for(utf8_idx = 0, idx = 0; idx < xml_in_len; idx++, utf8_idx++) {

    if(*((uint16_t *)&xml_in[idx]) <= 0x7F) {
      /*Byte is encoded in single btye*/
      utf8_set_out[utf8_idx] = xml_in[idx];

    } else if(*((uint16_t *)&(xml_in[idx])) <= 0x7FF) {
      /*Byte is spread accross 2 Bytes*/
      utf8_set_out[utf8_idx++] = 0x80 | (xml_in[idx] & 0x3F);
      utf8_set_out[utf8_idx] = 0xC0 | ((xml_in[idx + 1] & 0x1F) | (xml_in[idx] >> 6));
      idx++; 
    } else if(*((uint8_t *)&xml_in[idx]) <= 0xFFFF) {
      /*Byte to be spread into 3 Bytes*/
      utf8_set_out[utf8_idx++] = 0x80 | (xml_in[idx] & 0x3F);
      utf8_set_out[utf8_idx++] = 0x80 | ((xml_in[idx + 1] & 0xF) | (xml_in[idx] >> 6));
      utf8_set_out[utf8_idx] = 0xE0 | (xml_in[idx + 1] >> 4);
      idx++;
      
    } else if(*((uint32_t *)&xml_in[idx]) <= 0x10FFFF) {
      /*Bytes to be spread into 4 Bytes*/
      
    } else {
      fprintf(stderr, "\n%s:%d Not Supported UTF-8 as of now\n",
                      __FILE__,
                      __LINE__);
    }
  }

  return(0);
}/*otp_compute_utf8*/

uint8_t *otp_get_ts(void) {

  time_t curr_time;
  struct tm *local_time;
  uint8_t *ts_ptr = NULL;

  /*Retrieving the current time*/
  curr_time = time(NULL);
  local_time = localtime(&curr_time);

  ts_ptr = (uint8_t *)malloc(sizeof(uint8_t) * 64);
  assert(ts_ptr != NULL);
  memset((void *)ts_ptr, 0, sizeof(uint8_t) * 64);

  snprintf(ts_ptr, 
           (sizeof(uint8_t) * 64),
           "%04d-%02d-%02dT%02d:%02d:%02d", 
           local_time->tm_year+1900, 
           local_time->tm_mon+1,
           local_time->tm_mday, 
           local_time->tm_hour,
           local_time->tm_min, 
           local_time->tm_sec);

  return(ts_ptr);
}/*otp_get_ts*/

/** @brief This function is to build the OTP xml
 *
 *  @param *len_ptr is the pointer to unsigned int which holds the 
 *          length of the partial otp xml
 *
 *  @return It will return pointer to unsigned char to partial OTP xml,
 *          caller must free the memory. 
 */
uint8_t *otp_compose_xml_v16(uint8_t *in_ptr, uint32_t *len_ptr) {
  int32_t ret = -1;
  uint8_t *xml_ptr = NULL;
  uint32_t len = 0;
  uint8_t *req_ptr;
  uint32_t req_size = 4000;

  req_ptr = (uint8_t *)malloc(sizeof(uint8_t) * req_size);
  assert(req_ptr != NULL);
  memset((void *)req_ptr, 0, (sizeof(uint8_t) * req_size));

  xml_ptr = otp_compose_otp_v16(in_ptr, &len);
  ret = snprintf(req_ptr,
                 req_size,
                 "%s%s%s",
                 "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n",
                 xml_ptr,
                 "\n");

  *len_ptr = (uint32_t)ret;
  free(xml_ptr);
  xml_ptr = NULL;

  return(req_ptr);
}/*otp_compose_xml_v16*/

/** @brief This function is to build the otp atg of OTP xml without 
 *         the end tag.
 *
 *  @param *len_ptr is the pointer to unsigned int for length of otp tag of otp xml 
 *
 *  @return It returns pointer to char to otp xml tag and caller must free the memory.
 */
uint8_t *otp_compose_otp_v16(uint8_t *in_ptr, uint32_t *len_ptr) {

  int32_t ret = -1;
  uint8_t *req_ptr = NULL;
  uint32_t req_size = 1024;
  uint8_t *param_ptr = NULL;
  uint8_t *attr_ptr[12];
  uint32_t idx;

  param_ptr = uidai_get_param(in_ptr, "otp");
  assert(param_ptr != NULL);
  attr_ptr[0] = uidai_get_attr(param_ptr, "ac");
  attr_ptr[1] = uidai_get_attr(param_ptr, "lk");
  attr_ptr[2] = uidai_get_attr(param_ptr, "sa");
  attr_ptr[3] = uidai_get_attr(param_ptr, "tid");
  attr_ptr[4] = uidai_get_attr(param_ptr, "txn");
  attr_ptr[5] = uidai_get_attr(param_ptr, "type");
  attr_ptr[6] = uidai_get_attr(param_ptr, "uid");
  attr_ptr[7] = uidai_get_attr(param_ptr, "ver");
  free(param_ptr);
  param_ptr = NULL;

  param_ptr = uidai_get_param(in_ptr, "opts");
  assert(param_ptr != NULL);
  attr_ptr[8] = uidai_get_attr(param_ptr, "ch");
  free(param_ptr);
  param_ptr = NULL;

  attr_ptr[9] = otp_get_ts();

  req_ptr = (uint8_t *)malloc(sizeof(uint8_t) * req_size);
  assert(req_ptr != NULL);
  memset((void *)req_ptr, 0, (sizeof(uint8_t) * req_size));

  ret = snprintf(req_ptr,
                 req_size,
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%.2d%s",
                 "<Otp",
                 " ac=\"",
                 attr_ptr[0],
                 "\" lk=\"",
                 attr_ptr[1],
                 "\" sa=\"",
                 attr_ptr[2],
                 "\" tid=\"",
                 attr_ptr[3],
                 "\" ts=\"",
                 attr_ptr[9],
                 "\" txn=\"",
                 attr_ptr[4],
                 "\" type=\"",
                 attr_ptr[5],
                 "\" uid=\"",
                 attr_ptr[6],
                 "\" ver=\"",
                 /*It's value shall be 1.6*/
                 attr_ptr[7],
                 /*Otp attribute ends here*/
                 "\">\n",
                 /*opts - options tag starts*/
                 "  <Opts ch=\"",
                 atoi(attr_ptr[8]),
                 "\"/>");

  *len_ptr = (uint32_t)ret;

  for(idx = 0; idx < 10; idx++) {

    if(attr_ptr[idx]) {
      free(attr_ptr[idx]);
      attr_ptr[idx] = NULL;
    }

  }
  return(req_ptr);
}/*otp_compose_otp_v16*/

/** @brief This function is to build the xml in c14n format to compute the message
 *         digest. In c14n format every xml tag shall be of form <tag></tang>
 *
 *  @param *c14n_len_ptr is the pointer to unsigned int to hold length of c14n xml 
 * 
 *  @return It returns the pointer to char for c14n xml, the caller has to free the memory
 */
uint8_t *otp_compose_c14n_v16(uint8_t *in_ptr, uint32_t *c14n_len_ptr) {

  int32_t ret = -1;
  uint8_t *c14n_ptr = NULL;
  uint32_t c14n_size = 1024;
  uint8_t *param_ptr = NULL;
  uint8_t *attr_ptr[12];
  uint32_t idx;

  param_ptr = uidai_get_param(in_ptr, "otp");
  assert(param_ptr != NULL);
  attr_ptr[0] = uidai_get_attr(param_ptr, "ac");
  attr_ptr[1] = uidai_get_attr(param_ptr, "lk");
  attr_ptr[2] = uidai_get_attr(param_ptr, "sa");
  attr_ptr[3] = uidai_get_attr(param_ptr, "tid");
  attr_ptr[4] = uidai_get_attr(param_ptr, "txn");
  attr_ptr[5] = uidai_get_attr(param_ptr, "type");
  attr_ptr[6] = uidai_get_attr(param_ptr, "uid");
  attr_ptr[7] = uidai_get_attr(param_ptr, "ver");
  free(param_ptr);
  param_ptr = NULL;

  param_ptr = uidai_get_param(in_ptr, "opts");
  assert(param_ptr != NULL);
  attr_ptr[8] = uidai_get_attr(param_ptr, "ch");
  free(param_ptr);
  param_ptr = NULL;

  attr_ptr[9] = otp_get_ts();

  c14n_ptr = (uint8_t *)malloc(sizeof(uint8_t) * c14n_size);
  assert(c14n_ptr != NULL);
  memset((void *)c14n_ptr, 0, (sizeof(uint8_t) * c14n_size));

  ret = snprintf(c14n_ptr,
                 c14n_size,
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%.2d%s%s%s",
                 "<Otp",
                 " ac=\"",
                 attr_ptr[0],
                 "\" lk=\"",
                 attr_ptr[1],
                 "\" sa=\"",
                 attr_ptr[2],
                 "\" tid=\"",
                 attr_ptr[3],
                 "\" ts=\"",
                 attr_ptr[9],
                 "\" txn=\"",
                 attr_ptr[4],
                 "\" type=\"",
                 attr_ptr[5],
                 "\" uid=\"",
                 attr_ptr[6],
                 "\" ver=\"",
                 /*It's value shall be 1.6*/
                 attr_ptr[7],
                 /*Otp attribute ends here*/
                 "\">\n",
                 /*opts - options tag starts*/
                 "  <Opts ch=\"",
                 atoi(attr_ptr[8]),
                 "\"></Opts>\n",
                 /*https://www.di-mgt.com.au/xmldsig2.html#c14nit*/
                 "  \n",
                 "</Otp>");

  *c14n_len_ptr = (uint32_t)ret;

  for(idx = 0; idx < 10; idx++) {

    if(attr_ptr[idx]) {
      free(attr_ptr[idx]);
      attr_ptr[idx] = NULL;
    }
  }

  return(c14n_ptr);
}/*otp_compose_c14n_v16*/

uint8_t *otp_compose_http_request(uint8_t *in_ptr,
                                  uint8_t *signed_xml, 
                                  uint32_t signed_xml_len, 
                                  uint32_t *http_req_len) {

  uint8_t *req_ptr = NULL;
  uint32_t req_len = 0;
  int32_t ret = -1;
  uint32_t req_size = signed_xml_len + 1024;
  uint8_t *param_ptr = NULL;
  uint8_t *attr_ptr[10];
  uint32_t idx;

  param_ptr = uidai_get_param(in_ptr, "uidai");
  assert(param_ptr != NULL);

  attr_ptr[0] = uidai_get_attr(param_ptr, "host");
  attr_ptr[1] = uidai_get_attr(param_ptr, "uri");
  free(param_ptr);
  param_ptr = NULL;

  param_ptr = uidai_get_param(in_ptr, "otp");
  assert(param_ptr != NULL);

  attr_ptr[2] = uidai_get_attr(param_ptr, "ac");
  attr_ptr[3] = uidai_get_attr(param_ptr, "uid");
  attr_ptr[4] = uidai_get_attr(param_ptr, "lk");
  free(param_ptr);
  param_ptr = NULL; 
  
  req_ptr = (uint8_t *) malloc(req_size);
  assert(req_ptr != NULL);
  memset((void *)req_ptr, 0, req_size);

  /*Prepare http request*/
  ret = snprintf((char *)req_ptr,
                 req_size,
                 "%s%s%s%s%s"
                 "%s%c%s%c%s"
                 "%s%s%s%s%s"
                 "%s%s%s%d%s",
                 /*https://<host>/otp/<ver>/<ac>/<uid[0]>/<uid[1]>/<asalk>*/
                 "POST http://",
                 /*host*/
                 attr_ptr[0],
                 /*uri*/
                 attr_ptr[1],
                 "/",
                 /*ac*/
                 attr_ptr[2],
                 "/",
                 /*1st digit of uid*/
                 attr_ptr[3][0],
                 "/",
                 /*second digit of uid*/
                 attr_ptr[3][1],
                 "/",
                 /*lk*/
                 attr_ptr[4],
                 " HTTP/1.1\r\n",
                 "Host: ",
                 attr_ptr[0],
                 "\r\n",
                 "Content-Type: text/xml\r\n",
                 "Connection: Keep-alive\r\n",
                 "Content-Length: ",
                 signed_xml_len,
                 /*delimeter B/W http header and its body*/
                 "\r\n\r\n");

  memcpy((void *)&req_ptr[ret], signed_xml, signed_xml_len);
  *http_req_len = ret + signed_xml_len;

  for(idx = 0; idx < 5; idx++) {

    if(attr_ptr[idx]) {
      free(attr_ptr[idx]);
      attr_ptr[idx] = NULL;
    }
  }

  return(req_ptr); 
}/*otp_compose_http_request*/

/*
  1.Canonicalize* the text-to-be-signed, C = C14n(T).
  2.Compute the message digest of the canonicalized text, m = Hash(C).
  3.Encapsulate the message digest in an XML <SignedInfo> element, SI, in canonicalized form.
  4.Compute the RSA signatureValue of the canonicalized <SignedInfo> element, SV = RsaSign(Ks, SI).
  5.Compose the final XML document including the signatureValue, this time in non-canonicalized form.

 */
uint8_t *otp_sign_xml_v16(uint8_t *in_ptr, uint32_t *len_ptr) {

  uint8_t *c14n_otp_ptr;
  uint32_t c14n_otp_len;
  uint8_t *otp_digest;
  uint32_t otp_digest_len;
  uint8_t otp_b64[128];
  uint16_t otp_b64_len;
  uint8_t otp_b64_signature[512];
  uint16_t otp_b64_signature_len;
  uint8_t *signed_xml_ptr;
  uint16_t signed_xml_len;
  uint8_t *signature_value = NULL;
  uint16_t signature_value_len = 0;
  uint8_t *subject = NULL;
  uint16_t subject_len = 0;
  uint8_t *certificate = NULL;
  uint16_t certificate_len = 0;
  uint32_t otp_xml_len;
  uint8_t *final_xml_ptr;

  /*C14N - Canonicalization of <otp> portion of xml*/
  c14n_otp_ptr = otp_compose_c14n_v16(in_ptr, &c14n_otp_len); 

  otp_digest = (uint8_t *)malloc(sizeof(uint8_t) * 128);
  assert(otp_digest != NULL);
  memset((void *)otp_digest, 0, (sizeof(uint8_t) * 128));

  /*digest of c14n xml*/
  util_compute_digest(c14n_otp_ptr, 
                      c14n_otp_len, 
                      otp_digest, 
                      &otp_digest_len);

  free(c14n_otp_ptr);
  c14n_otp_ptr = NULL;
  c14n_otp_len = 0;

  memset((void *)otp_b64, 0, sizeof(otp_b64));
  otp_b64_len = 0;
  util_base64(otp_digest, otp_digest_len, otp_b64, &otp_b64_len);

  free(otp_digest);
  otp_digest = NULL;
  otp_digest_len = 0;

  signed_xml_ptr = (uint8_t *)malloc(sizeof(uint8_t) * 2048);
  assert(signed_xml_ptr != NULL);
  memset((void *)signed_xml_ptr, 0, (sizeof(uint8_t) * 2048));

  /*C14N for <SignedInfo> portion of xml*/
  util_c14n_signedinfo(signed_xml_ptr, 
                       (sizeof(uint8_t) * 2048), 
                       &signed_xml_len, 
                       /*Message Digest in base64*/
                       otp_b64);

  /*Creating RSA Signature - by signing digest with private key*/
  util_compute_rsa_signature(signed_xml_ptr, 
                             signed_xml_len, 
                             &signature_value, 
                             &signature_value_len);
  free(signed_xml_ptr);
  signed_xml_ptr = NULL;
  signed_xml_len = 0;

  memset((void *)otp_b64_signature, 0, sizeof(otp_b64_signature));
  otp_b64_signature_len = 0;

  util_base64(signature_value, 
              signature_value_len, 
              otp_b64_signature, 
              &otp_b64_signature_len);

  free(signature_value);
  signature_value = NULL;
  signature_value_len = 0;

  util_subject_certificate(&subject,
                           &subject_len,
                           &certificate,
                           &certificate_len);

  /*Create partial OTP xml*/ 
  final_xml_ptr = otp_compose_xml_v16(in_ptr, &otp_xml_len);
  *len_ptr = otp_xml_len;

  /*Append signed info to OTP xml*/
  util_compose_final_xml(&final_xml_ptr[otp_xml_len], 
                         (4000 - otp_xml_len), 
                         (uint16_t *)&otp_xml_len,
                         /*digest*/
                         otp_b64,
                         /*Signature Value*/
                         otp_b64_signature,
                         /*Subject Name*/
                         subject,
                         /*Certificate*/
                         certificate); 

  *len_ptr += otp_xml_len;

  otp_xml_len = snprintf(&final_xml_ptr[*len_ptr],
                         (4000 - *len_ptr),
                         "%s",
                         "</Otp>");
  
  *len_ptr += otp_xml_len;
  free(signature_value);
  signature_value = NULL;
  free(subject);
  free(certificate);

  return(final_xml_ptr);
}/*otp_sign_xml_v16*/

uint8_t *otp_main_ex_v16(uint8_t *in_ptr, 
                         uint32_t in_len, 
                         uint32_t *len_ptr) {

  uint8_t *otp_xml_ptr = NULL;
  uint8_t *http_req_ptr = NULL;
  uint32_t http_len;

  otp_xml_ptr = otp_sign_xml_v16(in_ptr, len_ptr);
  http_req_ptr = otp_compose_http_request(in_ptr, 
                                          otp_xml_ptr, 
                                          *len_ptr, 
                                          &http_len);
  free(otp_xml_ptr);
  otp_xml_ptr = NULL;

  fprintf(stderr, "\n%s:%d http_request %s\n", __FILE__, __LINE__, http_req_ptr);

  return(http_req_ptr);
}/*otp_main_ex_v16*/

/*===============================================
 * v25 - v2.5
 *===============================================*/

/** @brief This function is to build the xml in c14n format to compute the message
 *         digest. In c14n format every xml tag shall be of form <tag></tang>
 *
 *  @param *c14n_len_ptr is the pointer to unsigned int to hold length of c14n xml 
 * 
 *  @return It returns the pointer to char for c14n xml, the caller has to free the memory
 */
uint8_t *otp_compose_c14n_v25(uint8_t *in_ptr, uint32_t *c14n_len_ptr) {

  int32_t ret = -1;
  uint8_t *c14n_ptr = NULL;
  uint32_t c14n_size = 1024;
  uint8_t *param_ptr = NULL;
  uint8_t *attr_ptr[12];
  uint32_t idx;

  param_ptr = uidai_get_param(in_ptr, "otp");
  assert(param_ptr != NULL);
  attr_ptr[0] = uidai_get_attr(param_ptr, "ac");
  attr_ptr[1] = uidai_get_attr(param_ptr, "lk");
  attr_ptr[2] = uidai_get_attr(param_ptr, "sa");
  attr_ptr[3] = otp_get_ts();
  attr_ptr[4] = uidai_get_attr(param_ptr, "txn");
  attr_ptr[5] = uidai_get_attr(param_ptr, "type");
  attr_ptr[6] = uidai_get_attr(param_ptr, "uid");
  attr_ptr[7] = uidai_get_attr(param_ptr, "ver");
  free(param_ptr);
  param_ptr = NULL;

  param_ptr = uidai_get_param(in_ptr, "opts");
  assert(param_ptr != NULL);
  attr_ptr[8] = uidai_get_attr(param_ptr, "ch");
  free(param_ptr);
  param_ptr = NULL;

  c14n_ptr = (uint8_t *)malloc(sizeof(uint8_t) * c14n_size);
  assert(c14n_ptr != NULL);
  memset((void *)c14n_ptr, 0, (sizeof(uint8_t) * c14n_size));

  ret = snprintf(c14n_ptr,
                 c14n_size,
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%s%.2d"
                 "%s%s%s",
                 "<Otp",
                 " ac=\"",
                 attr_ptr[0],
                 "\" lk=\"",
                 attr_ptr[1],
                 "\" sa=\"",
                 attr_ptr[2],
                 "\" ts=\"",
                 attr_ptr[3],
                 "\" txn=\"",
                 attr_ptr[4],
                 "\" type=\"",
                 attr_ptr[5],
                 "\" uid=\"",
                 attr_ptr[6],
                 "\" ver=\"",
                 /*It's value shall be 1.6*/
                 attr_ptr[7],
                 /*Otp attribute ends here*/
                 "\">\n",
                 /*opts - options tag starts*/
                 "  <Opts ch=\"",
                 atoi(attr_ptr[8]),
                 "\"></Opts>\n",
                 /*https://www.di-mgt.com.au/xmldsig2.html#c14nit*/
                 "  \n",
                 "</Otp>");

  *c14n_len_ptr = (uint32_t)ret;

  for(idx = 0; idx < 9; idx++) {

    if(attr_ptr[idx]) {
      free(attr_ptr[idx]);
      attr_ptr[idx] = NULL;
    }
  }

  return(c14n_ptr);
}/*otp_compose_c14n_v25*/

uint8_t *otp_compose_xml_v25(uint8_t *in_ptr, uint32_t *len_ptr) {
  int32_t ret = -1;
  uint8_t *xml_ptr = NULL;
  uint32_t len = 0;
  uint8_t *req_ptr;
  uint32_t req_size = 4000;

  req_ptr = (uint8_t *)malloc(sizeof(uint8_t) * req_size);
  assert(req_ptr != NULL);
  memset((void *)req_ptr, 0, (sizeof(uint8_t) * req_size));

  xml_ptr = otp_compose_otp_v25(in_ptr, &len);
  ret = snprintf(req_ptr,
                 req_size,
                 "%s%s%s",
                 "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n",
                 xml_ptr,
                 "\n");

  *len_ptr = (uint32_t)ret;
  free(xml_ptr);
  xml_ptr = NULL;

  return(req_ptr);
}/*otp_compose_xml_v25*/

/** @brief This function is to build the otp atg of OTP xml without 
 *         the end tag.
 *
 *  @param *len_ptr is the pointer to unsigned int for length of otp tag of otp xml 
 *
 *  @return It returns pointer to char to otp xml tag and caller must free the memory.
 */
uint8_t *otp_compose_otp_v25(uint8_t *in_ptr, uint32_t *len_ptr) {

  int32_t ret = -1;
  uint8_t *req_ptr = NULL;
  uint32_t req_size = 1024;
  uint8_t *param_ptr = NULL;
  uint8_t *attr_ptr[12];
  uint32_t idx;

  param_ptr = uidai_get_param(in_ptr, "otp");
  assert(param_ptr != NULL);
  attr_ptr[0] = uidai_get_attr(param_ptr, "ac");
  attr_ptr[1] = uidai_get_attr(param_ptr, "lk");
  attr_ptr[2] = uidai_get_attr(param_ptr, "sa");
  attr_ptr[3] = uidai_get_attr(param_ptr, "txn");
  attr_ptr[4] = uidai_get_attr(param_ptr, "type");
  attr_ptr[5] = uidai_get_attr(param_ptr, "uid");
  attr_ptr[6] = uidai_get_attr(param_ptr, "ver");
  free(param_ptr);
  param_ptr = NULL;

  param_ptr = uidai_get_param(in_ptr, "opts");
  assert(param_ptr != NULL);
  attr_ptr[7] = uidai_get_attr(param_ptr, "ch");
  free(param_ptr);
  param_ptr = NULL;

  attr_ptr[8] = otp_get_ts();

  req_ptr = (uint8_t *)malloc(sizeof(uint8_t) * req_size);
  assert(req_ptr != NULL);
  memset((void *)req_ptr, 0, (sizeof(uint8_t) * req_size));

  ret = snprintf(req_ptr,
                 req_size,
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%s%.2d"
                 "%s",
                 "<Otp",
                 " ac=\"",
                 attr_ptr[0],
                 "\" lk=\"",
                 attr_ptr[1],
                 "\" sa=\"",
                 attr_ptr[2],
                 "\" ts=\"",
                 attr_ptr[8],
                 "\" txn=\"",
                 attr_ptr[3],
                 "\" type=\"",
                 attr_ptr[4],
                 "\" uid=\"",
                 attr_ptr[5],
                 "\" ver=\"",
                 /*It's value shall be 1.6*/
                 attr_ptr[6],
                 /*Otp attribute ends here*/
                 "\">\n",
                 /*opts - options tag starts*/
                 "  <Opts ch=\"",
                 atoi(attr_ptr[7]),
                 "\"/>");

  *len_ptr = (uint32_t)ret;

  for(idx = 0; idx < 9; idx++) {

    if(attr_ptr[idx]) {
      free(attr_ptr[idx]);
      attr_ptr[idx] = NULL;
    }

  }
  return(req_ptr);
}/*otp_compose_otp_v25*/

uint8_t *otp_sign_xml_v25(uint8_t *in_ptr, 
                          uint32_t *len_ptr) {

  uint8_t *c14n_otp_ptr;
  uint32_t c14n_otp_len;
  uint8_t *otp_digest;
  uint32_t otp_digest_len;
  uint8_t otp_b64[128];
  uint16_t otp_b64_len;
  uint8_t otp_b64_signature[512];
  uint16_t otp_b64_signature_len;
  uint8_t *signed_xml_ptr;
  uint16_t signed_xml_len;
  uint8_t *signature_value = NULL;
  uint16_t signature_value_len = 0;
  uint8_t *subject = NULL;
  uint16_t subject_len = 0;
  uint8_t *certificate = NULL;
  uint16_t certificate_len = 0;
  uint32_t otp_xml_len;
  uint8_t *final_xml_ptr;

  /*C14N - Canonicalization of <otp> portion of xml*/
  c14n_otp_ptr = otp_compose_c14n_v25(in_ptr, &c14n_otp_len); 

  otp_digest = (uint8_t *)malloc(sizeof(uint8_t) * 128);
  assert(otp_digest != NULL);
  memset((void *)otp_digest, 0, (sizeof(uint8_t) * 128));

  /*digest of c14n xml*/
  util_compute_digest(c14n_otp_ptr, 
                      c14n_otp_len, 
                      otp_digest, 
                      &otp_digest_len);

  free(c14n_otp_ptr);
  c14n_otp_ptr = NULL;
  c14n_otp_len = 0;

  memset((void *)otp_b64, 0, sizeof(otp_b64));
  otp_b64_len = 0;
  util_base64(otp_digest, otp_digest_len, otp_b64, &otp_b64_len);

  free(otp_digest);
  otp_digest = NULL;
  otp_digest_len = 0;

  signed_xml_ptr = (uint8_t *)malloc(sizeof(uint8_t) * 2048);
  assert(signed_xml_ptr != NULL);
  memset((void *)signed_xml_ptr, 0, (sizeof(uint8_t) * 2048));

  /*C14N for <SignedInfo> portion of xml*/
  util_c14n_signedinfo(signed_xml_ptr, 
                       (sizeof(uint8_t) * 2048), 
                       &signed_xml_len, 
                       /*Message Digest in base64*/
                       otp_b64);

  /*Creating RSA Signature - by signing digest with private key*/
  util_compute_rsa_signature(signed_xml_ptr, 
                             signed_xml_len, 
                             &signature_value, 
                             &signature_value_len);
  free(signed_xml_ptr);
  signed_xml_ptr = NULL;
  signed_xml_len = 0;

  memset((void *)otp_b64_signature, 0, sizeof(otp_b64_signature));
  otp_b64_signature_len = 0;

  util_base64(signature_value, 
              signature_value_len, 
              otp_b64_signature, 
              &otp_b64_signature_len);

  free(signature_value);
  signature_value = NULL;
  signature_value_len = 0;

  util_subject_certificate(&subject,
                           &subject_len,
                           &certificate,
                           &certificate_len);

  /*Create partial OTP xml*/ 
  final_xml_ptr = otp_compose_xml_v25(in_ptr, &otp_xml_len);
  *len_ptr = otp_xml_len;

  /*Append signed info to OTP xml*/
  util_compose_final_xml(&final_xml_ptr[otp_xml_len], 
                         (4000 - otp_xml_len), 
                         (uint16_t *)&otp_xml_len,
                         /*digest*/
                         otp_b64,
                         /*Signature Value*/
                         otp_b64_signature,
                         /*Subject Name*/
                         subject,
                         /*Certificate*/
                         certificate); 

  *len_ptr += otp_xml_len;

  otp_xml_len = snprintf(&final_xml_ptr[*len_ptr],
                         (4000 - *len_ptr),
                         "%s",
                         "</Otp>");
  
  *len_ptr += otp_xml_len;
  free(signature_value);
  signature_value = NULL;
  free(subject);
  free(certificate);

  return(final_xml_ptr);
}/*otp_sign_xml_v25*/

uint8_t *otp_main_ex_v25(uint8_t *in_ptr, 
                         uint32_t in_len, 
                         uint32_t *len_ptr) {

  uint8_t *otp_xml_ptr = NULL;
  uint8_t *http_req_ptr = NULL;
  uint32_t http_len;

  otp_xml_ptr = otp_sign_xml_v25(in_ptr, len_ptr);
  http_req_ptr = otp_compose_http_request(in_ptr, 
                                          otp_xml_ptr, 
                                          *len_ptr, 
                                          &http_len);
  free(otp_xml_ptr);
  otp_xml_ptr = NULL;

  fprintf(stderr, "\n%s:%d http_request %s\n", __FILE__, __LINE__, http_req_ptr);

  return(http_req_ptr);
}/*otp_main_ex_v25*/

uint8_t *otp_main_ex(uint8_t *in_ptr, 
                     uint32_t in_len, 
                     uint16_t version, 
                     uint32_t *rsp_len) {

  if(16 == version) {
    /*version 1.6*/
    return(otp_main_ex_v16(in_ptr, in_len, rsp_len));

  } else if(25 == version) {
    /*version 2.5*/
    return(otp_main_ex_v25(in_ptr, in_len, rsp_len));

  } else {
    /*Invalid version*/
    fprintf(stderr, "%s:%d Invalid version %d\n", __FILE__, __LINE__, version);
    return(NULL);
  }

}/*otp_main_ex*/


#endif /* __OTP_C__ */
