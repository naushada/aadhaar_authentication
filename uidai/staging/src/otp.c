#ifndef __OTP_C__
#define __OTP_C__

#include "common.h"
#include "util.h"
#include "uidai.h"
#include "otp.h"

otp_ctx_t otp_ctx_g;

int32_t otp_compose_ts(void) {

  otp_ctx_t *pOtpCtx = &otp_ctx_g;
  time_t curr_time;
  struct tm *local_time;

  /*Retrieving the current time*/
  curr_time = time(NULL);
  local_time = localtime(&curr_time);
  memset((void *)pOtpCtx->ts, 0, sizeof(pOtpCtx->ts));

  snprintf(pOtpCtx->ts, 
           sizeof(pOtpCtx->ts),
           "%04d-%02d-%02dT%02d:%02d:%02d", 
           local_time->tm_year+1900, 
           local_time->tm_mon+1,
           local_time->tm_mday, 
           local_time->tm_hour,
           local_time->tm_min, 
           local_time->tm_sec);

  return(0);
}/*otp_compose_ts*/

int32_t otp_init_ex(uint8_t *in_ptr, uint32_t in_len) {

  uint8_t *attr[10];
  uint8_t *param_ptr = NULL;
  uint32_t idx = 0;
  otp_ctx_t *pOtpCtx = &otp_ctx_g;

  memset((void *)pOtpCtx, 0, sizeof(otp_ctx_t));

  param_ptr = uidai_get_param(in_ptr, "otp");
  attr[0] = uidai_get_attr(param_ptr, "ac");
  attr[1] = uidai_get_attr(param_ptr, "sa");
  attr[2] = uidai_get_attr(param_ptr, "lk");
  attr[3] = uidai_get_attr(param_ptr, "ver");
  attr[4] = uidai_get_attr(param_ptr, "type");
  attr[5] = uidai_get_attr(param_ptr, "tid");
  attr[6] = uidai_get_attr(param_ptr, "txn");
  attr[7] = uidai_get_attr(param_ptr, "uid");
  free(param_ptr);
  param_ptr = NULL;
 
  /*minus 1 for null terminated string*/
  strncpy(pOtpCtx->ac, (const char *)attr[0], sizeof(pOtpCtx->ac) -1);
  strncpy(pOtpCtx->sa, (const char *)attr[1], sizeof(pOtpCtx->sa) -1);
  strncpy(pOtpCtx->lk, (const char *)attr[2], sizeof(pOtpCtx->lk) -1);
  strncpy(pOtpCtx->ver, (const char *)attr[3], sizeof(pOtpCtx->ver) -1);
  strncpy(pOtpCtx->type, (const char *)attr[4], sizeof(pOtpCtx->type) -1);
  strncpy(pOtpCtx->tid, (const char *)attr[5], sizeof(pOtpCtx->tid) -1);
  strncpy(pOtpCtx->txn, (const char *)attr[6], sizeof(pOtpCtx->txn) -1);
  strncpy(pOtpCtx->uid, (const char *)attr[7], sizeof(pOtpCtx->uid) -1);

  for(idx = 0; idx < 8; idx++) {
    free(attr[idx]);
    attr[idx] = NULL;
  }

  param_ptr = uidai_get_param(in_ptr, "opts");
  attr[0] = uidai_get_attr(param_ptr, "ch");

  /*00 - Send OTP via both SMS & e-mail
   *01 - Send OTP via SMS only
   *02 - Send OTP via e-mail only
   */
  pOtpCtx->ch = (uint8_t)atoi(attr[0]);
  free(param_ptr);
  free(attr[0]);
  param_ptr = NULL;
  attr[0] = NULL;

  param_ptr = uidai_get_param(in_ptr, "uidai");
  attr[0] = uidai_get_attr(param_ptr, "uri");
  attr[1] = uidai_get_attr(param_ptr, "host");
  
  strncpy(pOtpCtx->uri, 
          (const char *)attr[0], 
          sizeof(pOtpCtx->uri) -1);

  strncpy(pOtpCtx->uidai_host_name, 
          (const char *)attr[1], 
          sizeof(pOtpCtx->uidai_host_name) -1);

  free(param_ptr);
  free(attr[0]);
  free(attr[1]);
  /*Retrieve the current time and compose ISO ts format*/
  otp_compose_ts();
  return(0);
}/*otp_init_ex*/

/** @brief This function is to build the OTP xml
 *
 *  @param *len_ptr is the pointer to unsigned int which holds the 
 *          length of the partial otp xml
 *
 *  @return It will return pointer to unsigned char to partial OTP xml,
 *          caller must free the memory. 
 */
uint8_t *otp_compose_xml_v16(uint32_t *len_ptr) {
  int32_t ret = -1;
  otp_ctx_t *pOtpCtx = &otp_ctx_g;
  uint8_t *xml_ptr = NULL;
  uint32_t len = 0;
  uint8_t *req_ptr;
  uint32_t req_size = 4000;

  req_ptr = (uint8_t *)malloc(sizeof(uint8_t) * req_size);
  assert(req_ptr != NULL);
  memset((void *)req_ptr, 0, (sizeof(uint8_t) * req_size));

  xml_ptr = otp_compose_otp_v16(&len);
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
uint8_t *otp_compose_otp_v16(uint32_t *len_ptr) {

  int32_t ret = -1;
  otp_ctx_t *pOtpCtx = &otp_ctx_g;
  uint8_t *req_ptr = NULL;
  uint32_t req_size = 1024;

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
                 pOtpCtx->ac,
                 "\" lk=\"",
                 pOtpCtx->lk,
                 "\" sa=\"",
                 pOtpCtx->sa,
                 "\" tid=\"",
                 pOtpCtx->tid,
                 "\" ts=\"",
                 pOtpCtx->ts,
                 "\" txn=\"",
                 pOtpCtx->txn,
                 "\" type=\"",
                 pOtpCtx->type,
                 "\" uid=\"",
                 pOtpCtx->uid,
                 "\" ver=\"",
                 /*It's value shall be 1.6*/
                 pOtpCtx->ver,
                 /*Otp attribute ends here*/
                 "\">\n",
                 /*opts - options tag starts*/
                 "  <Opts ch=\"",
                 pOtpCtx->ch,
                 "\"/>");

  *len_ptr = (uint32_t)ret;

  return(req_ptr);
}/*otp_compose_otp_v16*/

/** @brief This function is to build the xml in c14n format to compute the message
 *         digest. In c14n format every xml tag shall be of form <tag></tang>
 *
 *  @param *c14n_len_ptr is the pointer to unsigned int to hold length of c14n xml 
 * 
 *  @return It returns the pointer to char for c14n xml, the caller has to free the memory
 */
uint8_t *otp_compose_c14n_v16(uint32_t *c14n_len_ptr) {

  int32_t ret = -1;
  otp_ctx_t *pOtpCtx = &otp_ctx_g;
  uint8_t *c14n_ptr = NULL;
  uint32_t c14n_size = 1024;

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
                 pOtpCtx->ac,
                 "\" lk=\"",
                 pOtpCtx->lk,
                 "\" sa=\"",
                 pOtpCtx->sa,
                 "\" tid=\"",
                 pOtpCtx->tid,
                 "\" ts=\"",
                 pOtpCtx->ts,
                 "\" txn=\"",
                 pOtpCtx->txn,
                 "\" type=\"",
                 pOtpCtx->type,
                 "\" uid=\"",
                 pOtpCtx->uid,
                 "\" ver=\"",
                 /*It's value shall be 1.6*/
                 pOtpCtx->ver,
                 /*Otp attribute ends here*/
                 "\">\n",
                 /*opts - options tag starts*/
                 "  <Opts ch=\"",
                 pOtpCtx->ch,
                 "\"></Opts>\n",
                 /*https://www.di-mgt.com.au/xmldsig2.html#c14nit*/
                 "  \n",
                 "</Otp>");

  *c14n_len_ptr = (uint32_t)ret;

  return(c14n_ptr);
}/*otp_compose_c14n_v16*/

uint8_t *otp_compose_request(uint8_t *signed_xml, 
                             uint32_t signed_xml_len, 
                             uint32_t *http_req_len) {

  uint8_t *req_ptr = NULL;
  uint32_t req_len = 0;
  int32_t ret = -1;
  otp_ctx_t *pOtpCtx = &otp_ctx_g;

  uint32_t req_size = signed_xml_len + 1024;
  
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
                 pOtpCtx->uidai_host_name,
                 pOtpCtx->uri,
                 "/",
                 pOtpCtx->ac,
                 "/",
                 pOtpCtx->uid[0],
                 "/",
                 pOtpCtx->uid[1],
                 "/",
                 pOtpCtx->lk,
                 " HTTP/1.1\r\n",
                 "Host: ",
                 pOtpCtx->uidai_host_name,
                 "\r\n",
                 "Content-Type: text/xml\r\n",
                 "Connection: Keep-alive\r\n",
                 "Content-Length: ",
                 signed_xml_len,
                 /*delimeter B/W http header and its body*/
                 "\r\n\r\n");

  memcpy((void *)&req_ptr[ret], signed_xml, signed_xml_len);
  *http_req_len = ret + signed_xml_len;

  return(req_ptr); 
}/*otp_compose_request*/

/*
  1.Canonicalize* the text-to-be-signed, C = C14n(T).
  2.Compute the message digest of the canonicalized text, m = Hash(C).
  3.Encapsulate the message digest in an XML <SignedInfo> element, SI, in canonicalized form.
  4.Compute the RSA signatureValue of the canonicalized <SignedInfo> element, SV = RsaSign(Ks, SI).
  5.Compose the final XML document including the signatureValue, this time in non-canonicalized form.

 */
uint8_t *otp_sign_xml_v16(uint32_t *len_ptr) {

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
  c14n_otp_ptr = otp_compose_c14n_v16(&c14n_otp_len); 

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
  final_xml_ptr = otp_compose_xml_v16(&otp_xml_len);
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

  otp_xml_ptr = otp_sign_xml_v16(len_ptr);
  http_req_ptr = otp_compose_request(otp_xml_ptr, *len_ptr, &http_len);
  free(otp_xml_ptr);
  otp_xml_ptr = NULL;

  fprintf(stderr, "\n%s:%d http_request %s\n", __FILE__, __LINE__, http_req_ptr);

  return(http_req_ptr);
}/*otp_main_ex_v16*/

uint8_t *otp_main_ex_v25(uint8_t *in_ptr, 
                         uint32_t in_len, 
                         uint32_t *len_ptr) {

}/*otp_main_ex_v25*/

uint8_t *otp_main_ex(uint8_t *in_ptr, 
                     uint32_t in_len, 
                     uint16_t version, 
                     uint32_t *rsp_len) {

  otp_init_ex(in_ptr, in_len);

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


/*===================================TO BE REMOVED=======================================*/ 
int32_t otp_init(uint8_t *ac,
                 uint8_t *sa,
                 /*license key*/
                 uint8_t *lk,
                 uint8_t *ver,
                 uint8_t *uidai_host_name) {

  otp_ctx_t *pOtpCtx = &otp_ctx_g;
  memset((void *)pOtpCtx, 0, sizeof(otp_ctx_t));

  strncpy(pOtpCtx->ac, (const char *)ac, sizeof(pOtpCtx->ac));
  strncpy(pOtpCtx->sa, (const char *)sa, sizeof(pOtpCtx->sa));
  strncpy(pOtpCtx->lk, (const char *)lk, sizeof(pOtpCtx->lk));
  //strncpy(pOtpCtx->type, "A", 1);
  strncpy(pOtpCtx->type, "M", 1);
  strncpy(pOtpCtx->ver, "1.6", 3);

  /*00 - Send OTP via both SMS & e-mail
   *01 - Send OTP via SMS only
   *02 - Send OTP via e-mail only
   */
  pOtpCtx->ch = 0x00;

  strncpy(pOtpCtx->uidai_host_name, 
          (const char *)uidai_host_name, 
          strlen((const char *)uidai_host_name));

  return(0);
}/*otp_init*/

/**
 * @brief This function creates the canonicalise form of Otp 
 *        xml in which every blank spaces does matter.
 *        https://www.di-mgt.com.au/xmldsig2.html#exampleofenveloped
 *
 * @param c14n is to store the canonicalized xml
 * @param c14_max_len is the max buffer size of c14n
 * @param c14n_len is the length of canonicalised xml
 *
 * @param upon success returns 0 else < 0
 */
int32_t otp_build_c14n_otp_tag(uint8_t *c14n, 
                               uint16_t c14n_max_size, 
                               uint16_t *c14n_len) {
  int32_t ret = -1;
  otp_ctx_t *pOtpCtx = &otp_ctx_g;
  time_t curr_time;
  struct tm *local_time;

  /*Retrieving the current time*/
  curr_time = time(NULL);
  local_time = localtime(&curr_time);
  memset((void *)pOtpCtx->ts, 0, sizeof(pOtpCtx->ts));

  snprintf(pOtpCtx->ts, 
           sizeof(pOtpCtx->ts),
           "%04d-%02d-%02dT%02d:%02d:%02d", 
           local_time->tm_year+1900, 
           local_time->tm_mon+1,
           local_time->tm_mday, 
           local_time->tm_hour,
           local_time->tm_min, 
           local_time->tm_sec);

  ret = snprintf(c14n,
                 c14n_max_size,
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%.2d%s%s%s",
                 "<Otp",
                 " ac=\"",
                 pOtpCtx->ac,
                 "\" lk=\"",
                 pOtpCtx->lk,
                 "\" sa=\"",
                 pOtpCtx->sa,
                 "\" tid=\"public\"",
                 " ts=\"",
                 pOtpCtx->ts,
                 "\" txn=\"",
                 pOtpCtx->txn,
                 "\" type=\"",
                 pOtpCtx->type,
                 "\" uid=\"",
                 pOtpCtx->uid,
                 "\" ver=\"",
                 /*It's value shall be 1.6*/
                 pOtpCtx->ver,
                 /*Otp attribute ends here*/
                 "\">\n",
                 /*opts - options tag starts*/
                 "  <Opts ch=\"",
                 pOtpCtx->ch,
                 "\"></Opts>\n",
                 /*https://www.di-mgt.com.au/xmldsig2.html#c14nit*/
                 "  \n",
                 "</Otp>");

  *c14n_len = (uint16_t)ret;

  return(0);
}/*otp_build_c14n_otp_tag*/
/*
  1.Canonicalize* the text-to-be-signed, C = C14n(T).
  2.Compute the message digest of the canonicalized text, m = Hash(C).
  3.Encapsulate the message digest in an XML <SignedInfo> element, SI, in canonicalized form.
  4.Compute the RSA signatureValue of the canonicalized <SignedInfo> element, SV = RsaSign(Ks, SI).
  5.Compose the final XML document including the signatureValue, this time in non-canonicalized form.

 */
int32_t otp_sign_xml(uint8_t **signed_xml, 
                     uint16_t *signed_xml_len) {

  uint8_t c14n_otp_xml[5096];
  uint16_t c14n_otp_xml_len;
  uint8_t otp_digest[1024];
  uint32_t otp_digest_len;
  uint8_t otp_b64[2024];
  uint16_t otp_b64_len;
  uint8_t otp_b64_signature[2024];
  uint16_t otp_b64_signature_len;
  uint8_t c14n_otp_signed_info_xml[5096];
  uint16_t c14n_otp_signed_info_xml_len;
  uint8_t *signature_value = NULL;
  uint16_t signature_value_len = 0;
  uint8_t *subject = NULL;
  uint16_t subject_len = 0;
  uint8_t *certificate = NULL;
  uint16_t certificate_len = 0;
  uint16_t idx;
  uint16_t otp_xml_len;

  memset((void *)c14n_otp_xml, 0, sizeof(c14n_otp_xml));
  /*C14N - Canonicalization of <otp> portion of xml*/
  otp_build_c14n_otp_tag(c14n_otp_xml, 
                         sizeof(c14n_otp_xml), 
                         &c14n_otp_xml_len);

  fprintf(stderr, "\n%s:%d otp_tag\n%s\nlen %d\n", 
                  __FILE__, 
                  __LINE__, 
                  c14n_otp_xml, 
                  c14n_otp_xml_len);

  memset((void *)otp_digest, 0, sizeof(otp_digest));

  util_compute_digest(c14n_otp_xml, 
                     c14n_otp_xml_len, 
                     otp_digest, 
                     &otp_digest_len);

  memset((void *)otp_b64, 0, sizeof(otp_b64));
  otp_b64_len = 0;
  util_base64(otp_digest, otp_digest_len, otp_b64, &otp_b64_len);

  /*C14N for <SignedInfo> portion of xml*/
  util_c14n_signedinfo(c14n_otp_signed_info_xml, 
                        sizeof(c14n_otp_signed_info_xml), 
                        &c14n_otp_signed_info_xml_len, 
                        /*Message Digest in base64*/
                        otp_b64);

  fprintf(stderr, "\n%s:%d SI\n%s\nlen %d\n", 
                  __FILE__, 
                  __LINE__, 
                  c14n_otp_signed_info_xml, 
                  c14n_otp_signed_info_xml_len);
 
  /*Creating RSA Signature - by signing digest with private key*/
  util_compute_rsa_signature(c14n_otp_signed_info_xml, 
                            c14n_otp_signed_info_xml_len, 
                            &signature_value, 
                            &signature_value_len);

  memset((void *)otp_b64_signature, 0, sizeof(otp_b64_signature));
  otp_b64_signature_len = 0;

  util_base64(signature_value, 
               signature_value_len, 
               otp_b64_signature, 
               &otp_b64_signature_len);

  util_subject_certificate(&subject,
                            &subject_len,
                            &certificate,
                            &certificate_len);

  /*Create the Final signed xml*/ 
  (*signed_xml) = (uint8_t *)malloc(5000);
  assert((*signed_xml) != NULL);
  memset((void *)(*signed_xml), 0, 5000);

  otp_compose_otp_xml(*signed_xml,
                      5000,
                      &otp_xml_len); 

  util_compose_final_xml((uint8_t *)&(*signed_xml)[otp_xml_len], 
                          (5000 - otp_xml_len), 
                          signed_xml_len,
                          /*digest*/
                          otp_b64,
                          /*Signature Value*/
                          otp_b64_signature,
                          /*Subject Name*/
                          subject,
                          /*Certificate*/
                          certificate); 

  *signed_xml_len += otp_xml_len;

  otp_xml_len = snprintf((uint8_t *)&(*signed_xml)[*signed_xml_len],
                         (5000 - *signed_xml_len),
                         "%s",
                         "</Otp>");
  
  *signed_xml_len += otp_xml_len;
  free(signature_value);
  signature_value = NULL;
  free(subject);
  free(certificate);

  return(0);
}/*otp_sign_xml*/


/**
 * We use the SHA-1 message digest function, which outputs a hash value 20 bytes long
 */

int32_t otp_compute_b64(uint8_t *sha1, 
                        uint16_t sha1_len, 
                        uint8_t *b64, 
                        uint16_t *b64_len) {

  uint16_t offset;
  uint16_t idx = 0;
  uint32_t tmp = 0;
  uint8_t *tmp_b64;
  uint8_t b64_set[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

  if(!sha1 || !sha1_len || !b64) {
    return -1;
  }

  for(offset = 0; offset < sha1_len; offset +=3)
  {
    if(sha1_len - offset >= 3)
    {
      tmp = ((sha1[offset] << 8 |
              sha1[offset + 1]) << 8 |
              sha1[offset + 2]) & 0xFFFFFF;

      b64[idx++] = b64_set[(tmp >> 18)  & 0x3F];
      b64[idx++] = b64_set[(tmp >> 12)  & 0x3F];
      b64[idx++] = b64_set[(tmp >> 6 )  & 0x3F];
      b64[idx++] = b64_set[(tmp >> 0 )  & 0x3F];
    }
    else if((sha1_len - offset) == 1)
    {
      tmp = sha1[offset];

      b64[idx++] = b64_set[(tmp >> 2)  & 0x3F];
      b64[idx++] = b64_set[(tmp << 4)  & 0x3F];
      b64[idx++] = '=';
      b64[idx++] = '=';

    }
    else if((sha1_len - offset) == 2)
    {
      tmp = (sha1[offset] << 8 |
             sha1[offset + 1]) & 0xFFFF;

      b64[idx++] = b64_set[(tmp >> 10)  & 0x3F];
      b64[idx++] = b64_set[(tmp >>  3)  & 0x3F];
      b64[idx++] = b64_set[(tmp <<  3)  & 0x3F];
      b64[idx++] = '=';
    }
  }


  tmp_b64 = (uint8_t *)malloc(idx + 64);
  uint16_t index = 0;

  for(offset = 0; index < idx; offset++) {
    if((offset > 0) && !(offset % 64)) {
      tmp_b64[offset] = '\n';
    } else {
      tmp_b64[offset] = b64[index++];
    }
  }

  *b64_len = offset;
  memcpy((void *)b64, tmp_b64, offset);
  return (0);
}/*otp_compute_b64*/

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

/** @brief This function is to build the OTP xml
 *
 *  @param *otp_xml is the pointer to unsigned char which will holds the 
 *          otp_xml
 *  @param otp_xml_size is the otp_xml buffer size, i.e. how big is this otp_xml
 *  @param *otp_xml_len is the output which will give the zise of opt_xml
 *
 *  @return It will return for success else < 0
 */
int32_t otp_compose_otp_xml(uint8_t *otp_xml, 
                            uint32_t otp_xml_max_size, 
                            uint16_t *otp_xml_len) {
  int32_t ret = -1;
  otp_ctx_t *pOtpCtx = &otp_ctx_g;

  ret = snprintf(otp_xml,
                 otp_xml_max_size,
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%s%.2d"
                 "%s",
                 "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n",
                 "<Otp xmlns=\"http://www.uidai.gov.in/authentication/otp/1.0\" ac=\"public\"",
                 " lk=\"",
                 pOtpCtx->lk,
                 "\" sa=\"",
                 pOtpCtx->sa,
                 "\" tid=\"public\"",
                 " ts=\"",
                 pOtpCtx->ts,
                 "\" txn=\"",
                 pOtpCtx->txn,
                 "\" type=\"",
                 pOtpCtx->type,
                 "\" uid=\"",
                 pOtpCtx->uid,
                 "\" ver=\"",
                 /*It's value shall be 1.6*/
                 pOtpCtx->ver,
                 /*Otp attribute ends here*/
                 "\">\n",
                 /*otps tag starts*/
                 "  <Opts ch=\"",
                 pOtpCtx->ch,
                 "\"/>\n");

  *otp_xml_len = ret;

  return(0);
}/*otp_compose_otp_xml*/

int32_t otp_request_otp(uint8_t *signed_xml, 
                        uint16_t signed_xml_len, 
                        uint8_t **http_req, 
                        uint32_t *http_req_len) {

  uint8_t *req_ptr = NULL;
  uint16_t req_len = 0;
  int32_t ret = -1;
  otp_ctx_t *pOtpCtx = &otp_ctx_g;

  uint16_t req_max_len = signed_xml_len + 1024;
  
  req_ptr = (uint8_t *) malloc(req_max_len);
  assert(req_ptr != NULL);
  memset((void *)req_ptr, 0, req_max_len);

  /*Prepare http request*/
  ret = snprintf((char *)req_ptr,
                 req_max_len,
                 "%s%s%s%s%s"
                 "%s%s%c%s%c"
                 "%s%s%s%s%s"
                 "%s%s%s%s%d"
                 "%s",
                 /*https://<host>/otp/<ver>/<ac>/<uid[0]>/<uid[1]>/<asalk>*/
                 "POST http://",
                 pOtpCtx->uidai_host_name,
                 "/otp/",
                 pOtpCtx->ver,
                 "/",
                 pOtpCtx->ac,
                 "/",
                 pOtpCtx->uid[0],
                 "/",
                 pOtpCtx->uid[1],
                 "/",
                 pOtpCtx->lk,
                 " HTTP/1.1\r\n",
                 "Host: ",
                 pOtpCtx->uidai_host_name,
                 "\r\n",
                 "Content-Type: text/xml\r\n",
                 "Connection: Keep-alive\r\n",
                 "Content-Length: ",
                 signed_xml_len,
                 /*delimeter B/W http header and its body*/
                 "\r\n\r\n");

  memcpy((void *)&req_ptr[ret], signed_xml, signed_xml_len);
  req_max_len = ret + signed_xml_len;
  *http_req = req_ptr;
  *http_req_len = req_max_len;

  return(0); 
}/*otp_request_otp*/

/**
 * @brief This function processes the response recived and 
 *  parses the received parameters. 
 *
 * @param conn_fd is the connection at which response is received.
 * @param packet_buffer holds the response buffer
 * @param packet_len is the received response length
 *
 * @return it returns 0 upon success else < 0 
 */
int32_t otp_process_rsp(uint8_t *param, 
                        uint8_t **rsp_ptr, 
                        uint32_t *rsp_len) {
  uint8_t *ret_ptr = NULL;
  uint8_t *act_ptr = NULL;
  uint8_t *txn_ptr = NULL;
  uint8_t *err_ptr = NULL;
  uint8_t uam_conn_id[8];
  uint8_t redir_conn_id[8];
  uint8_t conn_id[8];
  uint8_t uid[14];
  uint8_t status[64];
  uint32_t rsp_size = 512;

  /*Initialize the auto variables*/
  memset((void *)uid, 0, sizeof(uid));
  memset((void *)uam_conn_id, 0, sizeof(uam_conn_id));
  memset((void *)redir_conn_id, 0, sizeof(redir_conn_id));
  memset((void *)conn_id, 0, sizeof(conn_id));
  memset((void *)status, 0, sizeof(status));

  ret_ptr = uidai_get_rparam(param, "ret");
  txn_ptr = uidai_get_rparam(param, "txn");
  assert(txn_ptr != NULL);
  assert(ret_ptr != NULL);

  /*extracting element from txn*/ 
  sscanf(txn_ptr, "\"%[^-]-%[^-]-%[^-]-%[^-]-",
                  uam_conn_id,
                  redir_conn_id,
                  conn_id,
                  uid);
  free(txn_ptr);

  if(!strncmp(ret_ptr, "\"y\"", 3)) {
    strncpy(status, "status=success", sizeof(status));
  } else {
    uint8_t tmp_err[8];
    uint8_t tmp_actn[8];
    uint8_t tmp_str[128];

    memset((void *)tmp_err, 0, sizeof(tmp_err));
    err_ptr = uidai_get_rparam(param, "err");
    assert(err_ptr != NULL);
    sscanf(err_ptr, "\"%[^\"]\"", tmp_err);
    free(err_ptr);

    snprintf(status, 
             sizeof(status),
             "%s%s",
             "status=failed&reason=", 
             tmp_err);

    act_ptr = uidai_get_rparam(param, "actn");
    if(act_ptr) {
      fprintf(stderr, "\n%s:%d act_ptr %s\n", __FILE__, __LINE__, act_ptr);
      memset((void *)tmp_actn, 0, sizeof(tmp_actn));
      memset((void *)tmp_str, 0, sizeof(tmp_str));
      sscanf(act_ptr, "\"%[^\"]\"", tmp_actn); 
      snprintf(tmp_str, sizeof(tmp_str), "&actn=%s", tmp_actn);
      strcat(status, tmp_str);
      free(act_ptr);
    }
  }

  free(ret_ptr);
  /*Build final response*/
  *rsp_ptr = (uint8_t *)malloc(rsp_size);
  assert(*rsp_ptr != NULL);

  memset((void *)(*rsp_ptr), 0, rsp_size);
  /*/response?type=otp&uid=xxxxxxxxxxxx&ext_conn_id=dddd&status=success/failed&reason=err_code&conn_id=YYYYY*/
  *rsp_len = snprintf((*rsp_ptr), 
                      rsp_size,
                      "%s%s%s%s%s"
                      "%s%s%s%s%s",
                      "/response?type=",
                      "otp",
                      "&uid=",
                      uid,
                      "&ext_conn_id=",
                      uam_conn_id,
                      "&",
                      status,
                      "&conn_id=",
                      redir_conn_id);
  
  return(0);
}/*otp_process_rsp*/

/** @brief INPUT:
 *    T, text-to-be-signed, a byte string;
 *    Ks, RSA private key;
 *  OUTPUT: XML file, xml
 *    1.Canonicalize* the text-to-be-signed, C = C14n(T).
 *    2.Compute the message digest of the canonicalized text, m = Hash(C).
 *    3.Encapsulate the message digest in an XML <SignedInfo> element, SI, in canonicalized form.
 *    4.Compute the RSA signatureValue of the canonicalized <SignedInfo> element, SV = RsaSign(Ks, SI).
 *    5.Compose the final XML document including the signatureValue, this time in non-canonicalized form.
 *     https://www.di-mgt.com.au/xmldsig.html
 *
 *
 */
int32_t otp_main(int32_t conn_fd, 
                 uint8_t *packet_ptr, 
                 uint32_t packet_len, 
                 uint8_t **rsp_ptr, 
                 uint32_t *rsp_len) {

  otp_ctx_t *pOtpCtx = &otp_ctx_g;
  uint8_t *req_ptr = NULL;
  uint16_t req_len = 0;
  uint8_t *uid_ptr = NULL;
  uint8_t *ext_conn_ptr = NULL;
  uint8_t *conn_id_ptr = NULL;

  /* The Request would be of form
   * /request?type=otp&uid=xxxxxxxxxxxx&ext_conn_id=dddd&conn_id=
   * ext_conn_id is the socket connection at which user is connected to UAM
   * conn_id is the socket connection at which UAM is connected to redir
   */
  /*/request?type=otp&uid=9701361361&ext_conn_id=15&rc=y&ver=1.6&conn_id=20*/

  uid_ptr = uidai_get_param(packet_ptr, "uid");
  ext_conn_ptr = uidai_get_param(packet_ptr, "ext_conn_id");
  conn_id_ptr = uidai_get_param(packet_ptr, "conn_id");

  strncpy(pOtpCtx->uid, uid_ptr, (sizeof(pOtpCtx->uid) - 1));

  snprintf(pOtpCtx->txn,
           sizeof(pOtpCtx->txn),
           "%d-%d-%d-%s-SampleClient",
           atoi(ext_conn_ptr),
           atoi(conn_id_ptr),
           conn_fd,
           uid_ptr);

  otp_sign_xml(&req_ptr, 
               &req_len);

  otp_request_otp(req_ptr, 
                  req_len,
                  rsp_ptr, 
                  rsp_len);

  free(req_ptr);

  free(uid_ptr);
  free(ext_conn_ptr);
  free(conn_id_ptr);
  return(0);
}/*otp_main*/

#endif /* __OTP_C__ */
