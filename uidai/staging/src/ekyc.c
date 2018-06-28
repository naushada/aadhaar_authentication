#ifndef __eKYC_C__
#define __eKYC_C__

#include "common.h"
#include "util.h"
#include "auth.h"
#include "uidai.h"


uint8_t *ekyc_compose_xml_v20(uint8_t *in_ptr,
                              uint8_t *auth_xml_ptr,
                              uint32_t *len_ptr) {
  uint8_t *param_ptr = NULL;
  uint8_t *attr_ptr[10];
  uint32_t idx;
  uint32_t max_idx;
  uint8_t *ekyc_xml_ptr = NULL;
  uint32_t ekyc_xml_size = 6500;
  uint8_t *b64_auth_xml_ptr = NULL;
  uint32_t b64_auth_xml_size = 5500;
  uint16_t len;

  b64_auth_xml_ptr = (uint8_t *)malloc(sizeof(uint8_t) * b64_auth_xml_size);
  assert(b64_auth_xml_ptr != NULL);
  memset((void *)b64_auth_xml_ptr, 0, sizeof(uint8_t) * b64_auth_xml_size);

  util_base64(auth_xml_ptr, (uint16_t)strlen(auth_xml_ptr), b64_auth_xml_ptr, &len);

  fprintf(stderr, "%s:%d eKyc b64 %s\n", __FILE__, __LINE__, b64_auth_xml_ptr);

  param_ptr = uidai_get_param(in_ptr, "kyc");
  assert(param_ptr != NULL);

  attr_ptr[0] = uidai_get_attr(param_ptr, "ver");
  attr_ptr[1] = uidai_get_attr(param_ptr, "ra");
  attr_ptr[2] = uidai_get_attr(param_ptr, "rc");
  attr_ptr[3] = uidai_get_attr(param_ptr, "mec");
  attr_ptr[4] = uidai_get_attr(param_ptr, "lr");
  attr_ptr[5] = uidai_get_attr(param_ptr, "de");
  attr_ptr[6] = uidai_get_attr(param_ptr, "pfr");
  free(param_ptr);
  param_ptr = NULL;

  attr_ptr[7] = auth_get_ts();
  max_idx = 8;
 
  ekyc_xml_ptr = (uint8_t *)malloc(sizeof(uint8_t) * ekyc_xml_size);
  assert(ekyc_xml_ptr != NULL);
  memset((void *)ekyc_xml_ptr, 0, sizeof(uint8_t) * ekyc_xml_size);

  *len_ptr = snprintf(ekyc_xml_ptr,
                      (ekyc_xml_size * sizeof(uint8_t)),
                      "%s%s%s%s%s"
                      "%s%s%s%s%s"
                      "%s%s%s%s%s"
                      "%s%s%s%s%s",
                      "<Kyc ver=\"",
                      attr_ptr[0],
                      "\" ts=\"",
                      attr_ptr[7],
                      "\" ra=\"",
                      attr_ptr[1],
                      "\" rc=\"",
                      attr_ptr[2],
                      "\" mec=\"",
                      attr_ptr[3],
                      "\" lr=\"",
                      attr_ptr[4],
                      "\" de=\"",
                      attr_ptr[5],
                      "\" pfr=\"",
                      attr_ptr[6], 
                      "\">\n",
                      "  <Rad>",
                      b64_auth_xml_ptr,
                      "</Rad>\n</Kyc>");
  
  fprintf(stderr, "%s:%d eKyc XML %s\n", __FILE__, __LINE__, ekyc_xml_ptr);
  free(b64_auth_xml_ptr);
  b64_auth_xml_ptr = NULL;

  /*Freeing the allocated memory*/
  for(idx = 0; idx < max_idx; idx++) {
    free(attr_ptr[idx]);
    attr_ptr[idx] = NULL;
  }
  return(ekyc_xml_ptr);
}/*ekyc_compose_xml_v20*/

uint8_t *ekyc_compose_http_req(uint8_t *in_ptr,
                               uint8_t *kyc_xml, 
                               uint32_t *len_ptr) {

  uint8_t *http_req_ptr = NULL;
  uint32_t http_req_size = 6500;
  uint8_t *param_ptr;
  uint8_t *attr_ptr[10];
  uint32_t idx = 0;
  uint32_t max_idx = 0;

  param_ptr = uidai_get_param(in_ptr, "auth");
  assert(param_ptr != NULL);
  attr_ptr[0] = uidai_get_attr(param_ptr, "uid");
  attr_ptr[1] = uidai_get_attr(param_ptr, "ac");
  attr_ptr[2] = uidai_get_attr(param_ptr, "lk");
  free(param_ptr);
  param_ptr = NULL;

  param_ptr = uidai_get_param(in_ptr, "kyc");
  assert(param_ptr != NULL);
  attr_ptr[3] = uidai_get_attr(param_ptr, "uri");
  free(param_ptr);
  param_ptr = NULL;
  
  param_ptr = uidai_get_param(in_ptr, "uidai");
  assert(param_ptr != NULL);
  attr_ptr[4] = uidai_get_attr(param_ptr, "host");
  free(param_ptr);
  param_ptr = NULL;
  max_idx = 5;

  http_req_ptr = (uint8_t *)malloc(sizeof(uint8_t) * http_req_size); 
  assert(http_req_ptr != NULL);
  memset((void *)http_req_ptr, 0, (sizeof(uint8_t) * http_req_size));

  *len_ptr = snprintf(http_req_ptr, 
                      http_req_size,
                      "%s%s%s%s"
                      "%s%s%c%s%c"
                      "%s%s%s%s%s"
                      "%s%s%s%s%d"
                      "%s%s%s",
                      "POST http://",
                      /*host name*/
                      attr_ptr[4],
                      /*uri*/
                      attr_ptr[3],
                      "/",
                      /*ac*/
                      attr_ptr[1],
                      "/",
                      /*uid[0]*/
                      attr_ptr[0][0],
                      "/",
                      /*uid[1]*/
                      attr_ptr[0][1],
                      "/",
                      /*lk*/
                      attr_ptr[2],
                      " HTTP/1.1\r\n",
                      "Host: ",
                      /*host name*/
                      attr_ptr[4],
                      "\r\n",
                      "Content-Type: text/xml\r\n",
                      "Connection: Keep-alive\r\n",
                      "Content-Length: ",
                      (int32_t)strlen(kyc_xml),
                      "\r\n",
                      /*Payload delimeter*/
                      "\r\n",
                      kyc_xml);

  /*Freeing the allocated memory*/
  for(idx = 0; idx < max_idx; idx++) {
    free(attr_ptr[idx]);
    attr_ptr[idx] = NULL;
  }

  return(http_req_ptr);           
}/*ekyc_compose_http_req*/

uint8_t *ekyc_main_ex_v20(uint8_t *in_ptr,
                          uint32_t in_len,
                          uint32_t *len_ptr) {

  uint8_t *auth_ptr = NULL;
  uint8_t *http_req_ptr = NULL;
  uint8_t *param_ptr = NULL;
  uint8_t *version_ptr = NULL;
  uint8_t *ekyc_xml_ptr = NULL;

  param_ptr = uidai_get_param(in_ptr, "auth");
  version_ptr = uidai_get_attr(param_ptr, "ver");
  free(param_ptr);

  auth_init_ex(in_ptr, in_len);

  if(!strncmp(version_ptr, "1.6", 3)) {
    /*Retrieve the Auth version*/
    auth_ptr = auth_main_ex_v16(in_ptr, in_len, len_ptr);
    
  } else if(!strncmp(version_ptr, "2.0", 3)) {

  } else if(!strncmp(version_ptr, "2.5", 3)) {

  }

  ekyc_xml_ptr = ekyc_compose_xml_v20(in_ptr, auth_ptr, len_ptr);
  free(auth_ptr);
  auth_ptr = NULL;

  auth_ptr = ekyc_compose_http_req(in_ptr, ekyc_xml_ptr, len_ptr);
  free(ekyc_xml_ptr);
  ekyc_xml_ptr = NULL;

  fprintf(stderr, "%s:%d auth xml %s\n", __FILE__, __LINE__, auth_ptr); 
  free(version_ptr);

  return(auth_ptr);
}/*ekyc_main_ex_v20*/

uint8_t *ekyc_main_ex(uint8_t *in_ptr, 
                      uint32_t in_len, 
                      uint16_t version, 
                      int32_t rsp_fd) {

  uint8_t *req_ptr = NULL;
  uint32_t len = 0;

  if(20 == version) {
    /*ekyc version 2.0*/
    req_ptr = ekyc_main_ex_v20(in_ptr, in_len, &len);

  } else if(21 == version) {
    /*ekyc version 2.1*/

  } else if(25 == version) {
    /*ekyc version 2.5*/

  }

  return(req_ptr);
}/*ekyc_main_ex*/

#endif /*__eKYC_C__*/
