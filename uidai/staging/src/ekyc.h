#ifndef __eKYC_H__
#define __eKYC_H__



uint8_t *ekyc_main_ex(uint8_t *in_ptr,
                      uint32_t in_len,
                      uint16_t version,
                      int32_t rsp_fd);

uint8_t *ekyc_main_ex_v20(uint8_t *in_ptr,
                          uint32_t in_len,
                          uint32_t *len_ptr);

uint8_t *ekyc_compose_http_req(uint8_t *in_ptr,
                               uint8_t *auth_xml, 
                               uint32_t *len_ptr);

uint8_t *ekyc_compose_xml_v20(uint8_t *in_ptr,
                              uint8_t *auth_xml_ptr,
                              uint32_t *len_ptr);

uint8_t *ekyc_compose_xml_v21(uint8_t *in_ptr,
                              uint8_t *auth_xml_ptr,
                              uint32_t *len_ptr);

uint8_t *ekyc_main_ex_v21(uint8_t *in_ptr,
                          uint32_t in_len,
                          uint32_t *len_ptr);

uint8_t *ekyc_main_ex_v25(uint8_t *in_ptr,
                          uint32_t in_len,
                          uint32_t *len_ptr);

uint8_t *ekyc_compose_xml_v25(uint8_t *in_ptr,
                              uint8_t *auth_xml_ptr,
                              uint32_t *len_ptr);

#endif /*__eKYC_H__*/
