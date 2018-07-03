#ifndef __OTP_H__
#define __OTP_H__


uint8_t *otp_get_ts(void);

uint8_t *otp_compose_xml_v16(uint8_t *in_ptr, uint32_t *len_ptr);

uint8_t *otp_compose_otp_v16(uint8_t *in_ptr, uint32_t *len_ptr);

uint8_t *otp_compose_c14n_v16(uint8_t *in_ptr, uint32_t *c14n_len_ptr);

uint8_t *otp_compose_http_request(uint8_t *in_ptr,
                                  uint8_t *signed_xml, 
                                  uint32_t signed_xml_len, 
                                  uint32_t *http_req_len);

uint8_t *otp_sign_xml_v16(uint8_t *in_ptr, uint32_t *len_ptr);

uint8_t *otp_main_ex_v16(uint8_t *in_ptr, 
                         uint32_t in_len, 
                         uint32_t *len_ptr);

uint8_t *otp_compose_c14n_v25(uint8_t *in_ptr, uint32_t *c14n_len_ptr);

uint8_t *otp_compose_xml_v25(uint8_t *in_ptr, uint32_t *len_ptr);

uint8_t *otp_compose_otp_v25(uint8_t *in_ptr, uint32_t *len_ptr);

uint8_t *otp_sign_xml_v25(uint8_t *in_ptr, 
                          uint32_t *len_ptr);

uint8_t *otp_main_ex_v25(uint8_t *in_ptr, 
                         uint32_t in_len, 
                         uint32_t *len_ptr);

uint8_t *otp_main_ex(uint8_t *in_ptr, 
                     uint32_t in_len, 
                     uint16_t version, 
                     uint32_t *rsp_len);

int32_t otp_compute_utf8(uint8_t *xml_in, 
                         uint16_t xml_in_len, 
                         uint8_t *utf8_set_out, 
                         uint16_t *utf8_set_len);



#endif /* __OTP_H__ */
