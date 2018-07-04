#ifndef __AUTH_H__
#define __AUTH_H__

typedef struct {
  /*unique Aadhaar ID*/
  uint8_t uid[16];
  /*Resident Consent*/
  uint8_t rc[4];
  /*For Registered Devices shall be - registered else blank*/
  uint8_t tid[12];
  uint8_t ac[12];
  uint8_t sa[12];
  /*supported version value is 2.0*/
  uint8_t version[4]; 
  /*For auth with OTP, its value shall be same as was used in OTP*/
  uint8_t txn[64];
  /*license key*/
  uint8_t lk[70];
  /*Private key File name*/
  uint8_t private_key[128];
  /*Public key file name*/
  uint8_t public_key[128];
  /*passowrd of private key*/
  uint8_t password[24];
  /*256-bit session key*/
  uint8_t session_key[34];
  /*iv - last 12 bytes of ts*/
  uint8_t iv[16];
  /*aad - additional authentication data, last 16 bytes of ts*/
  uint8_t aad[20];
  /*ts - time stamp when PID is formed*/
  uint8_t ts[32];
  /*reuqest host name*/
  uint8_t uidai_host_name[128];
  /*request uri*/
  uint8_t uri[32];
  /*To be removed*/
  uint8_t b64_skey[2048];
  uint32_t skey_len;
}auth_ctx_t;


int32_t auth_init(const uint8_t *ac,
                  const uint8_t *sa,
                  const uint8_t *lk,
                  const uint8_t *private_key,
                  const uint8_t *public_key,
                  const uint8_t *host_name,
                  const uint8_t *uri,
                  const uint8_t *ver,
                  const uint8_t *tid,
                  const uint8_t *txn,
                  const uint8_t *password);

int32_t auth_cipher_gcm(uint8_t *data, 
                        uint16_t data_len, 
                        uint8_t *ciphered_data, 
                        int32_t *ciphered_data_len,
                        uint8_t *tag,
                        uint8_t is_hmac);

int32_t auth_skey(uint8_t *b64_skey, uint16_t b64_skey_size);

int32_t auth_compose_xml(uint8_t *auth_xml,
                         uint16_t auth_xml_size,
                         uint8_t *auth,
                         uint8_t *uses,
                         uint8_t *tkn,
                         uint8_t *meta,
                         uint8_t *skey,
                         uint8_t *hmac,
                         uint8_t *data);

int32_t auth_c14n_sign(uint8_t *c14n_auth_xml,
                       uint8_t *b64_digest,
                       uint8_t *b64_signature,
                       uint8_t *b64_subject,
                       uint8_t *b64_certificate);

int32_t auth_c14n_auth_xml(uint8_t *c14n_auth_xml, 
                           uint16_t c14n_auth_xml_size, 
                           uint8_t *auth_xml,
                           uint8_t *c14n_uses,
                           uint8_t *c14n_tkn, 
                           uint8_t *c14n_meta, 
                           uint8_t *skey, 
                           uint8_t *hmac, 
                           uint8_t *data);

int32_t auth_decipher(uint8_t *ciphered_txt, 
                      int32_t ciphered_txt_len, 
                      uint8_t *plain_txt, 
                      int32_t *plain_txt_len,
                      uint8_t *tag);

int32_t auth_cipher_ecb(uint8_t *data, 
                        uint16_t data_len, 
                        uint8_t *ciphered_data, 
                        int32_t *ciphered_data_len);


uint8_t *auth_main_ex(uint8_t *in_ptr, 
                      uint32_t in_len, 
                      uint16_t version, 
                      int32_t rsp_fd);

uint8_t *auth_main_ex_v16(uint8_t *in_ptr, 
                          uint32_t in_len, 
                          uint32_t *rsp_len);

void auth_init_ex(uint8_t *in_ptr, uint32_t in_len);

uint8_t *auth_main_ex_v20(uint8_t *in_ptr, 
                          uint32_t in_len, 
                          uint32_t *rsp_len);

int32_t auth_hmac_v20(uint8_t *hmac,
                      uint16_t hmac_size,
                      uint8_t *pid_xml);

int32_t auth_data_v20(uint8_t *data, 
                      uint16_t data_size, 
                      uint8_t *pid_xml);


int32_t auth_compose_pid_v20(uint8_t *in_ptr, 
                             uint32_t in_len, 
                             uint8_t **pid_init);

int32_t auth_compose_pi_v20(uint8_t *in_ptr, 
                            uint32_t in_len, 
                            uint8_t **pi_xml_ptr);

int32_t auth_compose_pa_v20(uint8_t *in_ptr, 
                            uint32_t in_len, 
                            uint8_t **pi_xml_ptr);

int32_t auth_compose_pfa_v20(uint8_t *in_ptr, 
                             uint32_t in_len, 
                             uint8_t **pi_xml_ptr);

int32_t auth_compose_pv_v20(uint8_t *in_ptr, 
                            uint32_t in_len, 
                            uint8_t **pi_xml_ptr);

int32_t auth_compose_demo_v20(uint8_t *in_ptr, 
                              uint32_t in_len, 
                              uint8_t **pi_xml_ptr);

int32_t auth_compose_bio_v20(uint8_t *in_ptr, 
                             uint32_t in_len, 
                             uint8_t **bio_xml_ptr);

int32_t auth_compose_meta_tag_v20(uint8_t *in_ptr, 
                                  uint32_t in_len, 
                                  uint8_t *meta_tag, 
                                  uint8_t *c14n_meta);

int32_t auth_compose_uses_tag_v20(uint8_t *in_ptr, 
                                  uint32_t in_len, 
                                  uint8_t *uses_tag, 
                                  uint8_t *c14n_uses);

int32_t auth_compose_auth_tag_v20(uint8_t *in_ptr, 
                                  uint32_t in_len, 
                                  uint8_t *auth_tag);

int32_t auth_compose_pid_xml_v20(uint8_t *in_ptr, 
                                 uint32_t in_len,
                                 uint8_t *pid_xml);

int32_t auth_compose_pid_xml_v16(uint8_t *in_ptr, 
                                 uint32_t in_len, 
                                 uint8_t *pid_xml_ptr);

int32_t auth_compose_pid_v16(uint8_t *in_ptr, 
                             uint32_t in_len, 
                             uint8_t **pid_init);

int32_t auth_compose_pv_v16(uint8_t *in_ptr, 
                            uint32_t in_len, 
                            uint8_t **pv_xml);

int32_t auth_compose_meta_tag_v16(uint8_t *in_ptr, 
                                  uint32_t in_len, 
                                  uint8_t *meta_tag, 
                                  uint8_t *c14n_meta);

int32_t auth_compose_tkn_tag_v16(uint8_t *in_ptr, 
                                 uint32_t in_len, 
                                 uint8_t *tkn_tag, 
                                 uint8_t *c14n_tkn);

int32_t auth_compose_uses_tag_v16(uint8_t *in_ptr, 
                                  uint32_t in_len, 
                                  uint8_t *uses_tag, 
                                  uint8_t *c14n_uses);

int32_t auth_compose_auth_tag_v16(uint8_t *in_ptr, 
                                  uint32_t in_len, 
                                  uint8_t *auth_tag);

int32_t auth_compose_pi_v16(uint8_t *in_ptr, 
                            uint32_t in_len, 
                            uint8_t **pi_xml_ptr);

int32_t auth_compose_demo_v16(uint8_t *in_ptr, 
                              uint32_t in_len, 
                              uint8_t **demo_xml_ptr);

int32_t auth_compose_pv_v16(uint8_t *in_ptr, 
                            uint32_t in_len, 
                            uint8_t **pv_xml_ptr);

int32_t auth_compose_bio_v16(uint8_t *in_ptr, 
                             uint32_t in_len, 
                             uint8_t **bio_xml_ptr);

int32_t auth_compose_pfa_v16(uint8_t *in_ptr, 
                             uint32_t in_len, 
                             uint8_t **pfa_xml_ptr);

int32_t auth_compose_pa_v16(uint8_t *in_ptr, 
                            uint32_t in_len, 
                            uint8_t **pa_xml_ptr);

int32_t auth_compose_pid_xml_v16(uint8_t *in_ptr, 
                                 uint32_t in_len, 
                                 uint8_t *pid_xml_ptr);

int32_t auth_restore_str(uint8_t *name_ptr, 
                         uint8_t *name_str);

int32_t auth_compose_pid_final(uint8_t **pid_xml);

uint8_t *auth_get_ts(void);

int32_t auth_compose_final_req(uint8_t *in_ptr,
                               uint8_t *out_ptr, 
                               uint32_t out_size, 
                               uint32_t *len_ptr, 
                               uint8_t *auth_xml_ptr);

uint8_t *auth_compose_http_req(uint8_t *in_ptr, 
                               uint8_t *auth_xml, 
                               uint32_t *len_ptr);

uint8_t *auth_main_ex_v25(uint8_t *in_ptr, 
                          uint32_t in_len, 
                          uint32_t *rsp_len);
#endif /* __AUTH_H__ */
