#ifndef __AUTH_H__
#define __AUTH_H__

typedef enum {
  AUTH_TYPE_PI  = 1,
  AUTH_TYPE_PA  = 2,
  AUTH_TYPE_PFA = 3,
  AUTH_TYPE_BIO = 4,
  AUTH_TYPE_BT  = 5,
  AUTH_TYPE_PIN = 6,
  AUTH_TYPE_OTP = 7,
  AUTH_TYPE_INVALID

}auth_type_t;

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
  /*Authentication Type*/
  auth_type_t auth_type;
  /*Private key File name*/
  uint8_t private_key[128];
  /*Public key file name*/
  uint8_t public_key[128];
  /*256-bit session key*/
  uint8_t session_key[34];
  /*iv - last 12 bytes of ts*/
  uint8_t iv[16];
  /*aad - additional authentication data, last 16 bytes of ts*/
  uint8_t aad[20];
  /*ts - time stamp when PID is formed*/
  uint8_t ts[32];
  uint8_t uidai_host_name[128];
  /*To be removed*/
  uint8_t b64_skey[2048];
  uint32_t skey_len;
}auth_ctx_t;


int32_t auth_init(const uint8_t *ac,
                  const uint8_t *sa,
                  const uint8_t *lk,
                  const uint8_t *private_key,
                  const uint8_t *public_key,
                  const uint8_t *host_name);


int32_t auth_meta(uint8_t *meta, 
                  uint16_t meta_size, 
                  uint8_t *c14n, 
                  uint16_t c14n_size);

int32_t auth_pid_otp(uint8_t *pid_otp, 
                     uint16_t pid_otp_size, 
                     uint8_t *otp_value, 
                     uint8_t *ts);

int32_t auth_data(uint8_t *data_tag, uint16_t data_tag_size, uint8_t *pid_xml);

int32_t auth_uses(uint8_t *uses_otp, 
                  uint16_t uses_otp_size, 
                  uint8_t *c14n, 
                  uint16_t c14n_size,
                  uint8_t *pid_uses_opt);

int32_t auth_cipher_gcm(uint8_t *data, 
                        uint16_t data_len, 
                        uint8_t *ciphered_data, 
                        int32_t *ciphered_data_len,
                        uint8_t *tag,
                        uint8_t is_hmac);

int32_t auth_hmac(uint8_t *hmac, 
                  uint16_t hmac_size, 
                  uint8_t *pid_xml);

int32_t auth_skey(uint8_t *b64_skey, uint16_t b64_skey_size);

int32_t auth_compose_xml(uint8_t *auth_xml,
                         uint16_t auth_xml_size,
                         uint16_t *tmp_len,
                         uint8_t *uses,
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
                           uint8_t *c14n_uses, 
                           uint8_t *c14n_meta, 
                           uint8_t *skey, 
                           uint8_t *hmac, 
                           uint8_t *data);

int32_t auth_auth_otp_xml(uint8_t *auth_otp_xml, 
                          uint32_t auth_otp_xml_size, 
                          uint8_t *pid_xml);

int32_t auth_req_auth(uint8_t *req_xml, 
                      uint32_t req_xml_size, 
                      uint32_t *req_xml_len, 
                      uint8_t *auth_xml,
                      uint8_t *uid);

int32_t auth_process_auth_otp_req(int32_t conn_fd, 
                                  uint8_t *req_ptr,
                                  uint8_t *req_xml,
                                  uint32_t req_xml_size,
                                  uint32_t *req_xml_len);

int32_t auth_decipher(uint8_t *ciphered_txt, 
                      int32_t ciphered_txt_len, 
                      uint8_t *plain_txt, 
                      int32_t *plain_txt_len,
                      uint8_t *tag);

int32_t auth_cipher_ecb(uint8_t *data, 
                        uint16_t data_len, 
                        uint8_t *ciphered_data, 
                        int32_t *ciphered_data_len);

int32_t auth_process_auth_pi_req(int32_t conn_fd, 
                                 uint8_t *req_ptr,
                                 uint8_t *req_xml,
                                 uint32_t req_xml_size,
                                 uint32_t *req_xml_len);

uint8_t *auth_get_pi_param(uint8_t (*pi_param)[2][64], 
                           const uint8_t *param_name);

int32_t auth_main(int32_t conn_fd, 
                  uint8_t *req_ptr, 
                  uint32_t req_len, 
                  uint8_t **rsp_ptr, 
                  uint32_t *rsp_len);

int32_t auth_process_rsp(uint8_t *param, uint8_t **rsp_ptr, uint32_t *rsp_len);
  
int32_t auth_process_req(int32_t conn_fd, 
                         uint8_t *req_ptr,
                         uint8_t *req_xml,
                         uint32_t req_xml_size,
                         uint32_t *req_xml_len);

#endif /* __AUTH_H__ */
