#ifndef __UTIL_H__
#define __UTIL_H__

typedef struct {
  
  uint8_t private_key_file[128];
  uint8_t public_key_file[128];

}util_ctx_t;

int32_t util_base64(uint8_t *input, 
                    uint16_t length, 
                    uint8_t *out_b64, 
                    uint16_t *b64_len);


int32_t util_compute_digest(uint8_t *xml, 
                            uint16_t xml_len, 
                            uint8_t *digest,
                            uint32_t *digest_len);

int32_t util_subject_certificate(uint8_t **subject,
                                 uint16_t *subject_len,
                                 uint8_t **certificate,
                                 uint16_t *certificate_len);

int32_t util_compute_rsa_signature(uint8_t *signed_info, 
                                   uint16_t signed_info_len, 
                                   uint8_t **signature_value, 
                                   uint16_t *signature_len);

int32_t util_c14n_signedinfo(uint8_t *c14n,
                             uint16_t c14n_max_size,
                             uint16_t *c14n_len,
                             uint8_t *sha1_digest);

int32_t util_compose_final_xml(uint8_t *out_xml, 
                               uint16_t out_xml_max_size, 
                               uint16_t *out_xml_len,
                               uint8_t *digest_b64,
                               uint8_t *signature_b64,
                               uint8_t *subject,
                               uint8_t *certificate);

int32_t util_init(uint8_t *public_key, uint8_t *private_key);

int32_t util_decrypt_skey(uint8_t *in, uint32_t inl, uint8_t *out, uint32_t *outl);

int32_t util_base64_decode(uint8_t *data,
                           uint32_t data_len,
                           uint8_t *out,
                           uint32_t *out_len);

int32_t util_base64_decode_ex(uint8_t *input, 
                    uint16_t length, 
                    uint8_t *out_b64, 
                    uint32_t *b64_len);
#endif /* __UTIL_H__ */
