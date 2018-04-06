#ifndef __OTP_H__
#define __OTP_H__

typedef struct {
  /*Transaction Id*/
  uint8_t txn[50];
  /*A 12 digits Aadhaar id*/
  uint8_t uid[16];
  /*A 10 bytes unique code for AUA*/
  uint8_t ac[16];
  /*A 10 bytes unique Sub AUA*/
  uint8_t sa[16];
  /*ASA license key*/
  uint8_t lk[64];
  /*"A" for Aadhaar, "M" for Mobile*/
  uint8_t type[4];
  /*channel 00 - send OTP via both SMS and Email
                 (this is the default)
    channel 01 - send OTP via SMS only
    channel 02 - send OTP via Email only
   */
  uint8_t ts[32];
  uint8_t ch;
  /*otp API version, It's 1.6 as of now*/
  uint8_t ver[4];
  /*host name in the form of URI*/
  uint8_t uidai_host_name[255];

}otp_ctx_t;

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
                            uint16_t *otp_xml_len);

/** @brief
 */

int32_t otp_init(uint8_t *ac,
                 uint8_t *sa,
                 /*license key*/
                 uint8_t *lk,
                 uint8_t *ver,
                 uint8_t *uidai_host_name);
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
                               uint16_t *c14n_len);
/*
  1.Canonicalize* the text-to-be-signed, C = C14n(T).
  2.Compute the message digest of the canonicalized text, m = Hash(C).
  3.Encapsulate the message digest in an XML <SignedInfo> element, SI, in canonicalized form.
  4.Compute the RSA signatureValue of the canonicalized <SignedInfo> element, SV = RsaSign(Ks, SI).
  5.Compose the final XML document including the signatureValue, this time in non-canonicalized form.

 */
int32_t otp_sign_xml(uint8_t **signed_xml, 
                     uint16_t *signed_xml_len);


/**
 * We use the SHA-1 message digest function, which outputs a hash value 20 bytes long
 */

int32_t otp_compute_b64(uint8_t *sha1, 
                        uint16_t sha1_len, 
                        uint8_t *b64, 
                        uint16_t *b64_len);

int32_t otp_compute_utf8(uint8_t *xml_in, 
                         uint16_t xml_in_len, 
                         uint8_t *utf8_set_out, 
                         uint16_t *utf8_set_len);


int32_t otp_request_otp(uint8_t *signed_xml, 
                        uint16_t signed_xml_len, 
                        uint8_t **http_req, 
                        uint32_t *http_req_len);

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
                        uint32_t *rsp_len);
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
                 uint32_t *rsp_len);




#endif /* __OTP_H__ */
