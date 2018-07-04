#ifndef __AUTH_C__
#define __AUTH_C__

#include "common.h"
#include "uidai.h"
#include "util.h"
#include "auth.h"

auth_ctx_t auth_ctx_g;

int32_t auth_dump_xml(uint8_t *auth_xml, uint32_t auth_xml_len) {
  FILE *fp;

  fp = fopen("Auth_xml.xml", "w");

  if(fwrite(auth_xml, 1, auth_xml_len, fp) < auth_xml_len) {
    /*Writing to xml failed*/
    fclose(fp);
    return(-1);
  }  

  fclose(fp);
  return(0);
}/*auth_dump_xml*/

int32_t auth_symmetric_keys(uint8_t *out_ptr, uint32_t out_len) {
  FILE *fp = NULL;
  int32_t rc;
  FILE *oFp = NULL;

  fp = fopen("/dev/urandom", "rb");

  if(!fp) {
    fprintf(stderr, "\n%s:%d opening of device file failed\n", __FILE__, __LINE__);
    return(-1);
  }

  rc = fread(out_ptr, 1, 32, fp);
  fclose(fp);

  if(rc < 32) {
    fprintf(stderr, "\n%s:%d shorter length than expected\n", __FILE__, __LINE__);
    return(-2);
  }

  return(0);
}/*auth_symmetric_keys*/

int32_t auth_compute_ts(uint8_t *ts, uint16_t ts_size) {

  time_t curr_time;
  struct tm *local_time;
  auth_ctx_t *pAuthCtx = &auth_ctx_g;

  /*Retrieving the current time*/
  curr_time = time(NULL);
  local_time = localtime(&curr_time);

  memset((void *)ts, 0, ts_size);
  snprintf(ts, 
           ts_size,
           "%04d-%02d-%02dT%02d:%02d:%02d", 
           local_time->tm_year+1900, 
           local_time->tm_mon+1, 
           local_time->tm_mday, 
           local_time->tm_hour, 
           local_time->tm_min, 
           local_time->tm_sec);

  memset((void *)pAuthCtx->ts, 0, sizeof(pAuthCtx->ts));
  memset((void *)pAuthCtx->iv, 0, sizeof(pAuthCtx->iv));
  memset((void *)pAuthCtx->aad, 0, sizeof(pAuthCtx->aad));
  /*copying iv & aad into its context, +1 for '\0' null byte*/ 
  strncpy(pAuthCtx->iv, (const char *)&ts[strlen(ts) - 12], 12);
  strncpy(pAuthCtx->aad, (const char *)&ts[strlen(ts) - 16], 16);
  strncpy(pAuthCtx->ts, (const char *)ts, sizeof(pAuthCtx->ts));

  return(0);
}/*auth_compute_ts*/

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
                  const uint8_t *password) {

  auth_ctx_t *pAuthCtx = &auth_ctx_g;
  memset((void *)pAuthCtx, 0, sizeof(auth_ctx_t));

  strncpy(pAuthCtx->ac, ac, sizeof(pAuthCtx->ac)); 
  strncpy(pAuthCtx->sa, sa, sizeof(pAuthCtx->sa)); 
  strncpy(pAuthCtx->lk, lk, sizeof(pAuthCtx->lk)); 
  strncpy(pAuthCtx->private_key, private_key, sizeof(pAuthCtx->private_key)); 
  strncpy(pAuthCtx->public_key, public_key, sizeof(pAuthCtx->public_key));
  strncpy(pAuthCtx->version, ver, sizeof(pAuthCtx->version));
  strncpy(pAuthCtx->rc, "Y", 1);
  strncpy(pAuthCtx->uidai_host_name, host_name, sizeof(pAuthCtx->uidai_host_name));

  /*For Registered devices tid shall be NULL*/
  memset(pAuthCtx->tid, 0, sizeof(pAuthCtx->tid));
  if(tid) {
    strncpy(pAuthCtx->tid, tid, sizeof(pAuthCtx->tid));
  }

  strncpy(pAuthCtx->txn, txn, sizeof(pAuthCtx->txn));
  strncpy(pAuthCtx->uri, uri, sizeof(pAuthCtx->uri));
  strncpy(pAuthCtx->password, password, sizeof(pAuthCtx->password));
  memset((void *)pAuthCtx->iv, 0, sizeof(pAuthCtx->iv));
  memset((void *)pAuthCtx->aad, 0, sizeof(pAuthCtx->aad));
   
  return(0);
}/*auth_init*/

/*===============================================
 * V25 - V2.5
 ===============================================*/

int32_t auth_compose_meta_tag_v25(uint8_t *in_ptr, 
                                  uint32_t in_len, 
                                  uint8_t *meta_tag, 
                                  uint8_t *c14n_meta) {
  uint8_t *meta = NULL;
  uint8_t *meta_attr[10];
  uint32_t offset = 0;
 
  meta = uidai_get_param(in_ptr, "meta");

  meta_attr[0] = uidai_get_attr(meta, "dc");
  meta_attr[1] = uidai_get_attr(meta, "dpId");
  meta_attr[2] = uidai_get_attr(meta, "mc");
  meta_attr[3] = uidai_get_attr(meta, "mi");
  meta_attr[4] = uidai_get_attr(meta, "rdsId");
  meta_attr[5] = uidai_get_attr(meta, "rdsVer");

  /*freeing memory*/
  free(meta);
  meta = NULL;

  offset += sprintf(&meta_tag[offset],
                    "%s",
                    "<Meta");
  if(meta_attr[0]) {
    /*dc*/
    offset += sprintf(&meta_tag[offset],
                      "%s%s%s",
                      " dc=\"",
                      meta_attr[0],
                      "\"");
  } else {
    /*dc*/
    offset += sprintf(&meta_tag[offset],
                      "%s%s",
                      " dc=\"",
                      "\"");
    
  }
  
  if(meta_attr[1]) {   
    /*dpId*/
    offset += sprintf(&meta_tag[offset],
                      "%s%s%s",
                      " dpId=\"",
                      meta_attr[1],
                      "\"");
  } else {
    /*dpId*/
    offset += sprintf(&meta_tag[offset],
                      "%s%s",
                      " dpId=\"",
                      "\"");
    
  }

  if(meta_attr[2]) {
    /*mc*/
    offset += sprintf(&meta_tag[offset],
                      "%s%s%s",
                      " mc=\"",
                      meta_attr[2],
                      "\"");
  } else {
    /*mc*/
    offset += sprintf(&meta_tag[offset],
                      "%s%s",
                      " mc=\"",
                      "\"");
    
  }

  if(meta_attr[3]) {
    /*mi*/
    offset += sprintf(&meta_tag[offset],
                      "%s%s%s",
                      " mi=\"",
                      meta_attr[3],
                      "\"");
  } else {
    /*mi*/
    offset += sprintf(&meta_tag[offset],
                      "%s%s",
                      " mi=\"",
                      "\"");
    
  }

  if(meta_attr[4]) {
    /*rdsId*/
    offset += sprintf(&meta_tag[offset],
                      "%s%s%s",
                      " rdsId=\"",
                      meta_attr[4],
                      "\"");
  } else {
    /*rdsId*/
    offset += sprintf(&meta_tag[offset],
                      "%s%s",
                      " rdsId=\"",
                      "\"");
    
  }

  if(meta_attr[5]) {
    /*rdsVer*/
    offset += sprintf(&meta_tag[offset],
                      "%s%s%s",
                      " rdsVer=\"",
                      meta_attr[5],
                      "\"");
  } else {
    /*rdsVer*/
    offset += sprintf(&meta_tag[offset],
                      "%s%s",
                      " rdsVer=\"",
                      "\"");
  }

  strncpy(c14n_meta, meta_tag, offset);
  sprintf(&meta_tag[offset],
          "%s",
          "/>");

  sprintf(&c14n_meta[offset],
          "%s",
          "></Meta>");

  for(offset = 0; offset < 6; offset++) {

    if(meta_attr[offset]) {
      free(meta_attr[offset]);
      meta_attr[offset] = NULL;
    }

  }

  return(0);
}/*auth_compose_meta_tag_v20*/

uint8_t *auth_main_ex_v25(uint8_t *in_ptr, 
                          uint32_t in_len, 
                          uint32_t *rsp_len) {
  
  uint8_t *pid_xml = NULL;
  uint8_t *auth_xml_tag[16];
  uint8_t *c14n[4];
  uint16_t version = 16;
  uint32_t idx = 0;
  int32_t opt_tkn = 0;
  uint8_t skey[512];
  uint16_t skey_size = sizeof(skey);
  uint8_t *data_x = NULL;
  uint16_t data_x_len = 512;
  uint8_t *hmac = NULL;
  uint16_t hmac_len = 256;
  uint8_t *c14n_auth_xml = NULL;
  uint16_t c14n_len = 6000;
  uint8_t *final_xml = NULL;
  uint16_t final_xml_size = 6000;
  uint8_t *b64_digest = NULL;
  uint8_t *b64_signature = NULL;
  uint8_t *b64_subject = NULL;
  uint8_t *b64_certificate = NULL;
  
  for(idx = 0; idx < 3; idx++) {
    auth_xml_tag[idx] = (uint8_t *)malloc(sizeof(uint8_t) * 256);
    assert(auth_xml_tag[idx] != NULL);
    memset((void *)auth_xml_tag[idx], 0, sizeof(uint8_t) * 256);
  }

  for(idx = 0; idx < 2; idx++) {
    c14n[idx] = (uint8_t *)malloc(sizeof(uint8_t) * 256);
    assert(c14n[idx] != NULL);
    memset((void *)c14n[idx], 0, sizeof(uint8_t) * 256);
  }

  /*Auth tag*/
  auth_compose_auth_tag_v20(in_ptr, in_len, auth_xml_tag[0]);
  /*Uses tag*/
  auth_compose_uses_tag_v20(in_ptr, 
                            in_len, 
                            auth_xml_tag[1], 
                            c14n[0]);
  /*Meta tag*/
  auth_compose_meta_tag_v25(in_ptr, 
                            in_len, 
                            auth_xml_tag[2], 
                            c14n[1]);
  /*Pid xml of Auth*/
  pid_xml = (uint8_t *)malloc(sizeof(uint8_t) * 1024);
  assert(pid_xml != NULL);
  memset((void *)pid_xml, 0, sizeof(uint8_t) * 1024);

  auth_compose_pid_xml_v20(in_ptr, 
                           in_len, 
                           pid_xml);

  fprintf(stderr, "\n%s\n", pid_xml);

  /*Skey tag of Final AUTH XML <Skey ..></Skey>*/
  memset((void *)skey, 0, sizeof(skey));
  auth_skey(skey, skey_size);

  data_x = (uint8_t *)malloc(sizeof(uint8_t) * data_x_len);
  assert(data_x != NULL);
  memset((void *)data_x, 0, data_x_len);
  auth_data_v20(data_x, data_x_len, pid_xml);
  
  hmac = (uint8_t *)malloc(sizeof(uint8_t) * hmac_len);
  assert(hmac != NULL);
  memset((void *)hmac, 0, hmac_len);
  auth_hmac_v20(hmac, hmac_len, pid_xml);

  free(pid_xml);
  pid_xml = NULL;

  /*signature of Auth XML*/
  c14n_auth_xml = (uint8_t *)malloc(sizeof(uint8_t) * c14n_len);
  assert(c14n_auth_xml != NULL);
  memset((void *)c14n_auth_xml, 0, c14n_len);
 
  auth_c14n_auth_xml(c14n_auth_xml, 
                     c14n_len, 
                     auth_xml_tag[0],
                     /*uses tag*/
                     c14n[0], 
                     /*No tkn tag for 2.0 & 2.5*/
                     NULL,
                     /*meta tag*/
                     c14n[1], 
                     skey, 
                     hmac, 
                     data_x);
  free(c14n[0]);
  free(c14n[1]);

  b64_digest = (uint8_t *)malloc(sizeof(uint8_t) * 2048);
  assert(b64_digest != NULL);
  memset((void *)b64_digest, 0, 2048);
  
  b64_signature = (uint8_t *)malloc(sizeof(uint8_t) * 2048);
  assert(b64_signature != NULL);
  memset((void *)b64_signature, 0, 2048);

  b64_subject = (uint8_t *)malloc(sizeof(uint8_t) * 2048);
  assert(b64_subject != NULL);
  memset((void *)b64_subject, 0, 2048);

  b64_certificate = (uint8_t *)malloc(sizeof(uint8_t) * 2048);
  assert(b64_certificate != NULL);
  memset((void *)b64_certificate, 0, 2048);

  fprintf(stderr,"\n%s:%d c14n auth xml is \n%s\n", __FILE__, __LINE__, c14n_auth_xml);
  auth_c14n_sign(c14n_auth_xml,
                 b64_digest,
                 b64_signature,
                 b64_subject,
                 b64_certificate);

  free(c14n_auth_xml);
  c14n_auth_xml = NULL;

  final_xml = (uint8_t *)malloc(sizeof(uint8_t) * final_xml_size);
  assert(final_xml != NULL);
  memset((void *)final_xml, 0, final_xml_size);

  auth_compose_xml(final_xml,
                   final_xml_size,
                   auth_xml_tag[0],
                   auth_xml_tag[1],
                   NULL,
                   auth_xml_tag[2],
                   skey,
                   hmac,
                   data_x);

  free(auth_xml_tag[0]);
  free(auth_xml_tag[1]);
  free(auth_xml_tag[2]);

  uint16_t final_xml_len = 0;
  uint16_t tmp_len = strlen(final_xml);

  util_compose_final_xml(&final_xml[tmp_len], 
                         (final_xml_size - tmp_len), 
                         &final_xml_len,
                         /*digest*/
                         b64_digest,
                         /*Signature Value*/
                         b64_signature,
                         /*Subject Name*/
                         b64_subject,
                         /*Certificate*/
                         b64_certificate); 

  final_xml_len += tmp_len;
  snprintf(&final_xml[final_xml_len], 
           final_xml_size, 
           "%s", 
           "</Auth>");

  free(b64_digest);
  free(b64_signature);
  free(b64_subject);
  free(b64_certificate);

  fprintf(stderr, "Final XML \n%s\n", final_xml);

  *rsp_len = strlen(final_xml);

  return(final_xml);
}/*auth_main_ex_v20*/


/*===================================================================================
 *
 *  v20
 */

uint8_t *auth_main_ex_v20(uint8_t *in_ptr, 
                          uint32_t in_len, 
                          uint32_t *rsp_len) {
  
  uint8_t *pid_xml = NULL;
  uint8_t *auth_xml_tag[16];
  uint8_t *c14n[4];
  uint16_t version = 16;
  uint32_t idx = 0;
  int32_t opt_tkn = 0;
  uint8_t skey[512];
  uint16_t skey_size = sizeof(skey);
  uint8_t *data_x = NULL;
  uint16_t data_x_len = 512;
  uint8_t *hmac = NULL;
  uint16_t hmac_len = 256;
  uint8_t *c14n_auth_xml = NULL;
  uint16_t c14n_len = 4000;
  uint8_t *final_xml = NULL;
  uint16_t final_xml_size = 5000;
  uint8_t *b64_digest = NULL;
  uint8_t *b64_signature = NULL;
  uint8_t *b64_subject = NULL;
  uint8_t *b64_certificate = NULL;
  
  for(idx = 0; idx < 3; idx++) {
    auth_xml_tag[idx] = (uint8_t *)malloc(sizeof(uint8_t) * 256);
    assert(auth_xml_tag[idx] != NULL);
    memset((void *)auth_xml_tag[idx], 0, sizeof(uint8_t) * 256);
  }

  for(idx = 0; idx < 2; idx++) {
    c14n[idx] = (uint8_t *)malloc(sizeof(uint8_t) * 256);
    assert(c14n[idx] != NULL);
    memset((void *)c14n[idx], 0, sizeof(uint8_t) * 256);
  }

  /*Auth tag*/
  auth_compose_auth_tag_v20(in_ptr, in_len, auth_xml_tag[0]);
  /*Uses tag*/
  auth_compose_uses_tag_v20(in_ptr, 
                            in_len, 
                            auth_xml_tag[1], 
                            c14n[0]);
  /*Meta tag*/
  auth_compose_meta_tag_v20(in_ptr, 
                            in_len, 
                            auth_xml_tag[2], 
                            c14n[1]);
  /*Pid xml of Auth*/
  pid_xml = (uint8_t *)malloc(sizeof(uint8_t) * 1024);
  assert(pid_xml != NULL);
  memset((void *)pid_xml, 0, sizeof(uint8_t) * 1024);

  auth_compose_pid_xml_v20(in_ptr, 
                           in_len, 
                           pid_xml);

  fprintf(stderr, "\n%s\n", pid_xml);

  /*Skey tag of Final AUTH XML <Skey ..></Skey>*/
  memset((void *)skey, 0, sizeof(skey));
  auth_skey(skey, skey_size);

  data_x = (uint8_t *)malloc(sizeof(uint8_t) * data_x_len);
  assert(data_x != NULL);
  memset((void *)data_x, 0, data_x_len);
  auth_data_v20(data_x, data_x_len, pid_xml);
  
  hmac = (uint8_t *)malloc(sizeof(uint8_t) * hmac_len);
  assert(hmac != NULL);
  memset((void *)hmac, 0, hmac_len);
  auth_hmac_v20(hmac, hmac_len, pid_xml);

  free(pid_xml);
  pid_xml = NULL;

  /*signature of Auth XML*/
  c14n_auth_xml = (uint8_t *)malloc(sizeof(uint8_t) * c14n_len);
  assert(c14n_auth_xml != NULL);
  memset((void *)c14n_auth_xml, 0, c14n_len);
 
  auth_c14n_auth_xml(c14n_auth_xml, 
                     c14n_len, 
                     auth_xml_tag[0],
                     /*uses tag*/
                     c14n[0], 
                     /*No tkn tag for 2.0 & 2.5*/
                     NULL,
                     /*meta tag*/
                     c14n[1], 
                     skey, 
                     hmac, 
                     data_x);
  free(c14n[0]);
  free(c14n[1]);

  b64_digest = (uint8_t *)malloc(sizeof(uint8_t) * 2048);
  assert(b64_digest != NULL);
  memset((void *)b64_digest, 0, 2048);
  
  b64_signature = (uint8_t *)malloc(sizeof(uint8_t) * 2048);
  assert(b64_signature != NULL);
  memset((void *)b64_signature, 0, 2048);

  b64_subject = (uint8_t *)malloc(sizeof(uint8_t) * 2048);
  assert(b64_subject != NULL);
  memset((void *)b64_subject, 0, 2048);

  b64_certificate = (uint8_t *)malloc(sizeof(uint8_t) * 2048);
  assert(b64_certificate != NULL);
  memset((void *)b64_certificate, 0, 2048);

  fprintf(stderr,"\n%s:%d c14n auth xml is \n%s\n", __FILE__, __LINE__, c14n_auth_xml);
  auth_c14n_sign(c14n_auth_xml,
                 b64_digest,
                 b64_signature,
                 b64_subject,
                 b64_certificate);

  free(c14n_auth_xml);
  c14n_auth_xml = NULL;

  final_xml = (uint8_t *)malloc(sizeof(uint8_t) * final_xml_size);
  assert(final_xml != NULL);
  memset((void *)final_xml, 0, final_xml_size);

  auth_compose_xml(final_xml,
                   final_xml_size,
                   auth_xml_tag[0],
                   auth_xml_tag[1],
                   NULL,
                   auth_xml_tag[2],
                   skey,
                   hmac,
                   data_x);

  free(auth_xml_tag[0]);
  free(auth_xml_tag[1]);
  free(auth_xml_tag[2]);

  uint16_t final_xml_len = 0;
  uint16_t tmp_len = strlen(final_xml);

  util_compose_final_xml(&final_xml[tmp_len], 
                         (final_xml_size - tmp_len), 
                         &final_xml_len,
                         /*digest*/
                         b64_digest,
                         /*Signature Value*/
                         b64_signature,
                         /*Subject Name*/
                         b64_subject,
                         /*Certificate*/
                         b64_certificate); 

  final_xml_len += tmp_len;
  snprintf(&final_xml[final_xml_len], 
           final_xml_size, 
           "%s", 
           "</Auth>");

  free(b64_digest);
  free(b64_signature);
  free(b64_subject);
  free(b64_certificate);

  fprintf(stderr, "Final XML \n%s\n", final_xml);

  *rsp_len = strlen(final_xml);

  return(final_xml);
}/*auth_main_ex_v20*/

int32_t auth_hmac_v20(uint8_t *hmac,
                      uint16_t hmac_size,
                      uint8_t *pid_xml) {

  uint8_t digest256[32];
  int32_t ciphered_data_len = 0;
  uint8_t ciphered_data[512];
  uint8_t b64_hmac[512];
  uint16_t b64_hmac_len;
  uint8_t tag[16];
  
  auth_ctx_t *pAuthCtx = &auth_ctx_g;
  SHA256_CTX ctx;

  memset((void *)digest256, 0, sizeof(digest256));

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, pid_xml, strlen((const char *)pid_xml));
  SHA256_Final(digest256, &ctx);

  memset((void *)tag, 0, sizeof(tag));
  memset((void *)ciphered_data, 0, sizeof(ciphered_data));
  auth_cipher_gcm(digest256, 
                  32, 
                  ciphered_data, 
                  &ciphered_data_len, 
                  tag, 
                  1/*is_hmac*/);

  memset((void *)b64_hmac, 0, sizeof(b64_hmac));
  util_base64(ciphered_data, 
              ciphered_data_len, 
              b64_hmac, 
              &b64_hmac_len);
 
  memset((void *)hmac, 0, hmac_size);
  snprintf(hmac, 
           hmac_size, 
           "%s%s%s",
           "<Hmac>",
           b64_hmac,
           "</Hmac>");

  return(0);
}/*auth_hmac_v20*/

int32_t auth_data_v20(uint8_t *data, 
                      uint16_t data_size, 
                      uint8_t *pid_xml) {

  uint8_t ciphered_data[512];
  int32_t ciphered_data_len;
  uint8_t b64[512];
  uint16_t b64_len;
  uint8_t plain_txt[512];
  int32_t plain_txt_len;
  uint8_t tag[16];
  
  memset((void *)ciphered_data, 0, sizeof(ciphered_data)); 
  memset((void *)tag, 0, sizeof(tag));

  auth_cipher_gcm(pid_xml, 
                  strlen(pid_xml), 
                  ciphered_data, 
                  &ciphered_data_len,
                  tag,
                  0/*is_hmac*/);

  memset((void *)b64, 0, sizeof(b64));
  util_base64(ciphered_data, ciphered_data_len, b64, &b64_len);

  memset((void *)data, 0, data_size);
  snprintf(data,
           data_size,
           "%s%s%s",
           "<Data type=\"X\">",
           b64,
           "</Data>");

  return(0);
}/*auth_data_v20*/


int32_t auth_compose_bio_v20(uint8_t *in_ptr, 
                             uint32_t in_len, 
                             uint8_t **bio_xml_ptr) {

  uint8_t *bio = NULL; 
  uint8_t *bio_attr[8];
  uint32_t offset = 0;
  uint8_t *bio_xml;
  uint32_t len = sizeof(uint8_t) * 1024;

  bio_xml = (uint8_t *)malloc(len);
  assert(bio_xml != NULL);
  memset((void *)bio_xml, 0, len);

  *bio_xml_ptr = bio_xml;
  bio  = uidai_get_param(in_ptr, "bio");
  assert(bio != NULL);

  bio_attr[0] = uidai_get_attr(bio, "type");
  bio_attr[1] = uidai_get_attr(bio, "posh");
  bio_attr[2] = uidai_get_attr(bio, "bs");
  bio_attr[3] = uidai_get_attr(bio, "value");

  free(bio);
  bio = NULL;

  offset += snprintf(&bio_xml[offset],
                     (len - offset),
                     "%s%s",
                     "  <Bios dih=\"\">\n",
                     "    <Bio");

  if(bio_attr[0] && strlen(bio_attr[0])) {
    /*type is present*/
    offset += snprintf(&bio_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " type=\"",
                       bio_attr[0],
                       "\"");
  }

  if(bio_attr[1] && strlen(bio_attr[1])) {
    /*posh is present*/
    offset += snprintf(&bio_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " posh=\"",
                       bio_attr[1],
                       "\"");
  }

  if(bio_attr[2] && strlen(bio_attr[2])) {
    /*bs is present*/
    offset += snprintf(&bio_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " bs=\"",
                       bio_attr[2],
                       "\"");
  }

  if(bio_attr[3] && strlen(bio_attr[3])) {
    /*value is present*/
    offset += snprintf(&bio_xml[offset],
                       (len - offset),
                       "%s%s%s%s",
                       ">",
                       bio_attr[3],
                       "</Bio>\n",
                       "  </Bios>\n");
  }

  fprintf(stderr, "\n%s:%d bio %s\n", __FILE__, __LINE__, bio_xml);

  for(offset = 0; offset < 4; offset++) {
    free(bio_attr[offset]);
    bio_attr[offset] = NULL;
  }

  return(0);
}/*auth_compose_bio_v20*/

int32_t auth_compose_pid_v20(uint8_t *in_ptr, 
                             uint32_t in_len, 
                             uint8_t **pid_init) {

  uint32_t len = sizeof(uint8_t) * 256;
  uint8_t ts[32];
  uint16_t ts_size = sizeof(ts);
  uint8_t pid_ver[4];

  (void)in_ptr;
  (void)in_len;

  *pid_init = (uint8_t *)malloc(len);
  assert(*pid_init != NULL);
  memset((void *)*pid_init, 0, len);

  auth_compute_ts(ts, ts_size);
  memset((void *)pid_ver, 0, sizeof(pid_ver));

  /*ver = 2.0 for both API2.0 & API2.5*/
  strncpy(pid_ver, "2.0", 3);

  snprintf(*pid_init, 
           len,
           "%s%s%s%s%s"
           "%s",
           "<Pid ts=\"",
           ts,
           "\" ver=\"",
           pid_ver,
           "\" wadh=\"",
           "\">"); 

  return(0);
}/*auth_build_pid_v20*/

int32_t auth_compose_pi_v20(uint8_t *in_ptr, 
                            uint32_t in_len, 
                            uint8_t **pi_xml_ptr) {

  auth_compose_pi_v16(in_ptr, in_len, pi_xml_ptr);

  return(0);
}/*auth_compose_pi_v20*/

int32_t auth_compose_pa_v20(uint8_t *in_ptr, 
                            uint32_t in_len, 
                            uint8_t **pi_xml_ptr) {

  auth_compose_pa_v16(in_ptr, in_len, pi_xml_ptr);

  return(0);
}/*auth_compose_pa_v20*/

int32_t auth_compose_pfa_v20(uint8_t *in_ptr, 
                             uint32_t in_len, 
                             uint8_t **pi_xml_ptr) {

  auth_compose_pfa_v16(in_ptr, in_len, pi_xml_ptr);

  return(0);
}/*auth_compose_pfa_v20*/

int32_t auth_compose_pv_v20(uint8_t *in_ptr, 
                            uint32_t in_len, 
                            uint8_t **pi_xml_ptr) {

  auth_compose_pv_v16(in_ptr, in_len, pi_xml_ptr);

  return(0);
}/*auth_compose_pv_v20*/

int32_t auth_compose_demo_v20(uint8_t *in_ptr, 
                              uint32_t in_len, 
                              uint8_t **pi_xml_ptr) {

  auth_compose_demo_v16(in_ptr, in_len, pi_xml_ptr);

  return(0);
}/*auth_compose_demo_v20*/

int32_t auth_compose_pid_xml_v20(uint8_t *in_ptr, 
                                 uint32_t in_len, 
                                 uint8_t *pid_xml_ptr) {

  uint8_t *arg_ptr[2];
  uint8_t *pid_xml[16];
  uint8_t *uses_attr[16];
  uint32_t idx = 0;
  uint32_t offset = 0;
  uint16_t version = 16;

  arg_ptr[0]  = uidai_get_param(in_ptr, "uses");

  /*Extract Uses for demographic to be encoded*/
  uses_attr[0] = uidai_get_attr(arg_ptr[0], "pi");
  uses_attr[1] = uidai_get_attr(arg_ptr[0], "pa");
  uses_attr[2] = uidai_get_attr(arg_ptr[0], "pfa");
  uses_attr[3] = uidai_get_attr(arg_ptr[0], "bio");
  uses_attr[4] = uidai_get_attr(arg_ptr[0], "pv");
  uses_attr[5] = uidai_get_attr(arg_ptr[0], "demo");

  free(arg_ptr[0]);
  arg_ptr[0] = NULL;

  /*Pid tag*/
  pid_xml[0] = NULL;
  auth_compose_pid_v20(in_ptr, in_len, &pid_xml[0]);

  pid_xml[1] = NULL;
  if(uses_attr[0] && !strncmp(uses_attr[0], "1", 1)) {
    /*Pi to be encoded in auth xml*/
    auth_compose_pi_v20(in_ptr, in_len, &pid_xml[1]);
  }

  pid_xml[2] = NULL;
  if(uses_attr[1] && !strncmp(uses_attr[1], "1", 1)) {
    /*Pa to be encoded in auth xml*/
    auth_compose_pa_v20(in_ptr, in_len, &pid_xml[2]);
  }

  pid_xml[3] = NULL;
  if(uses_attr[2] && !strncmp(uses_attr[2], "1", 1)) {
    /*Pfa to be encoded in auth xml*/
    auth_compose_pfa_v20(in_ptr, in_len, &pid_xml[3]);
  }

  pid_xml[4] = NULL;
  if(uses_attr[3] && !strncmp(uses_attr[3], "1", 1)) {
    /*Bio to be encoded in auth xml*/
    auth_compose_bio_v20(in_ptr, in_len, &pid_xml[4]);
  }

  pid_xml[5] = NULL;
  if(uses_attr[4] && !strncmp(uses_attr[4], "1", 1)) {
    /*Pv to be encoded in auth xml*/
    auth_compose_pv_v20(in_ptr, in_len, &pid_xml[5]);
  }

  pid_xml[6] = NULL;
  if(uses_attr[5] && !strncmp(uses_attr[5], "1", 1)) {
    /*Demo to be encoded in auth xml*/
    auth_compose_demo_v20(in_ptr, in_len, &pid_xml[6]);
  }

  pid_xml[7] = NULL;
  auth_compose_pid_final(&pid_xml[7]);

  /*<Pid i.e Pid Begining tag*/
  offset += sprintf(&pid_xml_ptr[offset],
                    "%s",
                     pid_xml[0]);

  if(pid_xml[1] || pid_xml[2] || pid_xml[3]) {
    /*Begining <Demo tag*/
    offset += sprintf(&pid_xml_ptr[offset],
                      "\n%s",
                       pid_xml[6]);

    for(idx = 1; idx < 4; idx++) {

      if(pid_xml[idx]) {
        offset += sprintf(&pid_xml_ptr[offset],
                          "%s",
                          pid_xml[idx]);
      }
    }
    /*Demo End Tag*/ 
    offset += sprintf(&pid_xml_ptr[offset],
                      "%s",
                       "  </Demo>\n");
  }

  /*<Bios tag*/
  if(pid_xml[4]) {
    offset += sprintf(&pid_xml_ptr[offset],
                      "%s",
                       pid_xml[4]);
    
  }

  /*<Pv tag*/
  if(pid_xml[5]) {
    offset += sprintf(&pid_xml_ptr[offset],
                      "%s",
                       pid_xml[5]);
  }

  /*<Pid Final tag*/
  offset += sprintf(&pid_xml_ptr[offset],
                    "%s",
                     pid_xml[7]);

  for(idx = 0; idx < 8; idx++) {

    if(pid_xml[idx]) {
      /*freeing the allocated memory*/
      free(pid_xml[idx]);
      pid_xml[idx] = NULL;
    }
  } 

  /*Freeing the uses_attr memory*/
  for(idx = 0; idx < 6; idx++) {
    free(uses_attr[idx]);
    uses_attr[idx] = NULL;
  }

  fprintf(stderr, "\n%s:%d %s\n", __FILE__, __LINE__, pid_xml_ptr);
  return(0);
}/*auth_compose_pid_xml_v20*/

int32_t auth_compose_meta_tag_v20(uint8_t *in_ptr, 
                                  uint32_t in_len, 
                                  uint8_t *meta_tag, 
                                  uint8_t *c14n_meta) {
  uint8_t *meta = NULL;
  uint8_t *meta_attr[10];
  uint32_t offset = 0;
 
  meta = uidai_get_param(in_ptr, "meta");

  meta_attr[0] = uidai_get_attr(meta, "dc");
  meta_attr[1] = uidai_get_attr(meta, "dpId");
  meta_attr[2] = uidai_get_attr(meta, "mc");
  meta_attr[3] = uidai_get_attr(meta, "mi");
  meta_attr[4] = uidai_get_attr(meta, "rdsId");
  meta_attr[5] = uidai_get_attr(meta, "rdsVer");
  meta_attr[6] = uidai_get_attr(meta, "udc");

  /*freeing memory*/
  free(meta);
  meta = NULL;

  offset += sprintf(&meta_tag[offset],
                    "%s",
                    "<Meta");
  if(meta_attr[0]) {
    /*dc*/
    offset += sprintf(&meta_tag[offset],
                      "%s%s%s",
                      " dc=\"",
                      meta_attr[0],
                      "\"");
  }
  
  if(meta_attr[1]) {   
    /*dpId*/
    offset += sprintf(&meta_tag[offset],
                      "%s%s%s",
                      " dpId=\"",
                      meta_attr[1],
                      "\"");
  }

  if(meta_attr[2]) {
    /*mc*/
    offset += sprintf(&meta_tag[offset],
                      "%s%s%s",
                      " mc=\"",
                      meta_attr[2],
                      "\"");
  }

  if(meta_attr[3]) {
    /*mi*/
    offset += sprintf(&meta_tag[offset],
                      "%s%s%s",
                      " mi=\"",
                      meta_attr[3],
                      "\"");
  }

  if(meta_attr[4]) {
    /*rdsId*/
    offset += sprintf(&meta_tag[offset],
                      "%s%s%s",
                      " rdsId=\"",
                      meta_attr[4],
                      "\"");
  }

  if(meta_attr[5]) {
    /*rdsVer*/
    offset += sprintf(&meta_tag[offset],
                      "%s%s%s",
                      " rdsVer=\"",
                      meta_attr[5],
                      "\"");
  }

  if(meta_attr[6]) {
    /*udc*/
    offset += sprintf(&meta_tag[offset],
                      "%s%s%s",
                      " udc=\"",
                      meta_attr[6],
                      "\"");
  }

  strncpy(c14n_meta, meta_tag, offset);

  sprintf(&meta_tag[offset],
          "%s",
          "/>");

  sprintf(&c14n_meta[offset],
          "%s",
          "></Meta>");

  for(offset = 0; offset < 7; offset++) {

    if(meta_attr[offset]) {
      free(meta_attr[offset]);
      meta_attr[offset] = NULL;
    }

  }

  return(0);
}/*auth_compose_meta_tag_v20*/

int32_t auth_compose_uses_tag_v20(uint8_t *in_ptr, 
                                  uint32_t in_len, 
                                  uint8_t *uses_tag, 
                                  uint8_t *c14n_uses) {

  uint8_t *uses = NULL;
  uint8_t *uses_attr[16];
  uint32_t offset = 0;
  uint8_t *pv = NULL;
  uint8_t *pv_attr[8];
 
  uses = uidai_get_param(in_ptr, "uses");

  uses_attr[0] = uidai_get_attr(uses, "pi");
  uses_attr[1] = uidai_get_attr(uses, "pa");
  uses_attr[2] = uidai_get_attr(uses, "pfa");
  uses_attr[3] = uidai_get_attr(uses, "bio");
  uses_attr[4] = uidai_get_attr(uses, "pv");
  uses_attr[5] = uidai_get_attr(uses, "demo");

  free(uses);
  offset += sprintf(&uses_tag[offset],
                    "%s",
                    "<Uses");
  /*Bio*/ 
  if(!strncmp(uses_attr[3], "1", 1)) {
    offset += sprintf(&uses_tag[offset],
                      "%s",
                      " bio=\"y\"");

    /*bt has to be present*/
    offset += sprintf(&uses_tag[offset],
                      "%s",
                      " bt=\"y\"");
  } else {
    offset += sprintf(&uses_tag[offset],
                      "%s",
                      " bio=\"n\"");
  }

  /*Otp*/
  if(!strncmp(uses_attr[4], "1", 1)) {
    pv = uidai_get_param(in_ptr, "pv");
    pv_attr[0] = uidai_get_attr(pv, "pin");
    pv_attr[1] = uidai_get_attr(pv, "otp");
    free(pv);

    if(pv_attr[0] && strlen(pv_attr[0])) {
      offset += sprintf(&uses_tag[offset],
                        "%s",
                        " pin=\"y\"");

    } else if(pv_attr[1] && strlen(pv_attr[1])) {
      offset += sprintf(&uses_tag[offset],
                        "%s",
                        " otp=\"y\"");
       
    } else {
      offset += sprintf(&uses_tag[offset],
                        "%s",
                        " otp=\"n\"");
    }

    free(pv_attr[0]);
    free(pv_attr[1]);

  } else {

    offset += sprintf(&uses_tag[offset],
                      "%s",
                      " otp=\"n\"");
  }

  /*Pa*/
  if(!strncmp(uses_attr[1], "1", 1)) {
    offset += sprintf(&uses_tag[offset],
                      "%s",
                      " pa=\"y\"");
  } else {
    offset += sprintf(&uses_tag[offset],
                      "%s",
                      " pa=\"n\"");
  }

  /*Pfa*/       
  if(!strncmp(uses_attr[2], "1", 1)) {
    offset += sprintf(&uses_tag[offset],
                      "%s",
                      " pfa=\"y\"");
  } else {
    offset += sprintf(&uses_tag[offset],
                      "%s",
                      " pfa=\"n\"");
  }

  /*Pi*/
  if(!strncmp(uses_attr[0], "1", 1)) {
    offset += sprintf(&uses_tag[offset],
                      "%s",
                      " pi=\"y\"");
  } else {
    offset += sprintf(&uses_tag[offset],
                      "%s",
                      " pi=\"n\"");
  }

  /*Attributes shall be in ascending order*/
  offset += sprintf(&uses_tag[offset],
                    "%s",
                    " pin=\"n\"");

  strncpy(c14n_uses, uses_tag, offset);

  sprintf(&uses_tag[offset],
          "%s",
          "/>");

  sprintf(&c14n_uses[offset],
          "%s",
          "></Uses>");

  /*ferring uses attr*/
  for(offset = 0; offset < 6; offset++) {
    free(uses_attr[offset]);
    uses_attr[offset] = NULL;
  }

  return(0);
}/*auth_compose_uses_tag_v20*/

int32_t auth_compose_auth_tag_v20(uint8_t *in_ptr, 
                                  uint32_t in_len, 
                                  uint8_t *auth_tag) {

  uint8_t *auth = NULL;
  uint8_t *auth_attr[16];
  uint32_t idx = 0;
 
  auth = uidai_get_param(in_ptr, "auth");

  auth_attr[0] = uidai_get_attr(auth, "uid");
  auth_attr[1] = uidai_get_attr(auth, "tid");
  auth_attr[2] = uidai_get_attr(auth, "ac");
  auth_attr[3] = uidai_get_attr(auth, "sa");
  auth_attr[4] = uidai_get_attr(auth, "ver");
  auth_attr[5] = uidai_get_attr(auth, "txn");
  auth_attr[6] = uidai_get_attr(auth, "lk");
  auth_attr[7] = uidai_get_attr(auth, "rc");
 
  free(auth);
  if(auth_attr[1]) {
    sprintf(auth_tag,
            "%s%s%s%s%s"
            "%s%s%s%s%s"
            "%s%s%s%s%s"
            "%s%s",
            "<Auth ac=\"",
            auth_attr[2],
            "\" lk=\"",
            auth_attr[6],
            "\" rc=\"",
            auth_attr[7],
            "\" sa=\"",
            auth_attr[3],
            "\" tid=\"",
            auth_attr[1],
            "\" txn=\"",
            auth_attr[5],
            "\" uid=\"",
            auth_attr[0],
            "\" ver=\"",
            auth_attr[4],
            "\">");
  } else {
    /*tid for public devices shall be empty*/
    sprintf(auth_tag,
            "%s%s%s%s%s"
            "%s%s%s%s%s"
            "%s%s%s%s%s"
            "%s",
            "<Auth ac=\"",
            auth_attr[2],
            "\" lk=\"",
            auth_attr[6],
            "\" rc=\"",
            auth_attr[7],
            "\" sa=\"",
            auth_attr[3],
            "\" tid=\"",
            "\" txn=\"",
            auth_attr[5],
            "\" uid=\"",
            auth_attr[0],
            "\" ver=\"",
            auth_attr[4],
            "\">");
  }

  for(idx = 0; idx < 8; idx++) {

    if(auth_attr[idx]) {
      free(auth_attr[idx]);
      auth_attr[idx] = NULL;
    }

  }

  return(0);
}/*auth_compose_auth_tag_v20*/

/*===============================================
 *
 * v16
 *==============================================*/

int32_t auth_data_v16(uint8_t *data, 
                      uint16_t data_size, 
                      uint8_t *pid_xml) {

  uint8_t ciphered_data[512];
  int32_t ciphered_data_len;
  uint8_t b64[512];
  uint16_t b64_len;
  uint8_t plain_txt[512];
  int32_t plain_txt_len;
  uint8_t tag[16];
  
  memset((void *)ciphered_data, 0, sizeof(ciphered_data)); 
  memset((void *)tag, 0, sizeof(tag));

  auth_cipher_ecb(pid_xml, 
                  strlen(pid_xml), 
                  ciphered_data, 
                  &ciphered_data_len);

  memset((void *)b64, 0, sizeof(b64));
  util_base64(ciphered_data, ciphered_data_len, b64, &b64_len);
  memset((void *)data, 0, data_size);

  snprintf(data,
           data_size,
           "%s%s%s",
           "<Data type=\"X\">",
           b64,
           "</Data>");

  return(0);
}/*auth_data_v16*/

int32_t auth_hmac_v16(uint8_t *hmac,
                      uint16_t hmac_size,
                      uint8_t *pid_xml) {

  uint8_t digest256[32];
  int32_t ciphered_data_len = 0;
  uint8_t ciphered_data[512];
  uint8_t b64_hmac[512];
  uint16_t b64_hmac_len;
  uint8_t tag[16];
  
  auth_ctx_t *pAuthCtx = &auth_ctx_g;
  SHA256_CTX ctx;

  memset((void *)digest256, 0, sizeof(digest256));

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, pid_xml, strlen((const char *)pid_xml));
  SHA256_Final(digest256, &ctx);

  memset((void *)tag, 0, sizeof(tag));
  memset((void *)ciphered_data, 0, sizeof(ciphered_data));
  auth_cipher_ecb(digest256, 32, ciphered_data, &ciphered_data_len);
  fprintf(stderr, "\n%s:%d ciphered data len HMAC %d\n", __FILE__, __LINE__, ciphered_data_len);
  memset((void *)b64_hmac, 0, sizeof(b64_hmac));
  util_base64(ciphered_data, ciphered_data_len, b64_hmac, &b64_hmac_len);
 
  memset((void *)hmac, 0, hmac_size);
  snprintf(hmac, 
           hmac_size, 
           "%s%s%s",
           "<Hmac>",
           b64_hmac,
           "</Hmac>");

  return(0);
}/*auth_hmac_v16*/

int32_t auth_compose_pi_v16(uint8_t *in_ptr, 
                            uint32_t in_len, 
                            uint8_t **pi_xml_ptr) {

  uint8_t *pi = NULL; 
  uint8_t *pi_attr[16];
  uint32_t offset = 0;
  uint8_t name_str[256];
  uint8_t *pi_xml;
  uint32_t len = sizeof(uint8_t) * 1024;

  pi_xml = (uint8_t *)malloc(len);
  assert(pi_xml != NULL);
  memset((void *)pi_xml, 0, len);

  *pi_xml_ptr = pi_xml;

  pi  = uidai_get_param(in_ptr, "pi");
  assert(pi != NULL);

  pi_attr[0] = uidai_get_attr(pi, "ms");
  pi_attr[1] = uidai_get_attr(pi, "mv");
  pi_attr[2] = uidai_get_attr(pi, "name");
  pi_attr[3] = uidai_get_attr(pi, "lname");
  pi_attr[4] = uidai_get_attr(pi, "lmv");
  pi_attr[5] = uidai_get_attr(pi, "gender");
  pi_attr[6] = uidai_get_attr(pi, "dob");
  pi_attr[7] = uidai_get_attr(pi, "dobt");
  pi_attr[8] = uidai_get_attr(pi, "age");
  pi_attr[9] = uidai_get_attr(pi, "phone");
  pi_attr[10] = uidai_get_attr(pi, "email");

  free(pi);
  offset += snprintf(&pi_xml[offset],
                     (len - offset),
                     "%s%s",
                     "\n",
                     "    <Pi");

  if(pi_attr[0] && strlen(pi_attr[0])) {
    /*ms is present*/
    offset += snprintf(&pi_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " ms=\"",
                       pi_attr[0],
                       "\"");
  }

  if(pi_attr[1] && strlen(pi_attr[1])) {
    /*mv is present*/
    offset += snprintf(&pi_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " mv=\"",
                       pi_attr[1],
                       "\"");
  }
  
  if(pi_attr[2] && strlen(pi_attr[2])) {
    /*name is present*/
    memset((void *)name_str, 0, sizeof(name_str));
    auth_restore_str(pi_attr[2], name_str);

    offset += snprintf(&pi_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " name=\"",
                       name_str,
                       "\"");
  }
  
  if(pi_attr[3] && strlen(pi_attr[3])) {
    /*lname is present*/
    offset += snprintf(&pi_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " lname=\"",
                       pi_attr[3],
                       "\"");
  }
  
  if(pi_attr[4] && strlen(pi_attr[4])) {
    /*lmv is present*/
    offset += snprintf(&pi_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " lmv=\"",
                       pi_attr[4],
                       "\"");
  }

  if(pi_attr[5] && strlen(pi_attr[5])) {
    /*gender is present*/
    offset += snprintf(&pi_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " gender=\"",
                       pi_attr[5],
                       "\"");
  }

  if(pi_attr[6] && strlen(pi_attr[6])) {
    /*dob is present*/
    offset += snprintf(&pi_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " dob=\"",
                       pi_attr[6],
                       "\"");
  }

  if(pi_attr[7] && strlen(pi_attr[7])) {
    /*dobt is present*/
    offset += snprintf(&pi_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " dobt=\"",
                       pi_attr[7],
                       "\"");
  }

  if(pi_attr[8] && strlen(pi_attr[8])) {
    /*age is present*/
    offset += snprintf(&pi_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " age=\"",
                       pi_attr[8],
                       "\"");
  }

  if(pi_attr[9] && strlen(pi_attr[9])) {
    /*phone is present*/
    offset += snprintf(&pi_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " phone=\"",
                       pi_attr[9],
                       "\"");
  }

  if(pi_attr[10] && strlen(pi_attr[10])) {
    /*email is present*/
    offset += snprintf(&pi_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " email=\"",
                       pi_attr[10],
                       "\"");
  }

  offset += snprintf(&pi_xml[offset],
                     (len - offset),
                     "%s",
                     "/>\n");

  fprintf(stderr, "\n%s:%d %s\n", __FILE__, __LINE__, pi_xml);

  /*freeing the allocated memory*/
  for(offset = 0; offset < 11; offset++) {
    free(pi_attr[offset]);
  }

  return(0);
}/*auth_compose_pi_v16*/

int32_t auth_compose_demo_v16(uint8_t *in_ptr, 
                              uint32_t in_len, 
                              uint8_t **demo_xml_ptr) {

  uint8_t *demo = NULL; 
  uint8_t *demo_attr[8];
  uint32_t offset = 0;
  uint8_t *demo_xml;
  uint32_t len = sizeof(uint8_t) * 64;

  demo_xml = (uint8_t *)malloc(len);
  assert(demo_xml != NULL);
  memset((void *)demo_xml, 0, len);

  *demo_xml_ptr = demo_xml;
  demo  = uidai_get_param(in_ptr, "demo");
  assert(demo != NULL);

  demo_attr[0] = uidai_get_attr(demo, "lang");
  free(demo);

  offset += snprintf(&demo_xml[offset],
                     (len - offset),
                     "%s",
                     "  <Demo");

  if(demo_attr[0] && strlen(demo_attr[0])) {
    /*lang is present*/
    if(strncmp(demo_attr[0], "NA", 2)) {
      offset += snprintf(&demo_xml[offset],
                         (len - offset),
                         "%s%s%s",
                         " lang=\"",
                         demo_attr[0],
                         "\" ");
    }
  }
  
  offset += snprintf(&demo_xml[offset],
                     (len - offset),
                     "%s",
                     ">");

  free(demo_attr[0]);

  return(0);
}/*auth_compose_demo_v16*/

int32_t auth_compose_pv_v16(uint8_t *in_ptr, 
                            uint32_t in_len, 
                            uint8_t **pv_xml_ptr) {

  uint8_t *pv = NULL; 
  uint8_t *pv_attr[8];
  uint32_t offset = 0;
  uint8_t *pv_xml;
  uint32_t len = sizeof(uint8_t) * 64;

  pv_xml = (uint8_t *)malloc(len);
  assert(pv_xml != NULL);
  memset((void *)pv_xml, 0, len);

  *pv_xml_ptr = pv_xml;
  pv  = uidai_get_param(in_ptr, "pv");
  assert(pv != NULL);

  pv_attr[0] = uidai_get_attr(pv, "otp");
  pv_attr[1] = uidai_get_attr(pv, "pin");

  free(pv);
  offset += snprintf(&pv_xml[offset],
                     (len - offset),
                     "\n%s",
                     "  <Pv");

  if(pv_attr[0] && strlen(pv_attr[0])) {
    /*otp is present*/
    offset += snprintf(&pv_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " otp=\"",
                       pv_attr[0],
                       "\"");
  }

  if(pv_attr[1] && strlen(pv_attr[1])) {
    /*pin is present*/
    offset += snprintf(&pv_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " pin=\"",
                       pv_attr[1],
                       "\"");
  }

  offset += snprintf(&pv_xml[offset],
                     (len - offset),
                     "%s",
                     "/>\n");

  for(offset = 0; offset < 2; offset++) {
    free(pv_attr[offset]);
  }

  return(0);
}/*auth_compose_pv_v16*/

int32_t auth_compose_bio_v16(uint8_t *in_ptr, 
                             uint32_t in_len, 
                             uint8_t **bio_xml_ptr) {

  uint8_t *bio = NULL; 
  uint8_t *bio_attr[8];
  uint32_t offset = 0;
  uint8_t *bio_xml;
  uint32_t len = sizeof(uint8_t) * 512;

  bio_xml = (uint8_t *)malloc(len);
  assert(bio_xml != NULL);
  memset((void *)bio_xml, 0, len);

  *bio_xml_ptr = bio_xml;
  bio  = uidai_get_param(in_ptr, "bio");
  assert(bio != NULL);

  bio_attr[0] = uidai_get_attr(bio, "type");
  bio_attr[1] = uidai_get_attr(bio, "posh");
  bio_attr[2] = uidai_get_attr(bio, "value");

  free(bio);
  offset += snprintf(&bio_xml[offset],
                     (len - offset),
                     "%s%s",
                     "  <Bios>\n",
                     "    <Bio");

  if(bio_attr[0] && strlen(bio_attr[0])) {
    /*type is present*/
    offset += snprintf(&bio_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " type=\"",
                       bio_attr[0],
                       "\"");
  }

  if(bio_attr[1] && strlen(bio_attr[1])) {
    /*type is present*/
    offset += snprintf(&bio_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " posh=\"",
                       bio_attr[1],
                       "\"");
  }

  if(bio_attr[2] && strlen(bio_attr[2])) {
    /*type is present*/
    offset += snprintf(&bio_xml[offset],
                       (len - offset),
                       "%s%s%s%s",
                       ">",
                       bio_attr[2],
                       "</Bio>\n",
                       "  </Bios>\n");
  }

  fprintf(stderr, "\n%s:%d bio %s\n", __FILE__, __LINE__, bio_xml);
  for(offset = 0; offset < 3; offset++) {
    free(bio_attr[offset]);
  }

  return(0);
}/*auth_compose_bio_v16*/

int32_t auth_compose_pfa_v16(uint8_t *in_ptr, 
                             uint32_t in_len, 
                             uint8_t **pfa_xml_ptr) {

  uint8_t *pfa = NULL; 
  uint8_t *pfa_attr[16];
  uint32_t offset = 0;
  uint8_t *pfa_xml;
  uint32_t len = sizeof(uint8_t) * 256;

  pfa_xml = (uint8_t *)malloc(len);
  assert(pfa_xml != NULL);
  memset((void *)pfa_xml, 0, len);

  *pfa_xml_ptr = pfa_xml;
  pfa  = uidai_get_param(in_ptr, "pfa");
  assert(pfa != NULL);

  pfa_attr[0] = uidai_get_attr(pfa, "ms");
  pfa_attr[1] = uidai_get_attr(pfa, "co");
  pfa_attr[2] = uidai_get_attr(pfa, "house");
  pfa_attr[3] = uidai_get_attr(pfa, "street");
  pfa_attr[4] = uidai_get_attr(pfa, "lm");
  pfa_attr[5] = uidai_get_attr(pfa, "loc");
  pfa_attr[6] = uidai_get_attr(pfa, "vtc");
  pfa_attr[7] = uidai_get_attr(pfa, "subdist");
  pfa_attr[8] = uidai_get_attr(pfa, "dist");
  pfa_attr[9] = uidai_get_attr(pfa, "state");
  pfa_attr[10] = uidai_get_attr(pfa, "pc");
  pfa_attr[11] = uidai_get_attr(pfa, "po");

  free(pfa);
  offset += snprintf(&pfa_xml[offset],
                     (len - offset),
                     "%s",
                     "    <Pfa");

  if(pfa_attr[0] && strlen(pfa_attr[0])) {
    /*ms is present*/
    offset += snprintf(&pfa_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " ms=\"",
                       pfa_attr[0],
                       "\"");
  }

  if(pfa_attr[1] && strlen(pfa_attr[1])) {
    /*mv is present*/
    offset += snprintf(&pfa_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " mv=\"",
                       pfa_attr[1],
                       "\"");
  }
  
  if(pfa_attr[2] && strlen(pfa_attr[2])) {
    /*av is present*/
    offset += snprintf(&pfa_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " av=\"",
                       pfa_attr[2],
                       "\"");
  }
  
  if(pfa_attr[3] && strlen(pfa_attr[3])) {
    /*lav is present*/
    offset += snprintf(&pfa_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " lav=\"",
                       pfa_attr[3],
                       "\"");
  }
  
  if(pfa_attr[4] && strlen(pfa_attr[4])) {
    /*lmv is present*/
    offset += snprintf(&pfa_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " lmv=\"",
                       pfa_attr[4],
                       "\"");
  }

  offset += snprintf(&pfa_xml[offset],
                     (len - offset),
                     "%s",
                     "/>\n");
  fprintf(stderr, "\n%s:%d pfa %s\n", __FILE__, __LINE__, pfa_xml);
  /*freeing the allocated memory*/
  for(offset = 0; offset < 5; offset++) {
    free(pfa_attr[offset]);
  }

  return(0);
}/*auth_compose_pfa_v16*/

int32_t auth_compose_pa_v16(uint8_t *in_ptr, 
                            uint32_t in_len, 
                            uint8_t **pa_xml_ptr) {

  uint8_t *pa = NULL; 
  uint8_t *pa_attr[16];
  uint32_t offset = 0;
  uint8_t *pa_xml;
  uint32_t len = sizeof(uint8_t) * 256;

  pa_xml = (uint8_t *)malloc(len);
  assert(pa_xml != NULL);
  memset((void *)pa_xml, 0, len);

  *pa_xml_ptr = pa_xml;
  pa  = uidai_get_param(in_ptr, "pa");
  assert(pa != NULL);

  pa_attr[0] = uidai_get_attr(pa, "ms");
  pa_attr[1] = uidai_get_attr(pa, "co");
  pa_attr[2] = uidai_get_attr(pa, "house");
  pa_attr[3] = uidai_get_attr(pa, "street");
  pa_attr[4] = uidai_get_attr(pa, "lm");
  pa_attr[5] = uidai_get_attr(pa, "loc");
  pa_attr[6] = uidai_get_attr(pa, "vtc");
  pa_attr[7] = uidai_get_attr(pa, "subdist");
  pa_attr[8] = uidai_get_attr(pa, "dist");
  pa_attr[9] = uidai_get_attr(pa, "state");
  pa_attr[10] = uidai_get_attr(pa, "pc");
  pa_attr[11] = uidai_get_attr(pa, "po");

  free(pa);
  offset += snprintf(&pa_xml[offset],
                     (len - offset),
                     "%s%s",
                     "\n",
                     "    <Pa");

  if(pa_attr[0] && strlen(pa_attr[0])) {
    /*ms is present*/
    offset += snprintf(&pa_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " ms=\"",
                       pa_attr[0],
                       "\"");
  }

  if(pa_attr[1] && strlen(pa_attr[1])) {
    /*co is present*/
    offset += snprintf(&pa_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " co=\"",
                       pa_attr[1],
                       "\"");
  }
  
  if(pa_attr[2] && strlen(pa_attr[2])) {
    /*house is present*/
    offset += snprintf(&pa_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " name=\"",
                       pa_attr[2],
                       "\"");
  }
  
  if(pa_attr[3] && strlen(pa_attr[3])) {
    /*street is present*/
    offset += snprintf(&pa_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " street=\"",
                       pa_attr[3],
                       "\"");
  }
  
  if(pa_attr[4] && strlen(pa_attr[4])) {
    /*lm is present*/
    offset += snprintf(&pa_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " lm=\"",
                       pa_attr[4],
                       "\"");
  }

  if(pa_attr[5] && strlen(pa_attr[5])) {
    /*loc is present*/
    offset += snprintf(&pa_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " loc=\"",
                       pa_attr[5],
                       "\"");
  }

  if(pa_attr[6] && strlen(pa_attr[6])) {
    /*vtc is present*/
    offset += snprintf(&pa_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " vtc=\"",
                       pa_attr[6],
                       "\"");
  }

  if(pa_attr[7] && strlen(pa_attr[7])) {
    /*subdist is present*/
    offset += snprintf(&pa_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " subdist=\"",
                       pa_attr[7],
                       "\"");
  }

  if(pa_attr[8] && strlen(pa_attr[8])) {
    /*dist is present*/
    offset += snprintf(&pa_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " dist=\"",
                       pa_attr[8],
                       "\"");
  }

  if(pa_attr[9] && strlen(pa_attr[9])) {
    /*state is present*/
    offset += snprintf(&pa_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " state=\"",
                       pa_attr[9],
                       "\"");
  }

  if(pa_attr[10] && strlen(pa_attr[10])) {

    /*pc is present*/
    offset += snprintf(&pa_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " pc=\"",
                       pa_attr[10],
                       "\"");
  }

  if(pa_attr[11] && strlen(pa_attr[11])) {
    /*po is present*/
    offset += snprintf(&pa_xml[offset],
                       (len - offset),
                       "%s%s%s",
                       " po=\"",
                       pa_attr[11],
                       "\"");
  }

  offset += snprintf(&pa_xml[offset],
                     (len - offset),
                     "%s",
                     "/>\n");

  fprintf(stderr, "\n%s:%d pa_xml[2] %s\n",__FILE__, __LINE__, pa_xml);
  /*freeing the allocated memory*/
  for(offset = 0; offset < 12; offset++) {
    free(pa_attr[offset]);
  }

  return(0);
}/*auth_compose_pa_v16*/

int32_t auth_compose_pid_v16(uint8_t *in_ptr, 
                           uint32_t in_len, 
                           uint8_t **pid_init) {

  uint32_t len = sizeof(uint8_t) * 128;
  uint8_t ts[32];
  uint16_t ts_size = sizeof(ts);
  uint8_t pid_ver[4];

  (void)in_ptr;
  (void)in_len;

  *pid_init = (uint8_t *)malloc(len);
  assert(*pid_init != NULL);
  memset((void *)*pid_init, 0, len);

  auth_compute_ts(ts, ts_size);
  memset((void *)pid_ver, 0, sizeof(pid_ver));

  strncpy(pid_ver, "1.0", 3);

  snprintf(*pid_init, 
           len,
           "%s%s%s%s%s",
           "<Pid ts=\"",
           ts,
           "\" ver=\"",
           pid_ver,
           "\">"); 

  return(0);
}/*auth_compose_pid_v16*/

int32_t auth_compose_pid_xml_v16(uint8_t *in_ptr, 
                                 uint32_t in_len, 
                                 uint8_t *pid_xml_ptr) {

  uint8_t *arg_ptr[2];
  uint8_t *pid_xml[16];
  uint8_t *uses_attr[16];
  uint32_t idx = 0;
  uint32_t offset = 0;
  uint16_t version = 16;

  arg_ptr[0]  = uidai_get_param(in_ptr, "uses");

  /*Extract Uses for demographic to be encoded*/
  uses_attr[0] = uidai_get_attr(arg_ptr[0], "pi");
  uses_attr[1] = uidai_get_attr(arg_ptr[0], "pa");
  uses_attr[2] = uidai_get_attr(arg_ptr[0], "pfa");
  uses_attr[3] = uidai_get_attr(arg_ptr[0], "bio");
  uses_attr[4] = uidai_get_attr(arg_ptr[0], "pv");
  uses_attr[5] = uidai_get_attr(arg_ptr[0], "demo");

  free(arg_ptr[0]);

  pid_xml[0] = NULL;
  auth_compose_pid_v16(in_ptr, in_len, &pid_xml[0]);

  pid_xml[1] = NULL;
  if(!strncmp(uses_attr[0], "1", 1)) {
    /*Pi to be encoded in auth xml*/
    auth_compose_pi_v16(in_ptr, in_len, &pid_xml[1]);
  }

  pid_xml[2] = NULL;
  if(!strncmp(uses_attr[1], "1", 1)) {
    /*Pa to be encoded in auth xml*/
    auth_compose_pa_v16(in_ptr, in_len, &pid_xml[2]);
  }

  pid_xml[3] = NULL;
  if(!strncmp(uses_attr[2], "1", 1)) {
    /*Pfa to be encoded in auth xml*/
    auth_compose_pfa_v16(in_ptr, in_len, &pid_xml[3]);
  }

  pid_xml[4] = NULL;
  if(!strncmp(uses_attr[3], "1", 1)) {
    /*Bio to be encoded in auth xml*/
    auth_compose_bio_v16(in_ptr, in_len, &pid_xml[4]);
  }

  pid_xml[5] = NULL;
  if(!strncmp(uses_attr[4], "1", 1)) {
    /*Pv to be encoded in auth xml*/
    auth_compose_pv_v16(in_ptr, in_len, &pid_xml[5]);
  }

  pid_xml[6] = NULL;
  if(!strncmp(uses_attr[5], "1", 1)) {
    /*Demo to be encoded in auth xml*/
    auth_compose_demo_v16(in_ptr, in_len, &pid_xml[6]);
  }

  pid_xml[7] = NULL;
  auth_compose_pid_final(&pid_xml[7]);

  /*<Pid i.e Pid Begining tag*/
  offset += sprintf(&pid_xml_ptr[offset],
                    "%s",
                     pid_xml[0]);

  if(pid_xml[1] || pid_xml[2] || pid_xml[3]) {
    /*Begining <Demo tag*/
    offset += sprintf(&pid_xml_ptr[offset],
                      "\n%s",
                       pid_xml[6]);

    for(idx = 1; idx < 4; idx++) {

      if(pid_xml[idx]) {
        offset += sprintf(&pid_xml_ptr[offset],
                          "%s",
                          pid_xml[idx]);
      }
    }
    /*Demo End Tag*/ 
    offset += sprintf(&pid_xml_ptr[offset],
                      "%s",
                       "  </Demo>\n");
  }

  /*<Bios tag*/
  if(pid_xml[4]) {
    offset += sprintf(&pid_xml_ptr[offset],
                      "%s",
                       pid_xml[4]);
    
  }

  /*<Pv tag*/
  if(pid_xml[5]) {
    offset += sprintf(&pid_xml_ptr[offset],
                      "%s",
                       pid_xml[5]);
  }

  /*<Pid Final tag*/
  offset += sprintf(&pid_xml_ptr[offset],
                    "%s",
                     pid_xml[7]);

  for(idx = 0; idx < 8; idx++) {

    if(pid_xml[idx]) {
      /*freeing the allocated memory*/
      free(pid_xml[idx]);
      pid_xml[idx] = NULL;
    }
  } 

  /*Freeing the uses_attr memory*/
  for(idx = 0; idx < 6; idx++) {
    free(uses_attr[idx]);
    uses_attr[idx] = NULL;
  }

  fprintf(stderr, "\n%s:%d %s\n", __FILE__, __LINE__, pid_xml_ptr);
  return(0);
}/*auth_compose_pid_xml_v16*/

int32_t auth_compose_meta_tag_v16(uint8_t *in_ptr, 
                                  uint32_t in_len, 
                                  uint8_t *meta_tag, 
                                  uint8_t *c14n_meta) {
  uint8_t *meta = NULL;
  uint8_t *meta_attr[16];
  uint32_t offset = 0;
 
  meta = uidai_get_param(in_ptr, "meta");

  meta_attr[0] = uidai_get_attr(meta, "udc");
  meta_attr[1] = uidai_get_attr(meta, "fdc");
  meta_attr[2] = uidai_get_attr(meta, "idc");
  meta_attr[3] = uidai_get_attr(meta, "pip");
  meta_attr[4] = uidai_get_attr(meta, "lot");
  meta_attr[5] = uidai_get_attr(meta, "lov");

  offset += sprintf(&meta_tag[offset],
                    "%s",
                    "<Meta");

  /*fdc*/
  offset += sprintf(&meta_tag[offset],
                    "%s%s%s",
                    " fdc=\"",
                    meta_attr[1],
                    "\"");
  /*idc*/
  offset += sprintf(&meta_tag[offset],
                    "%s%s%s",
                    " idc=\"",
                    meta_attr[2],
                    "\"");

  /*lot*/
  offset += sprintf(&meta_tag[offset],
                    "%s%s%s",
                    " lot=\"",
                    meta_attr[4],
                    "\"");

  /*lov*/
  offset += sprintf(&meta_tag[offset],
                    "%s%s%s",
                    " lov=\"",
                    meta_attr[5],
                    "\"");
  /*pip*/
  offset += sprintf(&meta_tag[offset],
                    "%s%s%s",
                    " pip=\"",
                    meta_attr[3],
                    "\"");
  /*udc*/
  offset += sprintf(&meta_tag[offset],
                    "%s%s%s",
                    " udc=\"",
                    meta_attr[0],
                    "\"");

  strncpy(c14n_meta, meta_tag, offset);

  sprintf(&meta_tag[offset],
          "%s",
          "/>");

  sprintf(&c14n_meta[offset],
          "%s",
          "></Meta>");

  for(offset = 0; offset < 6; offset++) {
    free(meta_attr[offset]);
  }

  return(0);
}/*auth_compose_meta_tag_v16*/

int32_t auth_compose_tkn_tag_v16(uint8_t *in_ptr, 
                                 uint32_t in_len, 
                                 uint8_t *tkn_tag, 
                                 uint8_t *c14n_tkn) {
  uint8_t *tkn = NULL;
  uint8_t *tkn_attr[16];
  uint32_t offset = 0;
 
  tkn = uidai_get_param(in_ptr, "tkn");

  tkn_attr[0] = uidai_get_attr(tkn, "type");
  tkn_attr[1] = uidai_get_attr(tkn, "value");

  free(tkn);
  fprintf(stderr, "\n%s:%d type is %s\n", __FILE__, __LINE__, tkn_attr[0]);

  if(!strncmp(tkn_attr[0], "NA", 2)) {
    /*do not encode tkn tag of Auth xml*/
    free(tkn_attr[0]);
    free(tkn_attr[1]);
    fprintf(stderr, "\n%s:%d 1.type is %s\n", __FILE__, __LINE__, tkn_attr[0]);
    return(1);

  } else {
    offset += sprintf(&tkn_tag[offset],
                      "%s",
                      "<Tkn");

    offset += sprintf(&tkn_tag[offset],
                      "%s%s%s",
                      " type=\"",
                      tkn_attr[0],
                      "\"");

    offset += sprintf(&tkn_tag[offset],
                      "%s%s%s",
                      " value=\"",
                      tkn_attr[1],
                      "\"");

    strncmp(c14n_tkn, tkn_tag, offset);

    sprintf(&tkn_tag[offset],
           "%s",
           "/>");

    sprintf(&c14n_tkn[offset],
           "%s",
           "></Tkn>");
  }

  free(tkn_attr[0]);
  free(tkn_attr[1]);

  return(0);
}/*auth_compose_tkn_tag_v16*/

int32_t auth_compose_uses_tag_v16(uint8_t *in_ptr, 
                                  uint32_t in_len, 
                                  uint8_t *uses_tag, 
                                  uint8_t *c14n_uses) {

  uint8_t *uses = NULL;
  uint8_t *uses_attr[16];
  uint32_t offset = 0;
  uint8_t *pv = NULL;
  uint8_t *pv_attr[8];
 
  uses = uidai_get_param(in_ptr, "uses");

  uses_attr[0] = uidai_get_attr(uses, "pi");
  uses_attr[1] = uidai_get_attr(uses, "pa");
  uses_attr[2] = uidai_get_attr(uses, "pfa");
  uses_attr[3] = uidai_get_attr(uses, "bio");
  uses_attr[4] = uidai_get_attr(uses, "pv");
  uses_attr[5] = uidai_get_attr(uses, "demo");

  free(uses);
  offset += sprintf(&uses_tag[offset],
                    "%s",
                    "<Uses");
  /*Bio*/ 
  if(!strncmp(uses_attr[3], "1", 1)) {
    offset += sprintf(&uses_tag[offset],
                      "%s",
                      " bio=\"y\"");

    /*bt has to be present*/
    offset += sprintf(&uses_tag[offset],
                      "%s",
                      " bt=\"y\"");
  } else {
    offset += sprintf(&uses_tag[offset],
                      "%s",
                      " bio=\"n\"");
  }

  /*Otp*/
  if(!strncmp(uses_attr[4], "1", 1)) {
    pv = uidai_get_param(in_ptr, "pv");
    pv_attr[0] = uidai_get_attr(pv, "pin");
    pv_attr[1] = uidai_get_attr(pv, "otp");
    free(pv);

    if(pv_attr[0] && strlen(pv_attr[0])) {
      offset += sprintf(&uses_tag[offset],
                        "%s",
                        " pin=\"y\"");

    } else if(pv_attr[1] && strlen(pv_attr[1])) {
      offset += sprintf(&uses_tag[offset],
                        "%s",
                        " otp=\"y\"");
       
    } else {
      offset += sprintf(&uses_tag[offset],
                        "%s",
                        " otp=\"n\"");
    }

    free(pv_attr[0]);
    free(pv_attr[1]);

  } else {

    offset += sprintf(&uses_tag[offset],
                      "%s",
                      " otp=\"n\"");
  }

  /*Pa*/
  if(!strncmp(uses_attr[1], "1", 1)) {
    offset += sprintf(&uses_tag[offset],
                      "%s",
                      " pa=\"y\"");
  } else {
    offset += sprintf(&uses_tag[offset],
                      "%s",
                      " pa=\"n\"");
  }

  /*Pfa*/       
  if(!strncmp(uses_attr[2], "1", 1)) {
    offset += sprintf(&uses_tag[offset],
                      "%s",
                      " pfa=\"y\"");
  } else {
    offset += sprintf(&uses_tag[offset],
                      "%s",
                      " pfa=\"n\"");
  }

  /*Pi*/
  if(!strncmp(uses_attr[0], "1", 1)) {
    offset += sprintf(&uses_tag[offset],
                      "%s",
                      " pi=\"y\"");
  } else {
    offset += sprintf(&uses_tag[offset],
                      "%s",
                      " pi=\"n\"");
  }

  /*Attributes shall be in ascending order*/
  offset += sprintf(&uses_tag[offset],
                    "%s",
                    " pin=\"n\"");

  strncpy(c14n_uses, uses_tag, offset);

  sprintf(&uses_tag[offset],
          "%s",
          "/>");

  sprintf(&c14n_uses[offset],
          "%s",
          "></Uses>");

  /*ferring uses attr*/
  for(offset = 0; offset < 6; offset++) {
    free(uses_attr[offset]);
  }

  return(0);
}/*auth_compose_uses_tag_v16*/

uint8_t *auth_main_ex_v16(uint8_t *in_ptr, 
                          uint32_t in_len, 
                          uint32_t *rsp_len) {
  
  uint8_t *pid_xml = NULL;
  uint8_t *auth_xml_tag[16];
  uint8_t *c14n[4];
  uint16_t version = 16;
  uint32_t idx = 0;
  int32_t opt_tkn = 0;
  uint8_t skey[512];
  uint16_t skey_size = sizeof(skey);
  uint8_t *data_x = NULL;
  uint16_t data_x_len = 512;
  uint8_t *hmac = NULL;
  uint16_t hmac_len = 256;
  uint8_t *c14n_auth_xml = NULL;
  uint16_t c14n_len = 4000;
  uint8_t *final_xml = NULL;
  uint16_t final_xml_size = 5000;
  uint8_t *b64_digest = NULL;
  uint8_t *b64_signature = NULL;
  uint8_t *b64_subject = NULL;
  uint8_t *b64_certificate = NULL;
  
  for(idx = 0; idx < 4; idx++) {
    auth_xml_tag[idx] = (uint8_t *)malloc(sizeof(uint8_t) * 256);
    assert(auth_xml_tag[idx] != NULL);
    memset((void *)auth_xml_tag[idx], 0, sizeof(uint8_t) * 256);
  }

  for(idx = 0; idx < 3; idx++) {
    c14n[idx] = (uint8_t *)malloc(sizeof(uint8_t) * 256);
    assert(c14n[idx] != NULL);
    memset((void *)c14n[idx], 0, sizeof(uint8_t) * 256);
  }

  auth_compose_auth_tag_v16(in_ptr, 
                            in_len, 
                            auth_xml_tag[0]);

  auth_compose_uses_tag_v16(in_ptr, 
                            in_len, 
                            auth_xml_tag[1], 
                            c14n[0]);

  opt_tkn = auth_compose_tkn_tag_v16(in_ptr, 
                                     in_len, 
                                     auth_xml_tag[2], 
                                     c14n[1]);

  auth_compose_meta_tag_v16(in_ptr, 
                            in_len, 
                            auth_xml_tag[3],
                            c14n[2]);

  pid_xml = (uint8_t *)malloc(sizeof(uint8_t) * 1024);
  assert(pid_xml != NULL);
  memset((void *)pid_xml, 0, sizeof(uint8_t) * 1024);

  auth_compose_pid_xml_v16(in_ptr, 
                         in_len, 
                         pid_xml);

  fprintf(stderr, "\n%s\n", pid_xml);

  /*Skey tag of Final AUTH XML <Skey ..></Skey>*/
  memset((void *)skey, 0, sizeof(skey));
  auth_skey(skey, skey_size);

  data_x = (uint8_t *)malloc(sizeof(uint8_t) * data_x_len);
  assert(data_x != NULL);
  memset((void *)data_x, 0, data_x_len);
  auth_data_v16(data_x, data_x_len, pid_xml);
  
  hmac = (uint8_t *)malloc(sizeof(uint8_t) * hmac_len);
  assert(hmac != NULL);
  memset((void *)hmac, 0, hmac_len);
  auth_hmac_v16(hmac, hmac_len, pid_xml);

  free(pid_xml);
  pid_xml = NULL;

  /*signature of Auth XML*/
  c14n_auth_xml = (uint8_t *)malloc(sizeof(uint8_t) * c14n_len);
  assert(c14n_auth_xml != NULL);
  memset((void *)c14n_auth_xml, 0, c14n_len);
 
  auth_c14n_auth_xml(c14n_auth_xml, 
                     c14n_len, 
                     auth_xml_tag[0],
                     /*uses tag*/
                     c14n[0], 
                     /*tkn tag*/
                     c14n[1],
                     /*meta tag*/
                     c14n[2], 
                     skey, 
                     hmac, 
                     data_x);
  free(c14n[0]);
  free(c14n[1]);
  free(c14n[2]);

  b64_digest = (uint8_t *)malloc(sizeof(uint8_t) * 2048);
  assert(b64_digest != NULL);
  memset((void *)b64_digest, 0, 2048);
  
  b64_signature = (uint8_t *)malloc(sizeof(uint8_t) * 2048);
  assert(b64_signature != NULL);
  memset((void *)b64_signature, 0, 2048);

  b64_subject = (uint8_t *)malloc(sizeof(uint8_t) * 2048);
  assert(b64_subject != NULL);
  memset((void *)b64_subject, 0, 2048);

  b64_certificate = (uint8_t *)malloc(sizeof(uint8_t) * 2048);
  assert(b64_certificate != NULL);
  memset((void *)b64_certificate, 0, 2048);

  fprintf(stderr,"\n%s:%d c14n auth xml is \n%s\n", __FILE__, __LINE__, c14n_auth_xml);
  auth_c14n_sign(c14n_auth_xml,
                 b64_digest,
                 b64_signature,
                 b64_subject,
                 b64_certificate);

  free(c14n_auth_xml);
  c14n_auth_xml = NULL;

  final_xml = (uint8_t *)malloc(sizeof(uint8_t) * final_xml_size);
  assert(final_xml != NULL);
  memset((void *)final_xml, 0, final_xml_size);

  auth_compose_xml(final_xml,
                   final_xml_size,
                   /*Auth tag*/
                   auth_xml_tag[0],
                   /*Uses tag*/
                   auth_xml_tag[1],
                   /*Tkn tag*/
                   auth_xml_tag[2],
                   /*Meta tag*/
                   auth_xml_tag[3],
                   skey,
                   hmac,
                   data_x);

  free(auth_xml_tag[0]);
  free(auth_xml_tag[1]);
  free(auth_xml_tag[2]);
  free(auth_xml_tag[3]);

  uint16_t final_xml_len = 0;
  uint16_t tmp_len = strlen(final_xml);

  util_compose_final_xml(&final_xml[tmp_len], 
                         (final_xml_size - tmp_len), 
                         &final_xml_len,
                         /*digest*/
                         b64_digest,
                         /*Signature Value*/
                         b64_signature,
                         /*Subject Name*/
                         b64_subject,
                         /*Certificate*/
                         b64_certificate); 

  final_xml_len += tmp_len;
  snprintf(&final_xml[final_xml_len], 
           final_xml_size, 
           "%s", 
           "</Auth>");

  free(b64_digest);
  free(b64_signature);
  free(b64_subject);
  free(b64_certificate);

  fprintf(stderr, "Final XML \n%s\n", final_xml);

  *rsp_len = strlen(final_xml);

  return(final_xml);
}/*auth_main_ex_v16*/

int32_t auth_compose_auth_tag_v16(uint8_t *in_ptr, 
                                  uint32_t in_len, 
                                  uint8_t *auth_tag) {

  uint8_t *auth = NULL;
  uint8_t *auth_attr[16];
  uint32_t idx = 0;
 
  auth = uidai_get_param(in_ptr, "auth");

  auth_attr[0] = uidai_get_attr(auth, "uid");
  auth_attr[1] = uidai_get_attr(auth, "tid");
  auth_attr[2] = uidai_get_attr(auth, "ac");
  auth_attr[3] = uidai_get_attr(auth, "sa");
  auth_attr[4] = uidai_get_attr(auth, "ver");
  auth_attr[5] = uidai_get_attr(auth, "txn");
  auth_attr[6] = uidai_get_attr(auth, "lk");
 
  free(auth);

  sprintf(auth_tag,
          "%s%s%s%s%s"
          "%s%s%s%s%s"
          "%s%s%s%s%s",
          "<Auth ac=\"",
          auth_attr[2],
          "\" lk=\"",
          auth_attr[6],
          "\" sa=\"",
          auth_attr[3],
          "\" tid=\"",
          auth_attr[1],
          "\" txn=\"",
          auth_attr[5],
          "\" uid=\"",
          auth_attr[0],
          "\" ver=\"",
          auth_attr[4],
          "\">");

  for(idx = 0; idx < 7; idx++) {
    free(auth_attr[idx]);
  }

  return(0);
}/*auth_compose_auth_tag_v16*/


int32_t auth_decipher(uint8_t *b64, 
                      int32_t b64_len, 
                      uint8_t *plain_txt, 
                      int32_t *plain_txt_len,
                      uint8_t *tag) {
 
  int32_t tmp_len = 0;
  uint8_t ci_txt[1024];
  uint32_t ci_len = 0;
  auth_ctx_t *pAuthCtx = &auth_ctx_g;
  EVP_CIPHER_CTX *x;
  uint8_t iv[20];
  uint8_t aad[20];
  uint8_t tmp_tag[20];

  memset((void *)tmp_tag, 0, sizeof(tmp_tag));
  memset((void *)iv, 0, sizeof(iv));
  memset((void *)aad, 0, sizeof(aad));
  memset((void *)ci_txt, 0, sizeof(ci_txt));

  util_base64_decode_ex(b64, b64_len, ci_txt, &ci_len);

  /*First 19 bytes shall be ts*/
  strncpy(iv, &ci_txt[strlen(pAuthCtx->ts) - 12], 12);
  strncpy(aad, &ci_txt[strlen(pAuthCtx->ts) - 16], 16);
  /*last 16 bytes shall be authentication tag*/
  memcpy(tmp_tag, &ci_txt[ci_len - 16], 16);

  fprintf(stderr, "\n%s:%d iv %s aad %s\n", __FILE__, __LINE__, iv, aad);

  x = EVP_CIPHER_CTX_new();

  if(!EVP_DecryptInit_ex(x, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
    fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return(-1);
  }

  if(!EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL)) {
    fprintf(stderr, "\n%s:%d Setting of iv len failed \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return(-2);
  }

  /* Now we can set key and IV */
  if(!EVP_DecryptInit_ex(x, NULL, NULL, pAuthCtx->session_key, iv)) {
    fprintf(stderr, "\n%s:%d Setting of keys and iv failed \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return(-2);
  }

  if(!EVP_DecryptUpdate(x, NULL, &tmp_len, aad, 16)) {
    fprintf(stderr, "\n%s:%d Setting of aad failed \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return(-2);
  }

  if(!EVP_DecryptUpdate(x, plain_txt, plain_txt_len, &ci_txt[strlen(pAuthCtx->ts)], (ci_len - (16 + strlen(pAuthCtx->ts))))) {
    /* Error */
    fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return 0;
  }

  if(!EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_SET_TAG, 16, tmp_tag)) {
    fprintf(stderr, "\n%s:%d SET TAG Failed \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return 0;
  }

  if(!EVP_DecryptFinal_ex(x, (plain_txt + *plain_txt_len), &tmp_len)) {
    /* Error */
    fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return 0;
  }

  *plain_txt_len += tmp_len;
  EVP_CIPHER_CTX_free(x);

  return(0); 
}/*auth_decipher*/

int auth_cipher_ecb(uint8_t *data, 
                    uint16_t data_len, 
                    uint8_t *ciphered_data, 
                    int32_t *ciphered_data_len) {
  int32_t tmp_len = 0;
  auth_ctx_t *pAuthCtx = &auth_ctx_g;
  EVP_CIPHER_CTX *x;
  const EVP_CIPHER *cipher;

  x = EVP_CIPHER_CTX_new();
  cipher = EVP_get_cipherbyname("aes-256-ecb");

  if(1 != EVP_EncryptInit_ex(x, cipher, NULL, pAuthCtx->session_key, NULL)) {
    fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return(-1);
  }

  if(1 != EVP_CIPHER_CTX_set_padding(x, EVP_PADDING_PKCS7)) {
    fprintf(stderr, "\n%s:%d Setting of PKCS7 Padding Failed\n",
                     __FILE__, __LINE__);
    return(-2);
  }

  /*key_length & iv_length is set based on EVP_aes_256_cbc type*/
  /*128-bits of block*/

  if(1 != EVP_EncryptInit_ex(x, NULL, NULL, pAuthCtx->session_key, NULL)) {
    fprintf(stderr, "\n%s:%d Setting of keys and iv failed \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return(-2);
  }

  if(NID_undef == EVP_CIPHER_nid(cipher)) {
    fprintf(stderr, "\n NID is undef\n");
  }

  if(1 != EVP_EncryptUpdate(x, ciphered_data, ciphered_data_len, data, data_len)) {
    /* Error */
    EVP_CIPHER_CTX_free(x);
    fprintf(stderr, "\n%s:%d Error", __FILE__, __LINE__);
    return 0;
  }

  if(1 != EVP_EncryptFinal_ex(x, (ciphered_data + *ciphered_data_len), &tmp_len)) {
    /* Error */
    fprintf(stderr, "\n%s:%d Error", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return 0;
  }

  *ciphered_data_len += tmp_len;
  EVP_CIPHER_CTX_reset(x);
  EVP_CIPHER_CTX_free(x);
  return(0); 

}/*auth_cipher_ecb*/

/**
 * @brief This function is to cipher the plain text by using
 *        symmetric algorithm namley AES + ECB + PKCS7_PADDING
 *        Padding is required to make ciphered data into block of 16
 *        bytes i.e 128bits. For AES + ECB + PKCS7 Padding IV (Initialization
 *        Vector) is not required.
 * @param data is a pointer to character which holds the data to be encrypted
 * @param data_len is the length of plain data to be encrypted
 * @param ciphered_data which holds the encrypted data
 * @param ciphered_data_len which holds the length of ciphered data
 *
 * @return upon success it returns 0 else less than zero.
 */
int32_t auth_cipher_gcm(uint8_t *data, 
                        uint16_t data_len, 
                        uint8_t *ciphered_data, 
                        int32_t *ciphered_data_len, 
                        uint8_t *tag,
                        uint8_t is_hmac) {
 
  int32_t tmp_len = 0;
  auth_ctx_t *pAuthCtx = &auth_ctx_g;
  EVP_CIPHER_CTX *x;
  int32_t offset = 0;
  uint8_t *ci_text = NULL;
  
  ci_text = (uint8_t *)malloc(1024);
  assert(ci_text != NULL);
  memset((void *)ci_text, 0, 1024);

  x = EVP_CIPHER_CTX_new();
  assert(x != NULL);

  /*Initializing Encryption Engine*/
  if(!EVP_EncryptInit_ex(x, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
    fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return(-2);
  }

  if(!EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) {
    fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
    /*Setting of iv Length failed*/
    EVP_CIPHER_CTX_free(x);
    return(-3);
  }

  /*Initializing symmetric key and iv*/
  if(!EVP_EncryptInit_ex(x, NULL, NULL, pAuthCtx->session_key, pAuthCtx->iv)) {
    fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return(-4);
  }

  if(!EVP_EncryptUpdate(x, NULL, &tmp_len, pAuthCtx->aad, 16)) {
    fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return(-5);
  }

  while(offset <= data_len - 16) {
    if(!EVP_EncryptUpdate(x, (ci_text + offset), &tmp_len, (data + offset), 16)) {
      /* Error */
      fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
      EVP_CIPHER_CTX_free(x);
      return(-6);
    }
    offset += tmp_len;
  }

  tmp_len = 0;
  if(offset < data_len) {
    if(!EVP_EncryptUpdate(x, (ci_text + offset), &tmp_len, (data + offset), (data_len - offset))) {
      /* Error */
      fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
      EVP_CIPHER_CTX_free(x);
      return(-7);
    }
    offset += tmp_len;
  }

  tmp_len = 0;
  if(!EVP_EncryptFinal_ex(x, (ci_text + offset), &tmp_len)) {
    /* Error */
    fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return(-7);
  }

  offset += tmp_len;
  /* Get the tag */
  if(!EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
    fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return(-8);
  }

  memcpy((void *)&ci_text[offset], tag, 16); 
  offset += 16;
 
  if(!is_hmac) { 
    /*pre-pend ts to the encrypted text*/
    memcpy((void *)ciphered_data, pAuthCtx->ts, strlen(pAuthCtx->ts));
    memcpy((void *)&ciphered_data[strlen(pAuthCtx->ts)], ci_text, offset);
    offset += strlen(pAuthCtx->ts);

  } else {
    /*Do not prepend the ts*/
    memcpy((void *)ciphered_data, ci_text, offset);
  }

  *ciphered_data_len = offset;

  EVP_CIPHER_CTX_reset(x);
  EVP_CIPHER_CTX_free(x);
  free(ci_text);

  /*Data is encrypted successfully*/
  return(0); 
}/*auth_cipher_gcm*/

int32_t auth_skey(uint8_t *b64_skey, uint16_t b64_skey_size) {

  auth_ctx_t *pAuthCtx = &auth_ctx_g;
  FILE *fp = NULL;
  X509 *x509;
  RSA *rsa;
  EVP_PKEY *pkey;
  BIO *bio;
  ASN1_TIME *expiry_date;
  uint8_t not_after[256];
  size_t len = sizeof(not_after);
  uint8_t *ci_txt;
  uint8_t b64_cipher[512];
  uint16_t b64_cipher_len;
  /*Length of encrypted session key*/
  int32_t ci_len = 0;
  uint8_t dd[4];
  uint8_t mm[4];
  uint8_t yyyy[8];
  uint8_t *tmp_ptr = NULL;
  char *save_ptr = NULL;
  uint16_t idx;
  int32_t rc;
  uint8_t *mm_str[] = {"Dummy", "Jan", "Feb", 
                       "Mar", "Apr", "May", 
                       "Jun", "Jul", "Aug", 
                       "Sep", "Oct", "Nov", 
                       "Dec", NULL};

  memset((void *)pAuthCtx->session_key, 0, sizeof(pAuthCtx->session_key));
  auth_symmetric_keys(pAuthCtx->session_key, sizeof(pAuthCtx->session_key));

  memset((void *)yyyy, 0, sizeof(yyyy));
  memset((void *)mm, 0, sizeof(mm));
  memset((void *)dd, 0, sizeof(dd));

  fp = fopen(pAuthCtx->public_key, "r");
  assert(fp != NULL);

  x509 = PEM_read_X509(fp, NULL, 0, NULL);
  assert(x509 != NULL);
  pkey = X509_get_pubkey(x509);
  fclose(fp);

  rsa = EVP_PKEY_get1_RSA(pkey);
  assert(rsa != NULL);

  /*Retrieve Certificate Expiry date*/
  expiry_date = X509_get_notAfter(x509);

  bio = BIO_new(BIO_s_mem());

  if(!bio) {
    fprintf(stderr, "\n%s:%d Instantiation of BIO failed\n", __FILE__, __LINE__);
    X509_free(x509);
    return(-2);
  }

  if(!ASN1_TIME_print(bio, expiry_date)) {
    fprintf(stderr, "\n%s:%d expiry date for bio failed\n", __FILE__, __LINE__);
    BIO_free(bio);
    X509_free(x509);
    return(-3);
  }

  if(!BIO_gets(bio, not_after, len)) {
    fprintf(stderr, "\n%s:%d retrieval of expiry date failed\n", __FILE__, __LINE__);
    BIO_free(bio);
    X509_free(x509);
    return(-4);
  }

  tmp_ptr = strtok_r(not_after, " ", &save_ptr);
  strncpy(mm, tmp_ptr, strlen((const char *)tmp_ptr));  
  tmp_ptr = strtok_r(NULL, " ", &save_ptr);
  strncpy(dd, tmp_ptr, strlen((const char *)tmp_ptr));
  tmp_ptr = strtok_r(NULL, " ", &save_ptr);
  tmp_ptr = strtok_r(NULL, " ", &save_ptr);
  strncpy(yyyy, tmp_ptr, strlen((const char *)tmp_ptr));
 
  for(idx = 0; mm_str[idx]; idx++) {
    if(!strncmp(mm_str[idx], mm, strlen((const char *)mm))) {
      break;
    }
  }

  BIO_free(bio);
  memset((void *)not_after, 0, sizeof(not_after));

  snprintf(not_after, 
           sizeof(not_after),
           "%s%.2d%s",
           yyyy,
           idx,
           dd);

  ci_txt = (uint8_t *)malloc(sizeof(uint8_t) * 1024);
  assert(ci_txt != NULL);

  memset((void *)ci_txt, 0, sizeof(uint8_t) * 1024);

  /*Encrypt Session key (256-bits) with public key*/
  ci_len = RSA_public_encrypt(32, 
                              pAuthCtx->session_key,
                              ci_txt, 
                              rsa,
                              RSA_PKCS1_PADDING);
  if(ci_len < 0) {
    fprintf(stderr, "\n%s:%d Encryption of session key with public key failed\n",
            __FILE__,
            __LINE__);
    return(-5);
  }

  util_base64(ci_txt, 
              ci_len, 
              b64_cipher, 
              &b64_cipher_len);

  memset((void *)b64_skey, 0, b64_skey_size);
  snprintf(b64_skey,
           b64_skey_size,
           "%s%s%s%s%s",
           "<Skey ci=\"",
           not_after,
           "\">",
           b64_cipher,
           "</Skey>");

  X509_free(x509);
  RSA_free(rsa);
  EVP_PKEY_free(pkey);
  free(ci_txt);
  ci_txt = NULL;

  return(0); 
}/*auth_skey*/

int32_t auth_compose_xml(uint8_t *auth_xml,
                         uint16_t auth_xml_size,
                         uint8_t *auth,
                         uint8_t *uses,
                         uint8_t *tkn,
                         uint8_t *meta,
                         uint8_t *skey,
                         uint8_t *hmac,
                         uint8_t *data) {
  if(tkn) {
    snprintf(auth_xml, 
             auth_xml_size,
             "%s%s%s%s%s"
             "%s%s%s%s%s"
             "%s%s%s%s%s",
             "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n",
             auth,
             "\n  ",
             uses,
             "\n  ",
             tkn,
             "\n  ",
             meta,
             "\n  ",
             skey,
             "\n  ",
             hmac,
             "\n  ",
             data,
             "\n");
  } else {
      
    snprintf(auth_xml, 
             auth_xml_size,
             "%s%s%s%s%s"
             "%s%s%s%s%s"
             "%s%s%s",
             "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n",
             auth,
             "\n  ",
             uses,
             "\n  ",
             meta,
             "\n  ",
             skey,
             "\n  ",
             hmac,
             "\n  ",
             data,
             "\n");
  }

  return(0);
}/*auth_compose_xml*/

int32_t auth_c14n_auth_xml(uint8_t *c14n_auth_xml, 
                           uint16_t c14n_auth_xml_size, 
                           uint8_t *auth_xml,
                           uint8_t *c14n_uses, 
                           uint8_t *c14n_tkn,
                           uint8_t *c14n_meta, 
                           uint8_t *skey, 
                           uint8_t *hmac, 
                           uint8_t *data) {
  if(c14n_tkn) {
    snprintf(c14n_auth_xml, 
             c14n_auth_xml_size,
             "%s%s%s%s%s"
             "%s%s%s%s%s"
             "%s%s%s%s%s",
             auth_xml,
             "\n  ",
             c14n_uses,
             "\n  ",
             c14n_tkn,
             "\n  ",
             c14n_meta,
             "\n  ",
             skey,
             "\n  ",
             hmac,
             "\n  ",
             data,
             "\n  \n",
             "</Auth>");
    } else {
      snprintf(c14n_auth_xml, 
               c14n_auth_xml_size,
               "%s%s%s%s%s"
               "%s%s%s%s%s"
               "%s%s%s",
               auth_xml,
               "\n  ",
               c14n_uses,
               "\n  ",
               c14n_meta,
               "\n  ",
               skey,
               "\n  ",
               hmac,
               "\n  ",
               data,
               "\n  \n",
               "</Auth>");
    }
  return(0);
}/*auth_c14n_auth_xml*/

int32_t auth_c14n_sign(uint8_t *c14n_auth_xml,
                       uint8_t *b64_digest,
                       uint8_t *b64_signature,
                       uint8_t *b64_subject,
                       uint8_t *b64_certificate) {

  uint8_t digest[20];
  uint32_t digest_len;
  uint16_t b64_digest_len = 0;
  uint8_t c14n_signed_info[2048];
  uint16_t c14n_signed_info_len = 0;
  uint8_t *signature_value = NULL;
  uint16_t signature_len;
  uint16_t b64_signature_len;
  uint8_t *subject = NULL;
  uint16_t subject_len = 0;
  uint8_t *certificate = NULL;
  uint16_t certificate_len = 0;

  memset((void *)digest, 0, sizeof(digest));
  util_compute_digest(c14n_auth_xml, 
                       strlen(c14n_auth_xml), 
                       digest, 
                       &digest_len);

  util_base64(digest, 
               digest_len, 
               b64_digest, 
               &b64_digest_len);

  memset((void *)c14n_signed_info, 0, sizeof(c14n_signed_info)); 
  util_c14n_signedinfo(c14n_signed_info, 
                        sizeof(c14n_signed_info), 
                        &c14n_signed_info_len,
                        b64_digest);

  util_compute_rsa_signature(c14n_signed_info, 
                              c14n_signed_info_len, 
                              &signature_value, 
                              &signature_len); 

  util_base64(signature_value, 
               signature_len, 
               b64_signature, 
               &b64_signature_len);  

  util_subject_certificate(&subject,
                            &subject_len,
                            &certificate,
                            &certificate_len);

  /*copy subject and certificate*/
  strncpy(b64_subject, subject, subject_len);
  strncpy(b64_certificate, certificate, certificate_len);
  
  free(signature_value);
  signature_value = NULL;
  free(subject);
  free(certificate);

  return(0);
}/*auth_c14n_sign*/

int32_t auth_restore_str(uint8_t *name_ptr, uint8_t *name_str) {
  uint32_t idx = 0;

  while(*name_ptr != '\0') {
    if(*name_ptr == '+') {
      name_str[idx++] = ' ';
      name_ptr++;
      continue;
    }
    name_str[idx++] = *name_ptr;
    name_ptr++;
  }
}/*auth_restore_str*/

int32_t auth_compose_pid_final(uint8_t **pid_xml) {

  uint32_t len = sizeof(uint8_t) * 32;

  *pid_xml = (uint8_t *)malloc(len);
  assert(*pid_xml != NULL);
  memset((void *)*pid_xml, 0, len);

  snprintf(*pid_xml,
           len,
           "%s",
           "</Pid>\n");
  
  return(0);
}/*auth_compose_pid_final*/

uint8_t *auth_get_ts(void) {
  uint8_t *ts_ptr = NULL;
  auth_ctx_t *pAuthCtx = &auth_ctx_g;
  /*+1 for NULL character*/
  uint32_t ts_len = (strlen(pAuthCtx->ts) * sizeof(uint8_t)) + 1;

  ts_ptr = (uint8_t *)malloc(ts_len);
  assert(ts_ptr != NULL);
  memset((void *)ts_ptr, 0, ts_len);

  strncpy(ts_ptr, (const char *)pAuthCtx->ts, ts_len);

  return(ts_ptr);
}/*auth_get_ts*/

int32_t auth_compose_final_req(uint8_t *in_ptr,
                               uint8_t *out_ptr, 
                               uint32_t out_size, 
                               uint32_t *len_ptr, 
                               uint8_t *auth_xml_ptr) {

  uint8_t *param_ptr = NULL;
  uint8_t *attr_ptr[8];
  uint32_t idx;

  param_ptr = uidai_get_param(in_ptr, "auth");
  assert(param_ptr != NULL);

  attr_ptr[0] = uidai_get_attr(param_ptr, "uid");
  attr_ptr[1] = uidai_get_attr(param_ptr, "ac");
  attr_ptr[2] = uidai_get_attr(param_ptr, "lk");
  free(param_ptr);
  param_ptr = NULL;

  param_ptr = uidai_get_param(in_ptr, "uidai");
  assert(param_ptr != NULL);

  attr_ptr[3] = uidai_get_attr(param_ptr, "host");
  attr_ptr[4] = uidai_get_attr(param_ptr, "uri");
  free(param_ptr);
  param_ptr = NULL;
  
  *len_ptr = snprintf(out_ptr, 
                      out_size,
                      "%s%s%s%s"
                      "%s%s%c%s%c"
                      "%s%s%s%s%s"
                      "%s%s%s%s%d"
                      "%s%s%s",
                      "POST http://",
                      /*host name*/
                      attr_ptr[3],
                      /*uri*/
                      attr_ptr[4],
                      "/",
                      /*ac*/
                      attr_ptr[1],
                      "/",
                      /*1st digit of uid*/
                      attr_ptr[0][0],
                      "/",
                      /*2nd digit of uid*/
                      attr_ptr[0][1],
                      "/",
                      /*lk*/
                      attr_ptr[2],
                      " HTTP/1.1\r\n",
                      "Host: ",
                      attr_ptr[3],
                      "\r\n",
                      "Content-Type: text/xml\r\n",
                      "Connection: Keep-alive\r\n",
                      "Content-Length: ",
                      (int32_t)strlen(auth_xml_ptr),
                      "\r\n",
                      /*Payload delimeter*/
                      "\r\n",
                      auth_xml_ptr);

  for(idx = 0; idx < 5; idx++) {
    free(attr_ptr[idx]);
    attr_ptr[idx] = NULL;
  }

  return(0);           
}/*auth_compose_final_req*/

uint8_t *auth_compose_http_req(uint8_t *in_ptr, 
                               uint8_t *auth_xml, 
                               uint32_t *len_ptr) {
  uint8_t *http_req_ptr = NULL;
  uint32_t http_req_size = 5000;

  http_req_ptr = (uint8_t *)malloc(sizeof(uint8_t) * http_req_size);
  assert(http_req_ptr != NULL);
  memset((void *)http_req_ptr, 0, (sizeof(uint8_t) * http_req_size));

  auth_compose_final_req(in_ptr,
                         http_req_ptr, 
                         http_req_size, 
                         len_ptr, 
                         auth_xml);

  return(http_req_ptr);
}/*auth_compose_http_req*/

void auth_init_ex(uint8_t *in_ptr, uint32_t in_len) {

  uint8_t *auth = NULL;
  uint8_t *uidai = NULL;
  uint8_t *crypto = NULL;
  uint8_t *crypto_attr[4];
  uint8_t *uidai_attr[4];
  uint8_t *auth_attr[16];
  uint32_t idx;

  auth = uidai_get_param(in_ptr, "auth");
  auth_attr[0] = uidai_get_attr(auth, "uid");
  auth_attr[1] = uidai_get_attr(auth, "tid");
  auth_attr[2] = uidai_get_attr(auth, "ac");
  auth_attr[3] = uidai_get_attr(auth, "sa");
  auth_attr[4] = uidai_get_attr(auth, "ver");
  auth_attr[5] = uidai_get_attr(auth, "txn");
  auth_attr[6] = uidai_get_attr(auth, "lk");
  free(auth);

  uidai = uidai_get_param(in_ptr, "uidai");
  uidai_attr[0] = uidai_get_attr(uidai, "uri");
  uidai_attr[1] = uidai_get_attr(uidai, "host");
  free(uidai);

  crypto = uidai_get_param(in_ptr, "crypto");
  crypto_attr[0] = uidai_get_attr(crypto, "public");
  crypto_attr[1] = uidai_get_attr(crypto, "private");
  crypto_attr[2] = uidai_get_attr(crypto, "password");
  free(crypto);

  auth_init(auth_attr[2],
            auth_attr[3],
            auth_attr[6],
            crypto_attr[1],
            crypto_attr[0],
            uidai_attr[1],
            uidai_attr[0],
            auth_attr[4],
            auth_attr[1],
            auth_attr[5],
            crypto_attr[2]);

  for(idx = 0; idx < 7; idx++) {

    if(auth_attr[idx]) {
      free(auth_attr[idx]);
      auth_attr[idx] = NULL;
    }

  } 

  for(idx = 0; idx < 2; idx++) {

    if(uidai_attr[idx]) {
      free(uidai_attr[idx]);
      uidai_attr[idx] = NULL;
    }

  }
 
  for(idx = 0; idx < 3; idx++) {

    if(crypto_attr[idx]) {
      free(crypto_attr[idx]);
      crypto_attr[idx] = NULL;
    }

  }

}/*auth_init_ex*/

uint8_t *auth_main_ex(uint8_t *in_ptr, 
                      uint32_t in_len, 
                      uint16_t version, 
                      int32_t rsp_fd) {

  uint32_t rsp_len = 0;
  uint8_t *rsp_ptr = NULL;
  uint8_t *http_req_ptr = NULL;

  auth_init_ex(in_ptr, in_len);
  if(16 == version) {
    rsp_ptr = auth_main_ex_v16(in_ptr, in_len, &rsp_len);
    http_req_ptr = auth_compose_http_req(in_ptr, rsp_ptr, &rsp_len);
    free(rsp_ptr);
    rsp_ptr = NULL;

  } else if(20 == version) {
    rsp_ptr = auth_main_ex_v20(in_ptr, in_len, &rsp_len);
    http_req_ptr = auth_compose_http_req(in_ptr, rsp_ptr, &rsp_len);
    free(rsp_ptr);
    rsp_ptr = NULL;

  } else if(25 == version) {
    rsp_ptr = auth_main_ex_v25(in_ptr, in_len, &rsp_len);
    http_req_ptr = auth_compose_http_req(in_ptr, rsp_ptr, &rsp_len);
    free(rsp_ptr);
    rsp_ptr = NULL;
    
  }

  return(http_req_ptr);
}/*auth_main_ex*/

#endif /* __AUTH_C__ */
