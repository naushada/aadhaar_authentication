#ifndef __UIDAI_H__
#define __UIDAI_H__

struct session {
  /*The subscriber is connected at the fd*/
  uint32_t conn_id;
  /*user <-> uam*/
  uint32_t uam_conn_id;
  /*uam <-> redir*/
  uint32_t redir_conn_id;
  /*could hold uid/mobile number*/
  uint8_t uid[14];
  /*aadhaar holder's name*/
  uint8_t uid_name[128];
  /*Request type - otp/auth */
  uint8_t req_type[8];
  /*Request subtype - auth_otp/auth_pi/auth_pa/auth_pfa*/
  uint8_t req_subtype[16];
  /*IP address of subscriber*/
  uint8_t ip_str[32];
  struct session *next;
};

typedef struct session uidai_session_t;

typedef struct {

  /*host name in the form of URI*/
  uint8_t uidai_host_name[128];
  uint32_t uidai_port;
  int32_t uidai_fd;

  /*TCP Connection B/W acc- access Controller and uidai task*/
  uint16_t port;
  uint32_t ip;
  int32_t fd;
  uint8_t ac[16];
  uint8_t sa[16];
  uint8_t lk[64];
  uint8_t public_fname[128];
  uint8_t private_fname[128];
  uidai_session_t *session;
}uidai_ctx_t;

/* Function Prototype*/


uint8_t *uidai_get_param(uint8_t *req_ptr, 
                         const uint8_t *param_name);

uint8_t *uidai_get_rparam(uint8_t *req_ptr, 
                          const uint8_t *param_name);

int32_t uidai_build_ext_rsp(uint8_t *req_ptr, 
                            uint8_t **rsp_ptr, 
                            uint32_t *rsp_len,
                            uint32_t *conn_id_ptr);

int32_t uidai_parse_uidai_rsp(int32_t conn_fd, 
                              uint8_t *packet_ptr, 
                              uint32_t chunked_starts_at, 
                              uint32_t chunked_len,
                              uint8_t *param);
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
int32_t uidai_process_uidai_rsp(int32_t conn_fd, 
                                uint8_t *packet_ptr, 
                                uint32_t packet_len, 
                                uint8_t **rsp_ptr,
                                uint32_t *rsp_len,
                                uint32_t *conn_id);

int32_t uidai_add_session(uidai_session_t **head, uint32_t conn_fd);

uidai_session_t *uidai_get_session(uidai_session_t *session, uint32_t conn_id);

int32_t uidai_set_fd(uidai_session_t *session, fd_set *rd);

uint32_t uidai_get_max_fd(uidai_session_t *session);

/**
 * @brief This function removes the matched node from the linked list if
 *        Elements are repeated.
 */
int32_t uidai_remove_session(uint32_t conn_id);

/**
 * @brief This function processes the response buffer
 *  without consuming the buffer and ensures that
 *  the complete response is received. It makes sure
 *  that incase of chunked response, end chunked is
 *  received.
 *
 * @param conn_fd is the connection at which response is received.
 * @param packet_buffer holds the response buffer
 * @param packet_len is the received response length
 *
 * @return it returns 0 if entire response is received else returns 1
 */
int32_t uidai_pre_process_uidai_rsp(int32_t conn_fd, 
                                    uint8_t *packet_ptr, 
                                    uint32_t packet_len);

int32_t uidai_process_req(int32_t conn_fd, 
                          uint8_t *packet_ptr, 
                          uint32_t packet_len);

int32_t uidai_recv(int32_t conn_fd, 
                   uint8_t *packet_ptr, 
                   uint32_t *packet_len,
                   int32_t flags);

int32_t uidai_send(int32_t conn_fd, 
                   uint8_t *packet_ptr, 
                   uint32_t packet_len);

int32_t uidai_connect_uidai(void);

int32_t uidai_init(uint32_t ip, 
                   uint32_t port, 
                   uint8_t *uidai_host, 
                   uint32_t uidai_port,
                   uint8_t *ac,
                   uint8_t *sa,
                   uint8_t *lk,
                   uint8_t *public_fname,
                   uint8_t *private_fname);

void *uidai_main(void *tid);

#endif /* __UIDAI_H__ */
