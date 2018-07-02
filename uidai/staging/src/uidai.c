#ifndef __UIDAI_C__
#define __UIDAI_C__

#include <unistd.h>
#include <signal.h>
#include "config.h"
#include "common.h"
#include "uidai.h"
#include "util.h"
#include "otp.h"
#include "auth.h"
#include "ekyc.h"

uidai_ctx_t uidai_ctx_g;

uint8_t *uidai_get_rparam(uint8_t *req_ptr, 
                          const uint8_t *p_name) {

  uint8_t param_name[32];
  uint8_t *param_value = NULL;
  uint8_t idx = 0;
  uint8_t flag = 0;
  uint8_t (*param_ptr)[1024] = (uint8_t (*)[1024])req_ptr;

  memset((void *)param_name, 0, sizeof(param_name));
  param_value = (uint8_t *)malloc(sizeof(uint8_t) * 1024);
  assert(param_value != NULL);
  memset((void *)param_value, 0, (sizeof(uint8_t) * 1024));
  
  while('\0' != param_ptr[idx][0]) {
    sscanf(param_ptr[idx], "%[^=]=%s", param_name, param_value);
    if(!strncmp(param_name, p_name, sizeof(param_name))) {
      flag = 1;
      break;      
    }
    idx++;
  }

  if(flag) {
    return(param_value);
  }

  return(NULL);
}/*uidai_get_rparam*/


uint8_t *uidai_get_param(uint8_t *req_ptr, 
                         const uint8_t *p_name) {

  uint8_t *tmp_req_ptr = NULL;
  uint8_t *line_ptr = NULL;
  uint8_t param_name[32];
  uint8_t *param_value = NULL;
  uint8_t flag = 0;
  char *save_ptr;
  uint32_t req_len = strlen(req_ptr);

  tmp_req_ptr = (uint8_t *) malloc(sizeof(uint8_t) * req_len);
  assert(tmp_req_ptr != NULL);
  memset((void *)tmp_req_ptr, 0, (sizeof(uint8_t) * req_len));

  memset((void *)param_name, 0, sizeof(param_name));
  param_value = (uint8_t *)malloc(sizeof(uint8_t) * 1024);
  assert(param_value != NULL);
  memset((void *)param_value, 0, (sizeof(uint8_t) * 1024));
  
  sscanf(req_ptr, "%*[^?]?%s", tmp_req_ptr);
  line_ptr = strtok_r(tmp_req_ptr, "&", &save_ptr);

  while(line_ptr) {
    sscanf(line_ptr, "%[^=]=%s", param_name, param_value);
    if(!strncmp(param_name, p_name, sizeof(param_name))) {
      flag = 1;
      break;      
    }
    line_ptr = strtok_r(NULL, "&", &save_ptr);
  }

  free(tmp_req_ptr);
  if(flag) {
    return(param_value);
  }

  return(NULL);
}/*uidai_get_param*/


int32_t uidai_build_ext_rsp(uint8_t *param_ptr, 
                            uint8_t **rsp_ptr, 
                            uint32_t *rsp_len,
                            uint32_t *conn_id_ptr) {
  uint8_t *txn;
  uint8_t conn_id[8];
  uidai_ctx_t *pUidaiCtx = &uidai_ctx_g;
  uidai_session_t *session = NULL;

  memset((void *)conn_id, 0, sizeof(conn_id)); 

  txn = uidai_get_rparam(param_ptr, "txn");
  assert(txn != NULL);

  /*txn format will be <uam_conn_id>-<redir_conn_id>-<uidai_conn_id>-<uid>-XXXXXXX*/
  sscanf(txn, "%*[^-]-%*[^-]-%[^-]-", conn_id);
  *conn_id_ptr = atoi(conn_id);

  fprintf(stderr, "\n%s:%d conn_id_ptr %d\n", __FILE__, __LINE__, *conn_id_ptr);
  session = uidai_get_session(pUidaiCtx->session, *conn_id_ptr);
  assert(session != NULL);
  fprintf(stderr, "\n%s:%d session->req_type %s\n", __FILE__, __LINE__,session->req_type);

  if(!strncmp(session->req_type, "otp", 3)) {
    /*Build otp Response*/
    otp_process_rsp(param_ptr, rsp_ptr, rsp_len);
    /*Add the subtype in response*/
    sprintf(&(*rsp_ptr)[*rsp_len],
            "%s%s%s%s",
            "&ip=",
            session->ip_str,
            "&name=",
            session->uid_name);

    *rsp_len = strlen(*rsp_ptr);

  } else if(!strncmp(session->req_type, "auth", 4)) {
    /*Build auth Response*/
  }

  return(0);  
}/*uidai_build_ext_rsp*/

int32_t uidai_parse_uidai_rsp(int32_t conn_fd, 
                              uint8_t *packet_ptr, 
                              uint32_t chunked_starts_at, 
                              uint32_t chunked_len,
                              uint8_t *param_ptr) {

  uint8_t *chunked_ptr = NULL;
  uint8_t *tmp_ptr = NULL;
  uint8_t first_line[512];
  uint8_t *token_ptr = NULL;
  char *save_ptr;
  uint8_t attr_name[64];
  uint8_t attr_value[512];
  uint32_t idx = 0;
  /*number of columns can be modified internally if need be*/
  uint8_t (*param)[1024] = (uint8_t (*)[1024])param_ptr;

  memset((void *)first_line, 0, sizeof(first_line));

  chunked_ptr = (uint8_t *)malloc(chunked_len);
  assert(chunked_ptr != NULL);

  memset((void *)chunked_ptr, 0, chunked_len);
  memcpy((void *)chunked_ptr, (void *)&packet_ptr[chunked_starts_at], chunked_len);

  /*The delimeter is space*/
  tmp_ptr = chunked_ptr;
  token_ptr = strtok_r(tmp_ptr, " ", &save_ptr);

  /*Start of the response*/
  while((token_ptr = strtok_r(NULL, " ", &save_ptr))) {
    strncpy(param[idx], token_ptr, sizeof(param[idx])); 
    idx++; 
  }

  param[idx][0] = '\0';
  free(chunked_ptr);

  return(0);
}/*uidai_parse_uidai_rsp*/

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
                                uint32_t *conn_id) {

  uint8_t *tmp_ptr = NULL;
  uint8_t *line_ptr = NULL;
  /*response body starts at*/
  uint32_t offset = 0;
  uint8_t is_response_chunked = 0;
  uint32_t chunked_len = 0;
  uint8_t hex_str[8];
  /*pointer to an whole array of 255 character*/
  uint8_t *param_ptr;
  uint32_t param_count;
  uint8_t status[8];
  uint32_t status_code;
  uint8_t proto[12];
  char *save_ptr;
  
  tmp_ptr = (uint8_t *)malloc(packet_len);
  memset((void *)tmp_ptr, 0, packet_len);
  memcpy((void *)tmp_ptr, packet_ptr, packet_len);

  /*Parse the Response*/
  line_ptr = strtok_r(tmp_ptr, "\n", &save_ptr);
  /*Extract the status code & status string*/
  memset((void *)status, 0, sizeof(status));
  memset((void *)proto, 0, sizeof(proto));
  status_code = 0;
  /*HTTP/1.1 200 OK*/
  sscanf(line_ptr, "%s%d%s",proto, (int32_t *)&status_code, status);
  /*Request was success*/
  if((!strncmp(status, "OK", 2)) && (200 == status_code)) {

    while(line_ptr) {

      /*+1 because of \r in each line*/
      offset += strlen((const char *)line_ptr) + 1;
      if(!strncmp(line_ptr, "\r",1)) {
        offset += 1;
        line_ptr = strtok_r(NULL, "\n", &save_ptr);
        offset += strlen((const char *)line_ptr);
        break;

      } else if(!strncmp(line_ptr, "Transfer-Encoding: chunked", 26)) {
        /*Response received in chunked*/
        is_response_chunked = 1;

      } else if(!strncmp(line_ptr, "Content-Length:", 15)) {
        /*Response is not chunked*/
        fprintf(stderr, "\nResponse is non-chunked\n");
        is_response_chunked = 0;
        sscanf(line_ptr, "%*[^:]: %d", &chunked_len);
      }

      /*flushing the previous contents*/
      line_ptr = NULL;
      line_ptr = strtok_r(NULL, "\n", &save_ptr);
    }

    if(is_response_chunked) {
      /*Get the chunked length*/
      memset((void *)hex_str, 0, sizeof(hex_str));
      snprintf(hex_str, sizeof(hex_str), "0x%s", line_ptr);
      sscanf((const char *)hex_str, "%x", &chunked_len);

      /*Allocate memory for param_ptr*/
      param_ptr = (uint8_t *)malloc(sizeof(uint8_t) * 16/*rows*/ * 1024/*columns*/);
      assert(param_ptr != NULL);
      memset((void *)param_ptr, 0, (sizeof(uint8_t) * 16 * 1024));

      /*Parse the first chunked and store them in param*/
      uidai_parse_uidai_rsp(conn_fd, 
                            packet_ptr, 
                            offset, 
                            chunked_len, 
                            param_ptr);

      for(offset = 0; param_ptr[offset]; offset++) {
        //fprintf(stderr, "\n%s:%d Array %s\n",__FILE__, __LINE__, (param_ptr + (offset * 1024)));
      }

      /*Prepare Response*/
      uidai_build_ext_rsp(param_ptr, rsp_ptr, rsp_len, conn_id);
      /*de-allocate the memory*/
      free(param_ptr);
    }
  }

  free(tmp_ptr);
  return(0);
}/*uidai_process_uidai_rsp*/

int32_t uidai_add_session(uidai_session_t **head, uint32_t conn_fd) {
  uidai_session_t *curr = *head;
  uidai_session_t *new = (uidai_session_t *)malloc(sizeof(uidai_session_t));

  assert(new != NULL);
  memset((void *)new, 0, sizeof(uidai_session_t));
  new->conn_id = conn_fd;
  new->next = NULL;

  if(!curr) {
    (*head) = new;
    return(0);
  }

  while(curr->next) {
    curr = curr->next;
  }

  curr->next = new;

  return(0);
}/*uidai_add_session*/

uidai_session_t *uidai_get_session(uidai_session_t *session, uint32_t conn_id) {

  if(session && (conn_id == session->conn_id)) {
    return(session);

  } else if(!session) {
    return(NULL);

  } else {
    return(uidai_get_session(session->next, conn_id));

  }
}/*uidai_get_session*/

int32_t uidai_set_fd(uidai_session_t *session, fd_set *rd) {

  while(session) {
    FD_SET(session->conn_id, rd);
    session = session->next;
  }

  return(0);
}/*uidai_set_fd*/

uint32_t uidai_get_max_fd(uidai_session_t *session) {
  uint32_t max_fd = 0;

  while(session) {
    max_fd = (max_fd > session->conn_id) ? max_fd: session->conn_id;
    session = session->next;
  }

  return(max_fd);
}/*uidai_get_max_fd*/

/**
 * @brief This function removes the matched node from the linked list if
 *        Elements are repeated.
 */
int32_t uidai_remove_session(uint32_t conn_id) {
  uidai_ctx_t *pUidaiCtx = &uidai_ctx_g;
  uidai_session_t *prev = NULL;
  uidai_session_t *curr = pUidaiCtx->session;
  uidai_session_t *next = NULL;

  if(!curr) {
    /*The list is empty, nothing to be removed*/
    return(0);
  }

  /*Element to be deleted at begining*/
  if(curr && !curr->next) {
    /*only one node*/
    if(conn_id == curr->conn_id) {
      /*Delete the head*/
      free(pUidaiCtx->session);
      pUidaiCtx->session = NULL;
    }
  }

  /*Element to be deleted in middle*/
  while(curr && curr->next) {
    if(conn_id == curr->conn_id) {
      /*Got the conn_id and it is to be removed*/
      prev->next = curr->next;
      free(curr);
      return(0);
    }
    prev = curr;
    curr = curr->next;
  }
  
  /*element is found at last node*/
  if(curr && !curr->next) {
    if(conn_id == curr->conn_id) {
      prev->next = NULL;
      free(curr);
    } 
   
  }

  return(0);
}/*redir_remove_session*/

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
                                    uint32_t packet_len) {
  uint8_t *tmp_ptr = NULL;
  uint8_t *line_ptr = NULL;
  uint8_t is_response_chunked = 0;
  uint16_t payload_len = 0;
  uint8_t is_end_chunked = 0;
  char *save_ptr;
  uidai_ctx_t *pUidaiCtx = &uidai_ctx_g;

  if(!packet_len) {
    /*connection has been closed*/
    return(0);
  }

  tmp_ptr = (uint8_t *)malloc(packet_len);
  assert(tmp_ptr != NULL);
  memset((void *)tmp_ptr, 0, packet_len);
  memcpy((void *)tmp_ptr, packet_ptr, packet_len);

  /*Parse the Response*/
  line_ptr = strtok_r(tmp_ptr, "\r\n", &save_ptr);
  while(line_ptr != NULL) {

    if(is_response_chunked) {
      if(!strncmp(line_ptr, "0",1)) {
        /*Whole chunked received*/
        is_end_chunked = 1;
      }

    } else if(!strncmp(line_ptr, "Transfer-Encoding: chunked", 26)) {
      /*Response received in chunked*/
      is_response_chunked = 1;

    } else if(!strncmp(line_ptr, "Content-Length:", 15)) {
      /*Response is not chunked*/
      fprintf(stderr, "\nResponse is non-chunked\n");
      is_response_chunked = 0;
      sscanf(line_ptr, "Content-Length: %d", (int32_t *)&payload_len);
    }

    line_ptr = NULL;
    line_ptr = strtok_r(NULL, "\r\n", &save_ptr);
  }

  if(is_response_chunked && is_end_chunked) {
    /*Complete chuncked received*/
    free(tmp_ptr);
    return(0);
  }

  free(tmp_ptr);
  /*wait for end of chunked*/
  return(1);
}/*uidai_pre_process_uidai_rsp*/


int32_t uidai_process_req(int32_t conn_fd, 
                          uint8_t *packet_ptr, 
                          uint32_t packet_len) {
  uint8_t *req_type;
  uint8_t *uid_ptr;
  uint8_t *ext_conn_id_ptr;
  uint8_t *conn_id_ptr;
  uint8_t *ip_ptr;
  uint8_t *name_ptr;
  uint8_t *subtype_ptr;
  uint8_t *rsp_ptr = NULL;
  uint32_t rsp_len = 0;

  uidai_ctx_t *pUidaiCtx = &uidai_ctx_g;
  uidai_session_t *session = NULL;

  session = uidai_get_session(pUidaiCtx->session, (uint32_t)conn_fd);
  assert(session != NULL);

  req_type = uidai_get_param(packet_ptr, "type");
  uid_ptr = uidai_get_param(packet_ptr, "uid");
  ext_conn_id_ptr = uidai_get_param(packet_ptr, "ext_conn_id");
  conn_id_ptr = uidai_get_param(packet_ptr, "conn_id");
  ip_ptr = uidai_get_param(packet_ptr, "ip");
  name_ptr = uidai_get_param(packet_ptr, "name");
  
  session->uam_conn_id = atoi(ext_conn_id_ptr);
  session->redir_conn_id = atoi(conn_id_ptr);
  memset((void *)session->ip_str, 0, sizeof(session->ip_str));
  strncpy(session->ip_str, ip_ptr, sizeof(session->ip_str));
  
  memset((void *)session->uid_name, 0, sizeof(session->uid_name));
  strncpy(session->uid_name, name_ptr, sizeof(session->uid_name));

  memset((void *)session->uid, 0, sizeof(session->uid));
  strncpy(session->uid, uid_ptr, sizeof(session->uid));
  memset((void *)session->req_type, 0, sizeof(session->req_type));
  strncpy(session->req_type, req_type, sizeof(session->req_type));

  if(!strncmp(req_type, "otp", 3)) {
    otp_main(conn_fd, packet_ptr, packet_len, &rsp_ptr, &rsp_len);

  } else if(!strncmp(req_type, "auth", 4)) {
    subtype_ptr = uidai_get_param(packet_ptr, "subtype");
    memset((void *)session->req_subtype, 0, sizeof(session->req_subtype));
    strncpy(session->req_subtype, subtype_ptr, sizeof(session->req_subtype));
    free(subtype_ptr);
    /*Process Auth Request*/

  } else {
    /*Request Type is not supported*/
    fprintf(stderr, "\n%s:%d Incorrect Request Type\n", __FILE__, __LINE__);
  }

  if(rsp_len) {
    if(pUidaiCtx->uidai_fd < 0) {
      /*Connect to uidai server*/
      uidai_connect_uidai();
    }

    fprintf(stderr, "\n%s:%d xml Request is \n%s", __FILE__, __LINE__, rsp_ptr);
    uidai_send(pUidaiCtx->uidai_fd, rsp_ptr, rsp_len);
    free(rsp_ptr);
    rsp_ptr = NULL;
  }

  free(req_type);
  free(uid_ptr);
  free(ext_conn_id_ptr);
  free(ip_ptr);
  free(conn_id_ptr);
  free(name_ptr);
  return(0);
}/*uidai_process_req*/


int32_t uidai_recv(int32_t conn_fd, 
                   uint8_t *packet_ptr, 
                   uint32_t *packet_len,
                   int32_t flags) {
  int32_t ret = -1;

  if(!packet_ptr) {
    *packet_len = 0;
  }

  ret = recv(conn_fd, packet_ptr, *packet_len, flags);

  if(ret > 0) {
    *packet_len = (uint32_t)ret;
  } else if(ret <= 0) {
    *packet_len = 0;
  }

  return(0);
}/*uidai_recv*/

int32_t uidai_send(int32_t conn_fd, 
                   uint8_t *packet_ptr, 
                   uint32_t packet_len) {
  uint16_t offset = 0;
  int32_t ret = -1;

  do {
    ret = send(conn_fd, 
               (const void *)&packet_ptr[offset], 
               (packet_len - offset), 
               0);
    
    if(ret > 0) {
      offset += ret;
      
      if(!(packet_len - offset)) {
        ret = 0;
      }

    } else {
      fprintf(stderr, "\n%s:%d send failed\n", __FILE__, __LINE__);
      perror("send Failed");
      break;
    }

  }while(ret);

  return(ret);
}/*uidai_send*/

int32_t uidai_connect_uidai(void) {
  struct hostent *he;
  struct in_addr **addr_list;
  int32_t i;
  uidai_ctx_t *pUidaiCtx = &uidai_ctx_g;
  struct sockaddr_in uidai_addr;
  socklen_t addr_len;
  int32_t fd;
  int32_t ret = -1;
  uint8_t ip_str[32];
  uint8_t ip[4];

  memset((void *)ip_str, 0, sizeof(ip_str));
  if(!(he = gethostbyname(pUidaiCtx->uidai_host_name))) {
    /*get the host info*/
    fprintf(stderr, "gethostbyname is returning an error\n");
    return (-1);
  }

  addr_list = (struct in_addr **) he->h_addr_list;

  for(i = 0; addr_list[i] != NULL; i++) {
    strcpy(ip_str ,inet_ntoa(*addr_list[i]));
    fprintf(stderr, "\n%s:%d uidai ip address %s\n",
                     __FILE__,
                     __LINE__,
                     ip_str);
    break;
  }
  
  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if(fd < 0) {
    fprintf(stderr, "\n%s:%d socket creation failed\n",
                    __FILE__,
                    __LINE__);
    return(-2);
  }

  sscanf((const char *)ip_str, 
         "%d.%d.%d.%d", 
         (int32_t *)&ip[0],
         (int32_t *)&ip[1],
         (int32_t *)&ip[2],
         (int32_t *)&ip[3]);

  uidai_addr.sin_family = AF_INET;
  uidai_addr.sin_port = htons(pUidaiCtx->uidai_port);

  uidai_addr.sin_addr.s_addr = htonl((ip[0] << 24 | 
                                ip[1] << 16 | 
                                ip[2] <<  8 | 
                                ip[3]));

  fprintf(stderr, "\n%s:%d uidai ip address %s\n",
                   __FILE__,
                   __LINE__,
                   ip_str);

  memset((void *)uidai_addr.sin_zero, 0, sizeof(uidai_addr.sin_zero));
  addr_len = sizeof(uidai_addr);

  ret = connect(fd, (struct sockaddr *)&uidai_addr, addr_len);

  if(ret < 0) {
    fprintf(stderr, "\n%s:%d connection with uidai failed\n",
                    __FILE__,
                    __LINE__);
    return(-3);
  }

  pUidaiCtx->uidai_fd = fd;

  return (0);
}/*uidai_connect_uidai*/

int32_t uidai_init_ex(uint8_t *ip_addr, 
                      uint32_t port, 
                      uint8_t *uidai_host, 
                      uint32_t uidai_port) {
  int32_t fd;
  struct sockaddr_in addr;
  size_t addr_len = sizeof(addr);
  uidai_ctx_t *pUidaiCtx = &uidai_ctx_g;

  if(pUidaiCtx->fd) {
    /*IP address is already bound to socket*/
    return(0);
  }

  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if(fd < 0) {
    fprintf(stderr, "\n%s:%d Creation of Socket failed\n", 
                    __FILE__, 
                    __LINE__);
    return(-1);
  }
  
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(ip_addr);

  memset((void *)addr.sin_zero, 0, sizeof(addr.sin_zero));
 
  if(bind(fd, (struct sockaddr *)&addr, addr_len)) {
    fprintf(stderr, "\n%s:%d bind failed\n", __FILE__, __LINE__);
    return(-2);
  }

  listen(fd, 5/*number of simultaneous connection*/);
  pUidaiCtx->fd = fd;
  pUidaiCtx->port = port;
  pUidaiCtx->ip = addr.sin_addr.s_addr;

  memset((void *)pUidaiCtx->uidai_host_name, 0, sizeof(pUidaiCtx->uidai_host_name));
  strncpy(pUidaiCtx->uidai_host_name, uidai_host, sizeof(pUidaiCtx->uidai_host_name));

  pUidaiCtx->uidai_port = uidai_port;
  pUidaiCtx->uidai_fd = -1;

  return(0);
}/*uidai_init_ex*/


int32_t uidai_init(uint32_t ip_addr, 
                   uint32_t port, 
                   uint8_t *uidai_host, 
                   uint32_t uidai_port,
                   uint8_t *ac,
                   uint8_t *sa,
                   uint8_t *lk,
                   uint8_t *public_fname,
                   uint8_t *private_fname) {
  int32_t fd;
  struct sockaddr_in addr;
  size_t addr_len = sizeof(addr);
  uidai_ctx_t *pUidaiCtx = &uidai_ctx_g;

  pUidaiCtx->session = NULL; 
  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if(fd < 0) {
    fprintf(stderr, "\n%s:%d Creation of Socket failed\n", 
                    __FILE__, 
                    __LINE__);
    return(-1);
  }
  
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(ip_addr);

  memset((void *)addr.sin_zero, 0, sizeof(addr.sin_zero));
 
  if(bind(fd, (struct sockaddr *)&addr, addr_len)) {
    fprintf(stderr, "\n%s:%d bind failed\n", __FILE__, __LINE__);
    return(-2);
  }

  listen(fd, 5/*number of simultaneous connection*/);
  pUidaiCtx->fd = fd;
  pUidaiCtx->port = port;
  pUidaiCtx->ip = ip_addr;

  memset((void *)pUidaiCtx->uidai_host_name, 0, sizeof(pUidaiCtx->uidai_host_name));
  strncpy(pUidaiCtx->uidai_host_name, uidai_host, strlen(uidai_host));

  pUidaiCtx->uidai_port = uidai_port;
  pUidaiCtx->uidai_fd = -1;

  memset((void *)pUidaiCtx->public_fname, 0, sizeof(pUidaiCtx->public_fname));
  strncpy(pUidaiCtx->public_fname, public_fname, strlen(public_fname));

  memset((void *)pUidaiCtx->private_fname, 0, sizeof(pUidaiCtx->private_fname));
  strncpy(pUidaiCtx->private_fname, private_fname, strlen(private_fname));

  util_init(pUidaiCtx->public_fname,
            pUidaiCtx->private_fname,
            "public");

  otp_init(ac, 
           sa, 
           lk, 
           "1.6", 
           "developer.uidai.gov.in");

  auth_init(ac, 
            sa, 
            lk, 
            pUidaiCtx->private_fname, 
            pUidaiCtx->public_fname, 
            "developer.uidai.gov.in",
            "/uidauth1.6",
            "1.6",
            "public",
            "DemoAuth",
            "public");

  return(0);
}/*uidai_init*/

void *uidai_main(void *tid) {
  int32_t ret = -1;
  fd_set rd;
  int32_t max_fd = 0;
  struct timeval to;
  uint8_t *buffer= NULL;
  uidai_ctx_t *pUidaiCtx = &uidai_ctx_g;
  uint32_t buffer_len;
  int32_t connected_fd = -1;
  uint8_t wait_for_more_data = 0;
  struct sockaddr_in peer_addr;
  socklen_t addr_len = sizeof(peer_addr);
  uidai_session_t *session = NULL;

  FD_ZERO(&rd);
  buffer_len = 5500;
  buffer = (uint8_t *)malloc(buffer_len);
  assert(buffer != NULL);

  for(;;) {
    to.tv_sec = 2;
    to.tv_usec = 0;

    uidai_remove_session((uint32_t)0);
    uidai_set_fd(pUidaiCtx->session, &rd);
    max_fd = uidai_get_max_fd(pUidaiCtx->session);

    /*listening fd for request from Access COntroller*/
    FD_SET(pUidaiCtx->fd, &rd);
    max_fd = max_fd > pUidaiCtx->fd ?max_fd: pUidaiCtx->fd;

    if(pUidaiCtx->uidai_fd > 0) {
      FD_SET(pUidaiCtx->uidai_fd, &rd);
      max_fd = max_fd > pUidaiCtx->uidai_fd? max_fd: pUidaiCtx->uidai_fd;
    }

    max_fd += 1;
    ret = select(max_fd, &rd, NULL, NULL, &to);

    if(ret > 0) {
      if(FD_ISSET(pUidaiCtx->fd, &rd)) {
        /*New Connection*/
        connected_fd = accept(pUidaiCtx->fd, 
                             (struct sockaddr *)&peer_addr, 
                             &addr_len);
        uidai_add_session(&pUidaiCtx->session, connected_fd);
      }

      for(session = pUidaiCtx->session; session; session = session->next) { 
        if((session->conn_id > 0) && FD_ISSET(session->conn_id, &rd)) {
          /*Request received from Access Controller /NAS*/
          memset((void *)buffer, 0, 5500);
          buffer_len = 5500;
          uidai_recv(session->conn_id, buffer, &buffer_len, 0);

          if(buffer_len) {
            fprintf(stderr, "\n%s:%d received for uidai Server %s\n", __FILE__, __LINE__, buffer);
            uidai_process_req(session->conn_id, buffer, buffer_len);
          } else {
            session->conn_id = 0;
          }
        }
      } 

      if((pUidaiCtx->uidai_fd > 0) && (FD_ISSET(pUidaiCtx->uidai_fd, &rd))) { 
        /*Response UIDAI Server*/
        do {
          memset((void *)buffer, 0, 5500);
          buffer_len = 5500;
          uidai_recv(pUidaiCtx->uidai_fd, buffer, &buffer_len, MSG_PEEK);
          wait_for_more_data = uidai_pre_process_uidai_rsp(pUidaiCtx->uidai_fd, 
                                                           buffer, 
                                                           buffer_len);
        }while(wait_for_more_data);

        if(buffer_len) {
          uint8_t *rsp_ptr = NULL;
          uint32_t rsp_len = 0;
          uint32_t conn_id = 0;

          memset((void *)buffer, 0, 3500);
          buffer_len = 3500;
          uidai_recv(pUidaiCtx->uidai_fd, 
                     buffer, 
                     &buffer_len, 
                     0);
          fprintf(stderr, "\n%s:%d Response from UIDAI is %s\n", __FILE__, __LINE__, buffer);
          uidai_process_uidai_rsp(pUidaiCtx->uidai_fd, 
                                  buffer, 
                                  buffer_len, 
                                  &rsp_ptr, 
                                  &rsp_len,
                                  &conn_id);

          if(rsp_len) {
            fprintf(stderr, "\n%s:%d response sent to NAS/ACC %s\n", __FILE__, __LINE__, rsp_ptr);
            uidai_send(conn_id, rsp_ptr, rsp_len);
            free(rsp_ptr);
          }

        } else if(!buffer_len) {
          /*connection has been closed*/
          close(pUidaiCtx->uidai_fd);
          pUidaiCtx->uidai_fd = -1;
          fprintf(stderr, "\n%s:%d Connection is being closed\n", __FILE__, __LINE__);
        }
      }
    }
  }

  return(0);
}/*uidai_main*/

/**
 * @brief This function parses the attribute for a given argument 
 *
 * @param in_ptr is the pointer to the received request from gui
 * @param in_len is the length of the received request
 * @param rsp_fd is the file descriptor on which response is sent to gui
 *
 * @return it returns 0 if entire response is received else returns 1
 */
uint8_t *uidai_get_attr(uint8_t *req_ptr, 
                        const uint8_t *p_name) {

  uint8_t *tmp_req_ptr = NULL;
  uint8_t *line_ptr = NULL;
  uint8_t param_name[32];
  uint8_t *param_value = NULL;
  uint8_t flag = 0;
  char *save_ptr;
  uint32_t req_len = strlen(req_ptr);

  tmp_req_ptr = (uint8_t *) malloc(sizeof(uint8_t) * req_len);
  assert(tmp_req_ptr != NULL);
  memset((void *)tmp_req_ptr, 0, (sizeof(uint8_t) * req_len));

  param_value = (uint8_t *)malloc(sizeof(uint8_t) * 1024);
  assert(param_value != NULL);

  sscanf(req_ptr, "{%[^}]}", tmp_req_ptr);
  line_ptr = strtok_r(tmp_req_ptr, ",", &save_ptr);

  while(line_ptr) {
    memset((void *)param_value, 0, (sizeof(uint8_t) * 1024));
    memset((void *)param_name, 0, sizeof(param_name));
    sscanf(line_ptr, "%[^=]=%s", param_name, param_value);

    if(!strncmp(param_name, p_name, (sizeof(param_name) - 1))) {
      //fprintf(stderr, "param_name %s param_value %s\n", param_name, param_value);
      flag = 1;
      break;      
    }

    line_ptr = strtok_r(NULL, ",", &save_ptr);
  }

  free(tmp_req_ptr);

  if(flag) {
    return(param_value);
  }

  return(NULL);
}/*uidai_get_attr*/

/**
 * @brief This function parses the request received from gui 
 *
 * @param in_ptr is the pointer to the received request from gui
 * @param in_len is the length of the received request
 * @param rsp_fd is the file descriptor on which response is sent to gui
 *
 * @return it returns 0 if entire response is received else returns 1
 */
uint8_t *uidai_parse_req(uint8_t *in_ptr, uint32_t in_len, int32_t rsp_fd) {

  uint8_t *arg_ptr[256];
  uint8_t *auth_attr[32];
  uint8_t *uses_attr[32];
  uint8_t *tkn_attr[8];
  uint8_t *meta_attr[32];
  uint32_t len = 0;
  uint32_t idx = 0;
  uint32_t offset = 0;
  uint16_t version = 0;
  uint8_t *rsp_ptr = NULL;
  uint8_t *crypto_attr[4];
  uint8_t *uidai_attr[4];
  uint8_t *uidai = NULL;
  uint8_t *crypto = NULL;
  uint8_t *tmp_ptr = NULL;

  arg_ptr[0]  = uidai_get_param(in_ptr, "request");

  if(!strncmp(arg_ptr[0], "otp", 3)) {
    arg_ptr[1]  = uidai_get_param(in_ptr, "otp");

  } else if(!strncmp(arg_ptr[0], "auth", 4)) {
    arg_ptr[1]  = uidai_get_param(in_ptr, "auth");

  } else if(!strncmp(arg_ptr[0], "ekyc", 4)) {
    arg_ptr[1]  = uidai_get_param(in_ptr, "kyc");

  } else {
    fprintf(stderr, "%s:%d Invalid Request %s\n", __FILE__, __LINE__,arg_ptr[0]);
  }
  offset = 2;

  /*Process auth attribute*/
  auth_attr[0] = uidai_get_attr(arg_ptr[1], "ver");

  if(!strncmp(auth_attr[0], "1.6", 3)) {
    /*version 1.6*/
    version = 16;
  } else if(!strncmp(auth_attr[0], "2.0", 3)) {
    /*version 2.0*/
    version = 20;
  } else if(!strncmp(auth_attr[0], "2.5", 3)) {
    /*version 2.5*/
    version = 25;
  }

  free(auth_attr[0]);
  auth_attr[0] = NULL;

  uidai = uidai_get_param(in_ptr, "uidai");
  uidai_attr[0] = uidai_get_attr(uidai, "host");
  free(uidai);
  uidai = NULL;
  uidai_init_ex("192.168.1.6", 8080, uidai_attr[0], 80);
  free(uidai_attr[0]);
  uidai_attr[0] = NULL;

  crypto = uidai_get_param(in_ptr, "crypto");
  crypto_attr[0] = uidai_get_attr(crypto, "public");
  crypto_attr[1] = uidai_get_attr(crypto, "private");
  crypto_attr[2] = uidai_get_attr(crypto, "password");
  free(crypto);
  crypto = NULL;

  util_init(crypto_attr[0], crypto_attr[1], crypto_attr[2]);
  free(crypto_attr[0]);
  free(crypto_attr[1]);
  free(crypto_attr[2]);
  
  if(!strncmp(arg_ptr[0], "auth", 4)) {
    /*auth_request*/
    rsp_ptr = auth_main_ex(in_ptr, in_len, version, rsp_fd);

  } else if(!strncmp(arg_ptr[0], "otp", 3)) {
    /*otp request*/
    rsp_ptr = otp_main_ex(in_ptr, in_len, version, &len);

  } else if(!strncmp(arg_ptr[0], "ekyc", 4)) {
    /*ekyc request*/
    rsp_ptr = ekyc_main_ex(in_ptr, in_len, version, rsp_fd);
  }

  for(idx = 0; idx < offset; idx++) {
    free(arg_ptr[idx]);
  }

  return(rsp_ptr);
}/*uidai_parse_req*/

/**
 * @brief This function spawns the gui whose stdin and stdout is mapped
 * respectively. rd_fd[0] shall be used for receiving request
 * and wr_fd[1] shall be used to send response to gui/user
 *
 * @param rd_fd is the file descriptor on which request is received from gui.
 * @param wr_fd is the file descriptor on which response is sent to gui
 *
 * @return it returns 0 if entire response is received else returns 1
 */
int32_t uidai_spawn_gui(int32_t rd_fd[2], int32_t wr_fd[2]) {

  uint8_t *cmd = "wish";
  close(rd_fd[1]);
  close(wr_fd[0]);

  /*mapp stdin to rd_fd[0]*/
  if(dup2(rd_fd[0], 0) < 0) {
    perror("dup:rd_fd[0]:");
    return(0);
  }

  /*mapp stdout to wr_fd[1]*/
  if(dup2(wr_fd[1], 1) < 0) {
    close(rd_fd[0]);
    perror("dup:wr_fd[1]");
    return(0);
  }

  if(execlp(cmd, cmd, NULL) < 0) {
    close(wr_fd[1]);
    /*launching/instantiating of wish failed*/
    perror("execlp:");
    exit(0);
  }

  close(rd_fd[0]);
  close(wr_fd[1]);

  return(0);
}/*uidai_spawn_gui*/

uint8_t *uidai_chunked_rsp(int32_t fd, uint32_t *rsp_len) {
  uint8_t wait_for_more_data;
  uint8_t *buffer = NULL;
  uint32_t buffer_size = 5500;
  uint32_t buffer_len = 0;
  uint8_t status[8];

  memset((void *)status, 0, sizeof(status) * sizeof(uint8_t));
  /*Allocate the memory*/
  buffer = (uint8_t *)malloc(sizeof(uint8_t) * buffer_size);
  assert(buffer != NULL);

  /*Response UIDAI Server*/
  do {
    memset((void *)buffer, 0, buffer_size);
    buffer_len = buffer_size;
    uidai_recv(fd, buffer, &buffer_len, MSG_PEEK);
    sscanf(buffer, "%*s%s%*s", status);

    if(strncmp(status, "200", 3)) {
      fprintf(stderr, "\n%s:%d %s", __FILE__, __LINE__, buffer);
      free(buffer);
      buffer = NULL;
      buffer_len = 0;
      break;
    }

    wait_for_more_data = uidai_pre_process_uidai_rsp(fd, 
                                                     buffer, 
                                                     buffer_len);
  }while(wait_for_more_data);

  if(buffer_len) {
    memset((void *)buffer, 0, buffer_size);
    buffer_len = buffer_size;
    uidai_recv(fd, 
               buffer, 
               &buffer_len, 
               0);
  }

  *rsp_len = buffer_len;
  return(buffer);
}/*uidai_chunked_rsp*/

uint8_t *uidai_get_rsp_param(uint8_t *rsp, 
                             uint32_t rsp_len, 
                             uint8_t *attr) {

  uint8_t *param_ptr = NULL;
  uint8_t param_name[256];
  uint32_t len = 1024;
  uint8_t *tmp_rsp = NULL;
  char *save_ptr = NULL;
  uint8_t *token_ptr = NULL;
  int32_t ret = -1;
  uint32_t idx = 0;

  tmp_rsp = (uint8_t *)malloc(sizeof(uint8_t) * rsp_len);
  assert(tmp_rsp != NULL);
  memset((void *)tmp_rsp, 0, rsp_len);
  memcpy((void *)tmp_rsp, rsp, rsp_len);

  param_ptr = (uint8_t *)malloc(sizeof(uint8_t) * len);
  assert(param_ptr != NULL);
  memset((void *)param_ptr, 0, len);

  token_ptr = strtok_r(tmp_rsp, " ", &save_ptr);
  while(token_ptr) {

    memset((void *)param_name, 0, sizeof(param_name));
    ret = sscanf(token_ptr, "%[^=]=%*s", param_name);
    
    if((1 == ret) && !strncmp(param_name, attr, sizeof(param_name))) {
      free(tmp_rsp);
      tmp_rsp = NULL;
      /*+1 for =*/
      ret = strlen(param_name) + 1;

      while((' ' != token_ptr[ret]) && 
            ('>' != token_ptr[ret]) && 
            ('/' != token_ptr[ret])) {
        param_ptr[idx++] = token_ptr[ret++];
      }
      param_ptr[idx] = 0;

      return(param_ptr); 
    }

    token_ptr = strtok_r(NULL, " ", &save_ptr);
  }

  free(tmp_rsp);
  free(param_ptr);
  param_ptr = NULL;
  tmp_rsp = NULL;
  return(NULL);
}/*uidai_get_rsp_param*/

int32_t uidai_parse_rsp(uint8_t *rsp_ptr, 
                        uint32_t rsp_len, 
                        int32_t wr_fd) {
  uint8_t *attr_ptr[10];
  uint8_t *rsp = NULL;
  uint32_t rsp_size = 2000;
  uint32_t idx;
  uint32_t len = 0;
  int32_t ret = -1;

  rsp = (uint8_t *)malloc(sizeof(uint8_t) * rsp_size);
  assert(rsp != NULL);
  memset((void *)rsp, 0, rsp_size);

  /*Parsing of uidai response attribute/param*/
  attr_ptr[0] = uidai_get_rsp_param(rsp_ptr, rsp_len, "ret");

  if(!strncmp(attr_ptr[0], "y", 1)) {
    /*Response is success*/
    attr_ptr[1] = uidai_get_rsp_param(rsp_ptr, rsp_len, "code");
    attr_ptr[2] = uidai_get_rsp_param(rsp_ptr, rsp_len, "ts");
    attr_ptr[3] = uidai_get_rsp_param(rsp_ptr, rsp_len, "txn");
    attr_ptr[4] = uidai_get_rsp_param(rsp_ptr, rsp_len, "info");

    len = snprintf(rsp, rsp_size,
                   "%s%s%s%s%s"
                   "%s%s%s%s%s"
                   "%s",
                   "response_display_response ",
                   /*ret*/
                   attr_ptr[0],
                   " ",
                   /*err*/
                   "\"\"",
                   " ",
                   /*code*/
                   attr_ptr[1],
                   " ",
                   /*actn*/
                   "\"\"",
                   " ",
                   /*info*/
                   attr_ptr[4],
                   "\n");
          
    for(idx = 0; idx < 5; idx++) {

      if(attr_ptr[idx]) {
        free(attr_ptr[idx]);
        attr_ptr[idx] = NULL;
      }

    }

  } else {
    /*Response is failure*/
    attr_ptr[1] = uidai_get_rsp_param(rsp_ptr, rsp_len, "code");
    attr_ptr[2] = uidai_get_rsp_param(rsp_ptr, rsp_len, "ts");
    attr_ptr[3] = uidai_get_rsp_param(rsp_ptr, rsp_len, "txn");
    attr_ptr[4] = uidai_get_rsp_param(rsp_ptr, rsp_len, "info");
    attr_ptr[5] = uidai_get_rsp_param(rsp_ptr, rsp_len, "err");
    attr_ptr[6] = uidai_get_rsp_param(rsp_ptr, rsp_len, "actn");

    len = snprintf(rsp, rsp_size,
                   "%s%s%s%s%s"
                   "%s%s%s%s%s"
                   "%s",
                   "response_display_response ",
                   /*ret*/
                   attr_ptr[0],
                   " ",
                   /*err*/
                   attr_ptr[5],
                   " ",
                   /*code*/
                   attr_ptr[1],
                   " ",
                   /*actn*/
                   attr_ptr[6],
                   " ",
                   /*info*/
                   attr_ptr[4],
                   "\n");

    for(idx = 0; idx < 7; idx++) {

      if(attr_ptr[idx]) {
        free(attr_ptr[idx]);
        attr_ptr[idx] = NULL;
      }

    }
  }
  /*Sending Response to GUI*/
  ret = write(wr_fd, rsp, len);
  free(rsp);
  rsp = NULL;

  return(0);
}/*uidai_parse_rsp*/

/**
 * @brief This function processes the received request fro gui
 * and send to uidai server, rd_fd[0] shall be used for receiving request
 * and wr_fd[1] shall be used to send response to gui/user
 *
 * @param rd_fd is the file descriptor on which request is received from gui.
 * @param wr_fd is the file descriptor on which response is sent to gui
 * @param gui_name is the TK script name to be executed
 *
 * @return it returns 0 if entire response is received else returns 1
 */
int32_t uidai_process_gui_req(int32_t rd_fd[2], 
                              int32_t wr_fd[2], 
                              uint8_t *gui_name) {

  int32_t ret = -1;
  uint32_t len = (sizeof(uint8_t) * 1024);
  uint8_t *req_ptr = NULL;
  uint8_t *rsp_ptr = NULL;
  uint32_t rsp_len = 0;
  int32_t status = 0;
  uidai_ctx_t *pUidaiCtx = &uidai_ctx_g; 
  
  close(rd_fd[1]);
  close(wr_fd[0]);
  ret = write(wr_fd[1], gui_name, strlen(gui_name));

  if(ret < 0) {
    fprintf(stderr, "sending of gui name failed\n");
    perror("gui_name:");
    exit(0);
  }

  req_ptr = (uint8_t *)malloc(len);
  assert(req_ptr != NULL);
  
  for(;;) {
    /*Request has been received from gui, Process it*/
    memset((void *)req_ptr, 0, len);
    ret = read(rd_fd[0], req_ptr, len);
    
    if(ret > 0) {
      if(!strncmp(req_ptr, "Exit", 4)) {
        /*Child is going to exit*/
        ret = write(wr_fd[1], "exit\n", 5);
        raise(SIGCHLD);
        continue;
      }
    }   
 
    if(ret > 0) {
      ret = write(2, req_ptr, ret);
      rsp_ptr = uidai_parse_req(req_ptr, (uint32_t)ret, wr_fd[1]);
      /*send the packet*/
      if(pUidaiCtx->uidai_fd < 0) {
        uidai_connect_uidai();
      }

      uidai_send(pUidaiCtx->uidai_fd, rsp_ptr, strlen(rsp_ptr));
      free(rsp_ptr);
      rsp_ptr = NULL;

      /*Response from UIDAI*/
      rsp_ptr = uidai_chunked_rsp(pUidaiCtx->uidai_fd, &rsp_len);
      /*Closing the connection with uidai server*/
      close(pUidaiCtx->uidai_fd);
      pUidaiCtx->uidai_fd = -1;

      if(rsp_len) {
        /*Sending response to GUI*/
        fprintf(stderr, "\n%s\n", rsp_ptr); 
        uidai_parse_rsp(rsp_ptr, rsp_len, wr_fd[1]);
        free(rsp_ptr);
        rsp_ptr = NULL;
      }

    } else if(0 == ret) {
      close(rd_fd[0]);
      close(wr_fd[1]);
      /*Freeing Memory*/
      free(req_ptr);
      req_ptr = NULL;
      /*CHILD has exited*/
      exit(0);
    }
  }

  return(0);
}/*uidai_process_gui_req*/

void uidai_signal_handler(int signum, siginfo_t *sinfo, void *arg) {

  printf("\nsignal received is %d\n", signum);

  if(SIGCHLD == signum || 
     SIGSEGV == signum ||
     SIGINT  == signum) {
    /*Child task has terminated*/
    printf("\nsignal received is %d\n", signum);
    exit(0);
  }
}/*uidai_signal_handler*/

int32_t main(int32_t argc, char *argv[]) {

  uint8_t *gui_path = "set argv {../../gui}; source ../../gui/main.tk\n";
  int32_t rd_fd[2];
  int32_t wr_fd[2];
  pid_t gui_process;
  struct sigaction sa;
  struct sigaction oldsa;

  memset (&sa, 0, sizeof(sa));
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = uidai_signal_handler;

  if(pipe(rd_fd) < 0) {
    perror("pipe rd_fd");
    return(0);
  }

  if(pipe(wr_fd) < 0) {
    close(rd_fd[0]);
    close(rd_fd[1]);
    perror("pipe wr_fd");
    return(0);
  }


  gui_process = fork();
  if(gui_process < 0) {
    perror("fork failed");
    close(rd_fd[0]);
    close(rd_fd[1]);
    close(wr_fd[0]);
    close(wr_fd[1]);
    return(0);
 
  } else if(gui_process) {

    memset((void *)&uidai_ctx_g, 0, sizeof(uidai_ctx_g));
    /*Register the signal Handler*/    
    sigaction((SIGINT|SIGCHLD), &sa, &oldsa);
    /*Parent Process*/
    uidai_process_gui_req(wr_fd, rd_fd, gui_path);

  } else {
    /*child process*/
    uidai_spawn_gui(rd_fd, wr_fd);
  }
}/*main*/

#endif /* __UIDAI_C__ */
