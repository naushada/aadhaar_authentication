#ifndef __UIDAI_C__
#define __UIDAI_C__

#include "config.h"
#include "common.h"
#include "uidai.h"
#include "util.h"
#include "otp.h"
#include "auth.h"

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
    auth_process_rsp(param_ptr, rsp_ptr, rsp_len);
    /*Add the subtype in response*/
    sprintf(&(*rsp_ptr)[*rsp_len],
            "%s%s%s%s%s"
            "%s",
            "&subtype=",
            session->req_subtype,
            "&ip=",
            session->ip_str,
            "&name=",
            session->uid_name);

    *rsp_len = strlen(*rsp_ptr);
  }
  fprintf(stderr, "\n%s:%d auth rsp %s\n", __FILE__, __LINE__, *rsp_ptr);        

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
  //sscanf((const char *)&packet_ptr[chunked_starts_at], "%*[^\n]\r\n%[^\n]", chunked_ptr);
  memcpy((void *)chunked_ptr, (void *)&packet_ptr[chunked_starts_at], chunked_len);

  //fprintf(stderr, "\n%s:%d chunked data %s\n", __FILE__, __LINE__, chunked_ptr);
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
    auth_main(conn_fd, packet_ptr, packet_len, &rsp_ptr, &rsp_len);

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
            pUidaiCtx->private_fname);

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
            "developer.uidai.gov.in");

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
  buffer_len = 3500;
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
          memset((void *)buffer, 0, 3500);
          buffer_len = 3500;
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
          memset((void *)buffer, 0, 3500);
          buffer_len = 3500;
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


int32_t main(int32_t argc, char *argv[]) {


}/*main*/

#endif /* __UIDAI_C__ */
