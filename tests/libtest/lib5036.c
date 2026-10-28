/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "first.h"

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7f000001
#endif

/* TFTP opcodes, RFC 1350 */
#define T5036_OPCODE_RRQ 1
#define T5036_OPCODE_WRQ 2
#define T5036_OPCODE_DATA 3
#define T5036_OPCODE_ACK 4

/* A rogue TFTP server: it answers the opening request with a packet
   meant for the opposite transfer direction. A correct client must
   reject that with CURLE_TFTP_ILLEGAL. */
struct t5036_rogue {
  curl_socket_t sock;
  bool request_seen;
  bool rogue_sent;
  bool is_upload;
};

/* Upload payload served by the read callback */
static const char t5036_upload_data[] =
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

/* Discard downloaded bytes to keep test stdout clean */
static size_t t5036_write_cb(char *ptr, size_t size, size_t nmemb,
                             void *userp)
{
  (void)ptr;
  (void)userp;
  return size * nmemb;
}

/* Serve the upload payload once, then signal EOF */
static size_t t5036_read_cb(char *ptr, size_t size, size_t nmemb,
                            void *userp)
{
  size_t *sent = (size_t *)userp;
  size_t full = size * nmemb;
  size_t left = sizeof(t5036_upload_data) - 1 - *sent;
  size_t copy = full < left ? full : left;
  if(!copy)
    return 0;
  memcpy(ptr, t5036_upload_data + *sent, copy);
  *sent += copy;
  return copy;
}

/* Read one incoming packet; answer the first opening request with a
   wrong-direction packet and ignore everything after that. */
static void t5036_serve(struct t5036_rogue *rogue)
{
  unsigned char pkt[516];
  struct sockaddr_in from;
  curl_socklen_t fromlen = sizeof(from);
  unsigned short opcode;
  int n = (int)recvfrom(rogue->sock, (char *)pkt, sizeof(pkt), 0,
                        (struct sockaddr *)&from, &fromlen);
  if(n < 4)
    return;
  opcode = (unsigned short)(((unsigned short)pkt[0] << 8) | pkt[1]);
  if(opcode != T5036_OPCODE_RRQ && opcode != T5036_OPCODE_WRQ)
    return;
  rogue->request_seen = TRUE;
  if(rogue->rogue_sent)
    return;
  if(!rogue->is_upload && opcode == T5036_OPCODE_RRQ) {
    /* Answer a download with ACK: only valid when transmitting */
    unsigned char reply[] = { 0, T5036_OPCODE_ACK, 0, 0 };
    if(sendto(rogue->sock, (const char *)reply, sizeof(reply), 0,
              (struct sockaddr *)&from, fromlen) == (int)sizeof(reply))
      rogue->rogue_sent = TRUE;
  }
  else if(rogue->is_upload && opcode == T5036_OPCODE_WRQ) {
    /* Answer an upload with DATA: only valid when receiving */
    unsigned char reply[] = { 0, T5036_OPCODE_DATA, 0, 1,
                              'r', 'o', 'g', 'u', 'e' };
    if(sendto(rogue->sock, (const char *)reply, sizeof(reply), 0,
              (struct sockaddr *)&from, fromlen) == (int)sizeof(reply))
      rogue->rogue_sent = TRUE;
  }
}

/* Run one transfer against the rogue server and require the client
   to fail it with CURLE_TFTP_ILLEGAL. */
static CURLcode t5036_run(bool is_upload, const char *fname)
{
  CURL *curl = NULL;
  CURLM *multi = NULL;
  struct t5036_rogue rogue;
  struct sockaddr_in sa;
  curl_socklen_t salen = sizeof(sa);
  unsigned short port;
  char url[64];
  CURLcode result = CURLE_OK;
  int running = 0;
  time_t deadline;
  size_t sent = 0;
  bool global_inited = FALSE;

  memset(&rogue, 0, sizeof(rogue));
  rogue.is_upload = is_upload;
  rogue.sock = CURL_SOCKET(AF_INET, SOCK_DGRAM, 0);
  if(rogue.sock == CURL_SOCKET_BAD) {
    curl_mfprintf(stderr, "socket creation error\n");
    return TEST_ERR_MAJOR_BAD;
  }

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = 0;

  if(bind(rogue.sock, (struct sockaddr *)&sa, sizeof(sa))) {
    curl_mfprintf(stderr, "bind() failed\n");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  if(getsockname(rogue.sock, (struct sockaddr *)&sa, &salen)) {
    curl_mfprintf(stderr, "getsockname() failed\n");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  port = ntohs(sa.sin_port);
  curl_msnprintf(url, sizeof(url), "tftp://127.0.0.1:%hu/%s", port, fname);

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  global_inited = TRUE;

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  multi = curl_multi_init();
  if(!multi) {
    curl_mfprintf(stderr, "curl_multi_init() failed\n");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 15000L);
  if(is_upload) {
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE,
                     (long)sizeof(t5036_upload_data) - 1L);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, t5036_read_cb);
    curl_easy_setopt(curl, CURLOPT_READDATA, &sent);
  }
  else {
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, t5036_write_cb);
  }
  curl_multi_add_handle(multi, curl);

  deadline = time(NULL) + 60;
  do {
    CURLMcode mresult = curl_multi_perform(multi, &running);
    if(mresult) {
      curl_mfprintf(stderr, "curl_multi_perform() failed: %d\n",
                    (int)mresult);
      result = TEST_ERR_MULTI;
      goto test_cleanup;
    }
    if(running) {
      fd_set fds;
      struct timeval tv;
      FD_ZERO(&fds);
      FD_SET(rogue.sock, &fds);
      tv.tv_sec = 0;
      tv.tv_usec = 100000;
      if(select((int)rogue.sock + 1, &fds, NULL, NULL, &tv) > 0)
        t5036_serve(&rogue);
      if(time(NULL) > deadline) {
        curl_mfprintf(stderr, "transfer against rogue TFTP server "
                      "did not finish in time\n");
        result = TEST_ERR_BAD_TIMEOUT;
        goto test_cleanup;
      }
    }
  } while(running);

  {
    CURLMsg *msg;
    int left = 0;
    msg = curl_multi_info_read(multi, &left);
    if(msg && msg->msg == CURLMSG_DONE)
      result = msg->data.result;
    else {
      curl_mfprintf(stderr, "no transfer result message\n");
      result = TEST_ERR_FAILURE;
      goto test_cleanup;
    }
  }

  if(!rogue.request_seen || !rogue.rogue_sent) {
    curl_mfprintf(stderr, "rogue TFTP server never answered the %s\n",
                  is_upload ? "WRQ" : "RRQ");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  if(result != CURLE_TFTP_ILLEGAL) {
    curl_mfprintf(stderr, "wrong-direction opening packet for %s was "
                  "not rejected: expected CURLE_TFTP_ILLEGAL (%d), "
                  "got %d\n", is_upload ? "upload" : "download",
                  (int)CURLE_TFTP_ILLEGAL, (int)result);
    if(result == CURLE_OK)
      result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }
  result = CURLE_OK;

test_cleanup:
  if(multi) {
    if(curl)
      curl_multi_remove_handle(multi, curl);
    curl_multi_cleanup(multi);
  }
  curl_easy_cleanup(curl);
  if(global_inited)
    curl_global_cleanup();
  if(rogue.sock != CURL_SOCKET_BAD)
    sclose(rogue.sock);

  return result;
}

static CURLcode test_lib5036(const char *URL)
{
  CURLcode result;
  (void)URL;

  result = t5036_run(FALSE, "t5036-download");
  if(result)
    return result;
  result = t5036_run(TRUE, "t5036-upload");
  if(result)
    return result;

  curl_mprintf("TFTP wrong-direction opening packets rejected\n");
  return CURLE_OK;
}
