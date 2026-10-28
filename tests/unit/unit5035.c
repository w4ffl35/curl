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
#include "unitcheck.h"

#include "urldata.h"
#include "ftplistparser.h"
#include "ftp-int.h"

static CURLcode t5035_setup(struct Curl_easy **easy)
{
  CURLcode result = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);
  *easy = curl_easy_init();
  if(!*easy) {
    curl_global_cleanup();
    return CURLE_OUT_OF_MEMORY;
  }
  return result;
}

static void t5035_stop(struct Curl_easy *easy)
{
  struct WildcardData *wc = easy->wildcard;
  if(wc) {
    if(wc->ftpwc) {
      struct ftp_wc *ftpwc = wc->ftpwc;
      if(ftpwc->parser)
        Curl_ftp_parselist_data_free(&ftpwc->parser);
      curlx_free(ftpwc);
      wc->ftpwc = NULL;
    }
    Curl_wildcard_dtor(&easy->wildcard);
  }
  curl_easy_cleanup(easy);
  curl_global_cleanup();
}

static CURLcode test_unit5035(const char *arg)
{
  struct Curl_easy *easy = NULL;
  struct WildcardData *wc = NULL;
  struct ftp_wc *ftpwc = NULL;

  UNITTEST_BEGIN(t5035_setup(&easy))

  (void)arg;

  /* Simulate an easy handle with wildcard matching enabled. */
  easy->state.wildcardmatch = TRUE;
  easy->wildcard = curlx_calloc(1, sizeof(struct WildcardData));
  fail_unless(easy->wildcard, "wildcard alloc failed");
  wc = easy->wildcard;
  Curl_wildcard_init(wc);

  /* Normal listing: MATCHING with a live parser routes to the parser. */
  wc->state = CURLWC_MATCHING;
  ftpwc = curlx_calloc(1, sizeof(struct ftp_wc));
  fail_unless(ftpwc, "ftpwc alloc failed");
  ftpwc->parser = Curl_ftp_parselist_data_alloc();
  fail_unless(ftpwc->parser, "parser alloc failed");
  wc->ftpwc = ftpwc;
  wc->dtor = NULL;
  fail_unless(Curl_ftp_listmode(easy),
              "MATCHING with live parser must use listing parser");
  Curl_ftp_parselist_data_free(&ftpwc->parser);
  curlx_free(ftpwc);
  wc->ftpwc = NULL;

  /*
   * Failed LIST: the parser data is gone but the state was left in
   * MATCHING by the buggy path. The writer must fall back to the user
   * callback instead of the internal listing parser with dangling data.
   */
  wc->state = CURLWC_MATCHING;
  wc->ftpwc = NULL;
  fail_unless(!Curl_ftp_listmode(easy),
              "MATCHING without parser must not use listing parser");

  /* Non-listing states never use the parser. */
  wc->state = CURLWC_DOWNLOADING;
  fail_unless(!Curl_ftp_listmode(easy),
              "DOWNLOADING must not use listing parser");
  wc->state = CURLWC_ERROR;
  fail_unless(!Curl_ftp_listmode(easy),
              "ERROR must not use listing parser");

  UNITTEST_END(t5035_stop(easy))
}
