/***************************************************************************
 *                                  _   _ ____  _
 *                             ___| | | |  _ \| |
 *                            / __| | | | |_) | |
 *                           | (__| |_| |  _ <| |___
 *                            \___|\___/|_| \_\_____|
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
#include "mime.h"

#if !defined(CURL_DISABLE_MIME) && (!defined(CURL_DISABLE_HTTP) || \
    !defined(CURL_DISABLE_SMTP) || !defined(CURL_DISABLE_IMAP))

/* DEBIAN-CVE-2026-92391: a deeply nested multipart MIME structure built
   through the public API must not exhaust the stack during cleanup.
   curl_mime_free() releases nested subparts iteratively, so freeing an
   arbitrarily deep chain must simply work. The depth here far exceeds
   what any recursive cleanup could survive on a default 8MB stack. */
#define T4783_DEPTH 100000

static CURLcode t4783_setup(void)
{
  CURLcode result = CURLE_OK;
  global_init(CURL_GLOBAL_ALL);
  return result;
}

static void t4783_stop(CURL *easy, curl_mime *mime)
{
  curl_mime_free(mime);
  if(easy)
    curl_easy_cleanup(easy);
  curl_global_cleanup();
}

static CURLcode test_unit4783(const char *arg)
{
  CURL *easy = NULL;
  curl_mime *top = NULL;
  curl_mime *mime = NULL;
  curl_mimepart *leaf;
  size_t i;

  UNITTEST_BEGIN(t4783_setup())

  easy = curl_easy_init();
  abort_unless(easy, "curl_easy_init()");
  top = curl_mime_init(easy);
  abort_unless(top, "curl_mime_init()");
  mime = top;

  /* Chain single-part levels: each new submime hangs off the previous
     level's only part, using only the public API. */
  for(i = 0; i < T4783_DEPTH; i++) {
    curl_mimepart *part = curl_mime_addpart(mime);
    curl_mime *sub;
    abort_unless(part, "curl_mime_addpart()");
    sub = curl_mime_init(easy);
    abort_unless(sub, "curl_mime_init()");
    abort_unless(curl_mime_subparts(part, sub) == CURLE_OK,
                 "curl_mime_subparts()");
    mime = sub;
  }

  /* The innermost level carries a payload so the chain is non-empty. */
  leaf = curl_mime_addpart(mime);
  abort_unless(leaf, "leaf curl_mime_addpart()");
  abort_unless(curl_mime_data(leaf, "x", 1) == CURLE_OK,
               "leaf curl_mime_data()");

  /* Transfer-time header preparation refuses absurd depth instead of
     recursing into it. */
  fail_unless(Curl_mime_prepare_headers(easy, top->firstpart, NULL, NULL,
                                        MIMESTRATEGY_FORM) ==
              CURLE_TOO_LARGE,
              "deep nesting accepted by prepare_headers");

  /* Freeing the top handle must release the whole chain without
     crashing. */
  curl_mime_free(top);
  top = NULL;

  UNITTEST_END(t4783_stop(easy, top))
}

#else /* mime disabled */

static CURLcode test_unit4783(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  puts("nothing to do when mime is disabled");
  UNITTEST_END_SIMPLE
}

#endif
