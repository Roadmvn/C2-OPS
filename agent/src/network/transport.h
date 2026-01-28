/*
 * transport.h - Communication HTTP avec le C2
 *
 * Utilise WinHTTP pour les requêtes HTTP/HTTPS.
 */

#ifndef TRANSPORT_H
#define TRANSPORT_H

#include "../../include/common.h"
#include "../core/config.h"

/* Transport context */
typedef struct {
  HINTERNET session;    /* Handle de session WinHTTP */
  HINTERNET connection; /* Handle de connexion */
  char host[256];       /* Hostname du C2 */
  INTERNET_PORT port;   /* Port */
  bool use_https;       /* HTTPS ou HTTP */
  char user_agent[256]; /* User-Agent */
  bool initialized;     /* Initialisé ? */
} transport_ctx_t;

/* Prototypes */

/*
 * Initialise le transport.
 */
int transport_init(transport_ctx_t *ctx, agent_config_t *config);

/*
 * Envoie une requête POST et récupère la réponse.
 *
 * Params:
 *   ctx         - Contexte de transport
 *   path        - Chemin de l'URL (ex: "/api/checkin")
 *   data        - Données à envoyer (body)
 *   response    - Pointeur vers la réponse (alloué par la fonction)
 *   response_len- Taille de la réponse
 *
 * Retourne STATUS_SUCCESS ou un code d'erreur.
 * L'appelant doit libérer response avec free().
 */
int transport_post(transport_ctx_t *ctx, const char *path, const char *data,
                   char **response, size_t *response_len);

/*
 * Envoie une requête GET.
 */
int transport_get(transport_ctx_t *ctx, const char *path, char **response,
                  size_t *response_len);

/*
 * Ferme la connexion et libère les ressources.
 */
void transport_cleanup(transport_ctx_t *ctx);

#endif /* TRANSPORT_H */
