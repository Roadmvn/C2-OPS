/*
 * profile.h - Support des profils malléables
 *
 * Les profils définissent comment le trafic HTTP est formaté
 * pour ressembler à du trafic légitime.
 */

#ifndef PROFILE_H
#define PROFILE_H

#include "../../include/common.h"

/* Malleable profile structure */
typedef struct {
  /* URIs pour les requêtes GET (récupération de tâches) */
  const char **get_uris;
  int get_uri_count;

  /* URIs pour les requêtes POST (envoi de résultats) */
  const char **post_uris;
  int post_uri_count;

  /* Headers HTTP à ajouter */
  const char **headers;
  int header_count;

  /* Données à ajouter avant/après le payload (pour le fake traffic) */
  const char *prepend;
  const char *append;

  /* User-Agent */
  const char *user_agent;

} malleable_profile_t;

/* Pre-defined profiles */

/* Profil par défaut - minimaliste */
extern const malleable_profile_t PROFILE_DEFAULT;

/* Profil jQuery - imite du trafic CDN */
extern const malleable_profile_t PROFILE_JQUERY;

/* Profil Microsoft - imite Windows Update */
extern const malleable_profile_t PROFILE_MICROSOFT;

/* Prototypes */

/*
 * Récupère le profil actif.
 */
const malleable_profile_t *profile_get_active(void);

/*
 * Définit le profil actif.
 */
void profile_set_active(const malleable_profile_t *profile);

/*
 * Sélectionne un URI GET aléatoire du profil.
 */
const char *profile_get_random_uri(void);

/*
 * Sélectionne un URI POST aléatoire du profil.
 */
const char *profile_post_random_uri(void);

/*
 * Transforme les données selon le profil (prepend/append).
 * Le résultat doit être libéré par l'appelant.
 */
char *profile_transform_data(const char *data);

/*
 * Inverse la transformation pour extraire les vraies données.
 * Le résultat doit être libéré par l'appelant.
 */
char *profile_untransform_data(const char *data, size_t len);

#endif /* PROFILE_H */
