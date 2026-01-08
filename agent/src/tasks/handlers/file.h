/*
 * file.h - Opérations sur les fichiers
 */

#ifndef HANDLER_FILE_H
#define HANDLER_FILE_H

#include "../../../include/common.h"

/*
 * Retourne le répertoire de travail courant.
 */
int handler_file_pwd(char **output, size_t *len);

/*
 * Change de répertoire.
 */
int handler_file_cd(const char *path, char **output, size_t *len);

/*
 * Liste les fichiers d'un répertoire.
 */
int handler_file_ls(const char *path, char **output, size_t *len);

/*
 * Télécharge un fichier (lit son contenu).
 */
int handler_file_download(const char *path, uint8_t **data, size_t *len);

/*
 * Upload un fichier (écrit le contenu).
 */
int handler_file_upload(const char *path, const uint8_t *data, size_t len);

/*
 * Supprime un fichier.
 */
int handler_file_rm(const char *path);

/*
 * Crée un répertoire.
 */
int handler_file_mkdir(const char *path);

#endif /* HANDLER_FILE_H */
