/*
 * strings.h - Manipulation de strings sécurisée
 *
 * Fonctions pour manipuler des strings de façon safe
 * et helper pour l'obfuscation.
 */

#ifndef STRINGS_H
#define STRINGS_H

#include "../../include/common.h"

/*
 * Concatène deux strings dans un nouveau buffer.
 * Le résultat doit être libéré par l'appelant.
 */
char *str_concat(const char *s1, const char *s2);

/*
 * Duplique une string.
 * Le résultat doit être libéré par l'appelant.
 */
char *str_dup(const char *s);

/*
 * Copie sécurisée avec troncation.
 * Garantit un null terminator.
 */
void str_copy(char *dest, size_t dest_size, const char *src);

/*
 * Compare deux strings de façon case-insensitive.
 */
int str_icmp(const char *s1, const char *s2);

/*
 * Vérifie si une string commence par un préfixe.
 */
bool str_starts_with(const char *str, const char *prefix);

/*
 * Vérifie si une string finit par un suffixe.
 */
bool str_ends_with(const char *str, const char *suffix);

/*
 * Convertit une string en int.
 * Retourne 0 si invalide.
 */
int str_to_int(const char *str);

/*
 * Convertit un int en string.
 * Le buffer doit faire au moins 12 caractères.
 */
void int_to_str(int value, char *buffer, size_t buffer_size);

/*
 * Wide string vers char string.
 * Le résultat doit être libéré par l'appelant.
 */
char *wstr_to_str(const wchar_t *wstr);

/*
 * Char string vers wide string.
 * Le résultat doit être libéré par l'appelant.
 */
wchar_t *str_to_wstr(const char *str);

/*
 * Hash d'une string (pour la comparaison rapide sans stocker la string).
 * Algorithme DJB2.
 */
uint32_t str_hash(const char *str);

/*
 * Hash d'une wide string.
 */
uint32_t wstr_hash(const wchar_t *wstr);

#endif /* STRINGS_H */
