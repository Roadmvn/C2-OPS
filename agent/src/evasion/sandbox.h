/*
 * sandbox.h - Détection de sandbox et VM
 *
 * Détecte si on s'exécute dans un environnement d'analyse.
 */

#ifndef SANDBOX_H
#define SANDBOX_H

#include "../../include/common.h"

/*
 * Check complet pour détecter un environnement sandbox/VM.
 */
bool is_sandbox_environment(void);

/*
 * Check le nombre de CPUs - les VMs en ont souvent peu.
 */
bool check_cpu_count(void);

/*
 * Check la RAM - les VMs en ont souvent peu.
 */
bool check_ram_size(void);

/*
 * Check l'uptime - les sandboxes ont souvent un uptime très court.
 */
bool check_uptime(void);

/*
 * Check les adresses MAC pour détecter les VMs.
 */
bool check_vm_mac_address(void);

/*
 * Check les clés registry VMware/VirtualBox.
 */
bool check_vm_registry_keys(void);

/*
 * Check les fichiers/drivers de VM.
 */
bool check_vm_files(void);

/*
 * Check les noms de machine suspects.
 */
bool check_computer_name(void);

/*
 * Check la taille du disque - les VMs ont souvent des disques petits.
 */
bool check_disk_size(void);

/*
 * Check le nombre de process - un vrai PC a beaucoup de process.
 */
bool check_process_count(void);

/*
 * Vérifie des interactions utilisateur récentes (souris, clavier).
 */
bool check_user_interaction(void);

#endif /* SANDBOX_H */
