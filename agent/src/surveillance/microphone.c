#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <stdio.h>

// GUIDs nécessaires pour WASAPI (souvent non définis en C pur sans les bons headers C++)
// Pour MinGW/GCC, ils sont généralement dans libuuid.a mais parfois il faut les définir manuellement.
// CLSID_MMDeviceEnumerator
const CLSID CLSID_MMDeviceEnumerator_Local = {0xBCDE0395, 0xE52F, 0x467C, {0x8E, 0x3D, 0xC4, 0x57, 0x92, 0x91, 0x69, 0x2E}};
// IID_IMMDeviceEnumerator
const IID IID_IMMDeviceEnumerator_Local = {0xA95664D2, 0x9614, 0x4F35, {0xA7, 0x46, 0xDE, 0x8D, 0xB6, 0x36, 0x17, 0xE6}};
// IID_IAudioClient
const IID IID_IAudioClient_Local = {0x1CB9AD4C, 0xDBFA, 0x4c32, {0xB1, 0x78, 0xC2, 0xF5, 0x68, 0xA7, 0x03, 0xB2}};
// IID_IAudioCaptureClient
const IID IID_IAudioCaptureClient_Local = {0xC8ADBD64, 0xE71E, 0x48a0, {0xA4, 0xDE, 0x18, 0x5C, 0x39, 0x5C, 0xD3, 0x17}};

// KSDATAFORMAT_SUBTYPE_PCM {00000001-0000-0010-8000-00aa00389b71}
const GUID KSDATAFORMAT_SUBTYPE_PCM_Local = {0x00000001, 0x0000, 0x0010, {0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71}};

// KSDATAFORMAT_SUBTYPE_IEEE_FLOAT {00000003-0000-0010-8000-00aa00389b71}
const GUID KSDATAFORMAT_SUBTYPE_IEEE_FLOAT_Local = {0x00000003, 0x0000, 0x0010, {0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71}};

/* 
 * Structure d'en-tête WAV standard 
 */
typedef struct {
    char        ChunkID[4];     // "RIFF"
    DWORD       ChunkSize;      // Taille totale - 8
    char        Format[4];      // "WAVE"
    char        Subchunk1ID[4]; // "fmt "
    DWORD       Subchunk1Size;  // 16 for PCM
    WORD        AudioFormat;    // 1 for PCM
    WORD        NumChannels;
    DWORD       SampleRate;
    DWORD       ByteRate;       // SampleRate * NumChannels * BitsPerSample/8
    WORD        BlockAlign;     // NumChannels * BitsPerSample/8
    WORD        BitsPerSample;
    char        Subchunk2ID[4]; // "data"
    DWORD       Subchunk2Size;  // Taille des données
} WAVHeader;

typedef struct {
    BYTE* data;
    DWORD size;
    DWORD capacity;
} AudioBuffer;

void AudioBuffer_Init(AudioBuffer* ab) {
    ab->capacity = 1024 * 1024; // 1MB initial
    ab->data = (BYTE*)calloc(1, ab->capacity);
    ab->size = 0;
}

void AudioBuffer_Append(AudioBuffer* ab, BYTE* src, DWORD len) {
    if (ab->size + len > ab->capacity) {
        ab->capacity = (ab->size + len) * 2;
        ab->data = (BYTE*)realloc(ab->data, ab->capacity);
    }
    memcpy(ab->data + ab->size, src, len);
    ab->size += len;
}

void AudioBuffer_Free(AudioBuffer* ab) {
    if (ab->data) free(ab->data);
    ab->data = NULL;
    ab->size = 0;
}

/*
 * Capture Audio via WASAPI (Loopback ou Microphone)
 * Windows Vista+ requis.
 */
BYTE* Microphone_Record(int seconds, DWORD* outSize) {
    HRESULT hr;
    IMMDeviceEnumerator *pEnumerator = NULL;
    IMMDevice *pDevice = NULL;
    IAudioClient *pAudioClient = NULL;
    IAudioCaptureClient *pCaptureClient = NULL;
    WAVEFORMATEX *pwfx = NULL;
    BYTE *result = NULL;
    AudioBuffer ab;
    
    CoInitialize(NULL);
    AudioBuffer_Init(&ab);

    // 1. Get Device Enumerator
    hr = CoCreateInstance(&CLSID_MMDeviceEnumerator_Local, NULL, CLSCTX_ALL, &IID_IMMDeviceEnumerator_Local, (void**)&pEnumerator);
    if (FAILED(hr)) goto cleanup;

    // 2. Get Default Audio Endpoint (eCapture = Microphone, eConsole = Default Role)
    hr = pEnumerator->lpVtbl->GetDefaultAudioEndpoint(pEnumerator, eCapture, eConsole, &pDevice);
    if (FAILED(hr)) goto cleanup;

    // 3. Activate Audio Client
    hr = pDevice->lpVtbl->Activate(pDevice, &IID_IAudioClient_Local, CLSCTX_ALL, NULL, (void**)&pAudioClient);
    if (FAILED(hr)) goto cleanup;

    // 4. Get Mix Format
    hr = pAudioClient->lpVtbl->GetMixFormat(pAudioClient, &pwfx);
    if (FAILED(hr)) goto cleanup;

    // Force PCM if float is returned (WASAPI often returns IEEE_FLOAT)
    // NOTE: Pour simplifier, on essaie d'utiliser le format natif retourné par GetMixFormat
    // et on espère que c'est compatible. Sinon il faudrait faire une conversion.
    
    // 5. Initialize Audio Client
    // AUDCLNT_STREAMFLAGS_LOOPBACK could be used for system audio
    hr = pAudioClient->lpVtbl->Initialize(pAudioClient, AUDCLNT_SHAREMODE_SHARED, 0, 10000000, 0, pwfx, NULL);
    if (FAILED(hr)) goto cleanup;

    // 6. Get Capture Client
    hr = pAudioClient->lpVtbl->GetService(pAudioClient, &IID_IAudioCaptureClient_Local, (void**)&pCaptureClient);
    if (FAILED(hr)) goto cleanup;

    // 7. Start Recording
    hr = pAudioClient->lpVtbl->Start(pAudioClient);
    if (FAILED(hr)) goto cleanup;

    // 8. Capture Loop
    DWORD startTick = GetTickCount();
    UINT32 packetLength = 0;
    BYTE *pData;
    UINT32 numFramesAvailable;
    DWORD flags;

    // Laisser de l'espace pour le header WAV (44 bytes)
    AudioBuffer_Append(&ab, (BYTE[44]){0}, 44);

    while (GetTickCount() - startTick < (DWORD)(seconds * 1000)) {
        Sleep(10); // Eviter CPU burn
        
        hr = pCaptureClient->lpVtbl->GetNextPacketSize(pCaptureClient, &packetLength);
        if (FAILED(hr)) break;

        while (packetLength != 0) {
            hr = pCaptureClient->lpVtbl->GetBuffer(pCaptureClient, &pData, &numFramesAvailable, &flags, NULL, NULL);
            if (FAILED(hr)) break;

            if (flags & AUDCLNT_BUFFERFLAGS_SILENT) {
                // Silence : écrire des zéros
                DWORD bytes = numFramesAvailable * pwfx->nBlockAlign;
                BYTE* silence = (BYTE*)calloc(1, bytes);
                AudioBuffer_Append(&ab, silence, bytes);
                free(silence);
            } else {
                AudioBuffer_Append(&ab, pData, numFramesAvailable * pwfx->nBlockAlign);
            }

            hr = pCaptureClient->lpVtbl->ReleaseBuffer(pCaptureClient, numFramesAvailable);
            if (FAILED(hr)) break;
            
            hr = pCaptureClient->lpVtbl->GetNextPacketSize(pCaptureClient, &packetLength);
            if (FAILED(hr)) break;
        }
    }

    pAudioClient->lpVtbl->Stop(pAudioClient);

    // 9. Construct WAV Header
    WAVHeader header;
    memcpy(header.ChunkID, "RIFF", 4);
    header.ChunkSize = ab.size - 8;
    memcpy(header.Format, "WAVE", 4);
    
    memcpy(header.Subchunk1ID, "fmt ", 4);
    header.Subchunk1Size = 16;
    header.AudioFormat = pwfx->wFormatTag; // 1 = PCM, 3 = IEEE Float
    header.NumChannels = pwfx->nChannels;
    header.SampleRate = pwfx->nSamplesPerSec;
    header.ByteRate = pwfx->nAvgBytesPerSec;
    header.BlockAlign = pwfx->nBlockAlign;
    header.BitsPerSample = pwfx->wBitsPerSample; // 16 or 32

    // Si le format est EXTENSIBLE, il faut extraire les infos
    if (pwfx->wFormatTag == WAVE_FORMAT_EXTENSIBLE) {
        WAVEFORMATEXTENSIBLE* pExt = (WAVEFORMATEXTENSIBLE*)pwfx;
        if (IsEqualGUID(&pExt->SubFormat, &KSDATAFORMAT_SUBTYPE_PCM_Local)) {
             header.AudioFormat = 1;
        } else if (IsEqualGUID(&pExt->SubFormat, &KSDATAFORMAT_SUBTYPE_IEEE_FLOAT_Local)) {
             header.AudioFormat = 3; 
        }
    }

    memcpy(header.Subchunk2ID, "data", 4);
    header.Subchunk2Size = ab.size - 44;

    // Copier header au début buffer
    memcpy(ab.data, &header, sizeof(WAVHeader));
    
    // Result
    *outSize = ab.size;
    result = ab.data;
    
    // Note: ab.data est transféré à result, ne pas free ici
    // Mais on doit free pwfx
    CoTaskMemFree(pwfx);

cleanup:
    if (pCaptureClient) pCaptureClient->lpVtbl->Release(pCaptureClient);
    if (pAudioClient) pAudioClient->lpVtbl->Release(pAudioClient);
    if (pDevice) pDevice->lpVtbl->Release(pDevice);
    if (pEnumerator) pEnumerator->lpVtbl->Release(pEnumerator);
    CoUninitialize();

    return result; // L'appelant doit free(result)
}
