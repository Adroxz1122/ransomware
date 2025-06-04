#define WIN32_NO_STATUS
#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#pragma comment(lib, "bcrypt.lib")

#define MAX_INPUT 2048
#define KEY_SIZE 512
#define IV_SIZE 256

typedef struct _AES
{
    PBYTE pPlainText;  
    DWORD dwPlainSize; 

    PBYTE pCipherText;  
    DWORD dwCipherSize; 

    PBYTE pKey; 
    PBYTE pIV;  
} AES, *PAES;

// Wrapper func for Install AesEncryptor that makes things easier
BOOL InstallAesEncryption(PAES pAes)
{
    BOOL bSTATE = TRUE;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKeyHandle = NULL;

    ULONG cbResult = 0;
    DWORD dwBlockSize = 0;

    DWORD cbKeyObject = 0; // nullto0
    PBYTE pbKeyObject = NULL;

    PBYTE pbCipherText = NULL;
    DWORD cbCipherText = 0; // nullto0

    NTSTATUS STATUS = 0;

    // Initializizng "hAlgorithm" as AES alg handle
    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!]BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }
    // getting the size of the key object variable pbKeyObject.
    // This is used by the BCRyptGenerateSymmeetricKey function later

    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // Getting the size of block used in AES
    // since this is AES it must be 16 bytes.

    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // Checking if the block size is 16 bytes
    if (dwBlockSize != 16)
    {
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // Allocating memory for the key object
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL)
    {
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // Setting block Cipher mode to CBC, This uses a 32 byte key and a 16 byte IV
    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // generating the key from AES key "pAes->pKey", the output will be saved in pbKeyObject and will be of size cbKeyObject
    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, 32, 0);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // Running BCryptEncrypt first time with NULL output parameters to retrieve the size of the output buffer
    // which is saved in cbCipherText
    STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIV, 16, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptEncrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // allocating enough memory for the output buffer, cbCipherText
    pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
    if (pbCipherText == NULL)
    {
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // Running BcryptEncrypt again with pbcipher text as the output buffer
    STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIV, 16, pbCipherText, cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptEncrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

// clean-up
_EndOfFunc:
    if (hKeyHandle)
    {
        BCryptDestroyKey(hKeyHandle);
    }
    if (hAlgorithm)
    {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }
    if (pbKeyObject)
    {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }
    if (pbCipherText != NULL && bSTATE)
    {
        pAes->pCipherText = pbCipherText;
        pAes->dwCipherSize = cbCipherText;
    }
    return bSTATE;
}

// The decryption implementation
BOOL InstallAesDecryption(PAES pAes)
{
    BOOL bSTATE = TRUE;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKeyHandle = NULL;

    ULONG cbResult = 0;
    DWORD dwBlockSize = 0;

    DWORD cbKeyObject = 0; // nullto0
    PBYTE pbKeyObject = NULL;

    PBYTE pbPlainText = NULL;
    DWORD cbPlainText = 0; // nullto0

    NTSTATUS STATUS = 0;

    // initializing halgorithm as AES algorithm
    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // Getting the size of the key object variable pbKeyObject, This is used by the BCryptGenerateSymmetricKey function later
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // Getting the size of the block used in the encryption. Since this is AES it should be 16 bytes.
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // checking if the block size is 16
    if (dwBlockSize != 16)
    {
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // allocating memory for the key object
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL)
    {
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // setting block cipher mode to CBC, this uses a 32 byte key and 16 byte IV
    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // generating key object from AES key "pAes->pKey".
    // output will be saved in pbkeyobject of size cbkeyobject
    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, 32, 0);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // running bcrypt first time with null output parameters to retrieve the size of the output buffer
    //  which is saved in cbPlaintext
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIV, 16, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // Allocating enough memory for the output buffer, cbPlainText
    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (pbPlainText == NULL)
    {
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // Running Bcryptdecrypt again with pbplaintext as the output buffer
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIV, 16, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

// clean-up
_EndOfFunc:
    if (hKeyHandle)
        BCryptDestroyKey(hKeyHandle);
    if (hAlgorithm)
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (pbKeyObject)
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbPlainText != NULL && bSTATE)
    {
        // if everything went well, we save pbPlainText and cbPlainText
        pAes->pPlainText = pbPlainText;
        pAes->dwPlainSize = cbPlainText;
    }
    return bSTATE;
}

BOOL SimpleEncryption(
    IN PVOID pPlainTextData,
    IN DWORD sPlainTextSize,
    IN PBYTE pKey,
    IN PBYTE pIV,
    OUT PVOID *pCipherTextData,
    OUT DWORD *sCipherTextSize)
{
    if (pPlainTextData == NULL || sPlainTextSize == 0 || pKey == NULL || pIV == NULL)
    {
        return FALSE;
    }
    // initializing the struct
    AES Aes = {
        .pKey = pKey,
        .pIV = pIV,
        .pPlainText = pPlainTextData,
        .dwPlainSize = sPlainTextSize};
    if (!InstallAesEncryption(&Aes))
    {
        return FALSE;
    }

    // saving output
    *pCipherTextData = Aes.pCipherText;
    *sCipherTextSize = Aes.dwCipherSize;

    return TRUE;
}

// Wrapper func for InstallAesDecryption that makes things easier
BOOL SimpleDecryption(
    IN PVOID pCipherTextData,
    IN DWORD sCipherTextSize,
    IN PBYTE pKey,
    IN PBYTE pIv,
    OUT PVOID *pPlainTextData,
    OUT DWORD *sPlainTextSize)
{
    if (pCipherTextData == NULL || sCipherTextSize == 0 || pKey == NULL || pIv == NULL)
    {
        return FALSE;
    }

    // initializing the struct again
    AES Aes = {
        .pKey = pKey,
        .pIV = pIv,
        .pCipherText = pCipherTextData,
        .dwCipherSize = sCipherTextSize};

    if (!InstallAesDecryption(&Aes))
    {
        return FALSE;
    }

    // output
    *pPlainTextData = Aes.pPlainText;
    *sPlainTextSize = Aes.dwPlainSize;

    return TRUE;
}

VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size)
{

    printf("unsigned char %s[] = {", Name);

    for (int i = 0; i < Size; i++)
    {
        if (i % 16 == 0)
            printf("\n\t");

        if (i < Size - 1)
        {
            printf("0x%0.2X, ", Data[i]);
        }
        else
        {
            printf("0x%0.2X ", Data[i]);
        }
    }

    printf("};\n\n\n");
}

// generate random bytes of size sSize
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize)
{
    for (int i = 0; i < sSize; i++)
    {
        pByte[i] = (BYTE)rand() % 0xFF;
    }
}

char *readlinedyncamic()
{
    size_t size = 64;
    size_t len = 0;
    char *buffer = malloc(size);
    if (!buffer)
        return NULL;

    int c;
    while ((c = getchar()) != '\n' && c != EOF)
    {
        if (len + 1 >= size)
        {
            size *= 2;
            char *temp = realloc(buffer, size);
            if (!temp)
            {
                free(buffer);
                return NULL;
            }
            buffer = temp;
        }
        buffer[len++] = (char)c;
    }

    buffer[len] = '\0';
    return buffer;
}

int main()
{
    BYTE pKey[32] = {0x1F, 0x82, 0xF2, 0xC5, 0x14, 0x41, 0x1E, 0x48, 0xB3, 0x29, 0x53, 0x24, 0xF6, 0x20, 0x70, 0x06, 0xE1, 0xE6, 0xC5, 0x53, 0x5B, 0x9B, 0x82, 0xC7, 0x3C, 0x82, 0x6F, 0x5C, 0xA7, 0x04, 0xDE, 0x6D};
    BYTE pIv[16] = {0xF5, 0xB1, 0xC8, 0xCE, 0x4A, 0xD9, 0x11, 0xEF, 0x39, 0x5E, 0xD6, 0xE7, 0xB9, 0xE2, 0x7E, 0x93};

    FILE *file = fopen("D:\\flag.txt", "rb");
    if (file == NULL)
    {
        perror("error opening file");
        return 1;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    char *file_data = malloc((size_t)file_size);
    FILE *outfile = fopen("D:\\flag.adrx", "wb");
    if (outfile == NULL)
    {
        perror("error in outfile");
        return 1;
    }
    if (!file_data)
    {
        perror("Memory allocation failed");
        fclose(file);
        fclose(outfile);
        return 1;
    }

    fread(file_data, 1, file_size, file);
    fclose(file);

    PVOID pCipherText = NULL;
    DWORD dwCipherSize = 0;

    if (!SimpleEncryption((PVOID)file_data, file_size, pKey, pIv, &pCipherText, &dwCipherSize))
    {
        fprintf(stderr, "Encryption failed.\n");
        free(file_data);
        fclose(outfile);
        return 1;
    }

    fwrite(pCipherText, 1, dwCipherSize, outfile);
    printf("[+] Encrypted data written to file.\n");

    PrintHexData("Ciphertext", pCipherText, dwCipherSize);

    // Del the og file
    if (remove("D:\\flag.txt") == 0)
    {
        printf("Original file deleted successfully.\n");
    }
    else
    {
        perror("Failed to delete original file");
    }

    // Cleanup
    free(file_data);
    HeapFree(GetProcessHeap(), 0, pCipherText);
    fclose(outfile);

    getchar();
    return 0;
}