#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <openssl/sha.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_fapi.h>

#define UNPROVISIONED_STATE "0000000000000000000000000000000000000000000000000000000000000000"
#define IMA_FILE "/sys/kernel/security/ima/ascii_runtime_measurements"
#define TPM_CONTEXT_FILE "/context"
#define SEALING_PCR 16U

long long getIMAFileSize();
int getIMAFileContents(char *buffer);
void getSelfHash(char *argv[], char outputBuffer[65]);
void SHA256HashToString(unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65]);
void hexToBytes(const char *restrict hexstr, uint8_t *restrict dst);
void *checkPCR(ESYS_CONTEXT *esys_context, char* out);
int compareHashes(const void *a, const void *b);

int main(int argc, char *argv[])
{
    printf("%s", "ICT2202 bonk!\n");
    if (getuid() != 0)
    {
        printf("%s", "Please run this program with superuser privileges.\n");
        exit(-1);
    }

    unsigned char selfHash[65];
    getSelfHash(argv, selfHash);

    /* Initialize the ESAPI context */
    TSS2_RC result;
    ESYS_CONTEXT *ctx;
    result = Esys_Initialize(&ctx, NULL, NULL);
    if (result != TSS2_RC_SUCCESS)
    {
        printf("\nError: Esys_Initialize\n");
    }

    char *imaFileContents = NULL;
    char *imaFileContentsCopy = NULL;
    long long fileSize = getIMAFileSize();
    imaFileContents = calloc(1, sizeof(char) * fileSize);
    imaFileContentsCopy = calloc(1, sizeof(char) * fileSize);
    getIMAFileContents(imaFileContents);
    strncpy(imaFileContentsCopy, imaFileContents, fileSize);

    // printf("IMA File Size = %lli\n", fileSize);

    unsigned char hash[65];
    unsigned char buf[65];
    SHA256(imaFileContents, fileSize, hash);
    SHA256HashToString(hash, buf);

    int pcr;                  // PCR that IMA stores to
    char template_hash[41];   // template-hash: sha1 hash(filedata-hash length, filedata-hash, pathname length, pathname)
    char template[41];        // template: ima templates
    char filedata_hash[72];   // algorithm:hash
    char filename_hint[4096]; // filepath and name

    int length = 0;
    int current = 0;

    // PCR     template-hash                     template filedata-hash                                                           filename-hint
    // 10 a299b10283deb996899cea45cdb557cc570b442b ima-ng sha256:4a8d913f1cb21825816e398c55ee043a3ed6f19c5233c8a3dd6663fbc7c28961 boot_aggregate
    for (char *p = strtok(imaFileContentsCopy, "\n"); p != NULL; p = strtok(NULL, "\n"))
    {
        sscanf(p, "%d %s %s %s %s", &pcr, template_hash, template, filedata_hash, filename_hint);
        if (strncmp(filedata_hash, "sha256:", 7) == 0)
        {
            // printf("%s\n", filedata_hash);
            length += 1;
        }
    }

    char **hashes;
    hashes = calloc(length - 1, sizeof(char *));
    for (char *p = strtok(imaFileContents, "\n"); p != NULL; p = strtok(NULL, "\n"))
    {
        char hashOnly[65];
        sscanf(p, "%d %s %s %s %s", &pcr, template_hash, template, filedata_hash, filename_hint);
        strncpy(hashOnly, filedata_hash + 7, 65);
        if (!strncmp(hashOnly, selfHash, 65))
        {
        }
        else if (strncmp(filedata_hash, "sha256:", 7) == 0)
        {
            hashes[current] = calloc(1, sizeof(char) * 65);
            strncpy(hashes[current], hashOnly, 65);
            current += 1;
        }
    }


    qsort(hashes, length - 1, sizeof(*hashes), compareHashes);

    printf("hash = %s\n", buf);

    TSS2_RC r;
    ESYS_TR pcrHandle_handle = SEALING_PCR; // choose PCR[16], software resettable
    TPML_DIGEST_VALUES digests = {
        .count = 1,
        .digests = {
            {.hashAlg = TPM2_ALG_SHA256,
             .digest = {
                 .sha256 = {}}},
        }};
    int provision = 0;
    unsigned char pcrValue[65]; 
    checkPCR(ctx, pcrValue);

    if (strncmp(UNPROVISIONED_STATE, pcrValue, 65))
    {
        r = Esys_PCR_Reset(
            ctx,
            pcrHandle_handle,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE);
        if (r != TSS2_RC_SUCCESS)
        {
            printf("\nError: Esys_PCR_Reset %d\n", r);
        }
        else
        {
            printf("System was provisioned before, resetted PCR[%d]\n", pcrHandle_handle);
        }
    }
    else
    {
        provision = 1;
        printf("%s", "System was not provisioned before, provisioning now\n");
    }

    for (int i = 0; i < length - 1; ++i)
    {
        uint8_t hash[32];
        hexToBytes(hashes[i], hash);
        memcpy(digests.digests->digest.sha256, hash, 32);
        r = Esys_PCR_Extend(ctx, pcrHandle_handle, ESYS_TR_PASSWORD,
                            ESYS_TR_NONE, ESYS_TR_NONE, &digests);
        if (r != TSS2_RC_SUCCESS)
        {
            printf("\nError: Esys_PCR_Extend\n: %d\n", r);
        }
    }

    checkPCR(ctx, pcrValue);
    printf("PCR[%d] = %s\n", SEALING_PCR, pcrValue);

    // cleanup resources
    free(imaFileContents);
    free(imaFileContentsCopy);

    for (int i = 0; i < length - 1; ++i)
    {
        free(hashes[i]);
    }
    free(hashes);

    exit(0);
}

long long getIMAFileSize()
{
    FILE *fptr = NULL;
    long long fileSize = 0;
    if ((fptr = fopen(IMA_FILE, "rb")) == NULL)
    {
        printf("[-] An error ocurred while opening IMA runtime measurements.\n");
        fileSize = -1;
    }
    else
    {
        char c;
        c = fgetc(fptr);
        while (c != EOF)
        {
            fileSize += 1;
            c = fgetc(fptr);
        }
    }
    fclose(fptr);
    return fileSize;
}

int getIMAFileContents(char *buffer)
{
    FILE *fptr = NULL;
    if ((fptr = fopen(IMA_FILE, "rb")) == NULL)
    {
        printf("[-] An error ocurred while opening IMA runtime measurements.\n");
    }
    else
    {
        char c;
        c = fgetc(fptr);
        while (c != EOF)
        {
            strncat(buffer, &c, 1);
            c = fgetc(fptr);
        }
    }
    fclose(fptr);
}

void getSelfHash(char *argv[], char outputBuffer[65])
{
    FILE *fptr = NULL;
    unsigned char hash[65];
    if ((fptr = fopen(argv[0], "rb")) == NULL)
    {
        printf("[-] An error ocurred. Please run this program with the full path.\n");
    }
    else
    {
        fseek(fptr, 0L, SEEK_END);
        int size = ftell(fptr);
        fseek(fptr, 0L, SEEK_SET);
        unsigned char *contents = malloc(size);
        fread(contents, size, 1, fptr);
        SHA256(contents, size, hash);
        SHA256HashToString(hash, outputBuffer);
        printf("self hash = %s\n", outputBuffer);
        free(contents);
    }
    fclose(fptr);
}

void SHA256HashToString(unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65])
{
    int i = 0;

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }

    outputBuffer[64] = 0;
}

void hexToBytes(const char *restrict hexstr, uint8_t *restrict dst)
{
    static const uint_fast8_t LOOKUP[256] =
        {
            ['0'] = 0x0,
            ['1'] = 0x1,
            ['2'] = 0x2,
            ['3'] = 0x3,
            ['4'] = 0x4,
            ['5'] = 0x5,
            ['6'] = 0x6,
            ['7'] = 0x7,
            ['8'] = 0x8,
            ['9'] = 0x9,
            ['a'] = 0xA,
            ['b'] = 0xB,
            ['c'] = 0xC,
            ['d'] = 0xD,
            ['e'] = 0xE,
            ['f'] = 0xF,
            ['A'] = 0xA,
            ['B'] = 0xB,
            ['C'] = 0xC,
            ['D'] = 0xD,
            ['E'] = 0xE,
            ['F'] = 0xF,
        };

    for (size_t i = 0; hexstr[i] != '\0'; i += 2)
    {
        *dst = LOOKUP[hexstr[i]] << 4 |
               LOOKUP[hexstr[i + 1]];
        dst++;
    }
}

void *checkPCR(ESYS_CONTEXT *esys_context, char* out)
{
    TSS2_RC r;
    char *hash;
    TPML_DIGEST *digest;
    TPML_PCR_SELECTION pcrSelection = {
        .count = 1,
        .pcrSelections[0].hash = TPM2_ALG_SHA256,
        .pcrSelections[0].sizeofSelect = 3,
        .pcrSelections[0].pcrSelect[SEALING_PCR / 8] = 1 << (SEALING_PCR % 8),
    };
    r = Esys_PCR_Read(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                      &pcrSelection, NULL, NULL, &digest);
    if (r != TSS2_RC_SUCCESS)
    {
        printf("\nError: Esys_PCR_Read %d\n", r);
    }
    SHA256HashToString(digest->digests[0].buffer, out);
}

int compareHashes(const void *a, const void *b)
{
    const char *arg1 = *(const char **)a;
    const char *arg2 = *(const char **)b;
    return strncmp(arg1, arg2, 64);
}
