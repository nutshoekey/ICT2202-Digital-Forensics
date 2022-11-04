#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <openssl/sha.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_fapi.h>

#define IMA_FILE "/sys/kernel/security/ima/ascii_runtime_measurements"

long long getIMAFileSize();
int getIMAFileContents(char *buffer);
void getSelfHash(char *argv[], char outputBuffer[65]);
void SHA256HashToString(unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65]);
int bytesToHex(uint8_t *buffer, uint size, char *out);
int compareHashes(const void *a, const void *b);
char *sortedMeasurements(FILE *file);

int main(int argc, char *argv[])
{
    printf("%s", "ICT2202 bonk!\n");
    seteuid(geteuid());

    char *imaFileContents = NULL;
    char *imaFileContentsCopy = NULL;
    long long fileSize = getIMAFileSize();
    imaFileContents = calloc(1, sizeof(char) * fileSize);
    imaFileContentsCopy = calloc(1, sizeof(char) * fileSize);
    getIMAFileContents(imaFileContents);
    strncpy(imaFileContentsCopy, imaFileContents, fileSize);
    // printf("%s", imaFileContents);

    printf("IMA File Size = %lli\n", fileSize);

    unsigned char hash[65];
    unsigned char buf[65];
    SHA256(imaFileContents, fileSize, hash);
    SHA256HashToString(hash, buf);

    unsigned char selfHash[65];
    getSelfHash(argv, selfHash);

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
        if(strncmp(filedata_hash, "sha256:", 7) == 0)
        {
            printf("%s\n", filedata_hash);
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
            printf("Excluded hash %s which is this program\n", selfHash);
        }
        else if(strncmp(filedata_hash, "sha256:", 7) == 0)
        {
            hashes[current] = calloc(1, sizeof(char) * 65);
            strncpy(hashes[current], hashOnly, 65);
            current += 1;
        }
        // printf("%d %s %s %s %s\n", pcr, template_hash, template, filedata_hash, filename_hint);
        // printf("hash only = %s\n", hashOnly);
    }

    for (int i = 0; i < length - 1; ++i)
    {
        printf("hash[%d]=%s\n", i, hashes[i]);
    }

    printf("length = %d\n", length);

    qsort(hashes, length - 1, sizeof(*hashes), compareHashes);

    for (int i = 0; i < length - 1; ++i)
    {
        printf("hash[%d]=%s\n", i, hashes[i]);
    }

    printf("length = %d\n", length);

    printf("hash = %s\n", buf);

    TSS2_RC result;

    /* Initialize the ESAPI context */
    ESYS_CONTEXT *ctx;
    result = Esys_Initialize(&ctx, NULL, NULL);

    if (result != TSS2_RC_SUCCESS)
    {
        printf("\nError: Esys_Initialize\n");
        exit(1);
    }

    uint32_t pcrUpdateCounter;
    int size;
    int i;
    int selectedPcr;
    TPML_PCR_SELECTION *pcrSelectionOut;
    TPML_DIGEST *pcrValues;
    char *tok;
    ssize_t num;
    TPML_PCR_SELECTION pcrSelectionIn;

    memset(&pcrSelectionIn, 0, sizeof(pcrSelectionIn));
    pcrSelectionIn.count = 1;
    pcrSelectionIn.pcrSelections[0].hash = TPM2_ALG_SHA256;
    pcrSelectionIn.pcrSelections[0].sizeofSelect = 3;
    pcrSelectionIn.pcrSelections[0].pcrSelect[10 / 8] |= 1 << (10 % 8);
    int rval = Esys_PCR_Read(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                             &pcrSelectionIn, &pcrUpdateCounter, &pcrSelectionOut, &pcrValues);
    /* Get random data */
    // TPM2B_DIGEST *
    // random_bytes;
    // result = Esys_GetRandom(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 20,
    //                         &random_bytes);

    if (rval != TSS2_RC_SUCCESS)
    {
        printf("\nError: Esys_PCR_Read\n %d", rval);
        exit(1);
    }

    printf("\n");
    for (int i = 0; i < pcrValues->count; i++)
    {
        for (int k = 0; k < pcrValues->digests[i].size; k++)
        {
            printf("%02x", pcrValues->digests[i].buffer[k]);
        }
        printf("\n");
    }
    printf("\n");

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

int bytesToHex(uint8_t *buffer, uint size, char *out)
{
    int i = 0;
    int bytesWritten = 0;
    for (i = 0; i < size; i++)
    {
        bytesWritten += snprintf(out, 3, "%02x", buffer[i]);
    }
    return bytesWritten;
}

int compareHashes(const void *a, const void *b)
{
    const char *arg1 = *(const char **)a;
    const char *arg2 = *(const char **)b;
    return strncmp(arg1, arg2, 65);
}
