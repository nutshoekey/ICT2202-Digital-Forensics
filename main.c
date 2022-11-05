#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <openssl/sha.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_fapi.h>

#define IMA_FILE "/sys/kernel/security/ima/ascii_runtime_measurements"
#define TPM_CONTEXT_FILE "/context"
#define SEALING_PCR 16U

long long getIMAFileSize();
int getIMAFileContents(char *buffer);
void getSelfHash(char *argv[], char outputBuffer[65]);
void SHA256HashToString(unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65]);
int bytesToHex(uint8_t *buffer, uint size, char *out);
void hexToBytes(const char *restrict hexstr, uint8_t *restrict dst);
int checkContextExists();
int saveContext(ESYS_CONTEXT *esys_context, ESYS_TR esys_handle);
int openContext(ESYS_CONTEXT *esys_context, ESYS_TR *outHandle);
int deleteContext();
int compareHashes(const void *a, const void *b);

int main(int argc, char *argv[])
{
    printf("%s", "ICT2202 bonk!\n");
    if (getuid() != 0)
    {
        printf("%s", "Please run this program with superuser privileges.\n");
        exit(-1);
    }

    printf("TSS2_ESYS_RC_BAD_REFERENCE: %d\n", TSS2_ESYS_RC_BAD_REFERENCE);
    printf("TSS2_ESYS_RC_MEMORY: %d\n", TSS2_ESYS_RC_MEMORY);
    printf("TSS2_ESYS_RC_BAD_SEQUENCE: %d\n", TSS2_ESYS_RC_BAD_SEQUENCE);
    printf("TSS2_ESYS_RC_INSUFFICIENT_RESPONSE: %d\n", TSS2_ESYS_RC_INSUFFICIENT_RESPONSE);
    printf("TSS2_ESYS_RC_MULTIPLE_DECRYPT_SESSIONS: %d\n", TSS2_ESYS_RC_MULTIPLE_DECRYPT_SESSIONS);
    printf("TSS2_ESYS_RC_MULTIPLE_ENCRYPT_SESSIONS: %d\n", TSS2_ESYS_RC_MULTIPLE_ENCRYPT_SESSIONS);
    printf("TSS2_ESYS_RC_BAD_TR: %d\n", TSS2_ESYS_RC_BAD_TR);

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
            // printf("Excluded hash %s which is this program\n", selfHash);
        }
        else if (strncmp(filedata_hash, "sha256:", 7) == 0)
        {
            hashes[current] = calloc(1, sizeof(char) * 65);
            strncpy(hashes[current], hashOnly, 65);
            current += 1;
            // printf("%d %s %s %s %s\n", pcr, template_hash, template, filedata_hash, filename_hint);
        }
        // printf("hash only = %s\n", hashOnly);
    }

    // for (int i = 0; i < length - 1; ++i)
    //{
    //     printf("hash[%d]=%s\n", i, hashes[i]);
    // }

    // printf("length = %d\n", length);

    qsort(hashes, length - 1, sizeof(*hashes), compareHashes);

    // for (int i = 0; i < length - 1; ++i)
    //{
    //     printf("hash[%d]=%s\n", i, hashes[i]);
    // }

    printf("length = %d\n", length);

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

    if (checkContextExists())
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
            printf("Resetted PCR[%d]\n", pcrHandle_handle);
        }
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

    ESYS_TR primaryHandle = ESYS_TR_NONE;
    ESYS_TR loadedKeyHandle = ESYS_TR_NONE;

    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;

    TPM2B_PUBLIC *outPublic2 = NULL;
    TPM2B_PRIVATE *outPrivate2 = NULL;
    TPM2B_CREATION_DATA *creationData2 = NULL;
    TPM2B_DIGEST *creationHash2 = NULL;
    TPMT_TK_CREATION *creationTicket2 = NULL;
    TPM2B_SENSITIVE_DATA *outData = NULL;

    TPM2B_AUTH authValuePrimary = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}};

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                .size = 0,
                .buffer = {0},
            },
            .data = {
                .size = 0,
                .buffer = {0},
            },
        },
    };

    inSensitivePrimary.sensitive.userAuth = authValuePrimary;

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_RESTRICTED |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                .size = 0,
            },
            .parameters.rsaDetail = {
                .symmetric = {.algorithm = TPM2_ALG_AES, .keyBits.aes = 128, .mode.aes = TPM2_ALG_CFB},
                .scheme = {.scheme = TPM2_ALG_NULL},
                .keyBits = 2048,
                .exponent = 0,
            },
            .unique.rsa = {
                .size = 0,
                .buffer = {},
            },
        },
    };

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 1,
        .pcrSelections[0].hash = TPM2_ALG_SHA256,
        .pcrSelections[0].sizeofSelect = 3,
        .pcrSelections[0].pcrSelect[16 / 8] = 1 << (16 % 8),
    };

    TPM2B_AUTH authValue = {
        .size = 0,
        .buffer = {}};

    TPM2B_AUTH authKey2 = {
        .size = 6,
        .buffer = {6, 7, 8, 9, 10, 11}};

    TPM2B_SENSITIVE_CREATE inSensitive2 = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                .size = 0,
                .buffer = {0}},
            .data = {.size = 8, .buffer = {3, 2, 3, 2, 3, 2, 3, 2}}}};

    inSensitive2.sensitive.userAuth = authKey2;

    TPM2B_PUBLIC inPublic2 = {
        .size = 0,
        .publicArea = {
            /* type = TPM2_ALG_RSA, */
            .type = TPM2_ALG_KEYEDHASH,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 /* TPMA_OBJECT_RESTRICTED | */
                                 /* TPMA_OBJECT_DECRYPT | */
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT
                                 /* TPMA_OBJECT_SENSITIVEDATAORIGIN */
                                 ),

            .authPolicy = {
                .size = 0,
            },
            /*
            .parameters.rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES,
                    .keyBits.aes = 128,
                    .mode.aes = TPM2_ALG_CFB
                },
                .scheme = {
                    .scheme = TPM2_ALG_NULL,
                },
                .keyBits = 2048,
                .exponent = 0
            },
            .unique.rsa = {
                .size = 0,
                .buffer = {}
                ,
            }
            */
            .parameters.keyedHashDetail = {.scheme = {.scheme = TPM2_ALG_NULL, .details = {.hmac = {.hashAlg = TPM2_ALG_SHA256}}}},
            .unique.keyedHash = {
                .size = 0,
                .buffer = {},
            },
        }};

    TPM2B_DATA outsideInfo2 = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR2 = {
        .count = 1,
        .pcrSelections[0].hash = TPM2_ALG_SHA256,
        .pcrSelections[0].sizeofSelect = 3,
        .pcrSelections[0].pcrSelect[16 / 8] = 1 << (16 % 8),
    };

    TPM2B_DIGEST pcr_digest_16 = {
        .size = 32,
        .buffer = {}
    };

    TPML_DIGEST *pcrValues;

    Esys_PCR_Read(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                             &creationPCR, NULL, NULL, &pcrValues);

    if (!checkContextExists())
    {
        printf("%s", "Context does not exist.\n");
        r = Esys_TR_SetAuth(ctx, ESYS_TR_RH_OWNER, &authValue);
        if (r != TSS2_RC_SUCCESS)
        {
            printf("\nError: Esys_TR_SetAuth %d\n", r);
        }

        r = Esys_CreatePrimary(ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                               ESYS_TR_NONE, ESYS_TR_NONE,
                               &inSensitivePrimary, &inPublic,
                               &outsideInfo, &creationPCR, &primaryHandle,
                               &outPublic, &creationData, &creationHash,
                               &creationTicket);
        if (r != TSS2_RC_SUCCESS)
        {
            printf("\nError: Esys_CreatePrimary %d\n", r);
        }

        printf("primaryHandle = %d\n", primaryHandle);

        r = Esys_TR_SetAuth(ctx, primaryHandle, &authValuePrimary);
        if (r != TSS2_RC_SUCCESS)
        {
            printf("\nError: Esys_TR_SetAuth %d\n", r);
        }

        ESYS_TR session = ESYS_TR_NONE;

        TPM2_SE sessionType = TPM2_SE_HMAC;
        TPMI_ALG_HASH authHash = TPM2_ALG_SHA256;
        TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_NULL };

        r = Esys_StartAuthSession(ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                NULL,
                                sessionType, &symmetric, authHash, &session);
        if (r != TSS2_RC_SUCCESS)
        {
            printf("\nError: Esys_StartAuthSession %d\n", r);
        }

        r = Esys_PolicyPCR(ctx,
                       session,
                       ESYS_TR_NONE,
                       ESYS_TR_NONE,
                       ESYS_TR_NONE, &pcrValues->digests[0], &creationPCR);
        if (r != TSS2_RC_SUCCESS)
        {
            printf("\nError: Esys_PolicyPCR %d\n", r);
        }
        /*
         * 2. Create second key with sealed data
         */
        r = Esys_Create(ctx,
                        primaryHandle,
                        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                        &inSensitive2,
                        &inPublic2,
                        &outsideInfo2,
                        &creationPCR2,
                        &outPrivate2,
                        &outPublic2,
                        &creationData2, &creationHash2, &creationTicket2);
        if (r != TSS2_RC_SUCCESS)
        {
            printf("\nError: Esys_Create %d\n", r);
        }
        printf("Second key created.\n");
        /*
         * 3. Load second key
         */
        r = Esys_Load(ctx,
                      primaryHandle,
                      ESYS_TR_PASSWORD,
                      ESYS_TR_NONE,
                      ESYS_TR_NONE, outPrivate2, outPublic2, &loadedKeyHandle);
        if (r != TSS2_RC_SUCCESS)
        {
            printf("\nError: Esys_Load %d\n", r);
        }

        printf("\nSecond Key loaded.\n");

        r = Esys_TR_SetAuth(ctx, loadedKeyHandle, &authKey2);
        if (r != TSS2_RC_SUCCESS)
        {
            printf("\nError: Esys_TR_SetAuth %d\n", r);
        }
        saveContext(ctx, loadedKeyHandle);
    }
    else
    {
        ESYS_TR savedContext;
        ESYS_TR session = ESYS_TR_NONE;
        openContext(ctx, &savedContext);
        TPM2_SE sessionType = TPM2_SE_POLICY;
        TPMI_ALG_HASH authHash = TPM2_ALG_SHA256;
        TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_NULL };

        r = Esys_StartAuthSession(ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                NULL,
                                sessionType, &symmetric, authHash, &session);
        if (r != TSS2_RC_SUCCESS)
        {
            printf("\nError: Esys_StartAuthSession %d\n", r);
        }
        r = Esys_PolicyPCR(ctx,
                       session,
                       ESYS_TR_NONE,
                       ESYS_TR_NONE,
                       ESYS_TR_NONE, &pcrValues->digests[0], &creationPCR);
        /*
         * 4. Unseal key
         */

        r = Esys_Unseal(ctx, session, ESYS_TR_PASSWORD,
                        ESYS_TR_NONE, ESYS_TR_NONE, &outData);
        if (r != TSS2_RC_SUCCESS)
        {
            printf("\nError: Esys_Unseal %d\n", r);
        }

        deleteContext();
    }

    /*
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
    pcrSelectionIn.pcrSelections[0].pcrSelect[8 / 8] |= 1 << (8 % 8);
    int rval = Esys_PCR_Read(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                             &pcrSelectionIn, &pcrUpdateCounter, &pcrSelectionOut, &pcrValues);
    // Get random data
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
    */

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

int checkContextExists()
{
    FILE *fptr = NULL;
    int ret = 0;
    if ((fptr = fopen(TPM_CONTEXT_FILE, "rb")) == NULL)
    {
        ret = 0;
    }
    else
    {
        ret = 1;
    }
    free(fptr);
    return ret;
}

int saveContext(ESYS_CONTEXT *esys_context, ESYS_TR esys_handle)
{
    TSS2_RC r;
    size_t buffer_size;
    uint8_t *buffer;
    TPMS_CONTEXT *context;
    FILE *fptr = NULL;
    int ret = 0;
    if ((fptr = fopen(TPM_CONTEXT_FILE, "wb+")) == NULL)
    {
        printf("%s", "Error writing to context file\n");
        ret = 0;
    }
    else
    {
        r = Esys_ContextSave(esys_context, esys_handle, &context);
        // r = Esys_TR_Serialize(esys_context, esys_handle, &buffer, &buffer_size);
        if (r != TSS2_RC_SUCCESS)
        {
            printf("\nError: Esys_ContextSave %d\n", r);
            ret = 0;
        }
        else
        {
            fwrite(context, sizeof(*context), 1, fptr);
            ret = 1;
        }
    }
    // free(buffer);
    return ret;
}

int openContext(ESYS_CONTEXT *esys_context, ESYS_TR *outHandle)
{
    TSS2_RC r;
    size_t buffer_size;
    uint8_t *buffer;
    FILE *fptr = NULL;
    TPMS_CONTEXT *context = malloc(sizeof(*context));
    int ret;

    if ((fptr = fopen(TPM_CONTEXT_FILE, "rb")) == NULL)
    {
        printf("%s", "Error reading context file\n");
        ret = 0;
    }
    else
    {
        fseek(fptr, 0L, SEEK_END);
        buffer_size = ftell(fptr);
        fseek(fptr, 0L, SEEK_SET);
        buffer = malloc(buffer_size * sizeof(char));
        fread(context, buffer_size, 1, fptr);
        r = Esys_ContextLoad(esys_context, context, outHandle);
        if (r != TSS2_RC_SUCCESS)
        {
            printf("\nError: Esys_ContextLoad %d\n", r);
            ret = 0;
        }
        else
        {
            ret = 1;
        }
    }
    free(context);
    return ret;
}

int deleteContext()
{
    remove(TPM_CONTEXT_FILE);
    printf("%s", "Deleted context file.\n");
}

int compareHashes(const void *a, const void *b)
{
    const char *arg1 = *(const char **)a;
    const char *arg2 = *(const char **)b;
    return strncmp(arg1, arg2, 64);
}
