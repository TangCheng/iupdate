#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "icrypt/md5.h"
#include "icrypt/rijndael-api-fst.h"
#include "firmware_pack.h"

static char g_aes_key[] = "50515253555657585A5B5C5D5F606162";

static void parse_version(int32_t ver, uint8_t* major, uint8_t * minor, uint8_t* revision) {
    ver = ver>>8;
    *revision = ver;
    ver = ver>>8;
    *minor = ver;
    ver = ver>>8;
    *major = ver;
}

static void print_version(int32_t version) {
    uint8_t major,minor,revision;
    parse_version(version, &major, &minor, &revision);
    printf("Version:%08x %d.%d.%d\n", version, major, minor, revision);
}

static void decode_data(char * buf, int32_t length) {
    int r;
    keyInstance keyInst;
    cipherInstance cipherInst;

    assert(buf);
    assert(length > 0);
    assert(length%AES_PAD_SIZE == 0);

    makeKey(&keyInst, DIR_DECRYPT, AES_KEY_SIZE, g_aes_key);

    r = cipherInit(&cipherInst, MODE_ECB, NULL);
    assert(r == TRUE);
    r = blockDecrypt(&cipherInst, &keyInst, (BYTE *)buf, length*8, (BYTE *)buf);
}

static void compute_md5(char * buf, int32_t length, char * md5) {
    MD5_CTX ctx;
    assert(buf);
    assert(md5);
    assert(length > 0);
    MD5_Init(&ctx);
    MD5_Update(&ctx, buf, length);
    MD5_Final((unsigned char*) md5, &ctx);
}

static int write_data(const char * filename, const char * buf, int32_t length) {
    FILE * pf;

    assert(filename && filename[0]);
    assert(buf);
    assert(length > 0);

    pf = fopen(filename, "wb");
    if (pf == NULL) {
        printf("ERROR: open file failed %s\n", filename);
        return FIRMWARE_PACK_ERR_FILE;
    } else {
        int32_t bytes_written;
        bytes_written = fwrite(buf, 1, length, pf);
        fclose(pf);

        return bytes_written == length ? FIRMWARE_PACK_OK:FIRMWARE_PACK_ERR_FILE;
    }
}

int extract_block(FILE * pf, const char * destdir, FirmwareBlock* block) {
    char * buf;
    int32_t bytes_read;
    int err;
    int ret = 0;
    char md5[MD5_SIZE];

    assert(pf != NULL);
    assert(block != NULL);

    if (block->length > MAX_BLOCK_SIZE){
        printf("ERROR:too large block length %d\n", block->length);
        return FIRMWARE_PACK_BAD_LENGTH;
    }
    buf =  (char*)malloc(block->length);
    if (buf == NULL){
        printf("ERROR:out of memory %s\n", __FUNCTION__);
        return FIRMWARE_PACK_OUT_MEM;
    }

    ret = FIRMWARE_PACK_OK;
    err = fseek(pf, block->offset, SEEK_SET);

    do {
        if (err != 0) {
            ret = FIRMWARE_PACK_ERR_FILE;
            printf("ERROR: fseek return %d, offset is %d\n", err, block->offset);
            break;
        }

        bytes_read = fread(buf, 1, block->length, pf);
        if (bytes_read != block->length) {
            ret = FIRMWARE_PACK_ERR_FILE;
            printf("ERROR: fread return failed expected %d by read %d\n", block->length, bytes_read);
            break;
        }

        decode_data(buf, block->length);
        compute_md5(buf, block->length, md5);
        if (memcmp(block->md5, md5, sizeof(md5)) != 0) {
            ret = FIRMWARE_PACK_BAD_MD5;
            printf("ERROR: md5 check failed\n");
            break;
        }

		char *fname = NULL;
		if (destdir)
			asprintf(&fname, "%s/%s", destdir, block->name);
		else
			asprintf(&fname, "./%s", block->name);

		if (fname) {
			ret = write_data(fname, buf, block->length - block->tail);
			printf("INFO: write %d bytes to %s\n", block->length - block->tail, block->name);
			free(fname);
		}
		else {
			printf("ERROR: out of memory.\n");
			ret = FIRMWARE_PACK_OUT_MEM;
		}

    } while (0);

    free(buf);

    return ret;
}

int firmware_pack_decode(const char * pack_file,
                         const char *destdir,
                         FirmwarePackHead* head)
{
    FILE * pf;
    int len;
    int ret;

    pf = fopen(pack_file, "rb");
    if (pf == NULL) {
        printf("open pack file failed %s\n", pack_file);
        return FIRMWARE_PACK_FAIL;
    }

    len = fread(head, 1, sizeof(*head), pf);
    if (len != sizeof(*head)) {
        printf("ERROR: read pack head failed %d\n", len);
        return FIRMWARE_PACK_BAD_HEAD;
    }

    ret = FIRMWARE_PACK_OK;
    do {
        int32_t file_len;
        int i;

        if (strncmp(head->magic, FIRMWARE_MAGIC, 4) != 0){
            printf("ERROR: bad head magic\n");
            ret = FIRMWARE_PACK_BAD_HEAD;
            break;
        }
        fseek(pf, 0, SEEK_END);
        file_len = ftell(pf);
        fseek(pf, 0, SEEK_SET);

        if (file_len != head->length) {
             printf("ERROR: length not match file_len:%d head.length:%d\n",
                    file_len, head->length);
            ret = FIRMWARE_PACK_BAD_LENGTH;
            break;
        }

        print_version(head->version);
        printf("length:%d\n", head->length);
        printf("notes:%s\n", head->notes);
        printf("block_count:%d\n", head->block_count);

        for (i = 0; i < head->block_count; ++i) {
            ret = extract_block(pf, destdir, &head->blocks[i]);
            if (ret != FIRMWARE_PACK_OK) {
                break;
            }
        }

    } while (0);

    fclose(pf);

    return ret;
}
