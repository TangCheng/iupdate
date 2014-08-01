#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "icrypt/md5.h"
#include "icrypt/rijndael-api-fst.h"
#include "firmware_pack.h"

static char g_aes_key[] = "50515253555657585A5B5C5D5F606162";

static char * load_file(const char* filename,  int pad, int32_t* length, int32_t * out_tail)
{
    char * buf = NULL;
    FILE* pf = NULL;

    assert(length != NULL);
    assert(filename != NULL);

    *length = 0;
    *out_tail = 0;
    pf = fopen(filename, "rb");
    if (pf == NULL)
    {
        printf("open file failed %s\n", filename);
    }
    else
    {
        int32_t len;
        fseek(pf, 0, SEEK_END);
        len = ftell(pf);
        fseek(pf, 0, SEEK_SET);

        if (len > 0)
        {
            int32_t bytes_read;
            int remain = len%pad;
            int tail = (pad - remain)%pad;

            buf = (char*) malloc(len + tail);
            assert(buf);

            bytes_read = fread(buf, 1, len, pf);
            if (bytes_read != len)
            {
                free(buf);
                buf = NULL;
                printf("fread failed read %d bytes but expect for %d\n", bytes_read, len);
            }
            else
            {
                if (tail > 0)
                {
                    memset(&buf[len],0, tail);
                }
                *length = len + tail;
                *out_tail = tail;
            }
        }
        fclose(pf);
    }
    return buf;
}

static void compute_md5(char * buf, int32_t length, char * md5)
{
    MD5_CTX ctx;

    assert(buf);
    assert(md5);
    assert(length > 0);

    MD5_Init(&ctx);
    MD5_Update(&ctx, buf, length);
    MD5_Final((unsigned char*) md5, &ctx);
}

static void encode_data(char * buf, int32_t length)
{
    int r;
    keyInstance keyInst;
    cipherInstance cipherInst;

    assert(buf);
    assert(length > 0);
    assert(length%AES_PAD_SIZE == 0);

    makeKey(&keyInst, DIR_ENCRYPT, AES_KEY_SIZE, g_aes_key);

    r = cipherInit(&cipherInst, MODE_ECB, NULL);
    assert(r == TRUE);
    r = blockEncrypt(&cipherInst, &keyInst, (BYTE *)buf, length*8, (BYTE *)buf);
}

static int load_block(const char * blockname,
                      const char * filename,
                      FirmwareBlockCtrl * block_ctrl)
{
    assert(blockname && filename);
    assert(block_ctrl);

    if (!blockname[0] || strlen(blockname) >= BLOCK_NAME_SIZE)
    {
        printf("ERROR: invalid block name %s\n", blockname);
        return 0;
    }

    block_ctrl->data = load_file(filename, AES_PAD_SIZE, &block_ctrl->block->length, &block_ctrl->block->tail);
    if (block_ctrl->data == NULL)
    {
        return 0;
    }

    strcpy(block_ctrl->block->name, blockname);
    compute_md5(block_ctrl->data, block_ctrl->block->length, block_ctrl->block->md5);
    encode_data(block_ctrl->data, block_ctrl->block->length);

    return 1;
}

static void free_block_ctrls(int block_count, FirmwareBlockCtrl * block_ctrls)
{
    int i;
    for (i = 0; i < block_count; ++i)
    {
        if (block_ctrls[i].data != NULL)
        {
            free(block_ctrls[i].data);
        }
    }
    free(block_ctrls);
}

int firmware_pack_encode(int32_t version,
                    int block_count,
                    const char ** block_names,
                    const char * notes,
                    const char * pack_file)
{
    int i;
    int32_t offset;
    FirmwarePackHead * head;
    FirmwareBlockCtrl * block_ctrls;
    FILE * fp;
    int ret = FIRMWARE_PACK_FAIL;

    assert(block_count > 0);
    assert(block_names != NULL);
    assert(pack_file != NULL && pack_file[0]);

    head = (FirmwarePackHead*)malloc(sizeof(*head));
    memset(head, 0, sizeof(*head));
    strncpy(head->magic, FIRMWARE_MAGIC, 4);
    head->version = version;
    head->block_count = block_count;
    if (notes)
    {
        strncpy(head->notes, notes, NOTES_SIZE - 1);
    }

    block_ctrls = (FirmwareBlockCtrl*)malloc(block_count * sizeof(*block_ctrls));
    memset(block_ctrls, 0, block_count * sizeof(*block_ctrls));

    offset = sizeof(*head);
    for (i = 0; i < block_count; ++i)
    {
        block_ctrls[i].block = &head->blocks[i];
        if (!load_block(block_names[i * 2], block_names[i * 2 + 1], &block_ctrls[i]))
        {
            free_block_ctrls(block_count, block_ctrls);
            free(head);
            return ret;
        }
        block_ctrls[i].block->offset = offset;
        offset +=  block_ctrls[i].block->length;
    }
    head->length = offset;

    fp = fopen(pack_file,"wb");
    if (fp == NULL)
    {
        printf("ERROR: create package file failed %s\n", pack_file);
    }
    else
    {
        fwrite(head, sizeof(*head), 1, fp);
        for (i = 0; i < block_count; ++i)
        {
            fwrite(block_ctrls[i].data, block_ctrls[i].block->length,1, fp);
            printf("INFO:package write %d bytes of block[%d] name:%s, pad:%d \n",
                   block_ctrls[i].block->length, i, block_ctrls[i].block->name,
                   block_ctrls[i].block->tail);
        }
        printf("INFO: firmware pack OK length %d\n", head->length);
        assert(ftell(fp) == head->length);
        fclose(fp);
        ret = FIRMWARE_PACK_OK;
    }
    free_block_ctrls(block_count, block_ctrls);
    free(head);

    return ret;
}


