#ifndef FIRMWARE_PACK_H_INCLUDED
#define FIRMWARE_PACK_H_INCLUDED

#define MD5_SIZE 16
#define AES_KEY_SIZE 128
#define AES_PAD_SIZE (AES_KEY_SIZE/8)

#define BLOCK_NAME_SIZE 16
#define NOTES_SIZE 64
#define MAX_BLOCKS 8

#define FIRMWARE_PACK_OK 0
#define FIRMWARE_PACK_FAIL -1
#define FIRMWARE_PACK_BAD_HEAD -2
#define FIRMWARE_PACK_BAD_LENGTH -3
#define FIRMWARE_PACK_BAD_MD5   -4
#define FIRMWARE_PACK_OUT_MEM   -5
#define FIRMWARE_PACK_ERR_FILE -6

#define FIRMWARE_MAGIC "IPNC"
#define MAX_BLOCK_SIZE (1024*1024*1024)

typedef struct tagFirmwareBlock {
    char name[BLOCK_NAME_SIZE];
    int32_t offset;
    int32_t length;
    int32_t tail;
    char md5[MD5_SIZE];
} FirmwareBlock;


typedef struct tagFirmwareBlockCtrl {
    FirmwareBlock* block;
    char * data;
} FirmwareBlockCtrl;

typedef struct tagFirmwarePackHead {
    char magic[4]; //magic, "Tang"
    int32_t version; //major.minor.seq
    int32_t length; //length of package file length, include this head
    int32_t block_count;
    FirmwareBlock blocks[MAX_BLOCKS];
    char notes[NOTES_SIZE];
} FirmwarePackHead;

//encode multi firmware file(block) into package
int firmware_pack_encode(int32_t version,
                         int block_count,
                         const char ** block_names,
                         const char * notes,
                         const char * pack_file);

int firmware_pack_decode(const char * pack_file,
                         const char * destdir,
                         FirmwarePackHead* head);


#endif // FIRMWARE_PACK_H_INCLUDED
