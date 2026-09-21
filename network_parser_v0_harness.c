/**
 * Đề tài 4: Dự án Fuzzing - Harness cho Black-box Fuzzing
 * File: network_parser_v0_harness.c
 * Chế độ: File input, stdin, hoặc random standalone
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define SYNC_WORD           0xDEADBEEF
#define MAX_PAYLOAD_SIZE    64
#define MIN_PACKET_SIZE     8

#define PARSE_OK                 0
#define ERR_NULL_INPUT          -1
#define ERR_TOO_SHORT           -2
#define ERR_SYNC_MISMATCH       -3
#define ERR_CHECKSUM_INVALID    -4
#define ERR_LENGTH_MISMATCH     -5

#pragma pack(push, 1)
typedef struct {
    uint32_t sync_word;
    uint8_t  cmd_id;
    uint16_t data_length;
    uint8_t  payload[MAX_PAYLOAD_SIZE];
    uint8_t  checksum;
} NetworkPacket;
#pragma pack(pop)

/* Inline parser implementation */
static uint8_t calculate_checksum(const uint8_t *data, size_t length)
{
    uint8_t csum = 0;
    for (size_t i = 0; i < length; i++) {
        csum ^= data[i];
    }
    return csum;
}

static void log_error_packet(const uint8_t *payload, uint16_t length)
{
    printf("[ERROR LOG] Goi tin bi loi, payload: ");
    char temp[128];
    if (length > 0 && length < sizeof(temp) - 1) {
        memcpy(temp, payload, length);
        temp[length] = '\0';
        printf(temp);  /* CWE-134 */
    }
    printf("\n");
}

static int parse_network_packet(const uint8_t *raw_data,
                                size_t         raw_length,
                                NetworkPacket *out_pkt)
{
    size_t offset = 0;

    if (raw_data == NULL || out_pkt == NULL) {
        return ERR_NULL_INPUT;
    }

    if (raw_length < MIN_PACKET_SIZE) {
        return ERR_TOO_SHORT;
    }

    uint32_t sync = 0;
    memcpy(&sync, &raw_data[offset], sizeof(uint32_t));
    offset += sizeof(uint32_t);

    if (sync != SYNC_WORD) {
        return ERR_SYNC_MISMATCH;
    }
    out_pkt->sync_word = sync;

    out_pkt->cmd_id = raw_data[offset];
    offset += sizeof(uint8_t);

    uint16_t data_len = 0;
    memcpy(&data_len, &raw_data[offset], sizeof(uint16_t));
    offset += sizeof(uint16_t);
    out_pkt->data_length = data_len;

    if (raw_length < offset + (size_t)data_len + 1) {
        if (data_len > 0 && data_len < 64) {
            log_error_packet(&raw_data[offset], data_len);
        }
        return ERR_LENGTH_MISMATCH;
    }

    /* CWE-120: Không kiểm tra data_len <= MAX_PAYLOAD_SIZE */
    memcpy(out_pkt->payload, &raw_data[offset], data_len);
    offset += data_len;

    uint8_t received_checksum = raw_data[offset];
    out_pkt->checksum = received_checksum;

    /* CWE-125: calculate_checksum có thể đọc tràn */
    uint8_t expected_checksum = calculate_checksum(raw_data, offset);

    if (received_checksum != expected_checksum) {
        log_error_packet(out_pkt->payload, data_len);
        return ERR_CHECKSUM_INVALID;
    }

    return PARSE_OK;
}

/* Harness kết nối dữ liệu vào parser */
int fuzz_harness(const uint8_t *data, size_t size)
{
    NetworkPacket pkt;
    memset(&pkt, 0, sizeof(NetworkPacket));
    return parse_network_packet(data, size, &pkt);
}

/* Sinh dữ liệu ngẫu nhiên (black-box - không biết cấu trúc) */
void generate_random_data(uint8_t *buffer, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        buffer[i] = (uint8_t)(rand() % 256);
    }
}

/* Chế độ fuzzing từ file */
int fuzzing_mode_file(const char *input_file)
{
    FILE *fp = fopen(input_file, "rb");
    if (fp == NULL) {
        return 1;
    }
    
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (file_size <= 0 || file_size > 65536) {
        fclose(fp);
        return 1;
    }
    
    uint8_t *data = (uint8_t *)malloc((size_t)file_size);
    if (data == NULL) {
        fclose(fp);
        return 1;
    }
    
    size_t bytes_read = fread(data, 1, (size_t)file_size, fp);
    fclose(fp);
    
    int result = fuzz_harness(data, bytes_read);
    
    free(data);
    return (result == PARSE_OK) ? 0 : 1;
}

/* Chế độ fuzzing từ stdin */
int fuzzing_mode_stdin(void)
{
    uint8_t buffer[65536];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), stdin);
    
    if (bytes_read == 0) {
        return 1;
    }
    
    int result = fuzz_harness(buffer, bytes_read);
    return (result == PARSE_OK) ? 0 : 1;
}

/* Chế độ random fuzzing standalone */
void fuzzing_mode_random(int iterations, unsigned int seed)
{
    printf("=======================================================\n");
    printf("  HARNESS - BLACK-BOX FUZZING (RANDOM MODE)\n");
    printf("=======================================================\n");
    printf("Iterations : %d\n", iterations);
    printf("Seed       : %u\n", seed);
    printf("=======================================================\n\n");
    
    srand(seed);
    
    int stats_sync_reject = 0;
    int stats_checksum_reject = 0;
    int stats_other_reject = 0;
    int stats_success = 0;
    
    for (int i = 0; i < iterations; i++) {
        size_t size = (size_t)(rand() % 200);
        uint8_t data[200];
        generate_random_data(data, size);
        
        int result = fuzz_harness(data, size);
        
        switch (result) {
            case ERR_SYNC_MISMATCH:
            case ERR_TOO_SHORT:
                stats_sync_reject++;
                break;
            case ERR_CHECKSUM_INVALID:
                stats_checksum_reject++;
                break;
            case PARSE_OK:
                stats_success++;
                break;
            default:
                stats_other_reject++;
                break;
        }
        
        if ((i + 1) % 1000 == 0) {
            printf("  [%6d] Sync: %d, Checksum: %d, Success: %d\n",
                   i + 1, stats_sync_reject, stats_checksum_reject, stats_success);
        }
    }
    
    printf("\n");
    printf("=======================================================\n");
    printf("  FUZZING RESULTS\n");
    printf("=======================================================\n");
    printf("Total Iterations      : %d\n", iterations);
    printf("Rejected at Sync      : %d (%.2f%%)\n", 
           stats_sync_reject, (stats_sync_reject * 100.0) / iterations);
    printf("Rejected at Checksum  : %d (%.2f%%)\n",
           stats_checksum_reject, (stats_checksum_reject * 100.0) / iterations);
    printf("Rejected (Other)      : %d (%.2f%%)\n",
           stats_other_reject, (stats_other_reject * 100.0) / iterations);
    printf("Successfully Parsed   : %d (%.2f%%)\n",
           stats_success, (stats_success * 100.0) / iterations);
    printf("\n");
    
    double blocked_pct = ((stats_sync_reject + stats_checksum_reject + stats_other_reject) * 100.0) / iterations;
    printf("TOTAL BLOCKED         : %.2f%%\n", blocked_pct);
    printf("=======================================================\n");
    printf("\n");
    printf("CONCLUSION:\n");
    printf("Black-box fuzzing khong the vuot qua 2 rao can:\n");
    printf("  1. MAGIC BYTE (0xDEADBEEF)\n");
    printf("  2. XOR CHECKSUM\n");
    printf("=> Khong the kich hoat loi CWE-120, CWE-134, CWE-125!\n");
    printf("=======================================================\n");
}

/* Main dispatcher */
int main(int argc, char *argv[])
{
    if (argc == 1) {
        fuzzing_mode_random(10000, (unsigned int)time(NULL));
        return 0;
    }
    
    if (strcmp(argv[1], "--stdin") == 0) {
        return fuzzing_mode_stdin();
    }
    
    if (strcmp(argv[1], "--random") == 0) {
        int iterations = (argc > 2) ? atoi(argv[2]) : 10000;
        unsigned int seed = (argc > 3) ? (unsigned int)atoi(argv[3]) : (unsigned int)time(NULL);
        fuzzing_mode_random(iterations, seed);
        return 0;
    }
    
    return fuzzing_mode_file(argv[1]);
}
