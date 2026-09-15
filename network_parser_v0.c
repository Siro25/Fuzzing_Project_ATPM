/**
 * Đề tài 4 : Dự án Fuzzing - Chủ đề bóc tách gói tin mạng
 * File      : network_parser_v0.c  (BẢN GỐC - CHỨA LỖ HỔNG)
 * Phiên bản : v0 (Vulnerable)
 * Thành viên: A
 * -----------------------------------------------------------------------------
 * Mô tả    : Module phân tích (parser) gói tin mạng theo giao thức tuỳ chỉnh.
 *            Gói tin yêu cầu vượt qua 2 rào cản:
 *              1. Magic Byte (Sync Word) 4 byte = 0xDEADBEEF
 *              2. XOR Checksum 1 byte phủ toàn bộ Header + Payload
 *
 * Lỗ hổng  : CWE-120 (Buffer Copy without Checking Size of Input)
 *            Hàm parse_network_packet() sử dụng memcpy() với data_length
 *            lấy trực tiếp từ input mà KHÔNG kiểm tra giới hạn, dẫn đến
 *            Stack Buffer Overflow khi data_length > MAX_PAYLOAD_SIZE.
 *
 * CẢNH BÁO : File này giữ nguyên sau khi chốt. Mọi bản vá nằm ở _v1.c.
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/** Sync Word (Magic Byte) - rào cản thứ nhất.
 *  Fuzzer phải đoán đúng 4 byte này mới vượt qua được bước đầu tiên. */
#define SYNC_WORD           0xDEADBEEF

/** Kích thước tối đa của vùng Payload trong struct (64 byte). */
#define MAX_PAYLOAD_SIZE    64

/** Kích thước tối thiểu của gói tin hợp lệ (Header + Checksum, không Payload).
 *  = sizeof(sync_word) + sizeof(cmd_id) + sizeof(data_length) + sizeof(checksum)
 *  = 4 + 1 + 2 + 1 = 8 byte */
#define MIN_PACKET_SIZE     8

/* =============================================================================
 * MÃ LỖI TRẢ VỀ
 * ===========================================================================*/

#define PARSE_OK                 0   /**< Phân tích thành công                */
#define ERR_NULL_INPUT          -1   /**< Con trỏ đầu vào NULL               */
#define ERR_TOO_SHORT           -2   /**< Dữ liệu quá ngắn, không đủ Header */
#define ERR_SYNC_MISMATCH       -3   /**< Sync Word không khớp 0xDEADBEEF    */
#define ERR_CHECKSUM_INVALID    -4   /**< Checksum XOR không hợp lệ          */
#define ERR_LENGTH_MISMATCH     -5   /**< Kích thước thực tế < data_length   */

/* =============================================================================
 * CẤU TRÚC GÓI TIN MẠNG (KHÔNG ĐỆM BYTE)
 * ===========================================================================*/

/**
 * @brief Cấu trúc gói tin mạng tuỳ chỉnh.
 *
 * Bố cục bộ nhớ (tổng tối đa 72 byte khi payload đầy):
 *
 *   Offset  Kích thước  Trường
 *   ------  ----------  ------
 *   0       4 byte      sync_word      (Magic Byte = 0xDEADBEEF)
 *   4       1 byte      cmd_id         (Mã lệnh)
 *   5       2 byte      data_length    (Độ dài payload khai báo)
 *   7       64 byte     payload        (Dữ liệu ứng dụng)
 *   71      1 byte      checksum       (XOR toàn bộ Header + Payload)
 *
 * #pragma pack(1) đảm bảo compiler KHÔNG chèn padding giữa các trường,
 * giúp ánh xạ 1:1 với dữ liệu nhị phân từ mạng.
 */
#pragma pack(push, 1)
typedef struct {
    uint32_t sync_word;                 /**< Sync Word - rào cản Magic Byte  */
    uint8_t  cmd_id;                    /**< Command ID - mã lệnh           */
    uint16_t data_length;               /**< Data Length - độ dài payload    */
    uint8_t  payload[MAX_PAYLOAD_SIZE]; /**< Payload - dữ liệu ứng dụng     */
    uint8_t  checksum;                  /**< Checksum - XOR toàn bộ gói      */
} NetworkPacket;
#pragma pack(pop)

/* =============================================================================
 * HÀM TÍNH CHECKSUM
 * ===========================================================================*/

/**
 * @brief Tính checksum XOR trên một vùng dữ liệu.
 *
 * Checksum = XOR lần lượt từng byte trong vùng [data, data + length).
 * Đây là rào cản tính toán thứ hai mà Fuzzer phải vượt qua.
 *
 * @param data    Con trỏ đến vùng dữ liệu cần tính.
 * @param length  Số byte cần XOR.
 * @return        Giá trị checksum 1 byte.
 */
static uint8_t calculate_checksum(const uint8_t *data, size_t length)
{
    uint8_t csum = 0;
    for (size_t i = 0; i < length; i++) {
        csum ^= data[i];
    }
    return csum;
}

/* =============================================================================
 * HÀM IN THÔNG TIN GÓI TIN (TIỆN ÍCH GỠ LỖI)
 * ===========================================================================*/

/**
 * @brief In nội dung gói tin đã phân tích ra stdout.
 *
 * @param pkt  Con trỏ đến cấu trúc NetworkPacket đã giải mã.
 */
static void print_packet_info(const NetworkPacket *pkt)
{
    printf("=== THONG TIN GOI TIN ===\n");
    printf("  Sync Word   : 0x%08X\n", pkt->sync_word);
    printf("  Command ID  : 0x%02X\n", pkt->cmd_id);
    printf("  Data Length : %u byte(s)\n", pkt->data_length);
    printf("  Payload     : ");

    /* In payload dưới dạng hex, giới hạn theo data_length */
    uint16_t print_len = pkt->data_length;
    if (print_len > MAX_PAYLOAD_SIZE) {
        print_len = MAX_PAYLOAD_SIZE;  /* Cắt hiển thị để tránh đọc rác */
    }
    for (uint16_t i = 0; i < print_len; i++) {
        printf("%02X ", pkt->payload[i]);
    }
    printf("\n");
    printf("  Checksum    : 0x%02X\n", pkt->checksum);
    printf("=========================\n");
}

/* =============================================================================
 * HÀM PHÂN TÍCH GÓI TIN CHÍNH
 * ===========================================================================*/

/**
 * @brief Phân tích (parse) dữ liệu thô thành cấu trúc gói tin mạng.
 *
 * Quy trình xử lý:
 *   1. Kiểm tra con trỏ NULL
 *   2. Kiểm tra kích thước tối thiểu (MIN_PACKET_SIZE = 8 byte)
 *   3. Đọc và kiểm tra Sync Word (rào cản Magic Byte)
 *   4. Đọc Command ID và Data Length
 *   5. Kiểm tra input đủ dài để chứa payload + checksum
 *   6. *** SAO CHÉP PAYLOAD KHÔNG KIỂM TRA GIỚI HẠN *** (CWE-120)
 *   7. Đọc và xác minh Checksum (rào cản tính toán)
 *
 * ┌──────────────────────────────────────────────────────────────────────┐
 * │ !!! LỖ HỔNG CWE-120 TẠI BƯỚC 6 !!!                                │
 * │                                                                      │
 * │ memcpy(out_pkt->payload, &raw_data[offset], data_len) được gọi với │
 * │ data_len lấy từ trường data_length trong input mà KHÔNG giới hạn   │
 * │ bởi MAX_PAYLOAD_SIZE. Nếu data_len > 64, dữ liệu sẽ tràn ra       │
 * │ ngoài mảng payload[64], ghi đè checksum, stack canary, saved RBP,   │
 * │ và return address trên stack → Stack Buffer Overflow.               │
 * └──────────────────────────────────────────────────────────────────────┘
 *
 * @param raw_data    Con trỏ đến bộ đệm dữ liệu thô từ mạng.
 * @param raw_length  Kích thước (byte) của bộ đệm raw_data.
 * @param out_pkt     Con trỏ đến cấu trúc NetworkPacket để ghi kết quả.
 * @return            Mã lỗi: PARSE_OK (0) nếu thành công, giá trị âm nếu lỗi.
 */
int parse_network_packet(const uint8_t *raw_data,
                         size_t         raw_length,
                         NetworkPacket *out_pkt)
{
    size_t offset = 0;

    /* -----------------------------------------------------------------------
     * Bước 1: Kiểm tra con trỏ đầu vào
     * --------------------------------------------------------------------- */
    if (raw_data == NULL || out_pkt == NULL) {
        fprintf(stderr, "[LOI] Con tro dau vao NULL.\n");
        return ERR_NULL_INPUT;
    }

    /* -----------------------------------------------------------------------
     * Bước 2: Kiểm tra kích thước tối thiểu
     * Gói tin hợp lệ ít nhất phải chứa: sync(4) + cmd(1) + len(2) + csum(1)
     * --------------------------------------------------------------------- */
    if (raw_length < MIN_PACKET_SIZE) {
        fprintf(stderr, "[LOI] Du lieu qua ngan: %zu byte (can >= %d).\n",
                raw_length, MIN_PACKET_SIZE);
        return ERR_TOO_SHORT;
    }

    /* -----------------------------------------------------------------------
     * Bước 3: Đọc và xác minh Sync Word (rào cản Magic Byte)
     * --------------------------------------------------------------------- */
    uint32_t sync = 0;
    memcpy(&sync, &raw_data[offset], sizeof(uint32_t));
    offset += sizeof(uint32_t);  /* offset = 4 */

    if (sync != SYNC_WORD) {
        fprintf(stderr, "[LOI] Sync Word khong khop: 0x%08X (can 0x%08X).\n",
                sync, SYNC_WORD);
        return ERR_SYNC_MISMATCH;
    }
    out_pkt->sync_word = sync;

    /* -----------------------------------------------------------------------
     * Bước 4: Đọc Command ID (1 byte) và Data Length (2 byte)
     * --------------------------------------------------------------------- */
    out_pkt->cmd_id = raw_data[offset];
    offset += sizeof(uint8_t);   /* offset = 5 */

    uint16_t data_len = 0;
    memcpy(&data_len, &raw_data[offset], sizeof(uint16_t));
    offset += sizeof(uint16_t);  /* offset = 7 */
    out_pkt->data_length = data_len;

    /* -----------------------------------------------------------------------
     * Bước 5: Kiểm tra input có đủ dài để chứa payload + checksum
     *
     * Tổng kích thước cần: offset_hiện_tại + data_length + 1 (checksum)
     * Đây chỉ kiểm tra input đủ dài, KHÔNG kiểm tra data_len <= 64.
     * --------------------------------------------------------------------- */
    if (raw_length < offset + (size_t)data_len + 1) {
        fprintf(stderr, "[LOI] Du lieu khong du: can %zu byte, co %zu byte.\n",
                offset + (size_t)data_len + 1, raw_length);
        return ERR_LENGTH_MISMATCH;
    }

    /* -----------------------------------------------------------------------
     * Bước 6: Sao chép Payload vào struct
     *
     * ╔══════════════════════════════════════════════════════════════════╗
     * ║  ██  LỖ HỔNG CWE-120: BUFFER OVERFLOW  ██                     ║
     * ║                                                                  ║
     * ║  memcpy() dưới đây dùng data_len từ gói tin input.             ║
     * ║  out_pkt->payload chỉ có 64 byte, nhưng data_len có thể       ║
     * ║  lên đến 65535 (giá trị tối đa của uint16_t).                  ║
     * ║                                                                  ║
     * ║  Nếu data_len > 64:                                            ║
     * ║    → Ghi đè checksum (byte ngay sau payload)                   ║
     * ║    → Ghi đè dữ liệu trên stack (nếu out_pkt nằm trên stack)  ║
     * ║    → Có thể ghi đè return address → thực thi mã tuỳ ý        ║
     * ║                                                                  ║
     * ║  BẢN VÁ (xem _v1.c): Thêm kiểm tra data_len <= MAX_PAYLOAD  ║
     * ╚══════════════════════════════════════════════════════════════════╝
     */
    memcpy(out_pkt->payload, &raw_data[offset], data_len);  /* !!! BUG !!! */
    offset += data_len;

    /* -----------------------------------------------------------------------
     * Bước 7: Đọc và xác minh Checksum (rào cản tính toán)
     *
     * Checksum = XOR( sync_word[4] | cmd_id[1] | data_length[2] | payload[N] )
     * Byte checksum nằm ngay sau payload trong luồng dữ liệu input.
     * --------------------------------------------------------------------- */
    uint8_t received_checksum = raw_data[offset];
    out_pkt->checksum = received_checksum;

    /*
     * Tính checksum kỳ vọng:
     * XOR toàn bộ vùng dữ liệu từ đầu gói tin (byte 0) đến hết payload,
     * tức là từ raw_data[0] đến raw_data[offset - 1], tổng cộng offset byte.
     */
    uint8_t expected_checksum = calculate_checksum(raw_data, offset);

    if (received_checksum != expected_checksum) {
        fprintf(stderr,
                "[LOI] Checksum khong hop le: nhan 0x%02X, can 0x%02X.\n",
                received_checksum, expected_checksum);
        return ERR_CHECKSUM_INVALID;
    }

    /* -----------------------------------------------------------------------
     * Phân tích thành công
     * --------------------------------------------------------------------- */
    printf("[OK] Phan tich goi tin thanh cong.\n");
    return PARSE_OK;
}

/* =============================================================================
 * HÀM XÂY DỰNG GÓI TIN HỢP LỆ (DÙNG CHO KIỂM THỬ)
 * ===========================================================================*/

/**
 * @brief Tạo một gói tin thô hợp lệ (có Sync Word và Checksum đúng).
 *
 * Hàm này dùng để tạo test-case hợp lệ, giúp kiểm tra parser hoạt động
 * đúng với đầu vào bình thường trước khi tiến hành fuzzing.
 *
 * @param cmd_id       Mã lệnh (1 byte).
 * @param payload      Dữ liệu payload.
 * @param payload_len  Độ dài payload (byte).
 * @param out_buf      Bộ đệm đầu ra chứa gói tin thô.
 * @param out_buf_size Kích thước tối đa của out_buf.
 * @return             Số byte đã ghi vào out_buf, hoặc -1 nếu lỗi.
 */
static int build_valid_packet(uint8_t        cmd_id,
                              const uint8_t *payload,
                              uint16_t       payload_len,
                              uint8_t       *out_buf,
                              size_t         out_buf_size)
{
    /* Tổng kích thước gói tin: Header(7) + Payload(N) + Checksum(1) */
    size_t total_size = 7 + (size_t)payload_len + 1;

    if (out_buf == NULL || total_size > out_buf_size) {
        fprintf(stderr, "[LOI] Bo dem dau ra khong du.\n");
        return -1;
    }

    size_t offset = 0;

    /* Ghi Sync Word */
    uint32_t sync = SYNC_WORD;
    memcpy(&out_buf[offset], &sync, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    /* Ghi Command ID */
    out_buf[offset] = cmd_id;
    offset += sizeof(uint8_t);

    /* Ghi Data Length */
    memcpy(&out_buf[offset], &payload_len, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    /* Ghi Payload */
    if (payload != NULL && payload_len > 0) {
        memcpy(&out_buf[offset], payload, payload_len);
        offset += payload_len;
    }

    /* Tính và ghi Checksum (XOR tất cả byte trước đó) */
    uint8_t csum = calculate_checksum(out_buf, offset);
    out_buf[offset] = csum;
    offset += 1;

    return (int)offset;
}

/* =============================================================================
 * ĐIỂM VÀO CHÍNH - CHẾ ĐỘ HOẠT ĐỘNG
 * ===========================================================================*/

/**
 * @brief Hàm main hỗ trợ 2 chế độ:
 *
 *   1. Chế độ Fuzzing (có tham số dòng lệnh):
 *      Đọc dữ liệu thô từ file → phân tích.
 *      Dùng lệnh: ./network_parser_v0 <input_file>
 *
 *   2. Chế độ Demo (không tham số):
 *      Tự tạo gói tin hợp lệ → phân tích → in kết quả.
 *      Dùng lệnh: ./network_parser_v0
 *
 * @param argc  Số tham số dòng lệnh.
 * @param argv  Mảng tham số dòng lệnh.
 * @return      0 nếu thành công, 1 nếu có lỗi.
 */
int main(int argc, char *argv[])
{
    printf("=====================================================\n");
    printf("  NETWORK PACKET PARSER v0 (VULNERABLE)\n");
    printf("  De tai 4 - Fuzzing Project\n");
    printf("  Dai hoc Phenikaa - Ky thuat Lap trinh An toan\n");
    printf("=====================================================\n\n");

    if (argc >= 2) {
        /* =================================================================
         * CHẾ ĐỘ 1: ĐỌC TỪ FILE (DÀNH CHO FUZZER)
         *
         * Fuzzer (ví dụ AFL, libFuzzer) sẽ sinh file input chứa dữ liệu
         * thô và gọi chương trình với đường dẫn file làm tham số.
         * =============================================================== */
        const char *input_file = argv[1];
        printf("[INFO] Doc du lieu tu file: %s\n", input_file);

        FILE *fp = fopen(input_file, "rb");
        if (fp == NULL) {
            fprintf(stderr, "[LOI] Khong mo duoc file: %s\n", input_file);
            return 1;
        }

        /* Xác định kích thước file */
        fseek(fp, 0, SEEK_END);
        long file_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        if (file_size <= 0 || file_size > 65536) {
            fprintf(stderr, "[LOI] Kich thuoc file khong hop le: %ld byte.\n",
                    file_size);
            fclose(fp);
            return 1;
        }

        /* Cấp phát bộ nhớ và đọc dữ liệu */
        uint8_t *raw_data = (uint8_t *)malloc((size_t)file_size);
        if (raw_data == NULL) {
            fprintf(stderr, "[LOI] Khong cap phat duoc bo nho.\n");
            fclose(fp);
            return 1;
        }

        size_t bytes_read = fread(raw_data, 1, (size_t)file_size, fp);
        fclose(fp);

        printf("[INFO] Da doc %zu byte tu file.\n\n", bytes_read);

        /* Phân tích gói tin */
        NetworkPacket pkt;
        memset(&pkt, 0, sizeof(NetworkPacket));

        int result = parse_network_packet(raw_data, bytes_read, &pkt);

        if (result == PARSE_OK) {
            print_packet_info(&pkt);
        } else {
            fprintf(stderr, "[INFO] Phan tich that bai, ma loi: %d\n", result);
        }

        free(raw_data);
        return (result == PARSE_OK) ? 0 : 1;

    } else {
        /* =================================================================
         * CHẾ ĐỘ 2: DEMO VỚI GÓI TIN HỢP LỆ
         *
         * Tạo một gói tin mẫu với payload = "HELLO_PHENIKAA" và phân tích
         * để chứng minh parser hoạt động đúng trong điều kiện bình thường.
         * =============================================================== */
        printf("[INFO] Che do DEMO - tao goi tin hop le.\n\n");

        /* Dữ liệu payload mẫu */
        const char *sample_data = "HELLO_PHENIKAA";
        uint16_t    sample_len  = (uint16_t)strlen(sample_data);
        uint8_t     sample_cmd  = 0x01;

        /* Tạo gói tin thô */
        uint8_t raw_buffer[256];
        int pkt_size = build_valid_packet(sample_cmd,
                                          (const uint8_t *)sample_data,
                                          sample_len,
                                          raw_buffer,
                                          sizeof(raw_buffer));
        if (pkt_size < 0) {
            fprintf(stderr, "[LOI] Khong tao duoc goi tin mau.\n");
            return 1;
        }

        printf("[INFO] Da tao goi tin mau: %d byte.\n", pkt_size);
        printf("[INFO] Hex dump: ");
        for (int i = 0; i < pkt_size; i++) {
            printf("%02X ", raw_buffer[i]);
        }
        printf("\n\n");

        /* Phân tích gói tin vừa tạo */
        NetworkPacket pkt;
        memset(&pkt, 0, sizeof(NetworkPacket));

        int result = parse_network_packet(raw_buffer, (size_t)pkt_size, &pkt);

        if (result == PARSE_OK) {
            print_packet_info(&pkt);
            printf("\n[OK] Demo thanh cong! Parser hoat dong binh thuong.\n");
        } else {
            fprintf(stderr, "[LOI] Demo that bai, ma loi: %d\n", result);
            return 1;
        }

        /* ---------------------------------------------------------------
         * Cảnh báo về lỗ hổng
         * ------------------------------------------------------------- */
        printf("\n");
        printf("!! CANH BAO !!\n");
        printf("File nay chua lo hong CWE-120 tai ham parse_network_packet().\n");
        printf("Truong data_length khong duoc kiem tra gioi han MAX_PAYLOAD.\n");
        printf("Neu data_length > 64 -> TRAN BO NHO DEM (Stack Overflow).\n");
        printf("Xem ban va an toan tai: network_parser_v1.c\n");

        return 0;
    }
}
