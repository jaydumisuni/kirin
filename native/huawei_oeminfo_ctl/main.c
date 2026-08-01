typedef unsigned int u32;
typedef unsigned long usize;

extern int rmt_oeminfo_read(int index, u32 length, void *data);
extern int rmt_oeminfo_write(int index, u32 length, const void *data);
extern int rmt_oeminfo_get_info(int index, u32 *length, u32 *age);

enum {
    STDERR_FD = 2,
    STDOUT_FD = 1,
    SYS_WRITE = 64,
    MAX_INDEX = 354,
    MAX_RECORD_SIZE = 65536,
};

static unsigned char record_buffer[MAX_RECORD_SIZE];

static long sys_write(int fd, const void *buffer, usize length) {
    register long x0 __asm__("x0") = fd;
    register const void *x1 __asm__("x1") = buffer;
    register usize x2 __asm__("x2") = length;
    register long x8 __asm__("x8") = SYS_WRITE;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}

static usize text_length(const char *value) {
    usize length = 0;
    while (value[length] != '\0') {
        length++;
    }
    return length;
}

static void print_text(int fd, const char *value) {
    sys_write(fd, value, text_length(value));
}

static void print_u32(int fd, u32 value) {
    char digits[10];
    usize count = 0;
    do {
        digits[count++] = (char)('0' + value % 10);
        value /= 10;
    } while (value != 0);
    while (count != 0) {
        sys_write(fd, &digits[--count], 1);
    }
}

static int parse_u32(const char *value, u32 *result) {
    u32 base = 10;
    u32 parsed = 0;
    usize index = 0;
    if (value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) {
        base = 16;
        index = 2;
    }
    if (value[index] == '\0') {
        return -1;
    }
    for (; value[index] != '\0'; index++) {
        unsigned char octet = (unsigned char)value[index];
        u32 digit;
        if (octet >= '0' && octet <= '9') {
            digit = octet - '0';
        } else if (base == 16 && octet >= 'a' && octet <= 'f') {
            digit = octet - 'a' + 10;
        } else if (base == 16 && octet >= 'A' && octet <= 'F') {
            digit = octet - 'A' + 10;
        } else {
            return -1;
        }
        if (digit >= base || parsed > (0xffffffffU - digit) / base) {
            return -1;
        }
        parsed = parsed * base + digit;
    }
    *result = parsed;
    return 0;
}

static int text_equal(const char *left, const char *right) {
    usize index = 0;
    while (left[index] == right[index]) {
        if (left[index] == '\0') {
            return 1;
        }
        index++;
    }
    return 0;
}

static int scan_records(u32 limit) {
    for (u32 index = 1; index <= limit; index++) {
        u32 length = 0;
        u32 age = 0;
        if (rmt_oeminfo_get_info((int)index, &length, &age) == 0) {
            print_text(STDOUT_FD, "ID=");
            print_u32(STDOUT_FD, index);
            print_text(STDOUT_FD, " LEN=");
            print_u32(STDOUT_FD, length);
            print_text(STDOUT_FD, " AGE=");
            print_u32(STDOUT_FD, age);
            print_text(STDOUT_FD, "\n");
        }
    }
    return 0;
}

static int read_record(u32 index, u32 length) {
    static const char hex[] = "0123456789ABCDEF";
    char pair[2];
    if (length == 0 || length > MAX_RECORD_SIZE) {
        print_text(STDERR_FD, "invalid record length\n");
        return 2;
    }
    if (rmt_oeminfo_read((int)index, length, record_buffer) != 0) {
        print_text(STDERR_FD, "OEMINFO read failed\n");
        return 3;
    }
    print_text(STDOUT_FD, "ID=");
    print_u32(STDOUT_FD, index);
    print_text(STDOUT_FD, " LEN=");
    print_u32(STDOUT_FD, length);
    print_text(STDOUT_FD, "\nHEX=");
    for (u32 offset = 0; offset < length; offset++) {
        pair[0] = hex[record_buffer[offset] >> 4];
        pair[1] = hex[record_buffer[offset] & 0x0f];
        sys_write(STDOUT_FD, pair, sizeof(pair));
    }
    print_text(STDOUT_FD, "\nASCII=");
    for (u32 offset = 0; offset < length; offset++) {
        char value = record_buffer[offset] >= 32 && record_buffer[offset] < 127
            ? (char)record_buffer[offset]
            : '.';
        sys_write(STDOUT_FD, &value, 1);
    }
    print_text(STDOUT_FD, "\n");
    return 0;
}

static int write_record(u32 index, const char *value) {
    usize length = text_length(value);
    if (length == 0 || length > MAX_RECORD_SIZE) {
        print_text(STDERR_FD, "invalid record value length\n");
        return 2;
    }
    if (rmt_oeminfo_write((int)index, (u32)length, value) != 0) {
        print_text(STDERR_FD, "OEMINFO write failed\n");
        return 3;
    }
    print_text(STDOUT_FD, "OEMINFO write completed: ID=");
    print_u32(STDOUT_FD, index);
    print_text(STDOUT_FD, " LEN=");
    print_u32(STDOUT_FD, (u32)length);
    print_text(STDOUT_FD, "\n");
    return 0;
}

static void usage(void) {
    print_text(
        STDERR_FD,
        "usage: huawei-oeminfo-ctl scan [MAX_ID] | read ID LENGTH | "
        "write-confirmed ID VALUE\n"
    );
}

int main(int argc, char **argv) {
    u32 first = 0;
    u32 second = 0;
    if (argc >= 2 && text_equal(argv[1], "scan")) {
        if (argc == 2) {
            return scan_records(MAX_INDEX);
        }
        if (argc == 3 && parse_u32(argv[2], &first) == 0 && first <= MAX_INDEX) {
            return scan_records(first);
        }
    } else if (argc == 4 && text_equal(argv[1], "read")) {
        if (parse_u32(argv[2], &first) == 0 && parse_u32(argv[3], &second) == 0) {
            return read_record(first, second);
        }
    } else if (argc == 4 && text_equal(argv[1], "write-confirmed")) {
        if (parse_u32(argv[2], &first) == 0 && first >= 1 && first <= MAX_INDEX) {
            return write_record(first, argv[3]);
        }
    }
    usage();
    return 2;
}
