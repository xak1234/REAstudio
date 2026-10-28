#include "fixture_api.h"
#include <cstdio>
#include <cstring>

extern "C" __declspec(dllexport) __declspec(noinline) int rea_parse_quantity(const char* text) {
    if (text == nullptr || *text == '\0') return -1;
    int value = 0;
    for (const char* c = text; *c != '\0'; ++c) {
        if (*c < '0' || *c > '9') return -1;
        value = value * 10 + (*c - '0');
        if (value > 10000) return -1;
    }
    return value;
}

int main(int argc, char** argv) {
    if (argc < 4) {
        std::fputs("usage: fixture price|invoice quantity tier [output]\n", stderr);
        return 1;
    }
    const int quantity = rea_parse_quantity(argv[2]);
    const int tier = rea_parse_quantity(argv[3]);
    if (std::strcmp(argv[1], "price") == 0) {
        const int total = rea_price(quantity, tier);
        if (total < 0) { std::fputs("invalid input\n", stderr); return 2; }
        std::printf("total=%d\nband=%s\n", total, rea_band(total));
        return 0;
    }
    if (std::strcmp(argv[1], "invoice") == 0 && argc == 5) {
        const int result = rea_emit_invoice(argv[4], quantity, tier);
        if (result != 0) { std::fprintf(stderr, "invoice error=%d\n", result); return result; }
        std::puts("invoice written");
        return 0;
    }
    std::fputs("unknown operation\n", stderr);
    return 1;
}
