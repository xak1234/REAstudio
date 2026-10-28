#include "fixture_api.h"
#include <cstdio>

REA_FIXTURE_API int rea_emit_invoice(const char* path, int quantity, int tier) {
    const int total = rea_price(quantity, tier);
    if (total < 0) return 2;
    FILE* output = nullptr;
    if (fopen_s(&output, path, "wb") != 0 || output == nullptr) return 3;
    const int written = std::fprintf(output,
        "REA-INVOICE-V1\nquantity=%d\ntier=%d\ntotal=%d\nband=%s\n",
        quantity, tier, total, rea_band(total));
    const int closed = std::fclose(output);
    return written < 0 || closed != 0 ? 4 : 0;
}
