#include "fixture_api.h"

REA_FIXTURE_API int rea_price(int quantity, int tier) {
    if (quantity < 0 || quantity > 10000 || tier < 0 || tier > 2) return -1;
    const int gross = quantity * 125;
    int discount = 0;
    if (tier == 1 && quantity >= 10) discount = 20;
    if (tier == 2 && quantity >= 3) discount = 35;
    return gross * (100 - discount) / 100;
}

REA_FIXTURE_API const char* rea_band(int total) {
    if (total < 0) return "INVALID";
    if (total >= 1000) return "BULK";
    return "STANDARD";
}
