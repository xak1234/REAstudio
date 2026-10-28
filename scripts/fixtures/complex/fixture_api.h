#pragma once

#ifdef REA_FIXTURE_BUILD
#define REA_FIXTURE_API extern "C" __declspec(dllexport) __declspec(noinline)
#else
#define REA_FIXTURE_API extern "C" __declspec(dllimport)
#endif

REA_FIXTURE_API int rea_price(int quantity, int tier);
REA_FIXTURE_API const char* rea_band(int total);
REA_FIXTURE_API int rea_emit_invoice(const char* path, int quantity, int tier);
