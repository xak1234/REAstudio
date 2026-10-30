/* Owned runtime fixture for REA Studio's import-reconstruction checks.
 * No CRT startup, global constructors, heap allocation, or external files.
 * Both the original and rebuilt executable must write exactly this one line.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

__declspec(noreturn) void WINAPI entry(void)
{
    static const char message[] = "REA_IAT_OK=42\r\n";
    const DWORD message_size = (DWORD)(sizeof(message) - 1U);
    DWORD written = 0;
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);

    if (output == NULL || output == INVALID_HANDLE_VALUE) {
        ExitProcess(2U);
    }
    if (!WriteFile(output, message, message_size, &written, NULL)
        || written != message_size) {
        ExitProcess(3U);
    }
    ExitProcess(0U);
}
