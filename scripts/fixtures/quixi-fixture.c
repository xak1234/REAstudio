__declspec(dllexport) __declspec(noinline) int quixi_add(int a, int b) {
    return a + b;
}
int main(void) {
    return quixi_add(20, 22) == 42 ? 0 : 1;
}
