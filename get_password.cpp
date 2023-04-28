#include "head.h"

void get_password(char* password) {
    HANDLE hStdin;
    DWORD mode;

    hStdin = GetStdHandle(STD_INPUT_HANDLE);
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));

    scanf("%s", password);

    SetConsoleMode(hStdin, mode);
}