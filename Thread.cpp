#include "head.h"
char *name;
char msg[MAX_BUF_SIZE];

DWORD WINAPI send_msg(LPVOID lpParam)
{
	SSL* ssl = ((SSL*)lpParam);
	char name_msg[NAME_SIZE + MAX_BUF_SIZE];
	for(;;)
	{
		
		fgets(msg, MAX_BUF_SIZE, stdin);
		if (!strcmp(msg, "q\n") || !strcmp(msg, "Q\n"))
		{
			TerminateThread(hThread[0], 0);
			ExitThread(0);
		}
		sprintf(name_msg, "[%s]: %s", name, msg);
		SSL_write(ssl, name_msg, strlen(name_msg));
		//int nRecv = send(sock, name_msg, strlen(name_msg), 0);
	}
	return NULL;
}

DWORD WINAPI recv_msg(LPVOID lpParam)
{
	SSL* ssl = ((SSL*)lpParam);
	char name_msg[NAME_SIZE + MAX_BUF_SIZE];
	int str_len;
	for(;;)
	{
		str_len = SSL_read(ssl, name_msg, NAME_SIZE + MAX_BUF_SIZE);
		if (str_len <= 0) {
			TerminateThread(hThread[1], 0);
			ExitThread(0);
		}
		name_msg[str_len] = 0;
		fputs(name_msg, stdout);
	}
	return NULL;
}

void error_handling(const char* msg)
{
	printf("%s\n", msg);
	WSACleanup();
	exit(1);
}