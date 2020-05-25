#define _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include<iostream>
#include<WinSock2.h>
#include<windows.h>
#include<ws2tcpip.h>
#include<string.h>
#include<fstream>
#include <thread>
#include<ctime>
#include<ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#define M220 "220 localhost\r\n"
#define M250_1 "250-SIZE 4096\r\n250 OK\r\n"
#define M250_2 "250 OK\r\n"
#define M354 "354 End with \".\"\r\n"
#define M221 "221 Bye\r\n"
#define RMEMSET memset(rbuf,0,4096)
#define SMEMSET memset(sbuf,0,4096)
#define SFPRNT fprintf(logfile, "Send: %s\n", sbuf)
#define RFPRNT fprintf(logfile, "Recv: %s\n", rbuf)
#define SEND send(sockfd, sbuf, strlen(sbuf), 0)
#define RECV recv(sockfd, rbuf, 4096, 0)
#define SERVER_PORT 25
#define SERVER_PORTS 465
#define c0 0
#define c1 1
#define c2 2
#define c3 3
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")
#pragma comment(lib,"ws2_32")
using namespace std;

char*host = (char*)malloc(150);
char*port = (char*)malloc(30);
char*emailfrom = (char*)malloc(150);
char*pass = (char*)malloc(100);
char*subject = (char*)malloc(60);
char*filename = (char*)malloc(70);
char*emailcontain = (char*)malloc(4096);
short*porttomail = (short*)malloc(30);
char addrFrom[40] = { '0' };
char addrTo[10][40] = { '0' };
int tonum = 0;
FILE*logfile;

struct Base64Date6
{
	unsigned int d4 : 6;
	unsigned int d3 : 6;
	unsigned int d2 : 6;
	unsigned int d1 : 6;
};

char ConvertToBase64(char uc)
{
	if (uc < 26)
	{
		return 'A' + uc;
	}
	if (uc < 52)
	{
		return 'a' + (uc - 26);
	}
	if (uc < 62)
	{
		return '0' + (uc - 52);
	}
	if (uc == 62)
	{
		return '+';
	}
	return '/';
}//  Э���м��ܲ���ʹ�õ���base64����

void EncodeBase64(char *dbuf, char *buf128, int len)
{
	struct Base64Date6 *ddd = NULL;
	int i = 0;
	char buf[256] = { 0 };
	char *tmp = NULL;
	char cc = '\0';
	memset(buf, 0, 256);
	strcpy(buf, buf128);
	for (i = 1; i <= len / 3; i++)
	{
		tmp = buf + (i - 1) * 3;
		cc = tmp[2];
		tmp[2] = tmp[0];
		tmp[0] = cc;
		ddd = (struct Base64Date6*)tmp;
		dbuf[(i - 1) * 4 + 0] = ConvertToBase64((unsigned int)ddd->d1);
		dbuf[(i - 1) * 4 + 1] = ConvertToBase64((unsigned int)ddd->d2);
		dbuf[(i - 1) * 4 + 2] = ConvertToBase64((unsigned int)ddd->d3);
		dbuf[(i - 1) * 4 + 3] = ConvertToBase64((unsigned int)ddd->d4);
	}
	if (len % 3 == 1)
	{
		tmp = buf + (i - 1) * 3;
		cc = tmp[2];
		tmp[2] = tmp[0];
		tmp[0] = cc;
		ddd = (struct Base64Date6*)tmp;
		dbuf[(i - 1) * 4 + 0] = ConvertToBase64((unsigned int)ddd->d1);
		dbuf[(i - 1) * 4 + 1] = ConvertToBase64((unsigned int)ddd->d2);
		dbuf[(i - 1) * 4 + 2] = '=';
		dbuf[(i - 1) * 4 + 3] = '=';
	}
	if (len % 3 == 2)
	{
		tmp = buf + (i - 1) * 3;
		cc = tmp[2];
		tmp[2] = tmp[0];
		tmp[0] = cc;
		ddd = (struct Base64Date6*)tmp;
		dbuf[(i - 1) * 4 + 0] = ConvertToBase64((unsigned int)ddd->d1);
		dbuf[(i - 1) * 4 + 1] = ConvertToBase64((unsigned int)ddd->d2);
		dbuf[(i - 1) * 4 + 2] = ConvertToBase64((unsigned int)ddd->d3);
		dbuf[(i - 1) * 4 + 3] = '=';
	}
	return;
}

void change_time(char p[], char *tim) {
	int pos = 0, pos1 = 0, flag = 0, i = 0;
	int j = 0;
	char str1[200];
	char str2[200];
	int len = strlen(tim);
	memset(str1, 0, sizeof(str1));
	memset(str2, 0, sizeof(str2));
	memset(p, 0, sizeof(p));
	while (tim[i] != '\0')
	{
		if (tim[i] == ' ')
			flag++;
		if (flag == 1 && !pos)
			pos = i;
		else if (flag == 4 && !pos1)
			pos1 = i;

		i++;
	}

	j = 0;
	for (i = pos; i < pos1; )
		str1[j++] = tim[i++];
	str1[j] = '\0';
	int len1 = strlen(str1);
	for (i = 0; i < len1; ++i) {
		if (str1[i] == ':') {
			for (j = i; j < len1; ++j)
				str1[j] = str1[j + 1];
			len1--;
		}
	}

	j = 0;
	for (i = pos1 + 1; i < len - 1; )
		str2[j++] = tim[i++];
	str2[j] = '\0';


	char p1[100] = "log_";
	char p2[100] = ".txt";

	j = 0;
	for (i = 0; i < strlen(p1);)
		p[j++] = p1[i++];
	for (i = 0; i < strlen(str2); )
		p[j++] = str2[i++];
	for (i = 0; i < strlen(str1); )
		p[j++] = str1[i++];
	for (i = 0; i < strlen(p2); )
		p[j++] = p2[i++];
	p[j] = '\0';
	for (i = 0; i < strlen(p); ++i) {
		if (p[i] == ' ')
			p[i] = '_';
	}

}

boolean getfile(char*emailto, char*host, char*port, char*emailfrom, /*char*pass,char*subject,*/ char*filename)
{

	char*From = new char[200];
	sprintf(From, "From: <%s>\r\n", emailfrom);//��emailform�е���Ϣ����"From"д��From
	emailfrom = From;
	char*To = new char[200];
	sprintf(To, "To:<%s>\r\n", emailto);
	emailto = To;
	short Port = 0;
	int i = 0;
	for (i = 0; i < strlen(port); i++)
	{
		Port = Port * 10 + port[i] - '0';
	}//���˿ں�ת��������
	*porttomail = Port;

	FILE*f;
	f = fopen(filename, "rb");
	if (!f)
	{
		printf("Cannot Open target Flie\n");
		return false;
	}
	fseek(f, 0L, SEEK_END);
	int size = ftell(f);
	fseek(f, 0L, SEEK_SET);
	cout << size << endl;
	char*contain = (char*)malloc(sizeof(char)*size);
	fread(contain, 1, size, f);//д��contain
	fclose(f);
	sprintf(emailcontain, "%s%s%s", From, To, /*Subject,*/ contain);
	//cout << emailcontain << endl;
	free(contain);
	return true;


}

void getAddr(char buf[], char addr[])
{
	long lenth;
	lenth = (long)strchr(buf, '>') - (long)strchr(buf, '<') - 1;
	strncpy(addr, (strchr(buf, '<') + 1), lenth);
}

int checkusername(char username[40])
{
	int s; s = c0; int flag = 0;
	for (int i = 0; i <= strlen(username); i++)
	{
		if (username[i] != '@')continue;
		else {
			s = c1;  flag = i; break;
		}
	}
	if (s == c0) return 0;

	for (int j = flag; j <= strlen(username); j++)
	{
		if (username[j] == '.') {
			s = c2; flag = j; break;
		}
	}
	if (s == c1) return 0;

	for (int k = flag; k <= strlen(username); k++)
	{
		if (username[k] == 'c') { s = c3; break; }
	}
	if (s == c2)return 0;
	if (s == c3)return 1;
}

void findIp(char *ip, int size) {
	WORD v = MAKEWORD(1, 1);
	WSADATA wsaData;
	WSAStartup(v, &wsaData); // �����׽��ֿ�  
	struct hostent *phostinfo = gethostbyname("");
	char *p = inet_ntoa(*((struct in_addr *)(*phostinfo->h_addr_list)));
	strncpy(ip, p, size - 1);
	ip[size - 1] = '\0';
	WSACleanup();
}

void receive(int sockfd, char addrFrom[], char addrTo[10][40], int&num)
{
	FILE *fp;
	fp = fopen("C:\\Users\\DELL\\source\\repos\\ttest\\Debug\\mail.txt", "w+");
	num = 0;
	 addrFrom[40] = { '0' };
	 addrTo[10][40] = { '0' };
	char p[200] = { '0' };
	time_t now = time(0);
	char*tim = ctime(&now);
	char*tim2 = ctime(&now);
	change_time(p, tim);
	logfile = fopen(p, "w+");
	setbuf(logfile, NULL);
	printf("this is logfile::%s\n", p);
	char k[80];
	sprintf_s(k, "-------this is a receive logfile-------");
	fprintf(logfile, "%s\n", k);
	printf("Date:%s\n", tim2);
	char sbuf[4096] = { 0 };
	char rbuf[4096] = { 0 };


	SMEMSET;
	sprintf_s(sbuf, M220);
	SFPRNT;
	SEND;//��220

	RMEMSET;
	RECV;
	RFPRNT;//��ehlo

	SMEMSET;
	sprintf_s(sbuf, M250_1);
	SFPRNT;
	SEND;//��250���ظ�ehlo��

	RMEMSET;
	RECV;
	getAddr(rbuf, addrFrom);//�շ�����
	printf("FROM: %s\n",addrFrom);

	SMEMSET;
	sprintf_s(sbuf, M250_2);
	SFPRNT;
	SEND;//��ȷ��ok

	while (1)
	{
		RMEMSET;
		RECV;
		RFPRNT;//���ռ���

		int flag = checkusername(rbuf);
		if (flag == 0 && rbuf[0] != 'D')
		{
			send(sockfd, "502 Mail Name Error!\r\n", strlen("502 Mail Name Error!\r\n"), 0);
			fprintf(logfile,"502 Mail Name Error!\r\n" );
			return;
		}
		if (rbuf[0] != 'R')
			break;
		else
		{
			getAddr(rbuf, addrTo[num]);
			printf("To: %s\r\n", addrTo[num]);
			num++;
			SMEMSET;
			sprintf_s(sbuf, M250_2);
			SFPRNT;
			SEND;//��250 ok
		}
	}

	SMEMSET;
	sprintf_s(sbuf, M354);
	SFPRNT;
	SEND;//��354��׼�������ʼ�����

	while (1)
	{
		RMEMSET;
		RECV;
		RFPRNT;//���Ľ���
		int lenth = strlen(rbuf);
		if (rbuf[lenth - 5] == '\r'&&rbuf[lenth - 4] == '\n'&&rbuf[lenth - 3] == '.'&&rbuf[lenth - 2] == '\r'&&rbuf[lenth - 1] == '\n')
		{
			char temp[4096] = { 0 };
			strncpy(temp, rbuf, lenth - 5);
			fprintf(fp, "%s", temp);
			fprintf(logfile, "%s", temp);
			break;
		}
		else
		{
			fprintf(fp, "%s", rbuf);
			fprintf(logfile, "%s", rbuf);
		}

	}
	SMEMSET;
	sprintf_s(sbuf, M250_2);
	SFPRNT;
	SEND;//��250ȷ�Ͻ���

	RMEMSET;
	RECV;
	RFPRNT;	//��quit

	SMEMSET;
	sprintf_s(sbuf, M221);
	SFPRNT;
	SEND;//��221�ر�����
	
	fclose(fp);
}

int openSocketRMail()
{
	int sockfd = 0;
	int abind = 0;
	int alisten = 0;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	int addr_len = sizeof(client_addr);
	int client = 0;
	memset(&server_addr, 0, sizeof(server_addr));
	memset(&client_addr, 0, sizeof(client_addr));

	
	WSADATA wsaData;// WSADATA�ṹ������Ҫ������ϵͳ��֧�ֵ�Winsock�汾��Ϣ
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	sockfd = socket(PF_INET, SOCK_STREAM, 0);//�����׽���

	if (sockfd < 0)
	{
		cout << "Open sockfd(TCP) error!" << endl;
		exit(-1);//����������
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(SERVER_PORT);
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	abind = ::bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));//�󶨶˿�
	if (abind < 0)
	{
		cout << " Bind error!" << endl;
		exit(-1);//����������
	}
	alisten = listen(sockfd, 9);//����
	if (alisten < 0)
	{
		cout << " Listen error!" << endl;
		exit(-1);//����������
	}

	printf("Listening on port: %d\n", SERVER_PORT);
	client = accept(sockfd, (struct sockaddr*)&client_addr, (socklen_t*)&addr_len);	
	char ip[20] = { 0 };
	findIp(ip, sizeof(ip));                                                 //��ȡ������ַ 
	printf("�ʼ��ͻ���IP��ַ��Mail client IP����127.0.0.1\n");				//���client ip 
	printf("�ʼ��ͻ��˶˿ںţ�Mail client host����25\n");				    //���client�˿�  
	printf("SMTP����IP��ַ��SMTP IP����%s \n", ip);//���SMTP����ip 
	printf("SMTP����Ķ˿ںţ�SMTP Port����%d\n ", ntohs(client_addr.sin_port)); 
	receive(client, addrFrom, addrTo, tonum);
	//sockfd�����ڼ���״̬��client������պͷ�������

	closesocket(client);
	closesocket(sockfd);
}

void send(int sockfd,int i)
{
	char buf[2500] = { 0 };
	char rbuf[1500] = { 0 };
	char login[200] = { 0 };
	char password[200] = { 0 };

	memset(rbuf, 0, 1500);
	recv(sockfd, rbuf, 1500, 0);
	fprintf(logfile, "%s\n", rbuf);

	memset(buf, 0, 2500);
	sprintf_s(buf, "EHLO HYL-PC\r\n");// EHLO
	send(sockfd, buf, strlen(buf), 0);
	memset(rbuf, 0, 1500);
	recv(sockfd, rbuf, 1500, 0);//EHLO Receive
	fprintf(logfile, "%s\n", rbuf);

	memset(buf, 0, 2500);
	sprintf_s(buf, "AUTH LOGIN\r\n");// AUTH LOGIN
	send(sockfd, buf, strlen(buf), 0);
	fprintf(logfile, "%s\n", buf);
	memset(rbuf, 0, 1500);
	recv(sockfd, rbuf, 1500, 0);//Auth Login Receive:
	fprintf(logfile, "%s\n", rbuf);
	
	memset(buf, 0, 2500);
	sprintf_s(buf, emailfrom);//user
	memset(login, 0, 128);
	EncodeBase64(login, buf, strlen(buf));//cBase64 UserName
	sprintf_s(buf, "%s\r\n", login);
	send(sockfd, buf, strlen(buf), 0);
	fprintf(logfile, "%s\n", buf);
	
	memset(rbuf, 0, 1500);
	recv(sockfd, rbuf, 1500, 0);//User Login Receive
	fprintf(logfile, "%s\n", rbuf);
	
	sprintf_s(buf, pass);//password
	memset(password, 0, 128);
	EncodeBase64(password, buf, strlen(buf));
	sprintf_s(buf, "%s\r\n", password);
	send(sockfd, buf, strlen(buf), 0);//Base64 Password
	fprintf(logfile, "%s\n", buf);
	
	memset(rbuf, 0, 1500);
	recv(sockfd, rbuf, 1500, 0);
	fprintf(logfile, "%s\n", rbuf);

	memset(buf, 0, 2500);
	sprintf_s(buf, "MAIL FROM: <%s>\r\n", emailfrom);
	send(sockfd, buf, strlen(buf), 0);
	fprintf(logfile, "%s\n", buf);
	memset(rbuf, 0, 1500);
	recv(sockfd, rbuf, 1500, 0);
	fprintf(logfile, "%s\n", rbuf);
	
	memset(buf, 0, 2500);
	sprintf_s(buf, "RCPT TO:<%s>\r\n", addrTo[i]);
	send(sockfd, buf, strlen(buf), 0);
	fprintf(logfile, "%s\n", buf);
	memset(rbuf, 0, 1500);
	recv(sockfd, rbuf, 1500, 0);
	fprintf(logfile, "%s\n", rbuf);
	
	memset(buf, 0, 2500);
	sprintf_s(buf, "DATA\r\n");// DATA ׼����ʼ�����ʼ�����
	send(sockfd, buf, strlen(buf), 0);
	fprintf(logfile, "%s\n", buf);
	memset(buf, 0, 1500);
	recv(sockfd, rbuf, 1500, 0);//Send Mail Prepare Receive
	fprintf(logfile, "%s\n", rbuf);

	memset(buf, 0, 2500);
	sprintf_s(buf, "%s\r\n.\r\n", emailcontain);// �����ʼ����ݣ�\r\n.\r\n���ݽ������
	send(sockfd, buf, strlen(buf), 0);
	fprintf(logfile, "%s\n", buf);
	memset(rbuf, 0, 1500);
	recv(sockfd, rbuf, 1500, 0);
	fprintf(logfile, "%s\n", rbuf);

	memset(buf, 0, 2500);
	sprintf_s(buf, "QUIT\r\n");
	send(sockfd, buf, strlen(buf), 0);
	fprintf(logfile, "%s\n", buf);
	memset(rbuf, 0, 1500);
	recv(sockfd, rbuf, 1500, 0);
	fprintf(logfile, "%s\n", rbuf);

	closesocket(sockfd);

}
void mail()
{
	while (1) {
		int sockfd = 0;
		openSocketRMail();
		WSADATA wsaData;
		WSAStartup(MAKEWORD(2, 2), &wsaData);
		struct sockaddr_in destiAddr = { 0 };//Internet ��ַ
		memset(&destiAddr, 0, sizeof(destiAddr));
		destiAddr.sin_family = AF_INET;//IPV4
		destiAddr.sin_port = htons(SERVER_PORT);
		hostent *hptr = gethostbyname(host);
		memcpy(&destiAddr.sin_addr.S_un.S_addr, hptr->h_addr_list[0], hptr->h_length);

		printf("IP of %s is : %d:%d:%d:%d\n",
			host,
			destiAddr.sin_addr.S_un.S_un_b.s_b1,
			destiAddr.sin_addr.S_un.S_un_b.s_b2,
			destiAddr.sin_addr.S_un.S_un_b.s_b3,
			destiAddr.sin_addr.S_un.S_un_b.s_b4);

		for (int i = 0; i < tonum; i++) {

			sockfd = socket(PF_INET, SOCK_STREAM, 0);
			if (sockfd < 0)
			{
				cout << "Open sockfd(TCP) error!" << endl;
				exit(-1);//����������
			}

			if (connect(sockfd, (struct sockaddr *)&destiAddr, sizeof(struct sockaddr)) < 0)//�ͻ��˵������֣��������ĵ�ַ����ַ����
			{

				cout << "Connect sockfd(TCP) error!" << endl;
				exit(-1);
			}
			fprintf(logfile, "-------this is a send logfile-------");
			getfile(addrTo[i], host, port, addrFrom, filename);
			send(sockfd, i);
		}
		//��������
	
	WSACleanup();
	//return;
}
}

void sslMail()
{
	while (1) {
		int ssockfd = 0;
		int sockfd = 0;
		char buf[2500] = { 0 };
		char rbuf[4096] = { 0 };
		char sbuf[4096] = { 0 };
		char login[200] = { 0 };
		char password[200] = { 0 };
		int rsockfd = 0;
		int abind = 0;
		int alisten = 0;
		struct sockaddr_in server_addr;
		struct sockaddr_in client_addr;
		int addr_len = sizeof(client_addr);
		int client = 0;

		const SSL_METHOD *fox = { 0 };//��Foxmail����ʱ�ļ��ܷ���
		const SSL_METHOD *ser; //�����������ʱ�ļ��ܷ���
		SSL_CTX* foxtx;		//SSL����֤�飬��Foxmailͨ��
		SSL_CTX* sertx;
		SSL* ssl;//����ʱʹ��
		X509* client_cert;
		char* str;
		WSADATA wsaData;
		WSAStartup(MAKEWORD(2, 2), &wsaData);
		struct sockaddr_in destiAddr = { 0 };
		X509* scert;
		memset(&destiAddr, 0, sizeof(destiAddr));
		destiAddr.sin_family = AF_INET;//IPV4
		destiAddr.sin_port = htons(SERVER_PORTS);
		hostent *hptr = gethostbyname(host);
		memcpy(&destiAddr.sin_addr.S_un.S_addr, hptr->h_addr_list[0], hptr->h_length);
		memset(&server_addr, 0, sizeof(server_addr));
		memset(&client_addr, 0, sizeof(client_addr));

		ssockfd = socket(PF_INET, SOCK_STREAM, 0);//�����׽���

		if (ssockfd < 0)
		{
			cout << "Open sockfd(TCP) error!" << endl;
			exit(-1);//����������
		}

		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(SERVER_PORTS);
		server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

		abind = ::bind(ssockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));//�󶨶˿�
		if (abind < 0)
		{
			cout << " Bind error!" << endl;
			exit(-1);//����������
		}

		alisten = listen(ssockfd, 9);//����
		if (alisten < 0)
		{
			cout << " Listen error!" << endl;
			exit(-1);//����������
		}

		//foxmail��ʼ��
		SSL_METHOD *method = NULL;
		SSL_library_init();
		SSL_load_error_strings();
		OpenSSL_add_ssl_algorithms();
		SSLeay_add_ssl_algorithms();
		fox = SSLv23_server_method();
		//fox = TLSv1_server_method();
		foxtx = SSL_CTX_new(SSLv23_server_method());
		//foxtx = SSL_CTX_new(TLSv1_server_method());
		if (!foxtx) {
			cout << "error!" << endl;
			exit(-1);//����������
		}
		if (SSL_CTX_use_certificate_file(foxtx, /*CERTF*/"server.pem", SSL_FILETYPE_PEM) <= 0) {
			cout << "error!" << endl;
			exit(-1);//����������
		}
		if (SSL_CTX_use_PrivateKey_file(foxtx, /*KEYF*/"server.pem", SSL_FILETYPE_PEM) <= 0) {
			cout << "error!" << endl;
			exit(-1);//����������
		}
		if (!SSL_CTX_check_private_key(foxtx)) {
			fprintf(stderr, "The private Key don��t match with the certificate\n");
			exit(5);
		}

		//���������ʼ��
		SSLeay_add_ssl_algorithms();
		ser = TLSv1_method();
		SSL_load_error_strings();
		sertx = SSL_CTX_new(ser);

		printf("Listening on port: %d\n", SERVER_PORTS);
		int len = sizeof(client_addr);
		client = accept(ssockfd, (struct sockaddr*)&client_addr, (socklen_t*)&len);
		//��ssl
		ssl = SSL_new(foxtx);
		SSL_set_fd(ssl, client);
		alisten = SSL_accept(ssl);
		SSL_CTX_load_verify_locations(foxtx, "server.pem", NULL);
		//��ӡ֤����Ϣ
		printf("SSL connection using %s\n", SSL_get_cipher(ssl));
		client_cert = SSL_get_certificate(ssl); SSL_get_peer_certificate(ssl);
		printf("%d", client_cert);
		if (client_cert != NULL) {
			printf("Client Certificate:\n");
			str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
			if (str == NULL)
				exit(-1);
			printf("\t subject: %s\n", str);
			OPENSSL_free(str);
			str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
			if (str == NULL)
				exit(-1);
			printf("\t issuer: %s\n", str);
			OPENSSL_free(str);
			X509_free(client_cert);
		}
		else
			printf("The Client hasn��t certificate.\n");
		char ip[20] = { 0 };
		findIp(ip, sizeof(ip));
		printf("�ʼ��ͻ���IP��ַ��Mail client IP����127.0.0.1\n");				//���client ip 
		printf("�ʼ��ͻ��˶˿ںţ�Mail client host����465\n");				    //���client�˿�  
		printf("SMTP����IP��ַ��SMTP IP����%s \n", ip);	
		printf("SMTP����Ķ˿ںţ�SMTP Port����%d\n ", ntohs(client_addr.sin_port));//���SMTP����ip   
		 addrFrom[40] = { '0' };
		 addrTo[10][40] = { '0' };
		const char *sendBuf[] = {                                   //���ͱ�ʾ��
			"220 LXY's SMTP Ready\r\n",
			"250 LXY's server|250 mail|250 PIPELINING\r\n",
			"250 OK\r\n",
			"250 OK\r\n",
			"354 Start mail input;end with <CR><LF>.<CR><LF>\r\n",
			"250 OK\r\n",
			"250 OK\r\n",
			"221 Bye\r\n",
			"502 Mail Name Error!\r\n" };

		FILE *fp;
		fp = fopen("C:\\Users\\DELL\\source\\repos\\ttest\\Debug\\mail.txt", "w+");//�洢�ʼ�����
		char p[200] = { '0' };
		tonum = 0;
		time_t now = time(0);
		char* txt;
		char*tim = ctime(&now);
		char*tim2 = ctime(&now);
		change_time(p, tim);
		logfile = fopen(p, "w+");
		setbuf(logfile, NULL);
		printf("this is logfile::%s\n", p);
		char k[80];
		sprintf_s(k, "-------this is a receive logfile-------");
		fprintf(logfile, "%s\n", k);
		fflush(logfile);
		printf("Date:%s\n", tim2);//�����ǰʱ��

		SSL_write(ssl, sendBuf[0], (int)strlen(sendBuf[0]));//��220
		fprintf(logfile, "%s\n", sendBuf[0]);
		fflush(fp);
		SSL_read(ssl, rbuf, sizeof(rbuf));//��ehlo
		fprintf(logfile, "%s\n", rbuf);
		fflush(fp);

		memset(rbuf, 0, sizeof(rbuf));
		SSL_write(ssl, sendBuf[1], strlen(sendBuf[1])); // send:250 OK
		fprintf(logfile, "%s\n", sendBuf[1]);
		SSL_read(ssl, rbuf, sizeof(rbuf)); //recv:MAIL FROM:<...> 
		getAddr(rbuf, addrFrom);
		printf("FROM: %s\n", addrFrom);
		fprintf(logfile, "%s\n", rbuf);
		fflush(fp);

		memset(rbuf, 0, sizeof(rbuf));
		SSL_write(ssl, sendBuf[2], strlen(sendBuf[2])); //send:250 OK
		fprintf(logfile, "%s\n", sendBuf[2]);

		while (1)
		{
			memset(rbuf, 0, sizeof(rbuf));
			SSL_read(ssl, rbuf, sizeof(rbuf));
			fprintf(logfile, "%s\n", rbuf);
			//���ռ���

			int flag = checkusername(rbuf);
			if (flag == 0 && rbuf[0] != 'D')
			{
				SSL_write(ssl, sendBuf[8], strlen(sendBuf[8]));
				fprintf(logfile, "%s\n", sendBuf[8]);
				return;
			}
			if (rbuf[0] != 'R')
			{
				break;
			}
			else
			{
				getAddr(rbuf, addrTo[tonum]);
				printf("To: %s\r\n", addrTo[tonum]);
				tonum++;
				SSL_write(ssl, sendBuf[3], strlen(sendBuf[3]));
				fprintf(logfile, "%s\n", rbuf);
				fprintf(logfile, "%s\n", sendBuf[3]);
				//��250 ok
			}
		}

		memset(rbuf, 0, sizeof(rbuf));
		SSL_write(ssl, sendBuf[4], strlen(sendBuf[4]));//354
		fprintf(logfile, "%s\n", sendBuf[4]);

		while (1)
		{
			memset(rbuf, 0, sizeof(rbuf));
			SSL_read(ssl, rbuf, sizeof(rbuf));
			fprintf(logfile, "%s\n", rbuf);

			//���Ľ���
			int lenth = strlen(rbuf);
			if (rbuf[lenth - 5] == '\r'&&rbuf[lenth - 4] == '\n'&&rbuf[lenth - 3] == '.'&&rbuf[lenth - 2] == '\r'&&rbuf[lenth - 1] == '\n')
			{
				char temp[4096] = { 0 };
				strncpy(temp, rbuf, lenth - 5);
				fprintf(fp, "%s", temp);
				fprintf(logfile, "%s", temp);
				break;
			}
			else
			{
				fprintf(fp, "%s", rbuf);
				fprintf(logfile, "%s", rbuf);
			}

		}

		memset(rbuf, 0, sizeof(rbuf));
		SSL_write(ssl, sendBuf[5], strlen(sendBuf[5]));
		fprintf(logfile, "%s", sendBuf[5]);
		//��250ȷ�Ͻ���

		memset(rbuf, 0, sizeof(rbuf));
		SSL_read(ssl, rbuf, sizeof(rbuf));//quit
		fprintf(logfile, "%s\n", rbuf);

		memset(rbuf, 0, sizeof(rbuf));
		SSL_write(ssl, sendBuf[7], strlen(sendBuf[7]));//221
		fprintf(logfile, "%s", sendBuf[7]);

		fclose(fp);
		closesocket(client);
		closesocket(ssockfd);
		SSL_free(ssl);

		for (int i = 0; i < tonum; i++) {
			struct sockaddr_in destiAddr = { 0 };
			//sockfd = socket(AF_INET, SOCK_STREAM, 0);
			memset(&destiAddr, 0, sizeof(destiAddr));
			destiAddr.sin_family = AF_INET;
			destiAddr.sin_port = htons(SERVER_PORT);
			hostent *hptr = gethostbyname(host);
			memcpy(&destiAddr.sin_addr.S_un.S_addr, hptr->h_addr_list[0], hptr->h_length);

			printf("IP of %s is : %d:%d:%d:%d\n",
				host,
				destiAddr.sin_addr.S_un.S_un_b.s_b1,
				destiAddr.sin_addr.S_un.S_un_b.s_b2,
				destiAddr.sin_addr.S_un.S_un_b.s_b3,
				destiAddr.sin_addr.S_un.S_un_b.s_b4);

			
				sockfd = socket(PF_INET, SOCK_STREAM, 0);
				if (sockfd < 0)
				{
					cout << "Open sockfd(TCP) error!" << endl;
					exit(-1);//����������
				}
				if (connect(sockfd, (struct sockaddr *)&destiAddr, sizeof(struct sockaddr)) < 0)//�ͻ��˵������֣��������ĵ�ַ����ַ����
				{
					cout << "Connect sockfd(TCP) error!" << endl;
					exit(-1);
				}
				fprintf(logfile, "-------this is a send logfile-------");
				getfile(addrTo[i], host, port, addrFrom, filename);
				send(sockfd, i);
			}
			WSACleanup();//��������
			//return;
		}
	}

int main(void)
{
	cout << "Enter the domain name of actual mail server: \n" << endl;
	cin >> host;
	const char*eemailfrom = "";//发件人邮箱
	strcpy(emailfrom, eemailfrom);
	const char*ppass = "";//登陆密码
	strcpy(pass, ppass);
	const char*ffilename = "C:\\Users\\DELL\\source\\repos\\ttest\\Debug\\mail.txt";
	strcpy(filename, ffilename);
		thread t1(mail);
		thread t2(sslMail);
		t1.join();
		t2.join();
	system("pause");

}