// md5.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include <SDKDDKVer.h>
#include <stdio.h>
#include <io.h>
#include <tchar.h>
#include <locale.h>
#include <windows.h>
#include "getopt.h"
#include "ansicolor.h"

#define SIZEOF_ARRAY(x) ((sizeof(x))/(sizeof(x[0])))

//MD5�ṹ����
typedef struct {
	ULONG i[2];
	ULONG buf[4];
	unsigned char in[64];
	unsigned char digest[16];
} MD5_CTX;

#define MD5DIGESTLEN 16
#define PROTO_LIST(list) list

typedef void (WINAPI* PMD5Init)(MD5_CTX *);
typedef void (WINAPI* PMD5Update)(MD5_CTX *, const UINT8 *, UINT32);
typedef void (WINAPI* PMD5Final)(MD5_CTX *);
const TCHAR* MD5_DLL_NAME = _T("advapi32.dll");

typedef struct {
	HINSTANCE hDLL;
	PMD5Init MD5Init;
	PMD5Update MD5Update;
	PMD5Final MD5Final;
} MD5_CLS;

//���ÿ���̨���ԣ�8�ֽ�λ�����ҷֱ�Ϊ�����������������죬�̣�����ǰ��������ǰ���죬�̣���
void set_output_color(WORD color){
	static HANDLE std_handle = NULL;
	if(std_handle == NULL) std_handle = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(std_handle, color);
}

typedef struct {
	BOOL is_help;
	BOOL is_check;
	TCHAR root_dir[256];
	TCHAR out_file[256];
} CMD_LINE;
CMD_LINE cmd;

#define STATIC_GETOPT
const struct option long_options[] = {
	{ _T("help"), no_argument, NULL, _T('h') },
	{ _T("file"), required_argument, NULL, _T('f') },
	{ _T("check"), no_argument, NULL, _T('c') },
	{ NULL, 0, NULL, 0 }
};
const TCHAR* SHORT_OPT_STR = _T("-hcf:");

const TCHAR* DEF_ROOT_DIR = _T("");
const TCHAR* DEF_OUT_FILE = _T("md5checksum.txt");

void hex2str(const byte *hex, int len, LPTSTR str) {
	int i;
	for (i = 0; i < len; i++) {
		str[i * 2] = "0123456789abcdef"[hex[i] >> 4];
		str[i * 2 + 1] = "0123456789abcdef"[hex[i] & 0x0F];
	}
	str[i * 2] = '\0';
}

void str2hex(LPCTSTR str, byte* buf) {
	byte b;
	TCHAR c;
	int count = 1;
	while(c = *str++) {
		if(c >= _T('0') && c <= _T('9')) b = (c - 0x30);
		else b = (c - 0x61 + 10);
		if(count > 1) {
			count = 1;
			*(buf++) |= b;
		}
		else {
			*buf = b << 4;
			count++;
		}
	}
}

BOOL md5_init(MD5_CLS* pmd5){
	HINSTANCE h;
	if ((h = LoadLibrary(MD5_DLL_NAME)) != NULL) {
		pmd5->hDLL = h;
		pmd5->MD5Init = (PMD5Init)GetProcAddress(h,"MD5Init");
		pmd5->MD5Update = (PMD5Update)GetProcAddress(h,"MD5Update");
		pmd5->MD5Final = (PMD5Final)GetProcAddress(h,"MD5Final");
	}
	return (h != NULL) ? TRUE : FALSE;
}

void md5_checksum(MD5_CLS* pmd5, const byte* src, int srclen, LPTSTR dst) {
	MD5_CTX ctx;
	pmd5->MD5Init(&ctx);
	pmd5->MD5Update(&ctx, src, srclen);
	pmd5->MD5Final(&ctx);
	hex2str(ctx.digest, 16, dst);
}

void usage(){
	set_output_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	_tprintf(_T("md5 - create list of md5 checksums over all in directory.\n"));
	set_output_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	_tprintf(_T("Release 1.0 base of 2015-12-15.\n"));
	_tprintf(_T("Kivensoft, http://kiven.vicp.net/\n"));
	_tprintf(_T("Distributed for free under the GNU Open Source License, without any warranty.\n\n"));

	set_output_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
	_tprintf(_T("md5 [options] [directory]\n"));
	set_output_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	_tprintf(_T("    options:\n"));
	set_output_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	_tprintf(_T("\t-f, --file"));
	set_output_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	_tprintf(_T("\t\t<filename> - md5 checksum file name.\n"));
	set_output_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	_tprintf(_T("\t-c, --check"));
	set_output_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	_tprintf(_T("\t\tdefine to checksum, if none, to gento.\n"));
	set_output_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	_tprintf(_T("\t-h, --help"));
	set_output_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	_tprintf(_T("\t\tshow help."));
}

void parse_options(int argc, _TCHAR* argv[], CMD_LINE* pcmdline) {
	pcmdline->is_help = FALSE;
	pcmdline->is_check = FALSE;
	_tcscpy_s(pcmdline->root_dir, SIZEOF_ARRAY(pcmdline->root_dir), DEF_ROOT_DIR);
	_tcscpy_s(pcmdline->out_file, SIZEOF_ARRAY(pcmdline->out_file), DEF_OUT_FILE);

	int idx = 0, c;
	while((c = getopt_long(argc, argv, SHORT_OPT_STR, long_options, &idx)) != -1) {
		switch(c){
		case _T('c'):
			pcmdline->is_check = TRUE;
			break;
		case _T('f'):
			_tcscpy_s(pcmdline->out_file, SIZEOF_ARRAY(pcmdline->out_file), optarg);
			break;
		case 1:
			_tcscpy_s(pcmdline->root_dir, SIZEOF_ARRAY(pcmdline->root_dir), optarg);
			break;
		case _T('h'):
		case _T('?'):
			pcmdline->is_help = true;
			break;
		}
	}
}

FILE* out_fp = NULL;
int start_pos = 0;
MD5_CLS md5obj;

BOOL file_md5(LPCTSTR filename, LPTSTR outstr) {
	FILE *fp;
	//���ļ�
	if(_tfopen_s(&fp, filename, _T("rb"))) return FALSE;

	byte p[4096];
	size_t plen;
	MD5_CTX ctx;
	//�Ի�������СΪ��λѭ����ȡ������md5����
	md5obj.MD5Init(&ctx);
	while((plen = fread(p, 1, sizeof(p), fp))) {
		md5obj.MD5Update(&ctx, p, plen);
	}
	md5obj.MD5Final(&ctx);
	fclose(fp);
	//md5У��ֵת���ַ�����ʾ��ʽ
	hex2str(ctx.digest, 16, outstr);
	return TRUE;
}

typedef void (cdecl *SEARCH_CALLBACK)(LPCTSTR, _tfinddata_t *);
void search_callback(LPCTSTR dir, _tfinddata_t* fd){
	TCHAR buf[512], digest[33];

	//����md5�����У���ļ�
	if(!_tcscmp(fd->name, cmd.out_file)) return;
	//���ҵ����ļ�
	_stprintf_s(buf, SIZEOF_ARRAY(buf), _T("%s\\%s"), dir, fd->name);
	if(!file_md5(buf, digest)) {
		set_output_color(FOREGROUND_RED | FOREGROUND_INTENSITY);
		_tprintf(_T("can't open file %s \n"), buf);
		return;
	}

	//д�뵽У���ļ���
	if(_tcslen(dir) == start_pos)
		_ftprintf(out_fp, _T("%s *%s\n"), digest, fd->name);
	else _ftprintf(out_fp, _T("%s *%s\\%s\n"), digest, dir + start_pos + 1, fd->name);
}

void file_list(LPCTSTR dir, SEARCH_CALLBACK cb) {
	TCHAR buf[1024];
	_tfinddata_t fd;
	intptr_t fh;

	//ѭ��Ŀ¼�µ�ÿ���ļ����д���
	_stprintf_s(buf, SIZEOF_ARRAY(buf), _T("%s\\*.*"), dir);
	if((fh = _tfindfirst(buf, &fd)) == -1) return;
	do {
		//����� . �� .. ����������
		if(!_tcscmp(fd.name, _T(".")) || !_tcscmp(fd.name, _T("..")))
			continue;
		//����ҵ�����Ŀ¼����ݹ����
		if(fd.attrib & _A_SUBDIR) {
			_stprintf_s(buf, SIZEOF_ARRAY(buf), _T("%s\\%s"), dir, fd.name);
			file_list(buf, cb);
		}
		//���ļ������ûص�����
		else cb(dir, &fd);
	} while (_tfindnext(fh, &fd) != -1);
	_findclose(fh);
}

//����У���ļ���һ�У�������ʽ - md5ֵ *�ļ���
void parse_line(LPTSTR src, int len, LPTSTR pchecksum, int cslen,
		LPTSTR pfilename, int fnlen){
	*pchecksum = 0; *pfilename = 0;
	if(src == NULL) return;
	int idx = 0;
	LPTSTR p = src, pend = src + len, pckend = pchecksum + cslen, pfnend = pfilename + fnlen;
	//�������׿ո�
	while(*p && p < pend && (*p == _T(' ') || *p == _T('\t'))) p++;
	//����md5ֱֵ�������ո�
	while(*p && p < pend && pchecksum < pckend && *p != _T(' ') && *p != _T('\t')) *pchecksum++ = *p++;
	//�����ļ�����ͷ�ո�
	while(*p && p < pend && (*p == _T(' ') || *p == _T('\t'))) p++;
	p++;
	//����ֱ����β
	while(*p && p < pend && pfilename < pfnend && *p != _T('\r') && *p != _T('\n')) *pfilename++ = *p++;
	//β���ӽ����ַ�
	*pchecksum = 0; *pfilename = 0;
}

int main_func(int argc, _TCHAR* argv[]) {
	_tsetlocale(LC_ALL, _T("chs"));

	parse_options(argc, argv, &cmd);
	if(cmd.is_help) {
		usage();
		return 0;
	}

	//�ж�ҪУ���·���Ƿ����
	//if(_taccess(cmd.root_dir, 0) == -1) {
	TCHAR full_path[512];
	if(!_tfullpath(full_path, cmd.root_dir, SIZEOF_ARRAY(full_path))) {
		set_output_color(FOREGROUND_RED | FOREGROUND_INTENSITY);
		_tprintf(_T("directory not exists."));
		return -1;
	}
	start_pos = _tcslen(full_path);

	//������ļ���׼����ȡ��д��
	if(_tfopen_s(&out_fp, cmd.out_file, cmd.is_check ? _T("r, ccs=UTF-8") : _T("w, ccs=UTF-8"))) {
		set_output_color(FOREGROUND_RED | FOREGROUND_INTENSITY);
		_tprintf(_T("can't open output file %s."), cmd.out_file);
		return -1;
	}

	//��ʼ������MD5��̬���ӿ�
	if (!md5_init(&md5obj)) {
		set_output_color(FOREGROUND_RED | FOREGROUND_INTENSITY);
		_tprintf(_T("can't load library %s."), MD5_DLL_NAME);
		return -1;
	}

	if(!cmd.is_check) file_list(full_path, search_callback);
	else {
		TCHAR read_data[1024], chksum[33], fname[256], schksum[33];
		size_t read_len;
		//���ж�ȡ����������
		while(_fgetts(read_data, SIZEOF_ARRAY(read_data), out_fp)){
			parse_line(read_data, SIZEOF_ARRAY(read_data),
				chksum, SIZEOF_ARRAY(chksum), fname, SIZEOF_ARRAY(fname));
			//������ʧ�ܣ����ǹ̶���md5ֵ��ʽ
			if(chksum[0] == 0 || fname[0] == 0) {
				//*_tcspbrk(read_data, _T("\r\n")) = 0;
				//set_output_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
				//_tprintf(_T("[%s] isn't checksum line.\n"), read_data);
				continue;
			}
			_stprintf_s(read_data, SIZEOF_ARRAY(read_data), _T("%s\\%s"), full_path, fname);
			//�����ļ���md5
			if(!file_md5(read_data, schksum)) {
				set_output_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
				_tprintf(_T("error\t - %s can't open. - %s\n"), fname, read_data);
				continue;
			}
			//���ı����еıȽ�
			if(_tcscmp(chksum, schksum)) {
				set_output_color(FOREGROUND_RED | FOREGROUND_INTENSITY);
				_tprintf(_T("error\t - %s md5 checksum is not equal.\n"), fname);
			}
			else {
				set_output_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
				_tprintf(_T("ok\t - %s check succeed.\n"), fname);
			}
		}
	}

	//_tprintf(LIGHT_BLUE _T("xxxx") RED _T("dddd\n"));
	return 0;
}

int _tmain(int argc, _TCHAR* argv[]) {
	md5obj.hDLL = NULL;
	out_fp = NULL;
	int ret = main_func(argc, argv);
	if(md5obj.hDLL != NULL) FreeLibrary(md5obj.hDLL);
	if(out_fp != NULL) fclose(out_fp);
	set_output_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	return ret;
}
