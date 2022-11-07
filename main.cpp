#include "pch.h"


#include <iostream>
#include <Ws2tcpip.h>
#include <winsock2.h>
#include <windows.h>
#include <winrt/Windows.Security.Credentials.h>
#include <winrt/Windows.Networking.h>
#include <winrt/Windows.Devices.Enumeration.h>
#include <winrt/Windows.Devices.WiFiDirect.h>
#include <winrt/Windows.Devices.WiFiDirect.Services.h>

#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#pragma comment(lib,"ws2_32.lib")

typedef struct {
    OVERLAPPED overlap;
    unsigned int mode;
} Context;

using namespace std;
using namespace winrt;
using namespace winrt::Windows::Devices::WiFiDirect;
using namespace Windows::Foundation::Collections;
using namespace Windows::Devices::Enumeration;
using namespace Windows::Foundation;
using namespace Windows::Security::Credentials;

void OnConnectionRequested(WiFiDirectConnectionListener sender, WiFiDirectConnectionRequestedEventArgs args)
{
    std::cout << "OnConnectionRequested" << std::endl;

    auto ConnectionRequest = args.GetConnectionRequest();
    DeviceInformation deviceInfo = ConnectionRequest.DeviceInformation();
    WiFiDirectDevice  wfdDevice = WiFiDirectDevice::FromIdAsync(deviceInfo.Id()).get();

    auto connectDeiveList = wfdDevice.GetConnectionEndpointPairs();
    size_t connectNum = connectDeiveList.Size();
    if (connectNum > 0) {
        const wchar_t* remoteIp = connectDeiveList.GetAt(0).RemoteHostName().ToString().c_str();
        const wchar_t* localIp = connectDeiveList.GetAt(0).LocalHostName().ToString().c_str();
        wprintf(L"local ip: %s, remote ip: %s \n", localIp, remoteIp);
    }
}

int main()
{
    /*
    std::wstring wssid = L"nstack_test";
    std::wstring wpass = L"87651234";
    WiFiDirectAdvertisementPublisher wlanPublish;
    std::cout << "begin0" << std::endl;
    //作为go
    wlanPublish.Advertisement().IsAutonomousGroupOwnerEnabled(true);
    //启用传统模式，作为普通接入点
    wlanPublish.Advertisement().LegacySettings().IsEnabled(true);
    wlanPublish.Advertisement().LegacySettings().Ssid(wssid);
    wlanPublish.Advertisement().LegacySettings().Passphrase().Password(wpass);
    std::cout << "begin2" << std::endl;
    // 作为普通模式（只要该应用程序位于前台，就很容易发现该设备）
    WiFiDirectConnectionListener listener;
    listener.ConnectionRequested(OnConnectionRequested);
    std::cout << "start2" << std::endl;
    wlanPublish.Start();

    Sleep(10000);
    */
    HANDLE iocpFd = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 100);
    Context contextWrite;
    Context context;
    memset(&contextWrite, 0, sizeof(contextWrite));
    memset(&context, 0, sizeof(context));
    WSADATA wsa_data;
    int ret = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (ret) {
        std::cout << "WSA START FAIL" << std::endl;
    }

    SOCKET fd = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
    struct sockaddr_in localAddr;
    socklen_t len = sizeof(localAddr);
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = 55222; // 本机随机端口，可更换为其他端口
    localAddr.sin_addr.s_addr = 0x0189A8C0; // 本机p2p地址，windows上固定为192.168.137.1
    int bindRet = bind(fd, (struct sockaddr*)&localAddr, len);
    if (bindRet == SOCKET_ERROR) {
        std::cout << "bind error:" << GetLastError() << std::endl;
    }
    if (CreateIoCompletionPort((HANDLE)fd, iocpFd, (ULONG_PTR)&context, 0) == NULL) {
        std::cout << "reg socket failed" << std::endl;
    }
    
    unsigned char buf[1024] = { 0 };
    DWORD flags = 0;
    WSABUF* wsaBuf = (WSABUF*)malloc(sizeof(WSABUF));
    wsaBuf->buf = (CHAR*)buf;
    wsaBuf->len = 1024;
    socklen_t dstAddrLen = sizeof(struct sockaddr_in);
    struct sockaddr_in dstAddr;
    dstAddr.sin_family = AF_INET;
    dstAddr.sin_addr.s_addr = 0x5489A8C0; //另一台连上p2p的电脑IP地址
    dstAddr.sin_port = 5353; //另一台电脑上常驻端口
    contextWrite.mode = 2;
    WSASendTo(fd, wsaBuf, 1, NULL, flags, (SOCKADDR*)&dstAddr, dstAddrLen,
        (OVERLAPPED*)(&contextWrite), NULL);

    while (1) {
        OVERLAPPED* ov = NULL;
        DWORD bytes = 0;
        Context context2;
        memset(&context2, 0, sizeof(context2));
        BOOL ret = GetQueuedCompletionStatus(iocpFd, &bytes, (PULONG_PTR)&context2, &ov, (DWORD)50);
        if (ret == FALSE) {
            int errcode = GetLastError();
            if (errcode == 1450) {
                std::cout << "GetQueuedCompletionStatus fail errcode 1450" << std::endl;
            }
            else {
                std::cout << "GetQueuedCompletionStatus fail errcode:" << GetLastError() << std::endl;
            }
        }

        else {
           // std::cout << "GetQueuedCompletionStatus succeeds.:" << GetLastError() << std::endl;
            
            Context* context1 = CONTAINING_RECORD(ov, Context, overlap);
            std::cout << "GetQueuedCompletionStatus ok,mode :" << context1->mode << std::endl;
            
            if (context1->mode == 2) {
                contextWrite.mode = 2;
                WSASendTo(fd, wsaBuf, 1, NULL, flags, (SOCKADDR*)&dstAddr, dstAddrLen,
                    (OVERLAPPED*)(&contextWrite), NULL); 
             
            }
            
         Sleep(300);
        }

    }
    return 0;
}
