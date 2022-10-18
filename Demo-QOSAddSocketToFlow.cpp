#include <iostream>
#include <qos2.h>
#include <winsock2.h>
#include <WS2tcpip.h>


int main()
{
    QOS_VERSION    Version;
    HANDLE         QoSHandle = NULL;
    QOS_FLOWID     QoSFlowId = 0; // Flow Id must be 0.
    SOCKET        ConnectionSocket;
    BOOL          QoSResult;
    WSADATA wsa_data;

    int ret = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (ret) {
        std::cerr << "WSAStartup failed" << std::endl;
        return 0;
    }
    ConnectionSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ConnectionSocket == -1) {
        std::cerr << "socket create fail" << std::endl;
        return 0;
    }
    // Initialize the QoS version parameter.
    Version.MajorVersion = 1;
    Version.MinorVersion = 0;

    // Get a handle to the QoS subsystem.
    QoSResult = QOSCreateHandle(
        &Version,
        &QoSHandle);

    if (QoSResult != TRUE) {
        std::cerr << "QOSCreateHandle failed. Error: ";
        std::cerr << WSAGetLastError() << std::endl;
        return 0;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = 0x14AFA80A;  //IP exists in the local subnet: 10.168.175.20
    addr.sin_port = 5353;
    // Add socket to flow.
    std::cerr << "gettick count start : ";
    std::cerr << GetTickCount() << std::endl;
    QoSResult = QOSAddSocketToFlow(
        QoSHandle,
        ConnectionSocket,
        (struct sockaddr*) &addr,
        QOSTrafficTypeExcellentEffort,
        QOS_NON_ADAPTIVE_FLOW,
        &QoSFlowId);
    std::cerr << "gettick count end: ";
    std::cerr << GetTickCount() << std::endl;
    if (QoSResult != TRUE) {
        std::cerr << "QOSAddSocketToFlow failed. Error: ";
        std::cerr << WSAGetLastError() << std::endl;
        return 0;
    }

    return 0;
}
