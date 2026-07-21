// how this jenkins and ssh scanner works
// do /scan then enter start and end ip range
// this tool then scans every ip between looking
// for port 8080 and 22 open on them ips
// if open it attempts to connect them to your server
// this does not use any exploits so only unsecure servers will
// connect if u want 100/100 sucsess rate include payloads or
// exploits which force connects via ...
// this is more of a framework u can build up off

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <vector>

#define SERVER_IP "127.0.0.1"  // ur server ip goes here (host this of it)

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

using namespace std;

bool IsValidIP(const char* ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0;
}

void PrintDebugLog(const char* format, ...) {
    char buffer[512];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    char timeStr[64];
    SYSTEMTIME st;
    GetLocalTime(&st);
    sprintf_s(timeStr, "%02d:%02d:%02d.%03d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    cout << "[" << timeStr << "] " << buffer << endl;
}

void ScanAndConnect(const string& ip) {
    SOCKET sock;
    struct sockaddr_in server;
    WSADATA wsaData;

    PrintDebugLog("Initializing Winsock for IP: %s...", ip.c_str());
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        PrintDebugLog("WSAStartup failed with error: %d", WSAGetLastError());
        return;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        PrintDebugLog("Error creating socket: %d", WSAGetLastError());
        WSACleanup();
        return;
    }

    struct timeval timeout;
    timeout.tv_sec = 2; 
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

    bool port22Open = false;
    bool port8080Open = false;

    PrintDebugLog("Checking port 22 on %s...", ip.c_str());
    server.sin_family = AF_INET;
    server.sin_port = htons(22);
    inet_pton(AF_INET, ip.c_str(), &server.sin_addr);

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAETIMEDOUT || err == WSAECONNREFUSED) {
            PrintDebugLog("  Port 22: CLOSED/TIMED OUT");
        }
        else {
            PrintDebugLog("  Port 22: ERROR (%d)", err);
        }
    }
    else {
        port22Open = true;
        PrintDebugLog("  Port 22: OPEN");

        const char* testMsg = "SCAN_HELLO\r\n";
        int sent = send(sock, testMsg, strlen(testMsg), 0);
        if (sent > 0) PrintDebugLog("  Port 22: Handshake sent successfully");
    }

    PrintDebugLog("Checking port 8080 on %s...", ip.c_str());
    server.sin_port = htons(8080);

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAETIMEDOUT || err == WSAECONNREFUSED) {
            PrintDebugLog("  Port 8080: CLOSED/TIMED OUT");
        }
        else {
            PrintDebugLog("  Port 8080: ERROR (%d)", err);
        }
    }
    else {
        port8080Open = true;
        PrintDebugLog("  Port 8080: OPEN");

        const char* testMsg = "SCAN_HELLO\r\n";
        int sent = send(sock, testMsg, strlen(testMsg), 0);
        if (sent > 0) PrintDebugLog("  Port 8080: Handshake sent successfully");
    }

    if (port22Open && port8080Open) {
        PrintDebugLog("Both ports open on %s. Attempting to connect to server %s...", ip.c_str(), SERVER_IP);

        SOCKET finalSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (finalSock != INVALID_SOCKET) {
            struct sockaddr_in destServer;
            destServer.sin_family = AF_INET;
            destServer.sin_port = htons(80); 
            inet_pton(AF_INET, SERVER_IP, &destServer.sin_addr);

            if (connect(finalSock, (struct sockaddr*)&destServer, sizeof(destServer)) == 0) {
                PrintDebugLog("SUCCESS: Connected to SERVER_IP (%s) from scanned host %s", SERVER_IP, ip.c_str());

                const char* responseMsg = "SCAN_COMPLETE\r\n";
                send(finalSock, responseMsg, strlen(responseMsg), 0);

                char buffer[1024];
                int recvLen = recv(finalSock, buffer, sizeof(buffer) - 1, 0);
                if (recvLen > 0) {
                    buffer[recvLen] = '\0';
                    PrintDebugLog("Received from server: %s", buffer);
                }
            }
            else {
                PrintDebugLog("FAILED: Could not connect to SERVER_IP (%s). Error: %d", SERVER_IP, WSAGetLastError());
            }
            closesocket(finalSock);
        }
        else {
            PrintDebugLog("FAILED: Could not create final socket.");
        }
    }
    else {
        PrintDebugLog("Skipping connection to server. One or more ports were closed.");
    }

    closesocket(sock);
    WSACleanup();
    PrintDebugLog("Finished processing %s.\n", ip.c_str());
}

int main() {
    PrintDebugLog("Starting IP Scanner Tool...");

    string startIP, endIP;

    cout << "Enter Start IP (e.g., 192.168.1.1): ";
    cin >> startIP;

    cout << "Enter End IP (e.g., 192.168.1.254): ";
    cin >> endIP;

    if (!IsValidIP(startIP.c_str()) || !IsValidIP(endIP.c_str())) {
        PrintDebugLog("Invalid IP address format.");
        return 1;
    }

    in_addr addrStart, addrEnd;
    inet_pton(AF_INET, startIP.c_str(), &addrStart);
    inet_pton(AF_INET, endIP.c_str(), &addrEnd);

    unsigned long ipStart = addrStart.s_addr;
    unsigned long ipEnd = addrEnd.s_addr;

    if (ipStart > ipEnd) {
        PrintDebugLog("Start IP is greater than End IP. Swapping");
        swap(ipStart, ipEnd);
    }

    PrintDebugLog("Scanning range from %s to %s...", startIP.c_str(), endIP.c_str());
    PrintDebugLog("------------------------------------------------");

    for (unsigned long ip = ipStart; ip <= ipEnd; ip++) {
        in_addr currentAddr;
        currentAddr.s_addr = ip;
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &currentAddr, ipStr, INET_ADDRSTRLEN);

        Sleep(50);

        ScanAndConnect(string(ipStr));
    }

    PrintDebugLog("Scan complete.");
    system("pause");
    return 0;
}
