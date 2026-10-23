typedef enum StatusCode {
    Success = 0x00000000,

    NoUAC = 0x0A000000,
    NoPrivilege,
    NoSecretKeyPointer,
    MismatchSecretKeyLength,
    ConnectionFailed,
    AppKeyInvalid,
    RegistryWriteFailed,
    MemoryAllocFailed,
    ServiceFailed,
    DriverVerifyFailed,
    CmdCallFailed,

    ShellcodeRequestFailed,
    ShellcodeVerifyFailed,
    LoopbackServerFailed,
    LoopbackThreadFailed,
    LoopbackTimeout,
    LoopbackAcceptFailed,
    LoopbackHandshakeFailed,
    LoopbackSendFailed,
    LoopbackAllocFailed,

    UserBanned = 0x0B000000,
    InvalidSecretKey,
    Disallowed,
    ServerInternalError,
    ParameterError,
    InvalidResponse,
    Timeout,
    InvalidFileType,
    FileNotAvailable,
    ServerError,

    InvalidFunction = 0x0C000000,
    MapperRequestFailed,
    DataSourceVerifyFailed,
    FileWriteFailed,
    DseRequestFailed
};

/*
0x00000000
└── Success                           成功

0x0A000000 - 初始化/驱动相关错误
├── NoUAC                             需要管理员权限
├── NoPrivilege                       无法启用驱动加载权限
├── NoSecretKeyPointer                无效密钥指针
├── MismatchSecretKeyLength           密钥长度错误
├── ConnectionFailed                  连接服务器失败
├── AppKeyInvalid                     AppKey无效
├── RegistryWriteFailed               注册表写入失败
├── MemoryAllocFailed                 内存分配失败
├── ServiceFailed                     服务创建/启动失败
├── DriverVerifyFailed                驱动验证失败
├── CmdCallFailed                     Cmd调用失败
├── ShellcodeRequestFailed            从服务器拉取 shellcode 失败
├── ShellcodeVerifyFailed             shellcode 数据源验证失败
├── LoopbackServerFailed              loopback WSAStartup/socket/bind/listen 失败
├── LoopbackThreadFailed              loopback 服务线程创建失败
├── LoopbackTimeout                   loopback 等待驱动连入超时
├── LoopbackAcceptFailed              loopback accept 失败
├── LoopbackHandshakeFailed           loopback 握手魔数不匹配
├── LoopbackSendFailed                loopback 推送 shellcode 失败
└── LoopbackAllocFailed               loopback 响应缓冲区分配失败

0x0B000000 - 服务器返回错误
├── UserBanned = 0x0B000000           用户被封禁
├── InvalidSecretKey                  无效密钥
├── Disallowed                        访问被拒绝
├── ServerInternalError               服务器内部错误
├── ParameterError                    参数错误
├── InvalidResponse                   无效API响应
├── Timeout                           连接超时
├── InvalidFileType                   无效文件类型
├── FileNotAvailable                  文件不可用
└── ServerError                       服务器错误

0x0C000000 - 调用/请求错误
├── InvalidFunction = 0x0C000000      无效函数ID
├── MapperRequestFailed               Mapper请求失败
├── DataSourceVerifyFailed            数据源验证失败
├── FileWriteFailed                   文件写入失败
└── DseRequestFailed                  DSE请求失败
*/