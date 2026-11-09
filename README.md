# elf2epf

将已经链接完成的 **x86-64、ELF64、小端 ELF** 转换成 EPF v1.0。支持普通程序 `.epf` 和动态链接库 `.eps`，提供转换前检查、文件查看、格式校验及依赖检查。

实现依据 `EPF-V1.0-Spec.md` 中的 `$EPF` 魔数、128 字节文件头、64 字节段表、RVA 地址模型和独立动态目录。默认输出不包含节表、静态符号表或调试节；装载所需内容完全通过段表和动态目录定位。

## 构建

要求 CMake 3.16+ 和支持 C++17 的编译器，转换器没有第三方运行时库依赖（使用平台 C/C++ 标准库）。

Linux / WSL：

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/elf2epf --help
ctest --test-dir build --output-on-failure
```

Windows：在已配置 Visual Studio C++ 工具链的终端执行：

```powershell
cmake -S . -B build-windows -A x64
cmake --build build-windows --config Release
.\build-windows\Release\elf2epf.exe --help
```

也支持 CMake + MinGW 配置（尚未验证 MinGW 构建）。Windows 入口接收宽字符参数，文件路径使用 `std::filesystem`，支持中文路径。已使用 MSVC 19.50 构建并运行 Windows 原生 CLI 测试，包括中文路径、EXEC/SHARED 转换及与 Linux 输出逐字节比较。集成测试使用 Linux/WSL 的 GCC、GNU ld、Python 3，并在 x86-64 Linux 上执行生成的代码。

## 配置目标平台

转换不会更改机器指令的函数调用、系统调用或启动约定。**输入必须已经针对你的操作系统 ABI 构建。** 普通 Linux 程序的 glibc、TLS、符号版本等要求通常不能由基础 EPF v1 表示。

复制并修改 `profiles/example-x86_64.ini`：

```ini
os_abi=0x8000
abi_version=1
map_align=4096
interpreter=/system/ld-epf.epf
```

`0x8000` 仅为项目本地示例值，不代表已分配的正式 EPF ABI 编号；请替换为你的系统编号。解释器路径也必须对应目标系统实际实现的 EPF 加载器。

- `os_abi`：必须显式提供，允许 `0..65535`。不会复制 ELF 的 `EI_OSABI`。
- `abi_version`：默认 `1`，允许 `0..65535`。
- `map_align`：默认 `4096`，必须为 `4096..256 MiB` 范围内的 2 的幂。
- `interpreter`：可省略；需要解释器的程序若未配置此项，转换会失败。共享库不写入 `INTERP`。

配置文件采用 UTF-8 `key=value`，空行和以 `#` 开头的行被忽略；值不加引号。未知键、重复键会报错。命令行配置覆盖文件中的配置，与参数排列顺序无关。

不使用配置文件时，也可以显式传入 `--os-abi 32768 --abi-version 1 --map-align 4096`。

## 使用

```sh
# 检查完整转换流程；不创建输出文件
./build/elf2epf check app.elf --type exec --profile profiles/example-x86_64.ini

# 普通程序：ET_EXEC -> 固定地址 EXEC；ET_DYN -> PIE EXEC
./build/elf2epf convert app.elf -o app.epf --type exec --profile profiles/example-x86_64.ini

# 动态链接库：必须是共享库 ET_DYN，不能把固定地址程序变成库
./build/elf2epf convert libmath.so -o libmath.eps --type shared \
  --profile profiles/example-x86_64.ini --soname libmath.eps

# 显式重命名依赖；不会仅依据扩展名自动修改 NEEDED
./build/elf2epf convert app.elf -o app.epf --type exec \
  --profile profiles/example-x86_64.ini --map-needed libmath.so=libmath.eps

./build/elf2epf inspect app.epf
./build/elf2epf verify app.epf
./build/elf2epf verify app.epf --deps
./build/elf2epf verify app.epf --library-path ./libraries
```

`verify` 默认只检查单文件格式。`--deps` 或任一 `--library-path` 会进一步装入依赖元数据，检查依赖图、ABI 和未解析的强符号，整个过程不执行输入代码。独立检查一个有导入的共享库时，必须同时提供其完整依赖。

依赖按声明顺序查找，先搜索使用者文件所在目录，再搜索命令行给出的目录。此工具的基础平台约定只接受单个文件名作为库名，不接受路径或 `.` / `..`。使用实际文件身份去重，两个同 `SONAME` 文件不会被自动视为同一模块。依赖必须为 `SHARED`，且 `os_abi`、`abi_version`、`map_align` 匹配。

输出路径必须不存在，输入文件不会被覆盖。通过校验后，工具在目标目录写临时文件，再利用硬链接提交完整文件，避免替换已有目标；目标文件系统须支持硬链接（如 NTFS、ext4）。相同输入和参数生成相同字节，不写时间戳。

退出码：`0` 成功，`1` 格式/能力/转换/IO 错误，`2` 命令行参数错误。诊断前缀包括 `E_FORMAT`、`E_LAYOUT`、`E_TARGET`、`E_ABI`、`E_UNSUPPORTED`、`E_DEPENDENCY`、`E_SYMBOL`、`E_RESOURCE`、`E_IO`、`E_ARGUMENT`。

## 构建可转换的示例 ELF

以下命令在 x86-64 Linux/WSL 的 GNU 工具链下使用。它们不链接 Linux CRT 或 libc；真实应用应换成你的 OS SDK 和启动代码。

```sh
# 固定地址程序：示例入口读取数据与 BSS，随后停在 pause 循环。
cc -c examples/minimal.S -o build/minimal.o
ld -static -z noexecstack -e _start build/minimal.o -o build/minimal.elf
./build/elf2epf convert build/minimal.elf -o build/minimal.epf \
  --type exec --profile profiles/example-x86_64.ini

# 共享库：没有系统调用，包含函数、全局数据和一个需要重定位的指针。
cc -fPIC -fcf-protection=none -fno-stack-protector -fno-asynchronous-unwind-tables \
  -nostdlib -shared examples/libmath.c -Wl,-Bsymbolic,-z,now,-z,noexecstack,--hash-style=both \
  -Wl,-soname,libmath.so -o build/libmath.so
./build/elf2epf convert build/libmath.so -o build/libmath.eps \
  --type shared --profile profiles/example-x86_64.ini --soname libmath.eps
./build/elf2epf verify build/libmath.eps --deps
```

`--type` 表达目标用途，不能把任意共享库“制造”为一个正确程序。对 `ET_DYN --type exec`，调用者还须保证它采用程序启动约定；工具检查入口处于可执行段的文件内容中。对于 `--type shared`，带 `DF_1_PIE` 或 `PT_INTERP` 的输入会被拒绝。

## 转换语义

### 地址和布局

选择满足输入基址对齐要求的映像原点 `L`，所有原始内容统一使用 `RVA = ELF_VADDR - L`。固定程序设置 `image_base=L`，PIE/共享库设置 `image_base=0`。原代码、数据、GOT 和 PLT 的相对位置不变。

ELF 非页对齐段通过零填充前缀规范化，重新分配文件偏移；BSS 继续只占内存。输入的基址对齐要求由输出中至少一个相应对齐的 `LOAD` 表达，必要时添加只读对齐段。新增动态元数据位于追加的只读 `LOAD`，原始 ELF 装载字节（包括映射过的 ELF 头和旧动态表）作为普通载荷保留，避免移动链接时地址。

两个源段向目标页粒度取整后若重叠，会被拒绝；不会通过移动代码或合并不同权限规避。RELRO 只有在向外补齐的部分不覆盖其他原始程序内存时才会扩展，否则要求重新链接。所有 `LOAD` 可读，禁止 W+X。

### 动态符号、重定位和初始化

动态定义转换为 `IMAGE`，绝对符号转换为 `ABS`，导入转换为 `UNDEF`。保留名称原始字节及强弱属性。`HIDDEN/INTERNAL` 转成 EPF `HIDDEN`；`PROTECTED` 转成 `DEFAULT`，因为 EPF 内部定义始终绑定本模块。运行时不使用节索引。

| ELF 运行时重定位 | EPF | 加数处理 |
|---|---|---|
| `R_X86_64_NONE` | 省略 | 不写入 |
| `R_X86_64_64` | `ABS64` | 保留 |
| `R_X86_64_32` | `ABS32` | 保留，最终值须无符号 32 位可表示 |
| `R_X86_64_PC32` | `PCREL32` | 保留，最终差值须有符号 32 位可表示 |
| `R_X86_64_GLOB_DAT` | `ABS64` | 强制为零，原公式仅为 `S` |
| `R_X86_64_JUMP_SLOT` | `ABS64` | 强制为零，启动时绑定 |
| `R_X86_64_RELATIVE` / `R_X86_64_RELATIVE64` | `RELATIVE64` | `A-L` |

只处理动态目录指定的运行时表，不重复应用静态链接后留下的 `.rela.*` 节。输出重定位必须写入可写数据或 RELRO，禁止写入代码、越过目标边界、重叠写入及覆盖新的运行时元数据。需要解释器的程序不会沿用 ELF 解释器路径。

只依据节表、`DT_SYMTABSZ`、SysV 哈希或有效的非空 GNU 哈希推导完整动态符号数量。不同来源必须一致；**空 GNU 哈希不能确定总数**。如果删除节表后只剩空 GNU 哈希，应保留动态符号节，或使用 `--hash-style=both/sysv` 重新链接，不能按最大引用索引猜测导出。

INIT/FINI 数组重新生成小端 `u64 RVA`，新数组自身没有指针重定位。只有能静态确认的模块内函数可进入新数组。`DT_INIT` 放在 INIT 数组前端；`DT_FINI` 放在 FINI 数组前端，使逆序调用时它最后执行。旧数组及其重定位作为原始程序数据保留，避免破坏原地址，但启动链必须保证构造/析构只执行一次。

### OS SDK 必须遵守的约定

- 建议沿用 SysV AMD64 函数调用约定；系统调用、进程入口栈/寄存器、退出和解释器交接协议仍由目标 OS 定义。
- EPF 模块内定义绑定自身。现有 ELF 的符号抢占、主程序反向提供符号、全局加载命名空间等语义不会自动保留。SDK 应按 EPF 规则构建依赖，适用时使用 `-Bsymbolic`。
- 全部符号在启动时完成绑定。基础依赖图无环；导入只在当前模块的依赖闭包中按 NEEDED 顺序广度优先查找，强定义优先于弱定义，未解析弱引用取零。
- 动态启动的程序由 EPF 启动链管理初始化；无解释器的静态程序由用户启动代码调用初始化函数。静态 PIE 启动代码不能再次执行 ELF 自重定位。
- 输入不能依赖对旧 ELF 头、`_DYNAMIC`、ELF 辅助向量、ELF 延迟绑定解析器等结构的运行时解释。仅凭 ELF 二进制无法证明所有这些约束，须由配套 SDK 保证。
- `.eh_frame` 等原始装载内容可以保留，但首版没有提供异常展开登记协议。依赖 C++ 异常、展开登记或语言运行时发现机制的程序需要后续 ABI 扩展。

## 当前边界和资源限制

首版不支持 `ET_REL`、32 位/大端/其他架构、TLS、IFUNC/IRELATIVE、COPY、带符号 32 位绝对重定位、REL/RELR 输入、符号版本、RPATH/RUNPATH、PREINIT、可执行栈、代码运行时重定位、未知必需架构属性。CET/IBT/SHSTK 和高于 baseline 的 GNU ISA 必需属性在定义 EPF `arch_flags` ABI 前拒绝转换。

`verify/inspect` 当前同样只接受 x86-64、无节表的 EPF v1.0 EXEC/SHARED。可选节表与调试信息保留属于后续工作，不会把这些有效但未支持的 EPF 变体报告为已验证。

资源上限：单文件及转换输出 256 MiB、映像范围 16 GiB、段数 4096、符号/重定位/数组项数各 1,000,000；单个名称或路径 16 KiB，动态名称展开累计 64 MiB；依赖图 256 个实际文件，文件总大小 256 MiB。这些是工具实现上限，不是 EPF 格式本身的上限。

格式验证不等于目标 OS 运行验证。位置无关映像的最终装载基址、跨库 PCREL32 距离和全部重定位结果仍需加载器在实际基址确定后检查溢出。`--deps` 不打开或验证 INTERP 所指的目标系统文件。

## 验证方式

集成测试使用真实 ELF，独立解析 EPF，再在子进程中匿名映射、复制、清零、执行重定位并落实 RX/RW/RELRO 权限。测试覆盖固定地址入口、BSS/尾页、静态 PIE、非零输入基址、共享库导出和指针、跨库 PLT/GOT、弱导入、构造/析构顺序，以及无节表的 GNU/SysV 哈希输入。

另有畸形范围、权限、元数据、重定位及有界随机变异测试。测试加载器不实现自定义 OS 的进程栈和系统调用 ABI，不作为生产加载器发布。

Linux 地址/未定义行为检查可用单独构建目录运行：

```sh
cmake -S . -B build-sanitize -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined -no-pie"
cmake --build build-sanitize -j
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  ctest --test-dir build-sanitize --output-on-failure
```

构建上面的两个示例以及 Windows exe 后，可用 Windows Python 或启用 Windows 互操作的 WSL 运行原生 Windows 测试：

```sh
python tests/windows_smoke.py --tool build-windows/Release/elf2epf.exe --fixtures build --profile profiles/example-x86_64.ini
```

核心库公开 API 在 `include/elf2epf/converter.hpp`，分为 `convert`、`decode`、`inspect`、`verify_dependencies` 和文件/配置 IO，可独立嵌入其他工具。
