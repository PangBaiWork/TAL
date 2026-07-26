# TAL 安全审计报告

- 审计日期：2026-07-26
- 审计方式：人工静态审计、编译参数检查、Android ARM64 产物硬化属性检查
- 审计对象：TAL 自身维护的入口、`src/`、`include/`、构建脚本与根 `CMakeLists.txt`
- 未审计对象：`qbdi-src/`、`Triton/`、`boost-lite/`、`third_party/`、`libs/`、`Release/` 和构建目录中的依赖源码或生成文件
- 源码修改：本次审计未修改任何 TAL 或依赖源码，仅新增本报告

## 结论

当前 TAL 在处理被跟踪进程的指令、内存、符号以及并发 Hook 回调时，存在可导致宿主进程崩溃、越界读写、信息泄露或堆状态损坏的问题。最优先处理的是固定数组越界写、`TRACE_ARGS_MODE` 的无界读取、字符串探测的裸指针读取和全局状态数据竞争。

TAL 运行在被跟踪进程内部，因此这些问题的影响发生在目标进程权限和地址空间内。如果被跟踪代码、符号表、Hook 线程或控制脚本包含不可信输入，风险会明显上升。如果所有输入均完全可信，部分外部参数问题的实际严重度可相应降低。

| 编号 | 严重度 | 问题 | 主要影响 |
|---|---|---|---|
| TAL-SEC-001 | 高 | 寄存器分析固定数组可越界写 | 进程崩溃、堆栈内存破坏 |
| TAL-SEC-002 | 高 | 函数参数和 Hexdump 长度无上限 | 越界读、信息泄露、资源耗尽 |
| TAL-SEC-003 | 高 | 字符串探测直接无界读取目标内存 | 越界读、跨页崩溃、日志泄露 |
| TAL-SEC-004 | 高 | 全局跟踪状态缺少并发保护 | 数据竞争、容器损坏、错误跟踪 |
| TAL-SEC-005 | 高（条件性） | 自定义栈所有权和边界保护不足 | 悬空指针、栈重叠、内存破坏 |
| TAL-SEC-006 | 中 | C ABI 和分析结果缺少输入校验 | 空指针解引用、异常终止 |
| TAL-SEC-007 | 中 | 污点范围大小未限界且存在整数问题 | CPU/内存耗尽、范围判断错误 |
| TAL-SEC-008 | 中 | 关键安全功能失败后仍报告成功 | 漏跟踪、污点分析假阴性 |
| TAL-SEC-009 | 中 | Hook、映射及跟踪对象持续泄漏 | 长时间运行后的资源耗尽 |
| TAL-SEC-010 | 中 | Release 显式关闭 TAL 栈保护 | 降低内存破坏后的防护能力 |
| TAL-SEC-011 | 低 | 可变参数日志格式与实参类型不匹配 | 未定义行为、错误日志或崩溃 |
| TAL-SEC-012 | 低 | 日志文件创建和敏感数据落盘缺少保护 | 文件覆盖、符号链接风险、信息泄露 |

## 详细发现

### TAL-SEC-001：寄存器分析固定数组可越界写

严重度：高
可信度：高

原因：

- `Trace::RegAnalysis` 为读、写和读写寄存器分别使用容量为 2 或 4 的固定数组，但计数器在写入前递增，未检查数组容量。
- `TaintTrace::MemoryTrace()` 又维护了一组容量为 4 的局部数组，同样按指令操作数数量直接递增索引。
- 对寄存器编号的检查不能替代对“已收集操作数数量”的检查。一条包含较多寄存器操作数或重复分类的指令即可使索引超过数组边界。

位置：

- `include/trace.h:125-132`：固定容量数组和索引定义。
- `src/trace.cpp:342-365`：`++Tr_idx`、`++Tw_idx`、`++Cr_idx` 等操作后直接写数组。
- `src/taint_analyze.cpp:172-175`：第二组固定容量数组。
- `src/taint_analyze.cpp:187-213`：遍历全部操作数并直接递增数组索引。

影响：

被跟踪指令流可能触发栈上越界写，破坏相邻局部变量或对象状态，导致目标进程崩溃；在可控指令流和稳定内存布局下，不排除进一步利用的可能。

建议：

- 优先使用已有 QBDI 操作数数量构造有边界的容器，或使用最小的 `std::vector<int>`。
- 若保留固定数组，写入前必须检查容量，并明确处理超限指令。
- 对重复寄存器进行去重，避免相同寄存器重复消耗容量。

### TAL-SEC-002：函数参数和 Hexdump 长度无上限

严重度：高
可信度：高

原因：

- 导出函数 `set_function_print()` 接收有符号 `int`，却将 `hexdump_size` 直接赋给 `size_t`；负数会转换成极大的无符号长度。
- `argc` 没有上下限。负数随后会转换成 `size_t`，极大的正数或恶意构造的 C++ 符号参数列表也会产生大量参数读取。
- 超出寄存器参数数量后，代码直接从目标栈地址解引用 `uint64_t*`，未验证完整读取范围。
- `TryReadablePointer()` 的 `size` 参数未被使用，内存映射查询把 `range.size` 设为 0，仅验证起始地址，之后却按完整 `ARG_HEXDUMP_SIZE` 读取。

位置：

- `src/function_utils.cpp:22-26`：无校验地设置全局参数数量和 Hexdump 长度。
- `src/function_utils.cpp:208-241`：从符号名推断出的参数数量没有上限。
- `src/function_utils.cpp:244-340`：按参数数量扩展容器并直接读取目标栈。
- `src/function_utils.cpp:380-405`：只检查起始地址，映射范围大小为 0。
- `src/function_utils.cpp:408-478`：`size` 未参与可读范围验证，随后执行完整 Hexdump。
- `src/function_utils.cpp:486-507`：将可能为负数的 `argc` 转换成 `size_t`。

影响：

- 跨越可读映射边界时发生 SIGSEGV/SIGBUS，终止被跟踪进程。
- 将相邻可读内存写入日志，泄露密钥、令牌或其他进程内敏感数据。
- 极大参数数量可触发巨量分配、长循环和栈外读取，造成资源耗尽。

建议：

- 为参数数量和 Hexdump 长度设置较小且明确的硬上限，并拒绝负数。
- 对 `sp + offset` 和 `address + size` 做整数溢出检查。
- 验证整个 `[address, address + size)` 范围；跨页时逐段安全读取，遇到不可读页立即停止。
- 符号解析结果不能直接决定无限制的内存读取量。

### TAL-SEC-003：字符串探测直接无界读取目标内存

严重度：高
可信度：高

原因：

- `IsPrintable()` 在检查 `i < max` 之前先读取 `str[i]`，因此边界处会额外读取一个字节。
- `PrintStr()` 一直读取到非可打印字符，没有最大长度和映射边界检查。
- `CheckTaintedStr()` 仅判断地址大于常量 `0x3000`，随后固定读取 `ptr[0]` 至 `ptr[3]`，没有确认目标内存至少有 4 个可读字节。
- 污点字符串自身也未确认至少有 4 个字节；短字符串会造成对 `taint_str` 的越界读。
- `GetSameStrLen()` 和以 C 字符串形式写日志的操作都依赖可访问的 NUL 终止符。

位置：

- `src/utils.cpp:49-56`：无映射边界的相同前缀扫描。
- `src/utils.cpp:59-80`：边界检查顺序错误和无界字符串读取。
- `src/trace.cpp:318-335`：短污点字符串和目标地址均未做长度/可读范围检查。

影响：

被跟踪程序只需在页尾或映射边界附近访问内存，即可能让 TAL 额外读取不可访问页并使进程崩溃。读取到的连续内存还可能被写入日志，扩大敏感信息泄露范围。

建议：

- 所有字符串读取都使用显式最大长度。
- 先检查索引，再读取字节。
- 使用按页、可失败的安全读取接口，不直接解引用目标进程中的裸指针。
- 比较前先验证污点字符串长度，并按实际内存访问大小限制探测范围。

### TAL-SEC-004：全局跟踪状态缺少并发保护

严重度：高
可信度：高

原因：

- `cur_tracer`、`addr_set`、全局配置和 Triton 静态寄存器状态在多个导出 API 与 Hook 回调之间共享，没有互斥、原子或线程局部隔离。
- `addr_set` 会同时在 `trace()` 中插入、在 `on_enter()` 中删除；`std::unordered_set` 的并发写是未定义行为。
- `avoid_range`、`escape_execute`、日志流、QBDI VM 和符号缓存也可被不同线程同时读取或修改。
- Hook 的目标函数天然可能由多个线程同时执行，因此该问题不只依赖控制脚本主动并发调用。

位置：

- `library.cpp:51-52`：进程级 `cur_tracer` 和污点字符串指针。
- `library.cpp:128-146`：全局 `addr_set` 在 Hook 回调中修改。
- `library.cpp:198-286`：导出 API 读写全局 tracer 及其容器。
- `src/function_utils.cpp:22-26`、`src/function_utils.cpp:376-400`：非原子全局配置和内存映射状态。
- `include/triton_taint.h:20-25`、`src/triton_taint.cpp:8-12`：所有 Triton 实例共享寄存器指针和映射表。

影响：

可能出现容器内部结构损坏、悬空引用、错误寄存器值、日志交叉写入和目标进程崩溃。数据竞争本身属于 C++ 未定义行为。

建议：

- 将一次跟踪会话的状态收敛到明确拥有者，并按线程或 Hook 实例隔离。
- 控制面修改使用最小范围互斥；执行热路径避免同时修改容器。
- 在 Hook 生效前冻结配置，或使用不可变快照传递给回调。
- Triton 的当前寄存器状态至少应为实例成员或 `thread_local`，不能是进程级静态裸指针。

### TAL-SEC-005：自定义栈所有权和边界保护不足

严重度：高（条件性）
可信度：中

原因：

- 自定义栈由普通 `new[]` 堆缓冲区提供，没有保护页，也没有平台栈探测。
- `BorrowedStackAllocator` 只保存 `RawBufferStack*` 裸指针，`deallocate()` 不承担生命周期管理。
- `on_enter()` 中栈缓冲区由局部 `unique_ptr` 所有，但只有 allocator 被保存到 `Trace::stack`；后续 `on_resume()` 会再次使用这个 allocator。
- 如果 `on_enter()` 已返回但 Resume Hook 仍可触发，allocator 的 `backing` 将成为悬空指针；如果前一上下文仍挂起时重用同一缓冲区，则可能覆盖仍在使用的栈帧。

位置：

- `include/utils.h:53-74`：无保护页的堆栈和仅持有裸指针的 allocator。
- `include/trace.h:35-38`：`Trace` 只保存 allocator，没有保存栈缓冲区所有权。
- `library.cpp:41-48`：Resume Hook 复用保存的 allocator。
- `library.cpp:184-193`：栈缓冲区是 `on_enter()` 的局部所有者。

影响：

取决于 QBDI 转移和 Resume Hook 的精确时序，可能产生 use-after-free、活动栈重叠或无保护栈溢出，最终破坏目标进程堆内存。

建议：

- 让跟踪会话对象显式拥有栈缓冲区，确保其生命周期覆盖全部 Hook 和挂起上下文。
- 优先复用 Boost.Context 已提供的带保护页栈分配器，而不是维护裸堆缓冲区。
- 明确禁止同一栈被嵌套或并发复用，并为状态转换增加断言和失败路径。

### TAL-SEC-006：C ABI 和分析结果缺少输入校验

严重度：中
可信度：高

原因：

- `trace()` 未验证 `mode`。非法值不会创建 tracer，随后仍解引用 `cur_tracer`。
- `set_log_path()` 在检查空指针前直接构造 `std::string(path)`。
- 地址、范围和枚举参数没有进行规范化、映射存在性或加法溢出检查。
- `TritonTaint::InstTrace()` 未检查 `getInstAnalysis()` 返回值即解引用。
- 两处 `AnalyzeInst()` 的结果被直接访问 `mnemonic`，反汇编失败时可能为空。
- `run_on_stack()` 捕获异常后重新抛出，但 Frida C 回调和导出的 C ABI 没有统一异常边界；C++ 异常逃逸会导致终止或未定义行为。

位置：

- `library.cpp:15-29`：异常被重新抛到回调边界。
- `library.cpp:198-220`：非法 `mode` 可导致空指针解引用。
- `library.cpp:225-228`：`start + size` 未检查溢出。
- `library.cpp:255-261`：空路径会在检查 tracer 前崩溃。
- `src/triton_taint.cpp:75-81`：分析结果未判空。
- `src/taint_analyze.cpp:287-288`、`src/taint_analyze.cpp:367-369`：反汇编失败结果未判空。

影响：

错误配置、失效 Hook 地址、无法分析的指令或内存分配异常均可能直接终止目标进程。

建议：

- 每个导出 C API 在入口验证指针、枚举、地址和范围，并返回明确错误。
- 所有 C/C++ 边界使用 `noexcept` 包装层捕获异常，禁止异常逃逸。
- 对 QBDI、Capstone 和 Frida 的所有可失败返回值逐项处理。

### TAL-SEC-007：污点范围大小未限界且存在整数问题

严重度：中
可信度：高

原因：

- `add_taint_range()` 接收任意 64 位大小，没有最大值或地址加法检查。
- Triton 模式逐字节调用 `setTaintMemory()`，循环变量却是 `int`，与 `uint64_t size` 比较。超过 `INT_MAX` 后存在有符号溢出未定义行为，较小但很大的值也可长期占用 CPU 和内存。
- 普通污点范围计算 `base + size` 后再执行 `max -= 1`，零长度和整数回绕会产生异常范围。

位置：

- `library.cpp:246-250`：未验证的公开污点范围入口。
- `include/triton_taint.h:44-49`：按字节的无界循环和 `int`/`uint64_t` 类型不匹配。
- `src/trace_utils.cpp:66-88`：范围末端减一及 `base + size` 缺少溢出检查。

影响：

可导致分析线程长时间占满 CPU、Triton 状态持续膨胀、整数溢出后的错误范围传播和服务不可用。

建议：

- 拒绝零长度、回绕和超过合理上限的范围。
- 使用现有依赖提供的批量污点范围接口；若不存在，再以安全分块实现。
- 循环变量与大小使用相同的无符号类型，同时保留硬上限。

### TAL-SEC-008：关键安全功能失败后仍报告成功

严重度：中
可信度：高

原因：

- `set_taint_str(const char* str)` 完全忽略传入的 `str`，改为传递全局 `g_taint_str`；该全局变量初始化为 `nullptr` 且未见赋值，因此 API 返回 `true` 时实际没有设置污点字符串。
- Hook attach/replace 的返回值没有完整检查或向调用者传播，`trace()` 无条件记录 `hooked`。
- 默认日志路径设置失败后仍继续跟踪，可能产生没有审计日志的运行。

位置：

- `library.cpp:51-52`、`library.cpp:264-269`：污点字符串参数被忽略。
- `src/hook_utils.cpp:14-24`：replace 结果只记录日志。
- `src/hook_utils.cpp:27-39`：attach 结果被忽略并始终返回 listener。
- `library.cpp:150-152`、`library.cpp:219-221`：日志和 Hook 失败未传播。

影响：

调用方可能误以为污点源或 Hook 已生效，实际分析出现假阴性。对于安全分析工具，静默漏报会直接破坏结果可信度。

建议：

- 正确使用 API 实参并返回明确状态。
- 只有 Frida 确认 Hook 成功后才更新内部状态和打印成功日志。
- 日志创建失败时停止相关会话或向控制端返回可识别错误。

### TAL-SEC-009：Hook、映射及跟踪对象持续泄漏

严重度：中
可信度：高

原因：

- 每次 attach/replace 都 `new CallbackData`，但 listener 的销毁回调为 `nullptr`，detach 后也没有释放。
- 异常处理器上下文、backtracer、模块映射、内存映射和 tracer 缺少完整所有权与清理路径。
- QBDI `qbdi_getCurrentProcessMaps()` 返回的数组需要 `qbdi_freeMemoryMapArray()`，三个平台实现均未释放。
- 未命中符号时动态分配的 offset 字符串被长期缓存且没有统一释放。

位置：

- `src/hook_utils.cpp:14-39`：CallbackData、interceptor 和 listener 生命周期未闭合。
- `library.cpp:99-126`：异常处理器上下文和 backtracer 没有移除/释放路径。
- `library.cpp:146-148`：每次进入创建模块及内存映射。
- `library.cpp:205-212`：进程级 tracer 通过 `new` 创建且没有销毁 API。
- `include/trace.h:62-66`：析构函数只关闭一个日志流，没有清理 Frida 对象和污点字符串。
- `src/trace.cpp:162-168`：动态 offset 字符串无释放策略。
- `src/vm.cpp:127-160`、`src/vm.cpp:166-189`、`src/vm.cpp:195-223`：QBDI 映射数组未释放。

影响：

长时间运行、反复跟踪多个入口或频繁安装 Resume Hook 时，内存和 Frida/QBDI 对象持续增长，最终可能使目标进程资源耗尽。

建议：

- 使用 RAII 管理 Frida/QBDI 对象，并为 listener 提供 destroy notify。
- 提供明确、幂等的停止跟踪和会话销毁路径。
- 将符号名称存入 `std::string`，避免混合借用指针和裸分配指针。

### TAL-SEC-010：Release 显式关闭 TAL 栈保护

严重度：中
可信度：高

原因：

- Android NDK 默认命令行包含 `-fstack-protector-strong`，但 TAL 的 Release 参数随后加入 `-fno-stack-protector`，后者覆盖默认保护。
- Windows 入口文件还使用 `#pragma check_stack(off)`，会降低大栈增长时的探测能力。
- 本报告确认 Android 产物具备 NX 栈、GNU RELRO、立即绑定和 FORTIFY；问题仅是 TAL 自身编译单元的栈保护被主动关闭，不代表所有依赖都没有 canary。

位置：

- `CMakeLists.txt:139-150`，特别是 `CMakeLists.txt:145`：Release 明确添加 `-fno-stack-protector`。
- `library.cpp:2`：关闭 Windows 栈检查的 pragma。

影响：

该配置不会单独产生漏洞，但会降低 TAL-SEC-001 等栈内存破坏问题被及时检测和阻断的概率，使利用后果更严重。

建议：

- 删除 `-fno-stack-protector`，保留平台工具链的强栈保护默认值。
- 除非有经过测量且不可替代的原因，不要关闭 Windows 栈探测。

### TAL-SEC-011：可变参数日志格式与实参类型不匹配

严重度：低
可信度：高

原因：

- 多处使用 `%llx`/`%llu` 输出 `uint64_t`、`guint64` 或指针。Android ARM64 上这些类型可能是 `unsigned long` 或 `void*`，与格式要求的 `unsigned long long` 不一致。
- 可变参数没有类型转换保护，格式和实参不匹配属于 C/C++ 未定义行为。当前 Android 构建已对此产生多条编译警告。

位置：

- `src/utils.cpp:15-18`：`uint64_t` 使用 `%llx`。
- `library.cpp:37`、`library.cpp:132-145`、`library.cpp:163-178`：指针和 64 位类型使用不匹配格式。
- `src/utils.cpp:110-111`、`src/utils.cpp:230-240`：平台寄存器类型使用固定 `%llx`。

影响：

在当前常见 64 位 ABI 上通常表现为错误或侥幸正确的日志，但在不同 ABI、优化条件或平台上可能读取错误参数并导致崩溃。

建议：

- 指针统一使用 `%p`。
- 固定宽度整数使用 `<cinttypes>` 的 `PRIu64`/`PRIx64`，或改用类型安全的 C++ 格式化接口。
- 将 `-Wformat` 问题作为 TAL 自身代码的构建错误处理。

### TAL-SEC-012：日志文件创建和敏感数据落盘缺少保护

严重度：低
可信度：高

原因：

- 跟踪日志包含寄存器、函数参数和目标进程内存内容，本身属于敏感数据。
- 输出路径由调用方直接拼接，使用 `std::ios::trunc` 打开；没有限制目录、拒绝符号链接、独占创建或显式设置最小权限。
- 默认文件写入目标进程当前工作目录，安全性依赖进程 umask 和目录权限。

位置：

- `library.cpp:255-261`：接受任意日志路径前缀。
- `src/trace.cpp:216-228`：直接拼接文件名并截断打开。
- `src/function_utils.cpp:460-478`：函数参数指向的内存被写入日志。
- `src/trace.cpp:181-211`：内存访问值和字符串被写入日志。

影响：

在工作目录可被其他用户写入或日志路径来源不可信时，可能覆盖已有文件或跟随符号链接；日志权限过宽还会泄露进程内敏感信息。

建议：

- 由可信控制端提供并验证专用输出目录。
- 使用拒绝符号链接和独占创建的底层文件接口，再交给 C++ 流管理。
- 明确设置仅当前用户可读写的权限，并提供关闭参数内存转储的选项。

## 修复优先级

1. 先修复 TAL-SEC-001、002、003、004，阻断明确的越界写、无界读和并发未定义行为。
2. 明确自定义栈状态机和所有权，验证 TAL-SEC-005 的所有 Resume 路径。
3. 为全部 C ABI 建立统一校验和异常边界，同时限制参数、Hexdump 与污点范围。
4. 补齐 Hook/日志失败传播和资源释放，使分析结果能够被可靠信任。
5. 恢复工具链默认硬化并清理格式警告。

## 审计限制

- 本次为静态审计，没有对目标进程执行畸形指令流、并发 Hook、跨页地址或超大参数的动态触发测试。
- 未审计任何子项目或第三方依赖内部实现；仅在确认 TAL 是否正确调用公开 API 时进行了只读检索。
- 未对 Windows 和 Linux 产物分别进行完整运行时验证；构建硬化属性检查基于当前 Android ARM64 Release 产物。
- 行号对应本报告创建时的工作区版本；源码修改后应重新核对。
