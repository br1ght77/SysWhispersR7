# SysWhispersR7

Rapid7 Fork的ReflectiveDLLInjection中Syscall实现得很巧妙 https://github.com/rapid7/ReflectiveDLLInjection/tree/master/dll/src ，但仅仅实现了4个NT函数。如果使用其他NT函数还需要计算函数哈希值来初始化，不方便使用。

于是利用SysWhispers3项目的代码将其自动生成更多可用的NT函数。
同时用SysWhispers3项目的哈希算法替换了Rapid7中的ROR13哈希算法。

大部分代码都来源于以下项目，我只是拼凑起来，修改了一点点。syscall的实现来自于[@cdelafuente-r7](https://github.com/cdelafuente-r7)

    https://github.com/rapid7/ReflectiveDLLInjection
    https://github.com/klezVirus/SysWhispers3

根据[pull1](https://github.com/rapid7/ReflectiveDLLInjection/pull/16)
[pull2](https://github.com/rapid7/ReflectiveDLLInjection/pull/17)

支持以下系统的64/32/wow64 不支持Debug模式编译，只支持Release
```
Windows 11 x64
Windows 10 x64
Windows 8.1
Windows 8
Windows 7 x64 and x86
Windows Server 2019 x64
Windows Server 2016 x64
Windows Server 2012 x64
Windows Server 2008 R2 x64
Windows XP
Windows Vista SP2
```
我只测试了win10/win7 的x64/wow64，其它系统未测

## Usage
和SysWhispers3差不多，但是去除了一些选项
```
C:\>python SysWhispersR7.py -h
  -h, --help            show this help message and exit
  -p PRESET, --preset PRESET
                        Preset ("all", "common")
  -a {x86,x64}, --arch {x86,x64}
                        Architecture
  -c {msvc,mingw,all}, --compiler {msvc,mingw,all}
                        Compiler
  -f FUNCTIONS, --functions FUNCTIONS
                        Comma-separated functions
  -o OUT_FILE, --out-file OUT_FILE
                        Output basename (w/o extension)
```

```
python .\SysWhispersR7.py --preset common -o syscalls_common -a x64
python .\SysWhispersR7.py --preset all    -o syscalls_all    -a all
python .\SysWhispersR7.py --functions NtProtectVirtualMemory,NtWriteVirtualMemory  -o syscalls_func  -a all
```

在代码中包含头文件后，只需要调用Init_syscall函数初始化就可以使用NT函数了
```c
#include "syscall.h"
int main(){
    Init_syscall();

    SIZE_T writtenbytes = 0;
    LPVOID address = NULL;
    SIZE_T SIZE_t = 0x1000;
    
    SWR7NtAllocateVirtualMemory((HANDLE)-1, &addres, (ULONG_PTR)0, &SIZE_t, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    printf("Allocated at 0x%x", address);
}
```

## Feature

### SysWhispers3项目的缺点

    1.每一个NT函数都有重复的汇编代码，区别仅仅是函数哈希的不同，占用过多的代码体积。
    2.SysWhispers3项目的wow64仅支持win10，在win7下不工作（因为win7和win10中的NT函数实现有差异）。
    3.SysWhispers3项目的NT汇编函数具有syscall指令(sysenter)的硬编码、jmp r11这种跳转寄存器的特征代码。
    jumper模式寻找syscall指令也会在代码中出现硬编码0F05。

### Rapid7/ReflectiveDLLInjection syscall的优点

其跳转执行syscall的方式，是通过将stub的地址放到返回地址的位置，然后ret跳转到stub执行syscall. 类似于jmp rax 等价于push rax,ret。

64位中stub的位置是NT函数的第8个字节后，因为win10和win7的syscall前8字节都是完成将调用号赋值到rax寄存器。这样就不用查找syscall指令(sysenter/wow64SystemServiceCall)的地址，代码中也无需出现syscall指令(sysenter)的硬编码。同时也跳过了开头可能的hook代码（jmp loc_7FFFxxxxxxxx的汇编指令加上后续的000000也是8个字节），这点真的很巧妙。

32位中stub的位置是NT函数的第5个字节后

x64中的NT函数
```
    // On x64 Windows, the function starts like this:
    // 4C 8B D1          mov r10, rcx
    // B8 96 00 00 00    mov eax, 96h   ; syscall number
    //
    // If it is hooked a `jmp <offset>` will be found instead
    // E9 4B 03 00 80    jmp 7FFE6BCA0000
    // folowed by the 3 remaining bytes from the original code:
    // 00 00 00
```
x86中的NT函数(包括wow64)
```
	// On x86 ntdll, it starts like this:
	// B8 F1 00 00 00    mov     eax, 0F1h   ; syscall number
	//
	// If it is hooked a `jmp <offset>` will be found instead
	// E9 99 00 00 00    jmp     775ECAA1
```
```c
NTSTATUS SyscallStub(Syscall* pSyscall, ...) {
	return DoSyscall();
}

NTSTATUS rdiNtAllocateVirtualMemory(Syscall* pSyscall, HANDLE hProcess, PVOID* pBaseAddress, ULONG_PTR pZeroBits, PSIZE_T pRegionSize, ULONG ulAllocationType, ULONG ulProtect) {
	return SyscallStub(pSyscall, hProcess, pBaseAddress, pZeroBits, pRegionSize, ulAllocationType, ulProtect);
}
```


```asm
DoSyscall Proc

  push r11                     ; store r11 on stack to be able to restore it later
  push r12                     ; store r12 on stack to be able to restore it later
  push r13                     ; store r13 on stack to be able to restore it later

  add rsp, 40h                 ; restore the stack pointer to the previous stack frame
  mov r11, [rsp+10h]           ; get the pointer to the Syscall structure that has been stored in the shadow space

  mov r10, [r11+10h]           ; store the syscall stub in r10. Note that the `.pStub` field is padded with 4 null bytes on x64.
  mov [rsp], r10               ; place the stub address on the stack, which will be used as return address

  mov rcx, rdx                 ; Arg1 is the pointer to the Syscall structure and we don't need it.
  mov rdx, r8                  ;   We need to shift all the arguments to have the correct arguments for the syscall.
  mov r8, r9                   ;   This meens, rdx move to rcx, r8 to rdx, r9 to r8 and first argument on the stack
  mov r9, [rsp+30h]            ;   to r9.

  ; Now, if the syscall needs more than 4 arguments, we need to deal with arguments stored on the stack
  xor r12, r12
  mov r12d, dword ptr [r11+4]  ; store the number of arguments in r12, which will be our counter
  cmp r12, 4                   ; we already processed 4 arguments, so, check if we have more
  jle _end                     ; we have less than 4 arguments, jump directly to _end
  sub r12, 4                   ; adjust the argument counter
  xor r13, r13                 ; zero out r13, this will be the index

_loop:
  mov r10, [rsp+38h+8*r13]     ; get the argument
  mov [rsp+30h+8*r13], r10     ; store it to the correct location
  inc r13                      ; increment the index
  cmp r13, r12                 ; check if we have more arguments to process
  jl _loop                     ; loop back to process the next argument

_end:
  mov r10, rcx                 ; store the first argument to r10, like the original syscall do
  xor rax, rax                 ; zero out rax
  mov eax, dword ptr [r11+8]   ; store the syscall number to eax

  mov r13, [rsp-40h]           ; restore r13
  mov r12, [rsp-38h]           ; restore r12
  mov r11, [rsp-30h]           ; restore r11
  ret                          ; return to the stub

DoSyscall ENDP
```
