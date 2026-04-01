# SysInject
Bypassing all **EDR hooks** while maintaining the cleanest `callstack` of all time with **proxy calls** and an **exception handler**.

# API hooking
EDRs, antiviruses, anticheats, sandboxes, and other security solutions commonly hook **Windows API functions** to allow them to monitor and detect malicious calls, this usually involves overwriting the start of the function with a `JMP` or another similar instruction that will redirect execution to the **EDR's module**, where it can check the parameters of the call. They can also hook **imported functions** in the `IAT` using a similar method, as most programs use imports to call **Windows functions**.

There has been plenty of research into potential bypasses for these hooks, but almost everything can be **mitigated adequately**, here are a few examples.

**API Unhooking:** This involves replacing the hooked function instructions with clean ones, allowing the function to be called without being redirected to the **EDR's module** for inspection. However this is no trouble to detect; memory protection changes to a module like `NTDLL` could already be an **indicator of compromise**, especially if they change it to both **writable and executable** like most unhookers do. The **EDR** can also just occasionally check the **integrity** of their hooks.

**Direct syscall:** The technique of **direct syscalls** consists of directly calling the `syscall` instruction for a **kernel function** from your own program, however, this is trivial to detect using the `callstack`, as it will show a **direct call** from the program module to the kernel. They can also be detected in a disassembly by searching for the **syscall instruction** (Hex `0x0F05`); no normal program calls these directly like this.

Here is an image of what the `callstack` of a **direct syscall** to `NtDelayExecution` looks like, as you can see, the module directly calls the kernel without passing through any **Windows libraries**:

<img width="295" height="203" alt="DirectSyscall_callstack" src="https://github.com/user-attachments/assets/1dbfbf13-0366-4696-bcdc-d345aa478c33" />

**Indirect syscall:** Indirect syscalls are similar to **direct syscalls**, however instead of directly embedding the `syscall` in the program, it will `JMP` to an existing `syscall` instruction in a system library like `NTDLL`, this makes the `callstack` appear much more legitimate as it will show it passing through a **native API** before the **system call**. But this can be a problem, as calls to **native APIs** are also relatively unusual for legitimate programs, therefore, **EDRs** like **Elastic** will flag you if you do a call to a function like `NtProtectVirtualMemory` from your module.

Because of this, products such as [Nighthawk C2](https://nighthawkc2.io/) try to **spoof the return address** to make it appear as if the native call came from a **system module or Win32 API**, instead of directly from the main module, however this introduces its own set of **detection possibilities**.

Also, some **indirect syscall** attempts try to do a system call using a `syscall` instruction in a different location to where that system call would normally be executed; for example, calling `NtAllocateVirtualMemory` using the `syscall` instruction for `NtDrawText`, this is a **massive indicator of compromise** as `NtAllocateVirtualMemory` is never legitimately called through that `syscall` instruction, contrary to belief in some [corners](https://github.com/Maldev-Academy/TrapFlagForSyscalling/) :)

Here is an image of what the `callstack` of an **indirect syscall** to `NtDelayExecution` looks like, as you can see, the module goes through the `NtDelayExecution` stub in `NTDLL` before calling the kernel:

<img width="294" height="208" alt="IndirectSyscall_callstack" src="https://github.com/user-attachments/assets/c60a0efe-8be3-4b42-a443-665ddfb3e6bd" />

# Enhancing callstack analysis with function hooking
**Callstack analysis** already seems advanced enough, but when combined with **function hooking**, a theoretical new opportunity is created, something powerful enough to catch all forms of **indirect syscalls**, and also allow easy detection of **indirect API calling** (Dynamically resolved functions).

The good thing about **indirect syscalls** is that they bypass hooks, but on the other hand, the bad thing about **indirect syscalls** is that they never go through the hooks. This simple anomaly has the potential to allow for **flawless detection** of all types of **indirect syscalls**; if a certain function is hooked, and a system call is executed there, but the `callstack` never shows it going through the **EDR's module for inspection**, that indicates an **indirect syscall** has been executed. It's similar to how **EDRs** could just check if their hooks were removed by **API unhooking**, they can also check if a function was called without going through the hook.

This opportunity goes even further though, **imports** in the `IAT` can also be hooked in a similar way, and if a function is called by the main module without it going through the **IAT hook**, that indicates the function has been located and executed **indirectly**, which could be seen as suspicious.

# SysInject: Evading callstack analysis and function hooking
**SysInject** is the solution to **callstack analysis with function hooking**, it goes through every **EDR hook** with **completely legitimate parameters**, and not only does it look like a normal function call on the `callstack`, but when combined with carefully picked **proxy call** hosts, calls can seem even more **legitimate than a legitimate process!**

The concept of **SysInject** is fairly simple; a custom **exception handler** will be registered and configured, after that, all you have to do is cause an **exception** to happen at the target `syscall` instruction once it's executed (`NtProtectVirtualMemory` for example). Once ready, execute ANY function which will end up calling that target `syscall` instruction. Once the `syscall` instruction is reached and the exception happens, the **exception handler** will replace the parameters for the call with all of your **configured parameters**, and then **continue execution**, whispering the `syscall` with all of our custom arguments, but every hook before it saw random legitimate ones!

The tricky part, and likely the best way to detect **SysInject**, would be what is required to cause the exception. I have included `2` versions of **SysInject**; `SysInjectBreakpoint.h` will use `Hardware Breakpoints`, and `SysInjectTrapFlag.h` will use the `Trap Flag`. Both can be used interchangeably and they both compile to the same size.

For fun, I have included **multiple different modes** you can use; 1: `Injection mode`, this is the main mode I've talked about earlier, it replaces the parameters with **custom ones** just before execution. 2: `Ghost mode`, this mode completely skips the target `syscall`, which could have some potential interesting uses... And I thought it was funny.

# Proxy calling and the SysInject example code
Because of the nature of how **SysInject** works, once we have set up target `syscalls` for the exception handler to "handle", we can then call **ANY function in ANY library** which ends up calling that target `syscall`, letting us **hijack** that function's call to use for ourselves, in the example code, we will call the function `_resetstkoflw()` in `MSVCRT.DLL`, which internally calls `VirtualProtect` and doesn't crash if there's an issue, making it a perfect target. Any **EDR** hooking `VirtualProtect` or `NtProtectVirtualMemory` will only see the **legitimate parameters** passed by `_resetstkoflw()`, and when it gets to the `syscall` instruction, they will be replaced with our ones. This is why the `callstack` seems even more legitimate than a **legitimate process**; it doesn't even look like we were the callers of `NtProtectVirtualMemory`! Directly calling the `VirtualProtect` function ourselves with random parameters of our choice also works fine though, and will be less likely to run into compatibility issues on different versions of Windows, however it doesn't have the stealth aspect that the **proxy calls** do.

The **SysInject** example code will test a few of the features; at the start, we will use `Ghost mode` on `NtDelayExecution`'s `syscall` instruction, then we will call `Sleep(4294967295)` to delay execution for the maximum value it supports (Highest unsigned 32 bit value, also known by its C macro `INFINITE`), but because we had a ghost on the `syscall`, there is **no delay at all!**

After that, we will **decrypt the shellcode**, which is located in the writable `.data` section. Then we will install an injector on `NtProtectVirtualMemory`, we will program this to set the memory protection of the decrypted shellcode to read execute (`RX`). Once done, we proxy call it using `_resetstkoflw()`.

This image shows the usermode `callstack` for the `NtProtectVirtualMemory` `syscall` in **SysInject**, as you can see, it goes from `SysInject.exe -> msvcrt.dll!resetstkoflw -> KernelBase.dll!VirtualProtect -> ntdll.dll!NtProtectVirtualMemory`:

<img width="929" height="520" alt="SysInject_protect_callstack" src="https://github.com/user-attachments/assets/96c5ea57-ed4f-479c-bed5-bdf8993b6a85" />

After setting the protection of the shellcode to executable, we will test **SysInject** on `NtDelayExecution` to make all delays `5` seconds, after configuring the parameters, we will call `Sleep(0)` to test it, and after calling it, we can observe that it doesn't delay for `0` milliseconds like the function call would indicate, but `5` seconds instead!

Here is an image of the callstack for this `syscall`, we can see it took the full path through all the expected modules, unlike the **direct and indirect syscall** `NtDelayExecution` calls. It will also have gone through any **EDR hooks**, but upon analysis, they would have only seen our dummy value `0`:

<img width="292" height="273" alt="SysInject_sleep_callstack" src="https://github.com/user-attachments/assets/1cc68b49-dae0-41f4-8640-5192c4560e85" />

Once finished, we will clear all the targeted `syscalls` and remove the **exception handler**, and then **execute the shellcode**. The design of this shellcode loader also can be nice for creating **sleeping implants**; not only does it execute in **backed memory**, but since the payload is stored in the writable `.data` section, the loader could theoretically just set the protection back to read write (`RW`) and encrypt the payload using the logic used to decrypt it, this could leave it looking identical to the **executable image on the disk** during sleep times, which could be good for evading **memory scanners**.

Because of some careful compile commands and usage of my **Shellcode-Toolkit** library, the proof of concept builds to a `6144` byte large PE executable file. It shouldn't be difficult to implement **SysInject** in a **shellcode or C2 implant**, the only reason it isn't is because of the decision to store the payload in a `.data` section, and also the **unwind sections** required to get a clean `callstack`.

Important note: **SysInject** does **NOT** hide your module on the `callstack`, it just allows you to bypass **EDR hooks** while keeping a beautiful `callstack` and evading the theoretical detections explained earlier. Good luck hiding your unbacked shellcode now that **Elastic took away your free pass!**

# Possible Improvements
There are probably many ways **SysInject** could be modified and upgraded, here are a few things you could do:

Earlier I talked about how **indirect API calling** can be detected using `IAT` hooks and the `callstack`. **SysInject** dynamically resolves all the functions it uses, but modifying it to fully use **imports** shouldn't be too hard, however **proxy call** targets will be limited (But maybe you can **proxy a proxy call**!?), and you might have to use `SetThreadContext` instead of `NtContinue`, which isn't ideal, as there's a lot of telemetry against `SetThreadContext` usage.

I believe it might be possible to remove usage of `RtlAddVectoredExceptionHandler` and **implement it locally**, as it isn't a kernel level function, but this might run into a similar issue that stuff like **indirect syscalls** have; items being added to the **VEH list** without a `RtlAddVectoredExceptionHandler` call could be suspicious.

You should be able to replace `RtlAddVectoredExceptionHandler` with `SetUnhandledExceptionFilter` if you want, but I haven't tested it myself.

# Issues
You will get some problems if you try to use **SysInject** to inject or ghost `NtGetContextThread` or `NtContinue`, as they are used internally by **SysInject** to cause exceptions at target syscall addresses.

The `Trap Flag` method can make the performance really bad, so make sure to clear all the **targeted syscalls** when not using it.

The `Hardware Breakpoints` method can only target at most `4 syscalls` at a time because of the limited amount of breakpoint debug registers.

# Credits and References
https://github.com/rad9800/TamperingSyscalls - The idea of **replacing parameters** just before the `syscall` instruction

https://malwaretech.com/2023/12/silly-edr-bypasses-and-where-to-find-them.html - **Excellent** idea of detection from the `callstack` not showing going through a **hooked function**

https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware - **Elastic** seems to have cracked down on the **ROP** `callstack` spoof, that method is likely more of an **indicator of compromise** than an evasion technique now, so I wanted to make this

https://doxygen.reactos.org/ - Easily finding a suitable function to **proxy call**
