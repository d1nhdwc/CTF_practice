#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SIZE 0x100

#define HEADER "\x48\x31\xc0\x48\x89\xe7\x48\x81\xe7\x00\xf0\xff\xff\x48\x81\xef\x00\x20\x00\x00\x48\xc7\xc1\x00\x06\x00\x00\xf3\x48\xab\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xe4\x48\x31\xed\x48\x31\xf6\x48\x31\xff\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff"

#define FLAG_SIZE 64

char flag[FLAG_SIZE];

void load_flag() {
  int fd;
  if ((fd = open("flag.txt", O_RDONLY)) == -1)
    error(EXIT_FAILURE, errno, "open flag");
  if (read(fd, flag, FLAG_SIZE) == -1)
    error(EXIT_FAILURE, errno, "read flag");
  if (close(fd) == -1)
    error(EXIT_FAILURE, errno, "close flag");
}

void setup() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);
  int ret = 0;
  if (ctx != NULL) {
    ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
      SCMP_A0(SCMP_CMP_EQ, STDOUT_FILENO));
    ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    ret |= seccomp_load(ctx);
  }
  seccomp_release(ctx);
  if (ctx == NULL || ret)
    error(EXIT_FAILURE, 0, "seccomp");
}

int main()
{
  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  setbuf(stderr, NULL);

  load_flag();
  puts("Welcome to Shellcode as a Service!");

  void* addr = mmap(NULL, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  memcpy(addr, HEADER, sizeof(HEADER));
  read(0, addr + sizeof(HEADER) - 1, SIZE);

  setup();
  goto *addr;
}
