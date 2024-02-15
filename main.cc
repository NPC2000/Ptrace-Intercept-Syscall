#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <elf.h>

#include <unistd.h>
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>

void read_file(pid_t child, char *file, user_regs_struct regs) {
	char *child_addr;
	int i;
	child_addr = (char *)regs.regs[1];
	do {
		long val;
		char *p;
		val = ptrace(PTRACE_PEEKTEXT, child, child_addr, NULL);
		if (val == -1) {
			printf("PTRACE_PEEKTEXT error: %s", strerror(errno));
			exit(1);
		}
		child_addr += sizeof(long);
		p = (char *)&val;
		for (i = 0; i < sizeof(long); ++i, ++file) {
			*file = *p++;
			if (*file == '\0')
				break;
		}
	}
	while (i == sizeof(long));
}

void process_signals(pid_t child) {
	bool in_syscall = true;
	int status;
	while (1) {

		struct user_regs_struct regs;
		struct iovec io = {
			.iov_base = &regs,
			.iov_len = sizeof(regs),
		};
		ptrace(PTRACE_SYSCALL, child, 0, 0);
		waitpid(child, &status, 0);
		ptrace(PTRACE_GETREGSET, child, (void *)NT_PRSTATUS, &io);

		if (WIFSTOPPED(status)) {

			switch (regs.regs[8]) {
			default:
				break;
			case __NR_openat:
				if (in_syscall) {				// syscall的before
					char pathname[255];
					read_file(child, pathname, regs);
					printf("[Openat %s]\n", pathname);
					in_syscall = false;
				} else {				// syscall的after
					in_syscall = true;
				}
			}
		}

		if (WIFEXITED(status)) {
			break;
		}

	}
}

int main() {
	int status;
	pid_t child;

	if ((child = fork()) == 0) {

		ptrace(PTRACE_TRACEME, 0, 0, 0);
		kill(getpid(), SIGSTOP);

		int fd = syscall(__NR_openat, AT_FDCWD, "/sdcard/1.txt", O_RDONLY);	// openat系统调用
		printf("openat fd:%d\n", fd);

	} else {
		waitpid(child, &status, 0);
		if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
			process_signals(child);
		}
	}
	return 0;
}
