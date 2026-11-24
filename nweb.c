/* nweb26.c — hardened tiny static web server (based on Nigel Griffiths nweb25)
 * Fixes: privilege drop, path/encoding checks, HTTP compliance, SIGCHLD reaping,
 * safer parsing, proper daemonization. Still a teaching example — not a full server.
 * Compile: cc -O2 -Wall -o nweb nweb26.c
 * Run as root for chroot/low ports, then it drops to nobody (65534).
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define VERSION 26
#define BUFSIZE 65536
#define ERROR      42
#define LOG        44
#define FORBIDDEN 403
#define NOTFOUND  404

struct {
	char *ext;
	char *filetype;
} extensions[] = {
	{"gif",  "image/gif"},
	{"jpg",  "image/jpeg"},
	{"jpeg", "image/jpeg"},
	{"png",  "image/png"},
	{"ico",  "image/x-icon"},
	{"zip",  "application/zip"},
	{"gz",   "application/gzip"},
	{"tar",  "application/x-tar"},
	{"htm",  "text/html"},
	{"html", "text/html"},
	{0, 0}
};

static void reap(int sig)
{
	(void)sig;
	while (waitpid(-1, NULL, WNOHANG) > 0)
		;
}

static void logger(int type, const char *s1, const char *s2, int socket_fd)
{
	int fd;
	char logbuffer[BUFSIZE * 2];
	const char *body403 =
		"<html><head><title>403 Forbidden</title></head><body>"
		"<h1>Forbidden</h1>"
		"<p>The requested URL, file type or operation is not allowed "
		"on this simple static file webserver.</p></body></html>\n";
	const char *body404 =
		"<html><head><title>404 Not Found</title></head><body>"
		"<h1>Not Found</h1>"
		"<p>The requested URL was not found on this server.</p></body></html>\n";
	int len403 = (int)strlen(body403);
	int len404 = (int)strlen(body404);

	switch (type) {
	case ERROR:
		snprintf(logbuffer, sizeof(logbuffer),
			 "ERROR: %s:%s Errno=%d exiting pid=%d",
			 s1 ? s1 : "", s2 ? s2 : "", errno, getpid());
		break;
	case FORBIDDEN:
		snprintf(logbuffer, sizeof(logbuffer),
			 "HTTP/1.1 403 Forbidden\r\n"
			 "Content-Length: %d\r\n"
			 "Connection: close\r\n"
			 "Content-Type: text/html\r\n\r\n%s",
			 len403, body403);
		(void)write(socket_fd, logbuffer, strlen(logbuffer));
		snprintf(logbuffer, sizeof(logbuffer), "FORBIDDEN: %s:%s",
			 s1 ? s1 : "", s2 ? s2 : "");
		break;
	case NOTFOUND:
		snprintf(logbuffer, sizeof(logbuffer),
			 "HTTP/1.1 404 Not Found\r\n"
			 "Content-Length: %d\r\n"
			 "Connection: close\r\n"
			 "Content-Type: text/html\r\n\r\n%s",
			 len404, body404);
		(void)write(socket_fd, logbuffer, strlen(logbuffer));
		snprintf(logbuffer, sizeof(logbuffer), "NOT FOUND: %s:%s",
			 s1 ? s1 : "", s2 ? s2 : "");
		break;
	case LOG:
		snprintf(logbuffer, sizeof(logbuffer), " INFO: %s:%s:%d",
			 s1 ? s1 : "", s2 ? s2 : "", socket_fd);
		break;
	default:
		return;
	}

	if ((fd = open("nweb.log", O_CREAT | O_WRONLY | O_APPEND, 0640)) >= 0) {
		(void)write(fd, logbuffer, strlen(logbuffer));
		(void)write(fd, "\n", 1);
		(void)close(fd);
	}
	if (type == ERROR || type == NOTFOUND || type == FORBIDDEN)
		exit(3);
}

/* Child: serve one request then exit */
static void web(int fd, int hit)
{
	long ret, len;
	int file_fd, buflen, i, j;
	char *fstr;
	static char buffer[BUFSIZE + 1];
	char path[BUFSIZE];

	ret = read(fd, buffer, BUFSIZE);
	if (ret <= 0) {
		logger(FORBIDDEN, "failed to read browser request", "", fd);
	}
	if (ret > 0 && ret < BUFSIZE)
		buffer[ret] = 0;
	else
		buffer[0] = 0;

	/* Flatten CR/LF for logging / simple parse */
	for (i = 0; i < ret; i++)
		if (buffer[i] == '\r' || buffer[i] == '\n')
			buffer[i] = '*';

	logger(LOG, "request", buffer, hit);

	if (strncmp(buffer, "GET ", 4) && strncmp(buffer, "get ", 4))
		logger(FORBIDDEN, "Only simple GET operation supported", buffer, fd);

	/* Null-terminate at first space (ignore HTTP version / headers) */
	for (i = 4; i < (int)ret && buffer[i]; i++) {
		if (buffer[i] == ' ') {
			buffer[i] = 0;
			break;
		}
	}

	/* Must be GET /something */
	if (buffer[4] != '/')
		logger(FORBIDDEN, "URL must start with /", buffer, fd);

	/* Reject encoded or raw parent-dir tricks and odd characters */
	for (j = 4; buffer[j]; j++) {
		if (buffer[j] == '%' || buffer[j] == '\0' ||
		    (buffer[j] == '.' && buffer[j + 1] == '.'))
			logger(FORBIDDEN, "Illegal path characters or ..", buffer, fd);
	}

	/* Default directory request to index.html */
	if (!strcmp(buffer, "GET /") || !strcmp(buffer, "get /"))
		strncpy(buffer, "GET /index.html", sizeof(buffer) - 1);

	buflen = (int)strlen(buffer);
	fstr = NULL;
	for (i = 0; extensions[i].ext != 0; i++) {
		len = (long)strlen(extensions[i].ext);
		if (buflen >= (int)len + 5 &&
		    !strncmp(&buffer[buflen - (int)len], extensions[i].ext, (size_t)len)) {
			fstr = extensions[i].filetype;
			break;
		}
	}
	if (fstr == NULL)
		logger(FORBIDDEN, "file extension type not supported", buffer, fd);

	/* Copy path (skip "GET ") into a clean buffer */
	if (buflen < 5)
		logger(FORBIDDEN, "path too short", buffer, fd);
	strncpy(path, &buffer[4], sizeof(path) - 1);
	path[sizeof(path) - 1] = 0;

	if ((file_fd = open(path, O_RDONLY)) == -1)
		logger(NOTFOUND, "failed to open file", path, fd);

	logger(LOG, "SEND", path, hit);

	len = (long)lseek(file_fd, (off_t)0, SEEK_END);
	if (len < 0)
		logger(NOTFOUND, "lseek failed", path, fd);
	(void)lseek(file_fd, (off_t)0, SEEK_SET);

	snprintf(buffer, sizeof(buffer),
		 "HTTP/1.1 200 OK\r\n"
		 "Server: nweb/%d\r\n"
		 "Content-Length: %ld\r\n"
		 "Connection: close\r\n"
		 "Content-Type: %s\r\n\r\n",
		 VERSION, len, fstr);
	logger(LOG, "Header", buffer, hit);
	(void)write(fd, buffer, strlen(buffer));

	while ((ret = read(file_fd, buffer, BUFSIZE)) > 0)
		(void)write(fd, buffer, (size_t)ret);

	close(file_fd);
	close(fd);
	exit(0);
}

int main(int argc, char **argv)
{
	int i, port, pid, listenfd, socketfd, hit;
	socklen_t length;
	static struct sockaddr_in cli_addr;
	static struct sockaddr_in serv_addr;

	if (argc != 3 || !strcmp(argv[1], "-?")) {
		printf("hint: nweb Port-Number Top-Directory\t\tversion %d\n\n"
		       "\tnweb is a small and very safe mini web server\n"
		       "\tnweb only serves files with the extensions listed below\n"
		       "\t and only from the named directory (via chroot) or its sub-directories.\n"
		       "\tThere are no fancy features = safer by design.\n\n"
		       "\tExample: nweb 8181 /home/nwebdir &\n\n"
		       "\tOnly Supports:", VERSION);
		for (i = 0; extensions[i].ext != 0; i++)
			printf(" %s", extensions[i].ext);
		printf("\n\tNot Supported: URLs containing \"..\" or %% encoding, Java, CGI\n"
		       "\tNot Supported as top dir: / /etc /bin /lib /tmp /usr /dev /sbin\n"
		       "\tNo warranty given or implied\n"
		       "\tHardened from Nigel Griffiths nweb (nag@uk.ibm.com)\n");
		exit(0);
	}

	if (!strncmp(argv[2], "/", 2) || !strncmp(argv[2], "/etc", 5) ||
	    !strncmp(argv[2], "/bin", 5) || !strncmp(argv[2], "/lib", 5) ||
	    !strncmp(argv[2], "/tmp", 5) || !strncmp(argv[2], "/usr", 5) ||
	    !strncmp(argv[2], "/dev", 5) || !strncmp(argv[2], "/sbin", 6)) {
		printf("ERROR: Bad top directory %s, see nweb -?\n", argv[2]);
		exit(3);
	}

	if (chroot(argv[2]) == -1) {
		printf("ERROR: Can't chroot to directory %s (%s)\n", argv[2], strerror(errno));
		exit(4);
	}
	if (chdir("/") == -1) {
		printf("ERROR: chdir after chroot failed\n");
		exit(4);
	}

	/* Drop privileges if we are root (common for low ports / chroot) */
	if (geteuid() == 0) {
		if (setgid(65534) == -1 || setuid(65534) == -1) {
			printf("ERROR: failed to drop privileges to nobody (65534)\n");
			exit(5);
		}
	}

	/* Daemonize */
	if (fork() != 0)
		return 0;
	(void)setsid();
	(void)signal(SIGHUP, SIG_IGN);
	(void)signal(SIGCHLD, reap);
	for (i = 0; i < 32; i++)
		(void)close(i);

	logger(LOG, "nweb starting", argv[1], getpid());

	if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		logger(ERROR, "system call", "socket", 0);

	port = atoi(argv[1]);
	if (port <= 0 || port > 60000)
		logger(ERROR, "Invalid port number (try 1->60000)", argv[1], 0);

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons((uint16_t)port);

	if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		logger(ERROR, "system call", "bind", 0);
	if (listen(listenfd, 64) < 0)
		logger(ERROR, "system call", "listen", 0);

	for (hit = 1;; hit++) {
		length = sizeof(cli_addr);
		socketfd = accept(listenfd, (struct sockaddr *)&cli_addr, &length);
		if (socketfd < 0) {
			if (errno == EINTR)
				continue;
			logger(ERROR, "system call", "accept", 0);
		}
		if ((pid = fork()) < 0) {
			logger(ERROR, "system call", "fork", 0);
		} else if (pid == 0) { /* child */
			(void)close(listenfd);
			web(socketfd, hit);
		} else { /* parent */
			(void)close(socketfd);
		}
	}
}
