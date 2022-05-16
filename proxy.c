#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
//#include "stb_ds.h"

#define arrlen(x) (sizeof(x)/(sizeof((x)[0])))

#define BUFSIZE 16384

typedef struct buffer {
	uint8_t *data;
	int len;
	int sent;
} buffer;

int is_buf_empty(buffer *buf) {
	assert(buf->sent <= buf->len);
	return buf->sent == buf->len;
}

int is_buf_full(buffer *buf) {
	assert(buf->sent <= buf->len);
	return buf->len == BUFSIZE;
}

int find_pattern_in_buf(buffer *buf, uint8_t *pattern, int pattern_len) {
	int result = -1;
	for(int i = 0; i < buf->len; i++) {
		uint8_t match = 1;
		for(int j = 0; j < pattern_len; j++) {
			if(buf->data[i+j] != pattern[j]) {
				match = 0;
				break;
			}
		}
		if(match) {
			result = i;
			break;
		}
	}
	return result;
}

typedef struct connection {
	uint8_t client_closed;
	uint8_t proxy_closed;
	uint8_t have_read_from_client;
	int client_fd;
	int proxy_fd;
	uint8_t client_read_ready;
	uint8_t proxy_read_ready;
	uint8_t client_write_ready;
	uint8_t proxy_write_ready;
	buffer client_buf;
	buffer proxy_buf;
} connection;

void print_error(char *error) {
	printf("Error: %s\n", error);
	exit(1);
}

int get_server_socket(char *port) {
	int sock;
	struct addrinfo hints;
	struct addrinfo *ai;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if(getaddrinfo(0, port, &hints, &ai) != 0) {
		print_error("getaddrinfo");
	}
	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if(socket < 0) {
		print_error("socket");
	}
	if(bind(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
		print_error("bind");
	}
	if(listen(sock, 20) < 0) {
		print_error("listen");
	}
	freeaddrinfo(ai);
	return sock;
}

int get_client_conn(char *ip, char *port) {
	int sock;
	struct addrinfo hints;
	struct addrinfo *ai;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if(getaddrinfo(ip, port, &hints, &ai) != 0) {
		return -1;
	}
	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if(socket < 0) {
		return -1;
	}
	if(connect(sock, ai->ai_addr, ai->ai_addrlen) != 0) {
		return -1;
	}
	return sock;
}

void add_epoll_fd(uint32_t events, int ep, int fd) {
	struct epoll_event event;
	event.events = events;
	event.data.fd = fd;
	if(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) != 0) {
		print_error("add_epoll_fd");
	}
}

connection *find_conn(int fd, connection *conns, int count) {
	for(int i = 0; i < count; i++) {
		connection *conn = conns + i;
		if(conn->client_fd == fd || conn->proxy_fd == fd) {
			return conns + i;
		}
	}
	return 0;
}

typedef struct buffer_result {
	int sockclosed;
	int eof;
} buffer_result;

buffer_result read_to_buffer(int fd, buffer *buf) {
	buffer_result result;
	result.sockclosed = 0;
	result.eof = 0;
	for(;;) {
		int spaceleft = BUFSIZE - buf->len;
		if(spaceleft > 0) {
			int n = recv(fd, buf->data + buf->len, spaceleft, 0);
			if(n > 0) {
				buf->len += n;
			} else if (n == 0) {
				result.sockclosed = 1;
				break;
			} else {
				if(errno != EAGAIN && errno != EWOULDBLOCK) {
					result.sockclosed = 1;
				} else {
					result.eof = 1;
				}
				break;
			}
		} else {
			break;
		}
	}
	return result;
}

buffer_result write_from_buffer(int fd, buffer *buf) {
	buffer_result result;
	result.sockclosed = 0;
	result.eof = 0;
	for(;;) {
		int left = buf->len - buf->sent;
		if(left > 0) {
			int n = send(fd, buf->data + buf->sent, left, MSG_NOSIGNAL);
			if(n > 0) {
				buf->sent += n;
			} else if(n == 0){
				result.sockclosed = 1;
				break;
			} else {
				if(errno != EAGAIN && errno != EWOULDBLOCK) {
					result.sockclosed = 1;
				} else {
					result.eof = 1;
				}
				break;
			}
		} else {
			break;
		}
	}

	if(is_buf_empty(buf)) {
		buf->len = 0;
		buf->sent = 0;
	}
	return result;
}

void inject_proxy_auth(buffer *buf, char *auth) {
	if(buf->len < 8) {
		return;
	}

	uint8_t matches_http_method = (
		!strncmp((char *)buf->data, "CONNECT ", 8)  || 
		!strncmp((char *)buf->data, "GET ", 4) ||
		!strncmp((char *)buf->data, "PUT ", 5) ||
		!strncmp((char *)buf->data, "PATCH ", 6) ||
		!strncmp((char *)buf->data, "DELETE ", 7) 
	);

	// TODO: precalc strlen
	int authbytes = strlen(auth);

	if(buf->len + authbytes > BUFSIZE) {
		return;
	}

	if(matches_http_method) {
		if(buf->data[buf->len - 4] != '\r' || buf->data[buf->len - 3] != '\n' || buf->data[buf->len - 2] != '\r' || buf->data[buf->len - 1] != '\n') {
			return;
		}
		memcpy(buf->data + buf->len - 2, auth, authbytes);
		buf->len += authbytes - 2;
		buf->data[buf->len] = 0;
		if(buf->len < BUFSIZE) buf->data[buf->len] = 0; // for debug printing
	} else if(!strncmp((char *)buf->data, "POST ", 5)) {
		int body = find_pattern_in_buf(buf, "\r\n\r\n", 4);
		if(body < 0) {
			return;
		}
		body += 4;
		
		memcpy(buf->data + body - 2 + authbytes, buf->data + body, buf->len - body);
		memcpy(buf->data + body - 2, auth, authbytes);
		buf->len += authbytes - 2;
		if(buf->len < BUFSIZE) buf->data[buf->len] = 0; // for debug printing
	} else {
		return;
	}
}

int base64encode(uint8_t *str, int bytes, uint8_t *output, int outbytes) {
	char alphabet[] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"};	

	int spaceneeded = (8*bytes + 5)/6 + 1;
	if(outbytes < spaceneeded) {
		print_error("base64encode: not enough space in output buffer\n");
	}

	int j = 0;
	int bytesleft = bytes % 3;
	for(int i = 0; i < bytes - bytesleft; ) {
		uint32_t byte2 = str[i++];
		uint32_t byte1 = str[i++];
		uint32_t byte0 = str[i++];
		uint32_t together = (byte2 << 16) | (byte1 << 8) | byte0;
		output[j++] = alphabet[together >> 18];
		output[j++] = alphabet[(together >> 12) & 0x3f];
		output[j++] = alphabet[(together >> 6) & 0x3f];
		output[j++] = alphabet[together & 0x3f];
	}
	if(bytesleft == 1) {
		uint32_t byte = str[bytes-1];
		output[j++] = alphabet[(byte & 0xfc) >> 2];
		output[j++] = alphabet[(byte & 0x3) << 4];
	} else if(bytesleft == 2) {
		uint32_t together = (str[bytes-2] << 8) | (str[bytes-1]);
		output[j++] = alphabet[together >> 10];
		output[j++] = alphabet[(together >> 4) & 0x3f];
		output[j++] = alphabet[(together & 0xf) << 2];
	}
	output[j] = 0;
	return j;
}

uint8_t *get_free_buffer(void **free_buffers, int *num_mallocs) {
	uint8_t *result = 0;
	if(*free_buffers) {
		result = *free_buffers;
		intptr_t next = *(intptr_t *)(result);
		*free_buffers = (void *)next;
	} else {
		result = malloc(BUFSIZE);
		*num_mallocs = (*num_mallocs) + 1;
	}
	return result;
}

void add_free_buffer(void **free_buffers, uint8_t *buffer) {
	assert(buffer);
	*(intptr_t *)buffer = (intptr_t)*free_buffers;
	*free_buffers = buffer;
}

void add_connection(int server_fd, connection *conns, int *conncount, int ep, char *proxy_ip, char *proxy_port, void **free_buffers, int *num_mallocs) {
	struct sockaddr_storage their_addr;
	socklen_t addr_size = sizeof(their_addr);
	int client_fd = accept(server_fd, (struct sockaddr *)&their_addr, &addr_size);
	if(client_fd < 0) {
		return;
	}
	connection conn;
	memset(&conn, 0, sizeof(conn));
	conn.client_fd = client_fd;
	conn.proxy_fd = get_client_conn(proxy_ip, proxy_port);
	if(conn.proxy_fd < 0) {
		close(client_fd);
		return;
	}
	conn.client_buf.data = get_free_buffer(free_buffers, num_mallocs);
	conn.proxy_buf.data = get_free_buffer(free_buffers, num_mallocs);

	fcntl(conn.client_fd, F_SETFL, O_NONBLOCK);
	fcntl(conn.proxy_fd, F_SETFL, O_NONBLOCK);

	conns[*conncount] = conn;
	*conncount = (*conncount) + 1;

	add_epoll_fd(EPOLLIN | EPOLLOUT | EPOLLET, ep, conn.client_fd);
	add_epoll_fd(EPOLLIN | EPOLLOUT | EPOLLET, ep, conn.proxy_fd);
}

int main(int argc, char **argv) {
	if(argc == 1) {
		printf("Usage: ./proxy <listen_port> <proxy_ip> <proxy_port> <proxy_username>:<proxy_password>\n");
		exit(0);
	}
	char *listen_port = argv[1];
	char *proxy_ip = argv[2];
	char *proxy_port = argv[3];
	char *proxy_auth = argv[4];

	char *proxy_auth_key = "Proxy-Authorization: Basic ";
	char proxy_auth_value[512];
	base64encode((uint8_t *)proxy_auth, strlen(proxy_auth), (uint8_t *)proxy_auth_value, sizeof(proxy_auth_value));
	char proxy_auth_buf[1024];
	assert(strlen(proxy_auth_key) + strlen(proxy_auth_value) + 4 < sizeof(proxy_auth_buf));
	sprintf(proxy_auth_buf, "%s%s\r\n\r\n", proxy_auth_key, proxy_auth_value);

	int server_fd = get_server_socket(listen_port);	

	int ep = epoll_create(20);
	if(ep < 0) {
		print_error("epoll");
	}
	add_epoll_fd(EPOLLIN, ep, server_fd);

	struct epoll_event events[32];
	connection conns[4096];
	memset(conns, 0, sizeof(conns));
	int conncount = 0;
	void *free_buffers = 0;
	int num_mallocs = 0;

	time_t last_print = 0;

	for(;;) {
		int fdcount = epoll_wait(ep, events, arrlen(events), -1);

		for(int i = 0; i < fdcount; i++) {
			struct epoll_event *event = events + i;
			if(event->data.fd == server_fd) {
				if(event->events & EPOLLIN) {
					if(conncount < arrlen(conns)) {
						add_connection(server_fd, conns, &conncount, ep, proxy_ip, proxy_port, &free_buffers, &num_mallocs);
					} else {
						print_error("ran out of connections");
					}
				} else {
					print_error("server_fd didn't get EPOLLIN");
				}
			} else {
				int sockfd = event->data.fd;
				connection *conn = find_conn(sockfd, conns, conncount);
				if(conn == 0) {
					print_error("failed to find connection with matching file descriptor");
				}
				if(event->events & EPOLLIN) {
					if(sockfd == conn->client_fd) {
						conn->client_read_ready = 1;
					} else {
						assert(sockfd == conn->proxy_fd);
						conn->proxy_read_ready = 1;
					}
				}
				if (event->events & EPOLLOUT) {
					if(sockfd == conn->client_fd) {
						conn->client_write_ready = 1;
					} else {
						assert(sockfd == conn->proxy_fd);
						conn->proxy_write_ready = 1;
					}
				}
				/*if(!(event->events & (EPOLLIN|EPOLLOUT))) {
					if(sockfd == conn->client_fd) {
						conn->client_read_ready = 0;
						conn->client_write_ready = 0;
						conn->client_closed = 1;
					} else {
						assert(sockfd == conn->proxy_fd);
						conn->proxy_read_ready = 0;
						conn->proxy_write_ready = 0;
						conn->proxy_closed = 1;
					}
				}*/
			}
		}

		for(int i = 0; i < conncount; i++) {
			connection *conn = conns + i;

			int keepgoing;
			do {
				keepgoing = 0;
				if(conn->client_read_ready) {
					buffer_result result = read_to_buffer(conn->client_fd, &conn->client_buf);
					if(!conn->have_read_from_client) {
						inject_proxy_auth(&conn->client_buf, proxy_auth_buf);
						conn->have_read_from_client = 1;
					}
					if(result.sockclosed) {
						conn->client_read_ready = 0;
						conn->client_closed = 1;
					} else if (result.eof) {
						conn->client_read_ready = 0;
					} else if(!is_buf_full(&conn->client_buf)) {
						keepgoing = 1;
					}
				}
				if(conn->proxy_write_ready && !is_buf_empty(&conn->client_buf)) {
					buffer_result result = write_from_buffer(conn->proxy_fd, &conn->client_buf);
					if(result.sockclosed) {
						conn->proxy_write_ready = 0;
						conn->proxy_closed = 1;
					} else if(result.eof) {
						conn->proxy_write_ready = 0;
					} else {
						keepgoing = 1;
					}
				}
			} while(keepgoing);

			do {
				keepgoing = 0;
				if(conn->proxy_read_ready) {
					buffer_result result = read_to_buffer(conn->proxy_fd, &conn->proxy_buf);
					if(result.sockclosed) {
						conn->proxy_read_ready = 0;
						conn->proxy_closed = 1;
					} else if(result.eof) {
						conn->proxy_read_ready = 0;
					} else if(!is_buf_full(&conn->proxy_buf)) {
						keepgoing = 1;
					}
				}

				if(conn->client_write_ready && !is_buf_empty(&conn->proxy_buf)) {
					buffer_result result = write_from_buffer(conn->client_fd, &conn->proxy_buf);
					if(result.sockclosed) {
						conn->client_write_ready = 0;
						conn->client_closed = 1;
					} else if(result.eof) {
						conn->client_write_ready = 0;
					} else {
						keepgoing = 1;
					}
				}
			} while(keepgoing);	
		}

		for(int i = 0; i < conncount;) {
			uint8_t closeit = 0;
			connection *conn = conns + i;
			if(conn->client_closed && conn->proxy_closed) {
				closeit = 1;
			} else if(conn->client_closed && is_buf_empty(&conn->client_buf)) {
				closeit = 1;
			} else if(conn->proxy_closed && is_buf_empty(&conn->proxy_buf)) {
				closeit = 1;
			}

			if(closeit) {
				close(conn->client_fd); // just in case
				close(conn->proxy_fd); // just in case
				conncount--;
				add_free_buffer(&free_buffers, conn->client_buf.data);
				add_free_buffer(&free_buffers, conn->proxy_buf.data);
				if(conncount > 0) {
					conns[i] = conns[conncount];
				}
			} else {
				i++;
			}
		}

		time_t now = time(0);
		if(now - last_print >= 300) {		
			printf("connections = %4d\tmallocs = %d\n", conncount, num_mallocs);
			last_print = now;
		}
	}
}
