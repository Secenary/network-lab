#include "driver.h"
#include "net.h"
#include "tcp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <stdbool.h>  // 添加bool类型支持
#include <windows.h>  // Windows平台特定函数

#define FTP_CONTROL_PORT 21
#define FTP_DATA_PORT_MIN 1025
#define FTP_DATA_PORT_MAX 65535
#define FTP_ROOT_DIR "./ftp_root"
#define MAX_FILENAME_LEN 256
#define MAX_CMD_LEN 256

// FTP连接状态
typedef struct {
    bool logged_in;               // 登录状态
    uint16_t data_port;          // 数据端口
    char current_cmd[5];         // 当前命令
    char filename[MAX_FILENAME_LEN]; // 文件名
    FILE *file;                  // 文件指针
    uint8_t remote_ip[NET_IP_LEN]; // 客户端IP
    uint16_t remote_port;        // 客户端端口
    uint16_t host_port;          // 服务器端口
} ftp_control_state_t;

// 全局状态表
map_t ftp_control_state_table;   // 控制连接状态表
map_t ftp_data_port_map;         // 数据端口映射表

// 生成控制连接键
static inline tcp_key_t generate_control_key(uint8_t remote_ip[NET_IP_LEN], 
                                            uint16_t remote_port, 
                                            uint16_t host_port) {
    tcp_key_t key;
    memcpy(key.remote_ip, remote_ip, NET_IP_LEN);
    key.remote_port = remote_port;
    key.host_port = host_port;
    return key;
}

// 检查路径安全性
static int check_path_safety(const char *path) {
    if (strstr(path, "..") != NULL) {
        return -1; // 路径包含..，不安全
    }
    return 0;
}

// 获取文件路径
static void get_file_path(char *filepath, const char *filename) {
    snprintf(filepath, MAX_FILENAME_LEN, FTP_ROOT_DIR "/%s", filename);
}

// 发送FTP响应
static void ftp_send_response(tcp_conn_t *tcp_conn, const char *response, 
                              uint16_t port, uint8_t *dst_ip, uint16_t dst_port) {
    char resp_buf[256];
    snprintf(resp_buf, sizeof(resp_buf), "%s\r\n", response);
    tcp_send(tcp_conn, (uint8_t *)resp_buf, strlen(resp_buf), port, dst_ip, dst_port);
}

// 数据连接处理函数
void ftp_data_handler(tcp_conn_t *tcp_conn, uint8_t *data, size_t len, 
                      uint8_t *src_ip, uint16_t src_port) {
    uint16_t data_port = tcp_conn->port;
    
    // 查找对应的控制连接
    tcp_key_t *ctrl_key = map_get(&ftp_data_port_map, &data_port);
    if (!ctrl_key) {
        tcp_close_connection(src_ip, src_port, data_port);
        return;
    }
    
    ftp_control_state_t *state = map_get(&ftp_control_state_table, ctrl_key);
    if (!state) {
        tcp_close_connection(src_ip, src_port, data_port);
        return;
    }
    
    tcp_conn_t *ctrl_conn = tcp_get_connection(
        state->remote_ip, state->remote_port, state->host_port, false);
    if (!ctrl_conn) {
        tcp_close_connection(src_ip, src_port, data_port);
        return;
    }
    
    // 处理命令
    if (strcmp(state->current_cmd, "LIST") == 0) {
        // 列出目录
        DIR *dir = opendir(FTP_ROOT_DIR);
        if (dir) {
            struct dirent *entry;
            char list_buf[512];
            while ((entry = readdir(dir)) != NULL) {
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                    continue;
                
                struct stat st;
                char filepath[MAX_FILENAME_LEN];
                get_file_path(filepath, entry->d_name);
                
                if (stat(filepath, &st) == 0) {
                    char type = S_ISDIR(st.st_mode) ? 'd' : '-';
                    char time_buf[32];
                    strftime(time_buf, sizeof(time_buf), "%b %d %H:%M", localtime(&st.st_mtime));
                    
                    snprintf(list_buf, sizeof(list_buf), "%c%c%c%c%c%c%c%c%c%c 1 ftp ftp %10ld %s %s",
                             type, 'r', 'w', 'x', 'r', 'w', 'x', 'r', 'w', 'x',
                             st.st_size, time_buf, entry->d_name);
                    tcp_send(tcp_conn, (uint8_t *)list_buf, strlen(list_buf), 
                             data_port, src_ip, src_port);
                }
            }
            closedir(dir);
        }
        ftp_send_response(ctrl_conn, "226 Directory send OK", 
                          state->host_port, state->remote_ip, state->remote_port);
    } 
    else if (strcmp(state->current_cmd, "RETR") == 0) {
        // 下载文件
        char filepath[MAX_FILENAME_LEN];
        get_file_path(filepath, state->filename);
        
        FILE *file = fopen(filepath, "rb");
        if (file) {
            char buf[1024];
            size_t bytes_read;
            while ((bytes_read = fread(buf, 1, sizeof(buf), file)) > 0) {
                tcp_send(tcp_conn, (uint8_t *)buf, bytes_read, 
                         data_port, src_ip, src_port);
            }
            fclose(file);
            ftp_send_response(ctrl_conn, "226 Transfer complete", 
                              state->host_port, state->remote_ip, state->remote_port);
        } else {
            ftp_send_response(ctrl_conn, "550 Failed to open file", 
                              state->host_port, state->remote_ip, state->remote_port);
        }
    } 
    else if (strcmp(state->current_cmd, "STOR") == 0) {
        // 上传文件
        if (state->file == NULL) {
            char filepath[MAX_FILENAME_LEN];
            get_file_path(filepath, state->filename);
            state->file = fopen(filepath, "wb");
            if (!state->file) {
                ftp_send_response(ctrl_conn, "550 Could not create file", 
                                  state->host_port, state->remote_ip, state->remote_port);
            }
        }
        
        if (state->file && len > 0) {
            fwrite(data, 1, len, state->file);
        }
        
        if (len == 0) { // 连接关闭
            if (state->file) {
                fclose(state->file);
                state->file = NULL;
                ftp_send_response(ctrl_conn, "226 Transfer complete", 
                                  state->host_port, state->remote_ip, state->remote_port);
            }
        }
    }
    
    // 关闭数据连接
    if (len == 0) {
        tcp_close(data_port);
        map_delete(&ftp_data_port_map, &data_port);
        state->data_port = 0;
        memset(state->current_cmd, 0, sizeof(state->current_cmd));
    }
}

// 控制连接处理函数
void ftp_control_handler(tcp_conn_t *tcp_conn, uint8_t *data, size_t len, 
                         uint8_t *src_ip, uint16_t src_port) {
    // 获取或创建控制状态
    tcp_key_t ctrl_key = generate_control_key(src_ip, src_port, tcp_conn->port);
    ftp_control_state_t *state = map_get(&ftp_control_state_table, &ctrl_key);
    
    if (!state) {
        // 新连接
        ftp_control_state_t new_state = {0};
        memcpy(new_state.remote_ip, src_ip, NET_IP_LEN);
        new_state.remote_port = src_port;
        new_state.host_port = tcp_conn->port;
        map_set(&ftp_control_state_table, &ctrl_key, &new_state);
        
        state = map_get(&ftp_control_state_table, &ctrl_key);
        ftp_send_response(tcp_conn, "220 FTP Server Ready", 
                          tcp_conn->port, src_ip, src_port);
        return;
    }
    
    // 处理命令
    char cmd_buf[MAX_CMD_LEN];
    if (len >= MAX_CMD_LEN) len = MAX_CMD_LEN - 1;
    memcpy(cmd_buf, data, len);
    cmd_buf[len] = '\0';
    
    // 移除回车换行
    char *newline = strchr(cmd_buf, '\r');
    if (newline) *newline = '\0';
    newline = strchr(cmd_buf, '\n');
    if (newline) *newline = '\0';
    
    // 解析命令
    char *cmd = strtok(cmd_buf, " ");
    char *arg = cmd ? strtok(NULL, " ") : NULL;
    
    if (!cmd) {
        ftp_send_response(tcp_conn, "500 Syntax error", 
                          tcp_conn->port, src_ip, src_port);
        return;
    }
    
    // 处理命令
    if (strcasecmp(cmd, "USER") == 0) {
        // 简化认证，任何用户名都接受
        state->logged_in = false; // 需要密码
        ftp_send_response(tcp_conn, "331 Password required", 
                          tcp_conn->port, src_ip, src_port);
    } 
    else if (strcasecmp(cmd, "PASS") == 0) {
        // 简化认证，任何密码都接受
        state->logged_in = true;
        ftp_send_response(tcp_conn, "230 User logged in", 
                          tcp_conn->port, src_ip, src_port);
    } 
    else if (!state->logged_in) {
        ftp_send_response(tcp_conn, "530 Not logged in", 
                          tcp_conn->port, src_ip, src_port);
    } 
    else if (strcasecmp(cmd, "PASV") == 0) {
        // 被动模式
        if (state->data_port != 0) {
            tcp_close(state->data_port);
            map_delete(&ftp_data_port_map, &state->data_port);
        }
        
        // 随机选择数据端口
        state->data_port = FTP_DATA_PORT_MIN + rand() % (FTP_DATA_PORT_MAX - FTP_DATA_PORT_MIN);
        
        if (tcp_open(state->data_port, ftp_data_handler) < 0) {
            ftp_send_response(tcp_conn, "425 Can't open data connection", 
                              tcp_conn->port, src_ip, src_port);
            state->data_port = 0;
            return;
        }
        
        // 记录映射
        map_set(&ftp_data_port_map, &state->data_port, &ctrl_key);
        
        // 发送被动模式响应
        char resp[128];
        snprintf(resp, sizeof(resp), "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)",
                 net_if_ip[0], net_if_ip[1], net_if_ip[2], net_if_ip[3],
                 state->data_port >> 8, state->data_port & 0xFF);
        ftp_send_response(tcp_conn, resp, tcp_conn->port, src_ip, src_port);
    } 
    else if (strcasecmp(cmd, "LIST") == 0) {
        if (state->data_port == 0) {
            ftp_send_response(tcp_conn, "425 Use PASV first", 
                              tcp_conn->port, src_ip, src_port);
            return;
        }
        
        strcpy(state->current_cmd, "LIST");
        ftp_send_response(tcp_conn, "150 Opening ASCII mode data connection for file list", 
                          tcp_conn->port, src_ip, src_port);
    } 
    else if (strcasecmp(cmd, "RETR") == 0) {
        if (!arg) {
            ftp_send_response(tcp_conn, "501 Syntax error in parameters", 
                              tcp_conn->port, src_ip, src_port);
            return;
        }
        
        if (state->data_port == 0) {
            ftp_send_response(tcp_conn, "425 Use PASV first", 
                              tcp_conn->port, src_ip, src_port);
            return;
        }
        
        if (check_path_safety(arg) != 0) {
            ftp_send_response(tcp_conn, "550 Invalid filename", 
                              tcp_conn->port, src_ip, src_port);
            return;
        }
        
        char filepath[MAX_FILENAME_LEN];
        get_file_path(filepath, arg);
        
        // 检查文件是否存在
        if (_access(filepath, 0) != 0) {
            ftp_send_response(tcp_conn, "550 File not found", 
                              tcp_conn->port, src_ip, src_port);
            return;
        }
        
        strcpy(state->current_cmd, "RETR");
        strncpy(state->filename, arg, MAX_FILENAME_LEN);
        ftp_send_response(tcp_conn, "150 Opening BINARY mode data connection", 
                          tcp_conn->port, src_ip, src_port);
    } 
    else if (strcasecmp(cmd, "STOR") == 0) {
        if (!arg) {
            ftp_send_response(tcp_conn, "501 Syntax error in parameters", 
                              tcp_conn->port, src_ip, src_port);
            return;
        }
        
        if (state->data_port == 0) {
            ftp_send_response(tcp_conn, "425 Use PASV first", 
                              tcp_conn->port, src_ip, src_port);
            return;
        }
        
        if (check_path_safety(arg) != 0) {
            ftp_send_response(tcp_conn, "550 Invalid filename", 
                              tcp_conn->port, src_ip, src_port);
            return;
        }
        
        // 检查磁盘空间 - Windows版本
        ULARGE_INTEGER free_bytes;
        if (GetDiskFreeSpaceEx(NULL, &free_bytes, NULL, NULL)) {
            if (free_bytes.QuadPart < 1024 * 1024) { // 小于1MB
                ftp_send_response(tcp_conn, "452 Insufficient storage space", 
                                  tcp_conn->port, src_ip, src_port);
                return;
            }
        }
        
        strcpy(state->current_cmd, "STOR");
        strncpy(state->filename, arg, MAX_FILENAME_LEN);
        state->file = NULL;
        ftp_send_response(tcp_conn, "150 Opening BINARY mode data connection", 
                          tcp_conn->port, src_ip, src_port);
    } 
    else if (strcasecmp(cmd, "QUIT") == 0) {
        ftp_send_response(tcp_conn, "221 Goodbye", 
                          tcp_conn->port, src_ip, src_port);
        
        // 清理资源
        if (state->data_port != 0) {
            tcp_close(state->data_port);
            map_delete(&ftp_data_port_map, &state->data_port);
        }
        if (state->file) {
            fclose(state->file);
        }
        
        // 关闭连接
        tcp_close_connection(src_ip, src_port, tcp_conn->port);
        map_delete(&ftp_control_state_table, &ctrl_key);
    } 
    else {
        ftp_send_response(tcp_conn, "502 Command not implemented", 
                          tcp_conn->port, src_ip, src_port);
    }
}

// 初始化FTP服务器
void ftp_init() {
    // 创建FTP根目录 - Windows版本
    if (mkdir(FTP_ROOT_DIR) != 0) {
        if (errno != OF_EXIST) {
            printf("Failed to create FTP root directory\n");
        }
    }
    
    // 初始化状态表
    map_init(&ftp_control_state_table, sizeof(tcp_key_t), sizeof(ftp_control_state_t), 
             0, 0, NULL, NULL);
    map_init(&ftp_data_port_map, sizeof(uint16_t), sizeof(tcp_key_t), 
             0, 0, NULL, NULL);
    
    // 打开控制端口
    if (tcp_open(FTP_CONTROL_PORT, ftp_control_handler) < 0) {
        printf("Failed to open FTP control port %d\n", FTP_CONTROL_PORT);
        exit(1);
    }
    
    printf("FTP server started on port %d\n", FTP_CONTROL_PORT);
}

int main(int argc, char const *argv[]) {
    if (net_init() == -1) {
        printf("net init failed.");
        return -1;
    }
    
    tcp_init();
    ftp_init();
    
    while (1) {
        net_poll();
    }
    
    return 0;
}

