#include "proc/cpu.h"
#include "mem/vmem.h"
#include "fs/inode.h"
#include "fs/dir.h"
#include "fs/file.h"
#include "lib/str.h"
#include "lib/print.h"
#include "syscall/syscall.h"
#include "syscall/sysfunc.h"

// 提取系统调用第n个参数对应的文件描述符及关联文件结构
// 执行成功返回0，参数非法或无对应文件返回-1
static int arg_fd(int n, int* pfd, file_t** pfile)
{
    // 从系统调用参数中提取文件描述符值
    int fd = 0;
    arg_uint32(n, (uint32*)(&fd));
    
    // 校验文件描述符是否在合法取值区间内
    if(fd < 0 || fd >= FILE_PER_PROC)
        return -1;
    
    // 获取当前进程文件描述符表中该fd对应的文件实例
    file_t* file = myproc()->filelist[fd];
    if(file == NULL)
        return -1;
    
    // 按需回填文件描述符和文件结构指针
    if(pfd) *pfd = fd;
    if(pfile) *pfile = file;

    return 0;
}

// 为指定文件结构分配一个可用的文件描述符
// 分配成功返回有效fd，描述符表满返回-1
static int fd_alloc(file_t* file)
{
    proc_t* curr_proc = myproc();

    // 遍历当前进程文件描述符表，寻找空闲项
    for(int file_desc = 0; file_desc < FILE_PER_PROC; file_desc++) {
        if(curr_proc->filelist[file_desc] == NULL) {
            curr_proc->filelist[file_desc] = file;
            return file_desc;
        }
    }

    return -1;
}

// 系统调用：打开或创建指定路径的文件
// 入参：文件路径path、打开模式open_mode
// 执行成功返回分配的文件描述符，失败返回-1
uint64 sys_open()
{
    char file_path[DIR_PATH_LEN];
    uint32 open_flag;

    arg_str(0, file_path, DIR_PATH_LEN);
    arg_uint32(1, &open_flag);

    file_t* target_file = file_open(file_path, open_flag);
    if(target_file == NULL)
        return -1;
    
    // 为打开的文件分配fd，分配失败则关闭文件释放资源
    int alloc_fd = fd_alloc(target_file);
    if(alloc_fd == -1)
        file_close(target_file);

    return alloc_fd;
}

// 系统调用：关闭指定文件描述符对应的文件
// 入参：待关闭文件的描述符fd
// 执行成功返回0，参数非法返回-1
uint64 sys_close()
{
    int target_fd;
    file_t* target_file;

    // 提取并校验文件描述符及对应文件
    if(arg_fd(0, &target_fd, &target_file) < 0)
        return -1;

    // 清空进程描述符表项并关闭文件
    myproc()->filelist[target_fd] = NULL;
    file_close(target_file);

    return 0;
}

// 系统调用：从指定文件中读取数据到用户空间
// 入参：文件描述符fd、读取字节长度len、用户空间存储地址addr
// 读取成功返回实际读取字节数，失败返回0
uint64 sys_read()
{
    uint32 read_len;
    uint64 user_addr;
    file_t* target_file;

    if(arg_fd(0, NULL, &target_file) < 0)
        return -1;
    arg_uint32(1, &read_len);
    arg_uint64(2, &user_addr);

    return file_read(target_file, read_len, user_addr, true);
}

// 系统调用：将用户空间数据写入指定文件
// 入参：文件描述符fd、写入字节长度len、用户空间数据地址addr
// 写入成功返回实际写入字节数，失败返回0
uint64 sys_write()
{
    uint32 write_len;
    uint64 user_addr;
    file_t* target_file;

    if(arg_fd(0, NULL, &target_file) < 0)
        return -1;
    arg_uint32(1, &write_len);
    arg_uint64(2, &user_addr);

    return file_write(target_file, write_len, user_addr, true);
}

// 系统调用：调整文件的当前读写偏移量
// 入参：文件描述符fd、偏移量offset、偏移模式flags（参考LSEEK系列宏）
// 调整成功返回新的文件偏移量，失败返回-1
uint64 sys_lseek()
{
    file_t* target_file;
    uint32 offset_val;
    int seek_flag;

    if(arg_fd(0, NULL, &target_file) < 0)
        return -1;
    arg_uint32(1, &offset_val);
    arg_uint32(2, (uint32*)(&seek_flag));

    return file_lseek(target_file, offset_val, seek_flag);
}

// 系统调用：复制指定的文件描述符
// 入参：待复制的原文件描述符fd
// 复制成功返回新文件描述符，失败返回-1
uint64 sys_dup()
{
    int new_file_desc;
    file_t* target_file;

    if(arg_fd(0, NULL, &target_file) < 0)
        return -1;
    
    // 分配新fd并复制文件引用
    new_file_desc = fd_alloc(target_file);
    file_dup(target_file);

    return new_file_desc;
}

// 系统调用：获取指定文件的属性元数据
// 入参：文件描述符fd、用户空间存储元数据的地址addr
// 获取成功返回0，失败返回-1
uint64 sys_fstat()
{
    uint64 user_addr;
    file_t* target_file;
    
    if(arg_fd(0, NULL, &target_file) < 0)
        return -1;
    arg_uint64(1, &user_addr);

    return file_stat(target_file, user_addr);
}

// 系统调用：读取指定目录中的目录项数据
// 入参：目录对应的文件描述符fd、用户空间存储地址addr、读取长度len
// 读取成功返回实际读取字节数，非目录文件或失败返回-1
uint64 sys_getdir()
{
    file_t* target_file;
    uint64 user_addr;
    uint32 read_len;

    if(arg_fd(0, NULL, &target_file) < 0)
        return -1;
    arg_uint64(1, &user_addr);
    arg_uint32(2, &read_len);

    // 校验目标文件是否为目录类型
    if(target_file->type != FD_DIR || target_file->ip == NULL)
        return -1;

    // 加锁读取目录项，保证数据一致性
    inode_lock(target_file->ip);
    read_len = dir_get_entries(target_file->ip, read_len, (void*)user_addr, true);
    inode_unlock(target_file->ip);

    return read_len;
}

// 系统调用：创建指定路径的目录
// 入参：待创建目录的完整路径path
// 创建成功返回0，路径非法或已存在返回-1
uint64 sys_mkdir()
{
    char dir_path[DIR_PATH_LEN];
    arg_str(0, dir_path, DIR_PATH_LEN);

    inode_t* dir_inode = path_create_inode(dir_path, FT_DIR, 0, 0);

    return (dir_inode == NULL) ? -1 : 0;
}

// 系统调用：切换当前进程的工作目录
// 入参：目标工作目录的完整路径path
// 切换成功返回0，路径非法返回-1
uint64 sys_chdir()
{
    char dir_path[DIR_PATH_LEN];
    arg_str(0, dir_path, DIR_PATH_LEN);

    return dir_change(dir_path);
}

// 系统调用：为已有文件创建硬链接
// 入参：原文件路径old_path、新链接文件路径new_path
// 创建成功返回0，路径非法或文件不存在返回-1
uint64 sys_link()
{
    char src_path[DIR_PATH_LEN], dest_path[DIR_PATH_LEN];
    arg_str(0, src_path, DIR_PATH_LEN);
    arg_str(1, dest_path, DIR_PATH_LEN);

    return path_link(src_path, dest_path);
}

// 系统调用：删除文件的硬链接（链接数为0时删除文件本身）
// 入参：待删除链接的文件路径path
// 删除成功返回0，路径非法返回-1
uint64 sys_unlink()
{
    char file_path[DIR_PATH_LEN];
    arg_str(0, file_path, DIR_PATH_LEN);

    return path_unlink(file_path);
}