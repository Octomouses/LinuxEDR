from bcc import BPF

bpf_source = """


    #include<uapi/linux/ptrace.h>
    #include<linux/sched.h>
    #include<linux/string.h>
    #include <linux/fs.h>
    ssize_t evfs_write(struct pt_regs *ctx,struct file *file, const char __user *buf, size_t count, loff_t *pos) {
//    long sys_write(struct pt_regs *ctx,unsigned int fd, const char __user *buf,size_t count){

        char comm[16];
        char buffer[100];
     //   u32 ptid;
    //    ptid = bpf_get_current_pid_tgid();
//        strncpy(file->f_path.dentry->d_iname,buffer,100);
     //   bpf_get_current_comm(&comm, sizeof(comm)); 
       // bpf_trace_printk("DataSize: %d ",count);
        bpf_trace_printk("%s",file->f_path.dentry->d_iname); 
//        if(count < 20 && count > 10)
           bpf_trace_printk("%s",buf);
    //      bpf_trace_printk("%d",ptid);
        
        return 0;
    }
    """
bpf = BPF(text=bpf_source)
execve_function = bpf.get_syscall_fnname("write")

bpf.attach_kprobe(event="ksys_write",fn_name="evfs_write")


while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
    except ValueError:
        continue
    if str(task) != "b'python3'" and str(task) != "b'sshd'" and len(msg) > 7:
    #if str(task) != "b'python3'" or str(task) != "b'sshd'":
        print(str(task) ,">>",msg)
       # bpf.trace_print()
        
