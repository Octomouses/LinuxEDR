from bcc import BPF

bpf_source = """


    #include<uapi/linux/ptrace.h>
    #include<linux/sched.h>
    #include<linux/string.h>
    #include <linux/fs.h>
    int syscall__execve(struct pt_regs *ctx, const char __user *filename ,const char __user *const __user *argv, const char __user *const __user *envp) {
//    int  kprobe__sys_execve(struct pt_regs *ctx,struct filename *filename,const char __user *const __user *__argv,const char __user *const __user *__envp) {
        char comm[16];
        char buffer[100];
        u32 ptid;
        ptid = bpf_get_current_pid_tgid();
        
        
          bpf_trace_printk(" -- %s,%s,%s",filename,argv[1],argv[3]);
          bpf_trace_printk("pid=%d -- %s,%s",ptid,filename,argv[1]);
        
        return 0;
    }
    """
bpf = BPF(text=bpf_source)
execve_function = bpf.get_syscall_fnname("execve")
print(execve_function)

bpf.attach_kprobe(event=execve_function,fn_name="syscall__execve")


while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
    except ValueError:
        continue
    if str(task) != "b'python3'" and str(task) != "b'sshd'" and len(msg) > 7:
    #if str(task) != "b'python3'" or str(task) != "b'sshd'":
        print(str(task) ,">>",msg)
       # bpf.trace_print()
        
