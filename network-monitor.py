from bcc import BPF
from bcc.utils import printb
program = """

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include<linux/sched.h>
#include<linux/utsname.h>
#include<linux/pid_namespace.h>


BPF_PERF_OUTPUT(events);
BPF_HASH(socklist,u32,struct sock *);
struct data_frame{
    u32 pid;
    char comm[100];
    u32 saddr;
    u32 daddr;
    u16 dport;
    u32 rcv_bytes;
    u32 send_bytes;
    u32 tid;
    char user[20]; 
};

int detect_v4_connect(struct pt_regs *ctx,struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid();
    socklist.update(&pid,&sk);
    

    return 0;
}


int detect_v4_connect_ret(struct pt_regs *ctx,struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid();
    struct sock **skp ,*sk2;
    skp = socklist.lookup(&pid);
    if (skp == 0) {
        return 0;
    }
    sk2 = *skp;
    
    struct data_frame data = {};

    u32 saddr,daddr;
    u16 dport;
    bpf_get_current_comm(data.comm,100);
    data.pid = pid;
    
    data.saddr = sk2->__sk_common.skc_rcv_saddr;
    data.daddr = sk2->__sk_common.skc_daddr;
//    saddr = sk2.__sk_common.skc_port;
   
    events.perf_submit(ctx,&data,sizeof(data));
    socklist.delete(&pid);


    return 0;
}

        
int detect_execve(struct pt_regs *ctx) {
    char comm[100];
    u64 ptgid;

//    ptgid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(comm,100);

    bpf_trace_printk("comm = %s\\n",&comm);
    

    return 0;
}



"""
b = BPF(text=program)
b.attach_kprobe(event=b.get_syscall_fnname("execve"),fn_name = "detect_execve")
b.attach_kprobe(event="tcp_connect",fn_name="detect_v4_connect")
b.attach_kretprobe(event="tcp_connect",fn_name = "detect_v4_connect_ret")

def get_print_event(b: BPF):
    def print_event(cpu,data,size):
        event = b["events"].event(data)
        printb(b"%06d %-16s %-16d %-16d" % (event.pid,event.comm,event.saddr,event.daddr))
    return print_event


b["events"].open_perf_buffer(get_print_event(b))


while True:
    try:
        (task,pid,cpu,flag,ts,msg) = b.trace_fields()
        print (ts,"--",task,"--",pid,"--",msg)
    except KeyboardInterrupt:
        exit()
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()



