#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/slab.h>
#include <asm/desc.h>
#include <asm/special_insns.h>

#define ACCELA_SIG 0xDEADC0DE
#define PACKET_THRESHOLD 1024

struct accela_stats {
    uint64_t pkts;
    uint64_t bytes;
    spinlock_t lock;
};

static struct accela_stats *global_stats;

static inline uint16_t asm_cksum(uint16_t *ptr, int nbytes) {
    uint32_t sum = 0;
    uint16_t odd_byte;
    uint16_t answer;

    asm volatile (
        "clc\n\t"
        "1: lodsw\n\t"
        "addw %%ax, %%dx\n\t"
        "adcl $0, %%edx\n\t"
        "loop 1b\n\t"
        : "+d"(sum), "+S"(ptr), "+c"(nbytes)
        :
        : "ax", "cc"
    );

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

static void get_idt_info(void) {
    struct desc_ptr idtr;
    unsigned long idt_base;

    asm volatile("sidt %0" : "=m"(idtr));
    idt_base = idtr.address;

    uint64_t *entry = (uint64_t *)idt_base;
    printk(KERN_DEBUG "ACCELA_ASM_CORE: IDT BASE @ %lx, VEC0: %llx\n", idt_base, be64_to_cpu(*entry));
}

static unsigned int main_net_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *tcph;
    uint32_t payload_len;

    if (!skb) return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP) return NF_ACCEPT;

    tcph = tcp_hdr(skb);
    payload_len = ntohs(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2);

    spin_lock(&global_stats->lock);
    global_stats->pkts++;
    global_stats->bytes += skb->len;

    if (payload_len > 0) {
        unsigned char *data = (unsigned char *)tcph + (tcph->doff << 2);

        uint32_t magic;
        asm volatile (
            "movl (%1), %%eax\n\t"
            "bswap %%eax\n\t"
            "movl %%eax, %0\n\t"
            : "=r"(magic)
            : "r"(data)
            : "eax"
        );

        if (magic == ACCELA_SIG) {
            printk(KERN_ALERT "ACCELA_SHADOW: ENCRYPTED PKT DETECTED. BYPASSING.\n");
            spin_unlock(&global_stats->lock);
            return NF_DROP;
        }
    }

    spin_unlock(&global_stats->lock);
    return NF_ACCEPT;
}

static struct nf_hook_ops accela_ops = {
    .hook = main_net_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static int __init accela_deep_init(void) {
    global_stats = kzalloc(sizeof(struct accela_stats), GFP_KERNEL);
    if (!global_stats) return -ENOMEM;

    spin_lock_init(&global_stats->lock);
    get_idt_info();

    if (nf_register_net_hook(&init_net, &accela_ops)) {
        kfree(global_stats);
        return -1;
    }

    return 0;
}

static void __exit accela_deep_exit(void) {
    nf_unregister_net_hook(&init_net, &accela_ops);
    printk(KERN_INFO "ACCELA_ASM_CORE: FINAL TRAFFIC: %llu bytes in %llu pkts\n",
           global_stats->bytes, global_stats->pkts);
    kfree(global_stats);
}

module_init(accela_deep_init);
module_exit(accela_deep_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ACCELA_DARK_OPS");
