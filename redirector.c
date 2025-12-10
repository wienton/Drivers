// redirector.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <net/checksum.h>

static __be32 target_ip = __constant_htonl(0x08080808); // 8.8.8.8
static __be32 redirect_ip = __constant_htonl(0x7f000001); // 127.0.0.1

// Функция пересчёта IP-контрольной суммы
static void recalc_ip_checksum(struct iphdr *iph)
{
    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}

static unsigned int packet_hook(void *priv,
                                struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
    struct iphdr *iph;
    __be32 old_daddr;

    if (!skb)
        return NF_ACCEPT;

    // Убедимся, что skb можно изменить
    if (skb_ensure_writable(skb, sizeof(struct iphdr)))
        return NF_DROP; // если не получилось — отбрасываем

    iph = ip_hdr(skb);
    if (!iph || iph->version != 4 || iph->ihl < 5)
        return NF_ACCEPT;

    // Проверяем, что целевой IP == 8.8.8.8
    if (iph->daddr != target_ip)
        return NF_ACCEPT;

    // old addr
    old_daddr = iph->daddr;

    // change static IP on 127.0.0.1
    iph->daddr = redirect_ip;

    // IP checksum
    recalc_ip_checksum(iph);

    // logging change 
    printk(KERN_INFO "[REDIRECT] IP redirect: %pI4 → %pI4\n",
           &old_daddr, &iph->daddr);

    return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
    .hook     = packet_hook,
    .hooknum  = NF_INET_PRE_ROUTING,
    .pf       = PF_INET,
    .priority = NF_IP_PRI_FIRST,
};

static int __init redirector_init(void)
{
    int ret = nf_register_net_hook(&init_net, &nfho);
    if (ret) {
        printk(KERN_ERR "error register hook\n");
        return ret;
    }
    printk(KERN_INFO "Redirector loaded: redirect 8.8.8.8 → 127.0.0.1\n");
    return 0;
}

static void __exit redirector_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "Redirector loade\n");
}

module_init(redirector_init);
module_exit(redirector_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Wienton");
MODULE_DESCRIPTION("Пример модификации IP-адреса в сетевом пакете");
