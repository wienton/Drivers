// packet_logger.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

static unsigned int packet_hook(void *priv,
                                struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;

    if (!skb) return NF_ACCEPT;

    iph = (struct iphdr *)skb_network_header(skb);
    if (!iph || iph->version != 4) return NF_ACCEPT;

    // Логируем IP-адреса
    printk(KERN_INFO "[PKT] %pI4 -> %pI4 | Proto: %u\n",
           &iph->saddr, &iph->daddr, iph->protocol);

    // Если TCP или UDP — логируем порты
    if (iph->protocol == IPPROTO_TCP) {
        tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);
        printk(KERN_INFO "TCP: %u -> %u\n",
               ntohs(tcph->source), ntohs(tcph->dest));
    }
    else if (iph->protocol == IPPROTO_UDP) {
        udph = (struct udphdr *)((__u32 *)iph + iph->ihl);
        printk(KERN_INFO "UDP: %u -> %u\n",
               ntohs(udph->source), ntohs(udph->dest));
    }

    return NF_ACCEPT; // Пропускаем пакет дальше
}

// Описание хука
static struct nf_hook_ops nfho = {
    .hook     = packet_hook,
    .hooknum  = NF_INET_PRE_ROUTING,  // Перехват на входе
    .pf       = PF_INET,              // IPv4
    .priority = NF_IP_PRI_FIRST,      // Высший приоритет
};

// Инициализация модуля
static int __init packet_logger_init(void)
{
    int ret = nf_register_net_hook(&init_net, &nfho);
    if (ret) {
        printk(KERN_ERR "Failed register hook\n");
        return ret;
    }
    printk(KERN_INFO "Packet logger loaded. Monitor traffic...\n");
    return 0;
}

// Выгрузка модуля
static void __exit packet_logger_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "Packet logger loaded.\n");
}

module_init(packet_logger_init);
module_exit(packet_logger_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Wienton");
MODULE_DESCRIPTION("Простой перехватчик сетевых пакетов");