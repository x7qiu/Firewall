#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <skbuff.h>     // skb_network_header()
#include <linux/ip.h>   // struct iphdr
#include <linux/tcp.h>  // struct tcphdr
#include <linux/udp.h>  // struct udphdr
#include <linux/netfilter_ipv4.h>   // hooknum

MODULE_LICENSE("GPL");
MODULE_AUTHOR("X.Qiu <qiux0518@gmail.com>")
MODULE_DESCRIPTION("mini firewall")



static struct nf_hooks_ops my_inputFilter;
//static struct nf_hooks_ops my_outputFilter;

unsigned int my_input_fn(unsigned int hooknum, struct sk_buff** skb, 
                        const struct net_device* in, net_device* out, 
                        int (*okfn)(struct sk_buff*)){
    
    struct sk_buff* sock_buff;
    struct iphdr*   ip_header;
    struct tcphdr*  tcp_header;
    struct udphdr*  udp_header;
    u16             sport, dport;
    u32             saddr, daddr;
    
    sock_buff = *skb;
    if (!sock_buff)
        return NF_ACCEPT;

    ip_header = (struct iphdr*)skb_network_header(sock_buff);
    if (!ip_header)
        return AF_ACCEPT;

    if (ip_header->protocol == IPPRO_TCP){
        tcp_header = (struct tcphdr*)skb_transport_header(sock_buff);
        snprintf(sport, 16, "%pI4", &tcp_header->source);
        snprintf(dport, 16, "%pI4", &tcp_header->dest);
    }

    if (ip_header->protocol == IPPRO_UDP){
        udp_header = (struct udphdr*)skb_transport_header(sock_buff);
        snprintf(sport, 16, "%pI4", &udp_header->source);
        snprintf(dport, 16, "%pI4", &udp_header->dest);
    }

    return NF_DROP;
}
    

    

        




int init_module(){
    my_input_filter = {
        .hook       = my_input_fn;
        .owner      = THIS_MODULE;
        .pf         = PF_INET:
        .hooknum    = NF_INET_PRE_ROUTING;
        .priority   = NF_INET_PRI_FIRST;
    };

    nf_register_hook(&my_input_filter);
    printk(KERN_DEBUG "firewall starts.\n");
    return 0;
}

void cleanup_module(){
    nf_unregister_hook(&my_input_filter);
    printk(KERN_DEBUG "firewall dismiss.\n");
}    
