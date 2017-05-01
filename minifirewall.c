#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>     // skb_network_header()
#include <linux/ip.h>   // struct iphdr
#include <linux/tcp.h>  // struct tcphdr
#include <linux/udp.h>  // struct udphdr
#include <linux/netfilter_ipv4.h>   // hooknum
//#include <netinet/in.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("X.Qiu <qiux0518@gmail.com>");
MODULE_DESCRIPTION("mini firewall");



static struct nf_hook_ops my_input_filter;
//static struct nf_hooks_ops my_outputFilter;

/* For kernel 2.6
unsigned int my_input_fn(unsigned int hooknum, struct sk_buff** skb, 
                        const struct net_device* in, const struct net_device* out, 
                        int (*okfn)(struct sk_buff*)){

	//struct sk_buff* sock_buff;
    //sock_buff = *skb;
*/

// For kernel 4.3
unsigned int my_input_fn(void* priv, struct sk_buff* skb, const struct nf_hook_state* state){
    struct iphdr*   ip_header;
    struct tcphdr*  tcp_header;
    struct udphdr*  udp_header;
    unsigned int    sport, dport;
    unsigned int  	saddr, daddr;
    
/* 
	// this line always triggers; not sure what's wrong
    if (skb){
    	printk(KERN_DEBUG "No sock_buff.\n");
        return NF_ACCEPT;
	}
*/

	// packets may not reach L4
    //ip_header = (struct iphdr*)skb_network_header(sock_buff);
    ip_header = (struct iphdr*)skb_network_header(skb);
    if (!ip_header){
    	printk(KERN_DEBUG "Failed to intercept packet.\n");
        return NF_ACCEPT;
	}
	saddr = (unsigned int)ip_header->saddr;
	daddr = (unsigned int)ip_header->daddr;

	if (ip_header->protocol == IPPROTO_ICMP){
		printk(KERN_DEBUG "ICMP packet detected and dropped");
		return NF_DROP;
	}

    if (ip_header->protocol == IPPROTO_TCP){
        tcp_header = (struct tcphdr*)skb_transport_header(skb);
    	printk(KERN_DEBUG "TCP traffic incoming.\n");

		sport = (unsigned int)tcp_header->source;
		dport = (unsigned int)tcp_header->dest;
  		printk("SOURCE port = %pI4,  DEST = %pI4\n", &saddr, &daddr);
  		printk("SOURCE IP address = %pI4,  DEST = %pI4\n", &sport, &dport);
        //snprintf(sport, 16, "%pI4", &tcp_header->source);
        //snprintf(dport, 16, "%pI4", &tcp_header->dest);
    }

    if (ip_header->protocol == IPPROTO_UDP){
        udp_header = (struct udphdr*)skb_transport_header(skb);
    	printk(KERN_DEBUG "UDP traffic incoming.\n");

		sport = (unsigned int)udp_header->source;
		dport = (unsigned int)udp_header->dest;
  		printk("SOURCE port = %pI4,  DEST = %pI4\n", &saddr, &daddr);
  		printk("SOURCE IP address = %pI4,  DEST = %pI4\n", &sport, &dport);
        //snprintf(sport, 16, "%pI4", &udp_header->source);
        //snprintf(dport, 16, "%pI4", &udp_header->dest);
    }

    return NF_DROP;
}
    

int init_module(){
    my_input_filter.hook       = (nf_hookfn*)my_input_fn;
    //my_input_filter.owner      = THIS_MODULE; // no longer this member field
    my_input_filter.pf         = PF_INET;
    my_input_filter.hooknum    = NF_INET_PRE_ROUTING;
    my_input_filter.priority   = NF_IP_PRI_FIRST;

    nf_register_hook(&my_input_filter);
    printk(KERN_DEBUG "firewall starts.\n");
    return 0;
}

void cleanup_module(){
    nf_unregister_hook(&my_input_filter);
    printk(KERN_DEBUG "firewall dismiss.\n");
}    