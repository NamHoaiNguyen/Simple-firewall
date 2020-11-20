#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/net.h>
#include <net/netlink.h>
#include <net/sock.h>

#include "../user/struct.h"

MODULE_LICENSE("GPL");

#define	NETLINK_TEST	31
#define NLMSG_SETECHO	0x11
#define NLMSG_COFIG	0x12
#define MAX_LENGTH 1024

static struct sock *sk;
static struct _CC_Config k_config;
static u32 pid = 0;

_CC_Config *get_config(void)
{
	return &k_config;
}

void netlink_kernel_recv(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	void *payload;
	struct sk_buff *out_skb;
	void *out_payload;
	struct nlmsghdr *out_nlh;
	long content_addr;
	int payload_len;
	int l;

	nlh = nlmsg_hdr(skb);
	switch (nlh->nlmsg_type) {
		case NLMSG_SETECHO:
			break;
		case NLMSG_COFIG:
			payload = nlmsg_data(nlh);
			payload_len = nlmsg_len(nlh);
			printk("[Module:recv]: payload length : %d\n", payload_len);  
			printk("[Module:recv]: recieved: %s, from: %d\n", (char *)payload, nlh->nlmsg_pid);
			pid = nlh->nlmsg_pid;
			out_skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);

			if (!out_skb) {
				printk("[Module:recv]: fail to create skb.\n");
				return;
			}
			out_nlh = nlmsg_put(out_skb, 0, 0, NLMSG_SETECHO, payload_len + strlen("rule address []") + 2, 0);

			if (!out_nlh){
                		printk("[Module:send]: fail to make the message\n");
                	return;
            		}
			out_payload = nlmsg_data(out_nlh);
	
			/*Get ip and port of website blocked*/
			kstrtoul(payload, 10, &content_addr);			
			memcpy(&k_config, (_CC_Config *)content_addr, sizeof(_CC_Config));
			printk("[Module:rule]: TCP: \t%d\n", k_config.TCP);
			printk("[Module:rule]: UDP: \t%d\n", k_config.UDP);
			printk("[Module:rule]: Len: \t%d\n", k_config.length);
			printk("[Module:rule]: Port: \t%d\n", k_config.port);
	
			for (l = 0; l < k_config.length; l++) {
				printk("[Module:rule]: Site: \t%s:%d\n", k_config.arr[l].IP, k_config.arr[l].port);
			}
		
			sprintf(out_payload, "rule address [%x]\n", (unsigned int)content_addr);
	
		/*Note: Must use nlh->nlmsg_pid (use a variable assigned this can cause error when sending message to user)*/	
			if (nlmsg_unicast(sk, out_skb, nlh->nlmsg_pid) < 0) {
				printk("[Module:send]: fail in unicasting out_skb.\n");
				return;
			}
			printk("[Module:send]: send ok.\n");
			break;
	
		default:
			printk("[Module:recv]: unknown msgtype received.\n");
	}
	
	return;
}

int netlink_kernel_send(char *message)
{
	struct sk_buff *skb_out;
	void *payload_out;
	struct nlmsghdr *nlh_out;
	skb_out = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb_out) {
		printk("Cant' create skb.\n");
		return -1;
	}

	nlh_out = nlmsg_put (skb_out, 0 ,0, NLMSG_SETECHO, MAX_LENGTH, 0);
	if (!nlh_out) {
		printk("[Module:send]: fail to make the message.\n");
		return -1;
	}

	payload_out = nlmsg_data(nlh_out);
	strcpy(payload_out, "");
	strcat(payload_out, message);

	if (nlmsg_unicast(sk, skb_out, pid) < 0) {	
		printk("[Module:send] : fail in unicast.\n");
		return -1;
	}

	printk("[Module:send]: send on.\n");
	return 0;
}


int ConnectControl(char *info)
{
//	printk("CHECK HAM CONNECT CONTROL.\n");
	printk("Info : %s\n", info);
	if (pid != 0) {
		netlink_kernel_send(info);
	}
	return 0;
}

void netlink_init(void)
{
	k_config.TCP = 0;
	k_config.UDP = 0;
	k_config.port = -1;
	k_config.length = 0;
	
	/*Register callback function*/
	struct netlink_kernel_cfg nlcfg = {
		.input = netlink_kernel_recv,
	};

	printk("[Module:netlink]: initialize netlink in kernel.\n");

	sk = netlink_kernel_create(&init_net, NETLINK_TEST, &nlcfg);
	if (!sk) 
		printk("[Module:netlink]: netlink create error.\n");
	else 
		printk("[Module:netlink]: netlink create successfully.\n");

	printk("[Module:netlink]: kernel moodule initialize successfully.\n");
}

void netlink_release(void)
{
	if (sk != NULL) {
		printk("[Module:exit]: existing...\n");
		netlink_kernel_release(sk);
	}
}
