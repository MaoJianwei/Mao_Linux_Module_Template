/*
===============================================================================
Driver Name		:		MaoNetHook
Author			:		JIANWEI MAO
License			:		GPL
Description		:		LINUX DEVICE DRIVER PROJECT
===============================================================================
*/

#include "MaoCommon.h"
#include "MaoLinuxModuleTemplate.h"

#include <linux/slab.h>
#include <net/net_namespace.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <linux/inet.h>
#include <linux/rhashtable.h>



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jianwei Mao");
MODULE_INFO(intree, "Y");



#define MAO_SYSFS_FILE_STATUS "status"
#define MAO_SYSFS_FILE_FLOW_SRC "flow_src"
#define MAO_SYSFS_FILE_FLOW_DST "flow_dst"
#define MAO_SYSFS_FILE_TUNNEL_SRC "tunnel_src"

#define MAO_SYSFS_FILE_ADD_ENTRY "add_entry" // "<SID-in-ipv6-address-format>;<behavior-name>"
#define MAO_SYSFS_FILE_DEL_ENTRY "del_entry" // "<SID-in-ipv6-address-format>"



static struct kobject * mao_sysfs_root;
static char * statusBuff;
static struct in6_addr flow_src = {0x00,0x0A, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0,0,0,0,0,0,0, 0x0A};	// default
static struct in6_addr flow_dst = {0x00,0x0C, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0,0,0,0,0,0,0, 0x0C};	// default
static struct in6_addr tunnel_src = {0x20,0x01, 0x0d,0xb8, 0x20,0x20, 0x00,0x01, 0,0,0,0,0,0,0, 0x01};	// default



static ssize_t mao_sysfs_read(struct kobject * kobj, struct attribute * attr, char * buff)
{
	if (0 == strcmp(attr->name, MAO_SYSFS_FILE_STATUS)) {
		return sprintf(buff, "%s", statusBuff); // PAGE_SIZE - 1;

	} else if (0 == strcmp(attr->name, MAO_SYSFS_FILE_FLOW_SRC)) {
		return sprintf(buff, "flow src: %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X\n",
				flow_src.s6_addr[0], flow_src.s6_addr[1], flow_src.s6_addr[2], flow_src.s6_addr[3], flow_src.s6_addr[4], flow_src.s6_addr[5], flow_src.s6_addr[6], flow_src.s6_addr[7],
				flow_src.s6_addr[8], flow_src.s6_addr[9], flow_src.s6_addr[10], flow_src.s6_addr[11], flow_src.s6_addr[12], flow_src.s6_addr[13], flow_src.s6_addr[14], flow_src.s6_addr[15]);

	} else if (0 == strcmp(attr->name, MAO_SYSFS_FILE_FLOW_DST)) {
		return sprintf(buff, "flow dst: %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X\n",
				flow_dst.s6_addr[0], flow_dst.s6_addr[1], flow_dst.s6_addr[2], flow_dst.s6_addr[3], flow_dst.s6_addr[4], flow_dst.s6_addr[5], flow_dst.s6_addr[6], flow_dst.s6_addr[7],
				flow_dst.s6_addr[8], flow_dst.s6_addr[9], flow_dst.s6_addr[10], flow_dst.s6_addr[11], flow_dst.s6_addr[12], flow_dst.s6_addr[13], flow_dst.s6_addr[14], flow_dst.s6_addr[15]);

	} else if (0 == strcmp(attr->name, MAO_SYSFS_FILE_TUNNEL_SRC)) {
		return sprintf(buff, "tunnel src: %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X\n",
				tunnel_src.s6_addr[0], tunnel_src.s6_addr[1], tunnel_src.s6_addr[2], tunnel_src.s6_addr[3], tunnel_src.s6_addr[4], tunnel_src.s6_addr[5], tunnel_src.s6_addr[6], tunnel_src.s6_addr[7],
				tunnel_src.s6_addr[8], tunnel_src.s6_addr[9], tunnel_src.s6_addr[10], tunnel_src.s6_addr[11], tunnel_src.s6_addr[12], tunnel_src.s6_addr[13], tunnel_src.s6_addr[14], tunnel_src.s6_addr[15]);

	} else {
		return 0;
	}
}



static ssize_t mao_sysfs_write(struct kobject * kobj, struct attribute * attr, const char * buff, size_t count)
{
	//PINFO("WRITE, Dir: %s, File: %s, Buf:%s, Size:%ld, StrLen:%ld, ActualCount:%ld, %ld",
	//		kobj->name, attr->name, buff, sizeof(buff), strlen(buff), count, PAGE_SIZE);

	if (0 == strcmp(attr->name, MAO_SYSFS_FILE_STATUS)) {
		if (count >= PAGE_SIZE) {
			memcpy(statusBuff, buff, PAGE_SIZE-1);
			statusBuff[PAGE_SIZE-1] = 0;
			return PAGE_SIZE-1;
		} else {
			memcpy(statusBuff, buff, count);
			statusBuff[count] = 0;
		}

	} else if (0 == strcmp(attr->name, MAO_SYSFS_FILE_FLOW_SRC)) {
		in6_pton(buff, count, flow_src.s6_addr, '\n', NULL);

	} else if (0 == strcmp(attr->name, MAO_SYSFS_FILE_FLOW_DST)) {
		in6_pton(buff, count, flow_dst.s6_addr, '\n', NULL);

	} else if (0 == strcmp(attr->name, MAO_SYSFS_FILE_TUNNEL_SRC)) {
		in6_pton(buff, count, tunnel_src.s6_addr, '\n', NULL);

	} else if (0 == strcmp(attr->name, MAO_SYSFS_FILE_ADD_ENTRY)) {

	} else if (0 == strcmp(attr->name, MAO_SYSFS_FILE_DEL_ENTRY)) {

	} else {
		// should return count to avoid infinite loop
	}
	return count; // avoid potential infinite loop
}


static struct attribute mao_sysfs_attrs[] = { // Read-only(4), Write-only(2), Read-Write(6)
		{.name = MAO_SYSFS_FILE_STATUS, .mode = 0666}, // for debug usage, read-write
		{.name = MAO_SYSFS_FILE_FLOW_SRC, .mode = 0666},
		{.name = MAO_SYSFS_FILE_FLOW_DST, .mode = 0666},
		{.name = MAO_SYSFS_FILE_TUNNEL_SRC, .mode = 0666},

		{.name = MAO_SYSFS_FILE_ADD_ENTRY, .mode = 0222},
		{.name = MAO_SYSFS_FILE_DEL_ENTRY, .mode = 0222},
};


static struct sysfs_ops mao_sysfs_func = {
		.show = mao_sysfs_read,
		.store = mao_sysfs_write
};

static struct kobj_type mao_sysfs_type = {
		.sysfs_ops = &mao_sysfs_func
};


static void mao_register_sysfs_files(void)
{
	mao_sysfs_root = kobject_create_and_add("mao", NULL);
	mao_sysfs_root->ktype = &mao_sysfs_type;

	int i;
	for(i = 0; i < ARRAY_SIZE(mao_sysfs_attrs); i++)
	{
		sysfs_create_file(mao_sysfs_root, mao_sysfs_attrs + i);
	}
}

static void mao_unregister_sysfs_files(void)
{
	int i;
	for(i = 0; i < ARRAY_SIZE(mao_sysfs_attrs); i++)
	{
		sysfs_remove_file(mao_sysfs_root, mao_sysfs_attrs + i);
	}

	kobject_del(mao_sysfs_root);
}





static unsigned int mao_nf_hook_nothing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return NF_ACCEPT;
}

static unsigned int mao_nf_hook_local_in_learn_session(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return NF_ACCEPT;
}

static unsigned int mao_nf_hook_post_routing_apply_session(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return NF_ACCEPT;
}




static struct nf_hook_ops all_netns_hook_ops[] = {
		{
				.hook = mao_nf_hook_nothing,
				.pf = NFPROTO_IPV6,
				.hooknum = NF_INET_PRE_ROUTING,
				.priority = NF_IP_PRI_FIRST,
		},
		{
				.hook = mao_nf_hook_local_in_learn_session,
				.pf = NFPROTO_IPV6,
				.hooknum = NF_INET_LOCAL_IN,
				.priority = NF_IP_PRI_FIRST,
		},
		{
				.hook = mao_nf_hook_nothing,
				.pf = NFPROTO_IPV6,
				.hooknum = NF_INET_FORWARD,
				.priority = NF_IP_PRI_FIRST,
		},
		{
				.hook = mao_nf_hook_post_routing_apply_session,
				.pf = NFPROTO_IPV6,
				.hooknum = NF_INET_LOCAL_OUT,
				.priority = NF_IP_PRI_FIRST,
		},
		{
				.hook = mao_nf_hook_nothing,
				.pf = NFPROTO_IPV6,
				.hooknum = NF_INET_POST_ROUTING,
				.priority = NF_IP_PRI_FIRST,
		}
};










static int __net_init netns_hook_init(struct net *net)
{
	PINFO("NETNS_HOOK_INIT: %d, %d, %d, %d, %d, HookRet: d, %d, d, %d, d",
			net->ifindex,
			net->netns_ids.idr_base, net->netns_ids.idr_next,
			net->user_ns->owner, net->user_ns->group,
			// nf_register_net_hook(net, all_netns_hook_ops),
			nf_register_net_hook(net, all_netns_hook_ops+1),
			//nf_register_net_hook(net, all_netns_hook_ops+2),
			nf_register_net_hook(net, all_netns_hook_ops+3)
			//nf_register_net_hook(net, all_netns_hook_ops+4)
			);
	return 0;
}

static void __net_exit netns_hook_exit(struct net *net)
{
	// nf_unregister_net_hook(net, all_netns_hook_ops);
	nf_unregister_net_hook(net, all_netns_hook_ops+1);
	//nf_unregister_net_hook(net, all_netns_hook_ops+2);
	nf_unregister_net_hook(net, all_netns_hook_ops+3);
	//nf_unregister_net_hook(net, all_netns_hook_ops+4);

	PINFO("NETNS_HOOK_EXIT", net->ifindex);
}

static struct pernet_operations all_netns_ops = {
		.init = netns_hook_init,
		.exit = netns_hook_exit,
};








static int __init MaoNetHook_init(void)
{
	PINFO("INIT");

	statusBuff = kzalloc(PAGE_SIZE, GFP_KERNEL);

	mao_register_sysfs_files();

	register_pernet_subsys(&all_netns_ops);

	return 0;
}

static void __exit MaoNetHook_exit(void)
{
	unregister_pernet_subsys(&all_netns_ops);

	mao_unregister_sysfs_files();

	kfree(statusBuff);

	PINFO("EXIT");
}


MODULE_DESCRIPTION("Mao linux module architecture.");
MODULE_VERSION("Mao v0.1");

MODULE_FIRMWARE("I need firmware1: qingdao");
MODULE_FIRMWARE("I need firmware2: beijing");

MODULE_ALIAS("Mao Alias.");
MODULE_SOFTDEP("Mao deps");

module_init(MaoNetHook_init);
module_exit(MaoNetHook_exit);

