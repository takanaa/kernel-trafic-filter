#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/spinlock.h>
#define MAX_IP_COUNT 30

typedef struct {
    unsigned int block_cnt; // Количество отброшенных пакетов
    __be32 ip_addr; // IP-адрес устройства, отправляющего ICMP пакеты
    unsigned int last_ping; // последний по счёту пинг
} ping_stats;

static struct nf_hook_ops nfho;
static ping_stats statistics[MAX_IP_COUNT];
static int stat_size = 0;
static int total_block = 0;
static DEFINE_SPINLOCK(stat_spinlock);

// Функция для вывода статистики
static void print_stat(void) {
    int i;
    spin_lock(&stat_spinlock);
    for (i = 0; i < stat_size; i++){
        printk(KERN_INFO "(STATS) IP %pI4: dropped %u ICMP requests\n", &statistics[i].ip_addr, statistics[i].block_cnt);
    }
    spin_unlock(&stat_spinlock);
    printk(KERN_INFO "(STATS) Dropped %u ICMP requests total\n", total_block);
}

unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct icmphdr *icmp_header;
    int ip_flag = 0; // флаг наличия ip в массиве
    int i;

    if (!skb) return NF_ACCEPT;
    ip_header = ip_hdr(skb);
    if (!ip_header) return NF_ACCEPT;

    // Пропускаем, если это loopback
    if (state->in && !strcmp(state->in->name, "lo")) return NF_ACCEPT;

    if (ip_header->protocol == IPPROTO_ICMP) {
        icmp_header = icmp_hdr(skb);
        if (icmp_header->type == ICMP_ECHO) {
            // Синхронизируем доступ к массиву
            spin_lock(&stat_spinlock);
            // Ищем IP в массиве
            for (i = 0; i < stat_size; i++) {
                if (statistics[i].ip_addr == ip_header->saddr) {
                    total_block++;
                    statistics[i].block_cnt++;
                    statistics[i].last_ping = total_block;
                    ip_flag = 1;
                    break;
                }
            }
            // Если IP не найден, добавляем новую запись (если есть место)
            if (ip_flag == 0) {
                if (stat_size < MAX_IP_COUNT) {
                    total_block++;
                    statistics[stat_size].block_cnt = 1;
                    statistics[stat_size].last_ping = total_block;
                    statistics[stat_size].ip_addr = ip_header->saddr;
                    stat_size++;
                } else {
                    // если места для нового IP больше нет, ищем тот,
                    // с которого дольше всего не было пингов, и записываем на его место
                    int j, min_idx = 0;
                    unsigned int min_ping = statistics[0].last_ping;
                    for (j = 1; j < stat_size; j++) {
                        if (statistics[j].last_ping < min_ping) {
                            min_ping = statistics[j].last_ping;
                            min_idx = j;
                        }
                    }
                    total_block++;
                    statistics[min_idx].block_cnt = 1;
                    statistics[min_idx].last_ping = total_block;
                    statistics[min_idx].ip_addr = ip_header->saddr;
                }
                //printk(KERN_INFO "ICMP request from %pI4 blocked, count: %u\n", &ip_header->saddr, 1);
            } //else
                //printk(KERN_INFO "ICMP request from %pI4 blocked, count: %u\n", &ip_header->saddr, statistics[i].block_cnt);
            spin_unlock(&stat_spinlock);
            return NF_DROP;
        }
    }
    //printk(KERN_INFO "ICMP request from %pI4 accepted\n", &ip_header->saddr);
    return NF_ACCEPT;
}

static int __init init_netfilter_hook(void) {
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_LOCAL_IN;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nfho.priv = NULL;

    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "(LOAD) ICMP block module loaded\n");
    return 0;
}

static void __exit exit_netfilter_hook(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    print_stat(); // Выводим статистику перед выгрузкой
    printk(KERN_INFO "(LOAD) ICMP block module unloaded\n");
}

module_init(init_netfilter_hook);
module_exit(exit_netfilter_hook);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Polina Netesova, SPbPU, 5131001/30001");
MODULE_DESCRIPTION("Netfilter module to block ICMP requests on NF_INET_LOCAL_IN chain");