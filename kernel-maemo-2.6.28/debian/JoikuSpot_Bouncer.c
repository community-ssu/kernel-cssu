/* 
 * Implementation of JoikuSpotBouncer module
 * JoikuSpot_Bouncer.c
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the license, or ( at your option ) any later version
 */

#include <linux/module.h>         /* needed by all kernel modules          */
#include <linux/init.h>           /* needed for custom init/exit functions */
#include <linux/kernel.h>         /* needed for KERN_ALERT macro           */
#include <linux/netfilter.h>      /* Hook register/unregister              */
#include <linux/netfilter_ipv4.h> /* nf_hook_priorities                    */
#include <linux/ip.h>             /* Ip header                             */
#include <linux/tcp.h>            /* Tcp Header                            */
#include <linux/udp.h>            /* Udp Header                            */
#include <net/inet_hashtables.h>  /* __inet_lookup()                       */
#include <net/inet_sock.h>        /* struct inet_sock                      */


/* Special macro to indicate license (to avoid tainting the kernel) */

MODULE_LICENSE( "Dual MIT/GPL" );
MODULE_AUTHOR ( "JoikuSoft Oy Ltd <info@joikusoft.com>" );

extern struct inet_hashinfo tcp_hashinfo;
extern struct proto udp_prot;
extern struct rwlock_t udp_hash_lock;

static struct sock *__udp4_lib_lookup( struct net *net ,
    unsigned long int saddr ,
    unsigned short int sport ,
    unsigned long int daddr ,
    unsigned short int dport ,
    int dif ,
    struct hlist_head udptable[] )
    {
    struct sock *sk , *result = NULL;
    struct hlist_node *node;
    unsigned short int hnum = ntohs( dport );
    int badness = -1;

    read_lock( &udp_hash_lock );

    sk_for_each ( sk , node , &udptable[ udp_hashfn ( net , hnum ) ] )
        {
        struct inet_sock *inet = inet_sk( sk );

        if ( net_eq ( sock_net( sk ) , net ) && sk->sk_hash == hnum &&
            !ipv6_only_sock( sk ) )
            {

            int score = ( sk->sk_family == PF_INET ? 1 : 0 );

            if ( inet->rcv_saddr )
                {
                if ( inet->rcv_saddr != daddr )
                    {
                    continue;
                    }
                score += 2;
                }
            if ( inet->daddr )
                {
                if ( inet->daddr != saddr )
                    {
                    continue;
                    }
                score += 2;
                }
            if ( inet->dport )
                {
                if ( inet->dport != sport )
                    {
                    continue;
                    }
                score += 2;
                }
            if ( sk->sk_bound_dev_if )
                {
                if ( sk->sk_bound_dev_if != dif )
                    {
                    continue;
                    }
                score += 2;
                }
            if ( score == 9 )
                {
                result = sk;
                break;
                }
                else if ( score > badness )
                {
                result  = sk;
                badness = score;
                }
            }
        }
    if ( result )
        {
        sock_hold ( result );
        }
    read_unlock ( &udp_hash_lock );
    return result;
    }


static unsigned int joikuspot_nf_hook ( unsigned int hook ,
    struct sk_buff *pskb ,
    const struct net_device *in ,
    const struct net_device *out ,
    int ( *okfn ) ( struct sk_buff * ) )
    {
    struct sock *sk;
    struct iphdr *iph = ipip_hdr ( pskb );

    if ( iph->protocol == 6 )
        {
        struct tcphdr *th, tcph;

        th = skb_header_pointer (
            pskb , iph->ihl << 2 , sizeof( tcph ) , &tcph );

        sk = __inet_lookup( dev_net ( pskb->dst->dev ) , &tcp_hashinfo , 
            iph->saddr , th->source , iph->daddr , th->dest , inet_iif ( pskb ) );

        if( !sk )
            {
            return NF_DROP;
            }
        else
            {
            return NF_ACCEPT;
            }
        }

    if ( iph->protocol == 17 )
        {
        struct udphdr *uh, udph;

        uh = skb_header_pointer (
            pskb , iph->ihl << 2 , sizeof( udph ) , &udph );

        sk = __udp4_lib_lookup( dev_net ( pskb->dst->dev ) , iph->saddr , uh->source ,
            iph->daddr , uh->dest , inet_iif ( pskb ) , udp_prot.h.udp_hash );

        if ( sk != NULL )
            {
            return NF_ACCEPT;
            }
        else
            {
            return NF_DROP;
            }
        }

    return NF_ACCEPT;
    }


static struct nf_hook_ops joikuspot_ops =
    {
    .hook     = joikuspot_nf_hook,
    .owner    = THIS_MODULE,
    .pf       = PF_INET,
    .hooknum  = NF_INET_LOCAL_IN,
    .priority = NF_IP_PRI_FIRST
    };

static int joikuspot_init( void )
    {
    int retval = 0;

    printk( KERN_DEBUG "JoikuSpot Bouncer Kernel Module init\n" );

    retval = nf_register_hook( &joikuspot_ops );

    if ( retval < 0 )
        {
        return retval;
        }

    return retval;
    }

static void joikuspot_exit( void ) 
    {
    nf_unregister_hook ( &joikuspot_ops );
    printk( KERN_DEBUG "JoikuSpot Bouncer Kernel Module exit\n" );
    }

module_init( joikuspot_init ); 
module_exit( joikuspot_exit );

