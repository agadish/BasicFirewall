/**
 * @file hw3secws.c
 * @author Assaf Gadish
 *
 * @brief A basic firewall with controlling character device.
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */
/*   I N C L U D E S   */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <asm/string.h>

#include "common.h"
#include "rule_table.h"
#include "fw_log.h"


/*   K E R N E L   A T T R I B U T E S   */
MODULE_LICENSE("GPL");


/*   M A C R O S   */
#define INVALID_MAJOR_NUMBER (-1)
#define CLASS_NAME "fw"
#define CHAR_DEVICE_NAME "fw_log"
#define SYSFS_RULES_DEVICE_NAME "rules"
#define SYSFS_RULES_FILE_NAME "rules"
#define SYSFS_LOG_RESET_DEVICE_NAME "log"
#define SYSFS_LOG_RESET_FILE_NAME "reset"


/*   F U N C T I O N S    D E C L A R A T I O N S   */
/**
 * @brief Init the module by registering all hooks
 *
 * @return 0 on succesful initialisation, non-zero value on error
 */
static int
__init hw3secws_init(void);

/**
 * @brief Clean the module by unregistering all hooks
 */
static void
__exit hw3secws_exit(void);

/**
 * @brief Print a kernel message that indicates a packet was accepted
 */
/* static void */
/* log_accept(void); */

/**
 * @brief Print a kernel message that indicates a packet was dropped
 */
/* static void */
/* log_drop(void); */

/**
 * @brief The netfilter hook of the driver on FORWARD chain
 * 
 * @param[in] priv Ignored
 * @param[in] skb The packet's socket buffer (ignored)
 * @param[in] state The packet's netfilter hook state (ignored)
 *
 * @return NF_ACCEPT
 */
static unsigned int
hw3secws_hookfn_forward(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
);

static int
init_drivers(void);

static void
clean_drivers(void);

static int
register_hooks(void);

static void
unregister_hooks(void);

static ssize_t
rules_display(struct device *dev, struct device_attribute *attr, char *buf);

static ssize_t
rules_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

static ssize_t
log_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

static inline void
zero_counters(void);


/*   G L O B A L S   */
/** 
 * @brief Netfilter hook for FORWARD packet chain, aka packets that are neither destinated to this
 *        machine nor sent by this machine
 */
static struct nf_hook_ops g_forward_hook;

/** 
 * @brief Character device of the module
 */
static struct file_operations g_fw_log_fops = {
    .owner = THIS_MODULE
};

static int g_major_number = INVALID_MAJOR_NUMBER;
static struct class *g_hw3secws_class = NULL;
static struct device *g_sysfs_rules_device = NULL;
static bool_t g_has_sysfs_rules_device = FALSE;
static struct device *g_sysfs_log_reset_device = NULL;
static bool_t g_has_sysfs_log_reset_device = FALSE;
static rule_table_t g_rule_table;

static DEVICE_ATTR(rules, S_IWUSR | S_IRUGO, rules_display, rules_modify); 
static DEVICE_ATTR(log_reset, S_IWUSR, NULL, log_modify); 


/*   F U N C T I O N S    I M P L E M E N T A T I O N S   */
/* static void */
/* log_accept(void) */
/* { */
/*     printk(KERN_INFO "*** Packet Accepted ***\n"); */
/* } */

/* static void */
/* log_drop(void) */
/* { */
/*     printk(KERN_INFO "*** Packet Dropped ***\n"); */
/* } */

static unsigned int
hw3secws_hookfn_forward(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
){

    __u8 result = NF_DROP;
    bool_t has_match = FALSE;

    UNUSED_ARG(priv);
    UNUSED_ARG(state);

    /* 1. Accept whitelist packets */
    if (RULE_TABLE_is_whitelist(&g_rule_table, skb)) {
        result = NF_ACCEPT;
        goto l_cleanup;
    }

    /* 2. Check the rule table */
    has_match = RULE_TABLE_check(&g_rule_table, skb, &result);
    /* 3. If it doesn't have match - drop it */
    if (!has_match) {
        result = NF_DROP;
    }

l_cleanup:

    return (unsigned int)result;
}

static inline void
zero_counters(void)
{
}

static int
register_hooks(void)
{
    int result = 0;
    int result_register_hook = -1;

    /* 1. Zero counters */
    zero_counters();

    /* 1. Register Forward hook */

    /* 4.1. Init struct fields */
    g_forward_hook.hook = hw3secws_hookfn_forward;
    g_forward_hook.hooknum = NF_INET_FORWARD;
    g_forward_hook.pf = PF_INET;
    g_forward_hook.priority = NF_IP_PRI_FIRST;

    /* 4.2. Register hook */
    result_register_hook = nf_register_net_hook(&init_net, &g_forward_hook);
    if (0 != result_register_hook) {
        result = result_register_hook;
        goto l_cleanup;
    }


    /* Success */
    result = 0;
l_cleanup:
    if (0 != result) {
        unregister_hooks();
    }

    return result;
}

static int
init_drivers(void)
{
    int result = 0;
    int result_device_create_file = -1;

    /* 1. Create character device */
    g_major_number = register_chrdev(0, CHAR_DEVICE_NAME, &g_fw_log_fops);
    if (0 > g_major_number) {
        result = -1;
        goto l_cleanup;
    }

    /* 2. Create sysfs class */
    g_hw3secws_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(g_hw3secws_class)) {
        result = -1;
        goto l_cleanup;
    }
        
    /* 3. Create sysfs rules device */
    /* 3.1. Create device */
    g_sysfs_rules_device = device_create(g_hw3secws_class, NULL, MKDEV(g_major_number, 0), NULL, SYSFS_RULES_DEVICE_NAME);
    if (IS_ERR(g_hw3secws_class)) {
        result = -1;
        goto l_cleanup;
    }
    g_has_sysfs_rules_device = TRUE;

    /* 3.2. Create file attributes */
    result_device_create_file = device_create_file(
        g_sysfs_rules_device,
        (const struct device_attribute *)&dev_attr_rules.attr
    );
    if (0 != result_device_create_file) {
        result = -1;
        goto l_cleanup;
    }

    /* 4. Create sysfs reset device */
    /* 4.1. Create device */
    /* g_sysfs_log_reset_device = device_create(g_hw3secws_class, NULL, MKDEV(g_major_number, 0), NULL, SYSFS_LOG_RESET_DEVICE_NAME); */
    /* if (IS_ERR(g_hw3secws_class)) { */
    /*     result = -1; */
    /*     goto l_cleanup; */
    /* } */
    /* g_has_sysfs_log_reset_device = TRUE; */

    /* 4.2. Create file attributes */
    /* result_device_create_file = device_create_file( */
    /*     g_sysfs_log_reset_device, */
    /*     (const struct device_attribute *)&dev_attr_log_reset.attr */
    /* ); */
    /* if (0 != result_device_create_file) { */
    /*     result = -1; */
    /*     goto l_cleanup; */
    /* } */
    /*  */
        
    /* Success */
    result = 0;
l_cleanup:
    if (0 != result) {
        clean_drivers();
    }

	return result;
}

static void
clean_drivers(void)
{
    if (NULL != g_sysfs_log_reset_device) {

        device_remove_file(g_sysfs_log_reset_device, (const struct device_attribute *)&dev_attr_log_reset.attr);
        g_sysfs_log_reset_device = NULL;
    }
    if (TRUE == g_has_sysfs_log_reset_device) {
        device_destroy(g_hw3secws_class, MKDEV(g_major_number, 0));
        g_has_sysfs_log_reset_device = FALSE;
    }

    if (NULL != g_sysfs_rules_device) {
        device_remove_file(g_sysfs_rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
        g_sysfs_rules_device = NULL;
    }
    if (TRUE == g_has_sysfs_rules_device) {
        device_destroy(g_hw3secws_class, MKDEV(g_major_number, 0));
        g_has_sysfs_rules_device = FALSE;
    }

    if (NULL != g_hw3secws_class) {
        class_destroy(g_hw3secws_class);
        g_hw3secws_class = NULL;
    }

    if (INVALID_MAJOR_NUMBER != g_major_number) {
        unregister_chrdev(g_major_number, CHAR_DEVICE_NAME);
        g_major_number = INVALID_MAJOR_NUMBER;
    }
}

static void
unregister_hooks(void)
{
    nf_unregister_net_hook(&init_net, &g_forward_hook);
}


static ssize_t
rules_display(struct device *dev, struct device_attribute *attr, char *buf)
{
    ssize_t result = -1;
    size_t buffer_length = PAGE_SIZE;
    bool_t was_modified = FALSE;

    UNUSED_ARG(dev);
    UNUSED_ARG(attr);

    printk(KERN_INFO "rules_display\tgot %lu rules\n", (unsigned long)g_rule_table.rules_count);

    was_modified = RULE_TABLE_dump_data(&g_rule_table, buf, &buffer_length);
    if (FALSE == was_modified) {
        result = -1;
        goto l_cleanup;
    }


    printk(KERN_INFO "rules_display\tcopied %lu bytes\n", (unsigned long)buffer_length);
    result = (ssize_t)buffer_length;
l_cleanup:

    return result;
}

static ssize_t
rules_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    ssize_t result = 0;
    bool_t was_modified = FALSE;

    printk(KERN_INFO "%s was called\n", __func__);

    was_modified = RULE_TABLE_set_data(&g_rule_table, buf, count);
    if (was_modified) {
        result = count;
    }
    printk(KERN_INFO "%s was called, was_modified=%d\n", __func__, was_modified);


    return result;
}

static ssize_t
log_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    ssize_t result = 0;

    printk(KERN_INFO "%s was called\n", __func__);
    if (0 == count) {
        goto l_cleanup;
    }

    if ('0' == buf[0]) {
        zero_counters();
        result = count;
    }

l_cleanup:

    return result;
}

static int
__init hw3secws_init(void)
{
    int result = -1;

    /* 1. Init globals */
    RULE_TABLE_init(&g_rule_table);

    /* 2. Init logs module */
    FW_LOG_init();

    /* 3. Register hooks */
    result = register_hooks();
    if (0 != result) {
        goto l_cleanup;
    }

    /* 4. Init char device and sysfs device */
    result = init_drivers();
    if (0 != result) {
        goto l_cleanup;
    }

    result = 0;
l_cleanup:
    if (0 != result) {
        clean_drivers();
        unregister_hooks();
    }

    return result;
}

static void __exit
hw3secws_exit(void)
{
    /* 1. Release device class file, class and character device */
    clean_drivers();

    /* 2. Release all the hooks */
    unregister_hooks();
    
    /* 3. Shutdown logs module */
    FW_LOG_shutdown();
}


/*   K E R N E L   H O O K S   */
module_init(hw3secws_init);
module_exit(hw3secws_exit);

