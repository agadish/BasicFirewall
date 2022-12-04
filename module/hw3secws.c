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
#include <linux/cdev.h>
#include <asm/string.h>

#include "common.h"
#include "rule_table.h"
#include "fw_log.h"


/*   K E R N E L   A T T R I B U T E S   */
MODULE_LICENSE("GPL");


/*   M A C R O S   */
#define INVALID_MAJOR_NUMBER (-1)
#define FW_CLASS_NAME "fw"
#define LOG_CHAR_DEVICE_NAME "fw_log"
#define RULES_CHAR_DEVICE_NAME "fw_rules"
#define SYSFS_RULES_DEVICE_NAME "rules"
#define SYSFS_RULES_FILE_NAME "rules"
#define SYSFS_LOG_DEVICE_NAME "log"
#define SYSFS_LOG_FILE_NAME "reset"


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

static int
init_log_driver(void);

static int
init_rules_driver(void);

static void
clean_drivers(void);

static void
clean_log_driver(void);

static void
clean_rules_driver(void);

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

static ssize_t
fw_log_read(struct file *fw_log_file,
            char __user *user_buffer,
            size_t requested_length,
            loff_t *offset);

static int
fw_log_open(struct inode *fw_log_inode, struct file *fw_log_file);

static int
fw_log_release(struct inode *fw_log_inode, struct file *fw_log_file);


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
    .owner = THIS_MODULE,
    .open = fw_log_open,
    .release = fw_log_release,
    .read = fw_log_read,
};

static struct file_operations g_fw_rules_fops = {
    .owner = THIS_MODULE,
};

static int g_major_number_log = INVALID_MAJOR_NUMBER;
static int g_major_number_rules = INVALID_MAJOR_NUMBER;
static struct class *g_hw3secws_class = NULL;
static struct device *g_sysfs_log_device = NULL;
static struct device *g_sysfs_rules_device = NULL;
static bool_t g_has_sysfs_rules_device = FALSE;
static bool_t g_has_sysfs_log_device = FALSE;
static struct cdev g_cdev_logs;

static rule_table_t g_rule_table;

static DEVICE_ATTR(rules, S_IWUSR | S_IRUGO, rules_display, rules_modify); 
static DEVICE_ATTR(reset, S_IWUSR, NULL, log_modify); 


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

static ssize_t
fw_log_read(struct file *fw_log_file,
            char __user *user_buffer,
            size_t requested_length,
            loff_t *offset)
{
    ssize_t read_length = -1;

    read_length = FW_LOG_dump(user_buffer, requested_length, offset);

    return read_length;
}

static int
fw_log_open(struct inode *fw_log_inode, struct file *fw_log_file)
{
    return 0;
}

static int
fw_log_release(struct inode *fw_log_inode, struct file *fw_log_file)
{
    return 0;
}


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

static int
register_hooks(void)
{
    int result = 0;
    int result_register_hook = -1;

    /* 1. Register Forward hook */
    /* 1.1. Init struct fields */
    g_forward_hook.hook = hw3secws_hookfn_forward;
    g_forward_hook.hooknum = NF_INET_FORWARD;
    g_forward_hook.pf = PF_INET;
    g_forward_hook.priority = NF_IP_PRI_FIRST;

    /* 1.2. Register hook */
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
init_log_driver(void)
{
    int result = 0;
    int result_device_create_file = -1;
    dev_t log_dev_number = 0;

    /* 1. Create character devices */
    /* g_major_number_log = register_chrdev(0, LOG_CHAR_DEVICE_NAME, &g_fw_log_fops); */
    log_dev_number = 0;
    g_major_number_log = alloc_chrdev_region(&log_dev_number, 0, 1, LOG_CHAR_DEVICE_NAME);
    if (0 > g_major_number_log) {
        printk(KERN_ERR "register_chrdev failed for %s\n", LOG_CHAR_DEVICE_NAME);
        result = -1;
        goto l_cleanup;
    }

    cdev_init(&g_cdev_logs, &g_fw_log_fops);
    result = cdev_add(&g_cdev_logs, log_dev_number, 1);
    if (0 != result) {
        printk(KERN_ERR "cdev_add failed with %d\n", result);
        goto l_cleanup;
    }

    /* 2. Create sysfs rules device */
    g_sysfs_log_device = device_create(g_hw3secws_class, NULL, log_dev_number, NULL, SYSFS_LOG_DEVICE_NAME);
    if (IS_ERR(g_hw3secws_class)) {
        result = -1;
        goto l_cleanup;
    }
    g_has_sysfs_log_device = TRUE;
    printk(KERN_INFO "RUN FOR FW: sudo mknod /dev/%s c %d %d\n", LOG_CHAR_DEVICE_NAME, MAJOR(log_dev_number), MINOR(log_dev_number));


    /* 3. Create sysfs device */
    result_device_create_file = device_create_file(
        g_sysfs_log_device,
        (const struct device_attribute *)&dev_attr_reset.attr
    );
    if (0 != result_device_create_file) {
        result = -1;
        goto l_cleanup;
    }

    /* 4. Create /dev/fw_log */
    /* cdev_init(&my_cdev,  */

    result = 0;
l_cleanup:
    if (0 != result) {
        clean_log_driver();
    }

	return result;
}

static int
init_rules_driver(void)
{
    int result = 0;
    int result_device_create_file = -1;

    /* 1. Create character devices */
    g_major_number_rules = register_chrdev(0, RULES_CHAR_DEVICE_NAME, &g_fw_rules_fops);
    if (0 > g_major_number_rules) {
        printk(KERN_ERR "register_chrdev failed for %s\n", RULES_CHAR_DEVICE_NAME);
        result = -1;
        goto l_cleanup;
    }

    /* 2. Create sysfs rules device */
    /* 2.1. Create device */
    g_sysfs_rules_device = device_create(g_hw3secws_class, NULL, MKDEV(g_major_number_rules, 0), NULL, SYSFS_RULES_DEVICE_NAME);
    if (NULL == g_sysfs_rules_device) {
        result = -1;
        goto l_cleanup;
    }
    g_has_sysfs_rules_device = TRUE;

    /* 3. Create sysfs device */
    result_device_create_file = device_create_file(
        g_sysfs_rules_device,
        (const struct device_attribute *)&dev_attr_rules.attr
    );
    if (0 != result_device_create_file) {
        result = -1;
        goto l_cleanup;
    }

    result = 0;
l_cleanup:
    if (0 != result) {
        clean_rules_driver();
    }

	return result;
}

static int
init_drivers(void)
{
    int result = 0;

    /* 1. Create sysfs class */
    g_hw3secws_class = class_create(THIS_MODULE, FW_CLASS_NAME);
    if (IS_ERR(g_hw3secws_class)) {
        result = -1;
        goto l_cleanup;
    }
    /* 2. Init log drivers */
    result = init_log_driver();
    if (0 != result) {
        goto l_cleanup;
    }

    /* 3. Init rules drivers */
    result = init_rules_driver();
    if (0 != result) {
        goto l_cleanup;
    }
        
    /* Success */
    result = 0;
l_cleanup:
    if (0 != result) {
        clean_drivers();
    }

	return result;
}

static void
clean_log_driver(void)
{
    if (NULL != g_sysfs_log_device) {
        device_remove_file(g_sysfs_log_device, (const struct device_attribute *)&dev_attr_reset.attr);
        g_sysfs_log_device = NULL;
    }

    if (TRUE == g_has_sysfs_log_device) {
        device_destroy(g_hw3secws_class, MKDEV(g_major_number_log, 0));
        g_has_sysfs_log_device = FALSE;
    }

    cdev_del(&g_cdev_logs);

    if (INVALID_MAJOR_NUMBER != g_major_number_log) {
        unregister_chrdev(g_major_number_log, LOG_CHAR_DEVICE_NAME);
        g_major_number_log = INVALID_MAJOR_NUMBER;
    }
}

static void
clean_rules_driver(void)
{
    if (NULL != g_sysfs_rules_device) {
        device_remove_file(g_sysfs_rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
        g_sysfs_rules_device = NULL;
    }

    if (TRUE == g_has_sysfs_rules_device) {
        device_destroy(g_hw3secws_class, MKDEV(g_major_number_rules, 0));
        g_has_sysfs_rules_device = FALSE;
    }

    if (INVALID_MAJOR_NUMBER != g_major_number_rules) {
        unregister_chrdev(g_major_number_rules, RULES_CHAR_DEVICE_NAME);
        g_major_number_rules = INVALID_MAJOR_NUMBER;
    }
}

static void
clean_drivers(void)
{
    /* 1. Clean rules driver */
    clean_rules_driver();

    /* 2. Clean log driver */
    clean_log_driver();

    /* 3. Destroy class */
    if (NULL != g_hw3secws_class) {
        class_destroy(g_hw3secws_class);
        g_hw3secws_class = NULL;
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
        FW_LOG_reset_logs();
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

