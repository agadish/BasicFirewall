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
#define INVALID_DEV_T_NUMBER (0)
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

/**
 * @brief Initialise the class and both drivers (log, rules)
 * 
 * @return 0 on success, non-zero on error
 */
static int
init_drivers(void);

/**
 * @brief Initialise the log driver
 * 
 * @return 0 on success, non-zero on error
 */
static int
init_log_driver(void);

/**
 * @brief Initialise the rules driver
 * 
 * @return 0 on success, non-zero on error
 */
static int
init_rules_driver(void);

/**
 * @brief Cleans the class and both drivers (log, rules)
 */
static void
clean_drivers(void);

/**
 * @brief Cleans the log driver
 */
static void
clean_log_driver(void);

/**
 * @brief Cleans the rules driver
 */
static void
clean_rules_driver(void);

/**
 * @brief Register the firewall's hooks, aka the FORWARD hook
 *
 * @return 0 on success, non-zero on error
 */
static int
register_hooks(void);

/**
 * @brief Cleanup the hooks, must be called at module shutdown in order to
 *        clean register_hooks operation
 */
static void
unregister_hooks(void);

/**
 * @brief Handle a read request from the sysfs rules driver
 *
 * @param[in] dev Ignored
 * @param[in] attr Ignored
 * @param[in] buf The buffer that will be copied to the user later. It's length
 *                is PAGE_SIZE
 *
 * @return Number of bytes were written, or negative value on error
 */
static ssize_t
rules_display(struct device *dev, struct device_attribute *attr, char *buf);

/**
 * @brief Handles a write request that modifies the rules
 *
 * @param[in] dev Ignored
 * @param[in] attr Ignored
 * @param[in] buf The buffer that holds the new rules
 * @param[in] count Length of buf
 *
 * @return Number of bytes were read, or negative value on error
 */
static ssize_t
rules_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

/**
 * @brief Handles a write that requests to zero the logs file
 *
 * @param[in] dev Ignored
 * @param[in] attr Ignored
 * @param[in] buf The buffer that holds the message
 * @param[in] count Length of buf
 *
 * @return Number of bytes were read, or negative value on error
 */
static ssize_t
log_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

/**
 * @brief Read logs from the firewall's logs module to the userspace.
 *        The logs are read as an array of log_row_t, with maximum size possible
 *
 * @param[in] fw_log_file Ignored
 * @param[out] user_buffer The user buffer which the logs will be copied to
 * @param[in] requested_length The length of user_buffer
 * @param[inout] offset The offset within the logs buffer. Will hold the new
 *                      offset later.
 *
 * @return Number of bytes were read, or negative value on error
 */
static ssize_t
fw_log_read(struct file *fw_log_file,
            char __user *user_buffer,
            size_t requested_length,
            loff_t *offset);

/**
 * @brief Called when the logs device is opened. Does nothing.
 *
 * @param[in] fw_log_inode Ignored
 * @param[in] fw_log_file Ignored
 *
 * @return 0 on success, non-zero on error
 */
static int
fw_log_open(struct inode *fw_log_inode, struct file *fw_log_file);

/**
 * @brief Called when the logs device is closed. Does nothing.
 *
 * @param[in] fw_log_inode Ignored
 * @param[in] fw_log_file Ignored
 *
 * @return 0 on success, non-zero on error
 */
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

static dev_t g_log_dev_number = INVALID_DEV_T_NUMBER;
static dev_t g_rules_dev_number = INVALID_DEV_T_NUMBER;
static struct class *g_hw3secws_class = NULL;
static struct device *g_sysfs_log_device = NULL;
static struct device *g_sysfs_rules_device = NULL;
static bool_t g_has_sysfs_rules_device = FALSE;
static bool_t g_has_sysfs_log_device = FALSE;
static struct cdev g_cdev_logs;

static rule_table_t g_rule_table;

/**
 * @brief The sysfs files
 */
/* rules write/read file */
static DEVICE_ATTR(rules, S_IWUSR | S_IRUGO, rules_display, rules_modify); 
/* logs reset file */
static DEVICE_ATTR(reset, S_IWUSR, NULL, log_modify); 


/*   F U N C T I O N S    I M P L E M E N T A T I O N S   */
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
    __u8 action = NF_DROP;
    bool_t has_match = FALSE;
    reason_t reason = REASON_FW_INACTIVE;

    UNUSED_ARG(priv);
    UNUSED_ARG(state);

    /* 1. Check if xmas packet */
    if (RULE_TABLE_is_xmas_packet(skb)) {
        action = NF_DROP;
        reason = REASON_XMAS_PACKET;
    } else if (RULE_TABLE_is_freepass(&g_rule_table, skb)) {
        /* 2. Accept freepass list packets without logging them:
         *    loopbacks packets, or non-TCP/UDP/ICMP packets */
        action = NF_ACCEPT;
        goto l_cleanup;
    }
    else {
        /* 3. Check the rule table */
        has_match = RULE_TABLE_check(&g_rule_table, skb, &action, &reason);
        if (!has_match) {
            /* 3.2. No match: drop the packet */
            action = NF_DROP;
            reason = REASON_NO_MATCHING_RULE;
        } else {
            /* printk(KERN_INFO "%s: has match reason=%d action=%d\n", __func__, reason, action); */
        }
    }

    /* 3. Log the packet with the action to the reason */
    /* Note: we have nothing to do with logging failure */
    (void)FW_LOG_log_match(skb, action, reason);

l_cleanup:

    return (unsigned int)action;
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
    int result_alloc_chrdev_region = -1;

    /* 1. Create character devices */
    /* 1.1. Allocate number */
    g_log_dev_number = INVALID_DEV_T_NUMBER;
    result_alloc_chrdev_region = alloc_chrdev_region(&g_log_dev_number, 0, 1, LOG_CHAR_DEVICE_NAME);
    if (0 > result_alloc_chrdev_region) {
        printk(KERN_ERR "register_chrdev failed for %s: %d\n",
               LOG_CHAR_DEVICE_NAME,
               result_alloc_chrdev_region);
        result = -1;
        goto l_cleanup;
    }

    /* 1.2. Initialise operations */
    cdev_init(&g_cdev_logs, &g_fw_log_fops);

    /* 1.3. Add the device */
    result = cdev_add(&g_cdev_logs, g_log_dev_number, 1);
    if (0 != result) {
        printk(KERN_ERR "cdev_add failed with %d\n", result);
        goto l_cleanup;
    }

    /* 2. Create sysfs rules device */
    g_sysfs_log_device = device_create(g_hw3secws_class, NULL, g_log_dev_number, NULL, SYSFS_LOG_DEVICE_NAME);
    if (IS_ERR(g_hw3secws_class)) {
        result = -1;
        goto l_cleanup;
    }
    g_has_sysfs_log_device = TRUE;
    printk(KERN_INFO "RUN FOR FW: sudo mknod /dev/%s c %d %d\n",
           LOG_CHAR_DEVICE_NAME,
           MAJOR(g_log_dev_number),
           MINOR(g_log_dev_number));

    /* 3. Create sysfs device */
    result_device_create_file = device_create_file(
        g_sysfs_log_device,
        (const struct device_attribute *)&dev_attr_reset.attr
    );
    if (0 != result_device_create_file) {
        result = -1;
        goto l_cleanup;
    }

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
    g_rules_dev_number = register_chrdev(0, RULES_CHAR_DEVICE_NAME, &g_fw_rules_fops);
    if (0 > g_rules_dev_number) {
        printk(KERN_ERR "register_chrdev failed for %s\n", RULES_CHAR_DEVICE_NAME);
        result = -1;
        goto l_cleanup;
    }

    /* 2. Create sysfs rules device */
    /* 2.1. Create device */
    g_sysfs_rules_device = device_create(g_hw3secws_class,
                                         NULL,
                                         MKDEV(g_rules_dev_number, 0),
                                         NULL,
                                         SYSFS_RULES_DEVICE_NAME);
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
        device_destroy(g_hw3secws_class, g_log_dev_number);
        g_has_sysfs_log_device = FALSE;
        g_log_dev_number = -1;
    }

    cdev_del(&g_cdev_logs);

    if (INVALID_DEV_T_NUMBER != g_log_dev_number) {
        unregister_chrdev_region(g_log_dev_number, 1);
        g_log_dev_number = INVALID_DEV_T_NUMBER;
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
        device_destroy(g_hw3secws_class, MKDEV(g_rules_dev_number, 0));
        g_has_sysfs_rules_device = FALSE;
    }

    if (INVALID_DEV_T_NUMBER != g_rules_dev_number) {
        unregister_chrdev(g_rules_dev_number, RULES_CHAR_DEVICE_NAME);
        g_rules_dev_number = INVALID_DEV_T_NUMBER;
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

    was_modified = RULE_TABLE_dump_data(&g_rule_table, buf, &buffer_length);
    if (FALSE == was_modified) {
        result = -1;
        goto l_cleanup;
    }

    result = (ssize_t)buffer_length;
l_cleanup:

    return result;
}

static ssize_t
rules_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    ssize_t result = 0;
    bool_t was_modified = FALSE;

    was_modified = RULE_TABLE_set_data(&g_rule_table, buf, count);
    if (was_modified) {
        result = count;
    }

    return result;
}

static ssize_t
log_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    ssize_t result = 0;

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

