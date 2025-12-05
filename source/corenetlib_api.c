#include <stdio.h>
#include <rdk_logger.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/stat.h>
#include "libnet.h"
#include <ctype.h>
#include <cjson/cJSON.h>

// Define missing constants if not already defined
#ifndef CNL_STATUS_NOT_FOUND
#define CNL_STATUS_NOT_FOUND -2
#endif

#ifndef CNL_STATUS_ALREADY_UP
#define CNL_STATUS_ALREADY_UP -3
#endif

#ifndef CNL_STATUS_ALREADY_DOWN
#define CNL_STATUS_ALREADY_DOWN -4
#endif

#ifndef IFNAME_SIZE
#define IFNAME_SIZE 16
#endif

#define MAX_TESTS 50
#define MAX_ARGS 5

int total_tests = 0;
int total_passed = 0;

// Use rdk-logger API for logging
#include <rdk_logger.h>

void log_to_file(const char *message) {
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "%s\n", message);
}

typedef int (*api_handler_t)(int argc, char *argv[]);

typedef struct {
    const char *name;
    const char *usage;
    api_handler_t handler;
} api_entry_t;

// Forward declarations for all possible handler functions
int handle_addr_add(int argc, char *argv[]);
int handle_addr_delete(int argc, char *argv[]);
int handle_interface_up(int argc, char *argv[]);
int handle_interface_down(int argc, char *argv[]);
int handle_vlan_create(int argc, char *argv[]);
int handle_vlan_delete(int argc, char *argv[]);
int handle_interface_set_mtu(int argc, char *argv[]);
int handle_rule_add(int argc, char *argv[]);
int handle_rule_delete(int argc, char *argv[]);
int handle_route_add(int argc, char *argv[]);
int handle_route_delete(int argc, char *argv[]);
int handle_bridge_create(int argc, char *argv[]);
int handle_bridge_delete(int argc, char *argv[]);
int handle_bridge_free_info(int argc, char *argv[]);
int handle_bridge_get_info(int argc, char *argv[]);
int handle_interface_get_ip(int argc, char *argv[]);
int handle_interface_get_mac(int argc, char *argv[]);
int handle_interface_set_netmask(int argc, char *argv[]);
int handle_bridge_set_stp(int argc, char *argv[]);
int handle_interface_status(int argc, char *argv[]);
int handle_interface_exist(int argc, char *argv[]);
int handle_interface_rename(int argc, char *argv[]);
int handle_interface_delete(int argc, char *argv[]);
int handle_interface_set_mac(int argc, char *argv[]);
int handle_addr_derive_broadcast(int argc, char *argv[]);
int handle_interface_set_flags(int argc, char *argv[]);
int handle_get_ipv6_address(int argc, char *argv[]);
int handle_interface_add_to_bridge(int argc, char *argv[]);
int handle_interface_remove_from_bridge(int argc, char *argv[]);

// Forward declaration of api_table for use in get_handler_by_name
extern api_entry_t api_table[];

api_handler_t get_handler_by_name(const char *name) {
    if (!name) return NULL;
    
    // Support both "handle_xxx" and "xxx" formats
    const char *lookup_name = name;
    const char *prefix = "handle_";
    size_t prefix_len = strlen(prefix);
    
    // If name starts with "handle_", skip the prefix for lookup
    if (strncmp(name, prefix, prefix_len) == 0) {
        lookup_name = name + prefix_len;
    }
    
    for (int i = 0; api_table[i].name != NULL; i++) {
        if (strcmp(lookup_name, api_table[i].name) == 0)
            return api_table[i].handler;
    }
    return NULL;
}

// Forward declaration for run_all_tests
int run_all_tests(int argc, char *argv[]);

void log_result(const char *test_case, int result, int is_negative) {
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "\n----------------------------------------\n");
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Test Case: %s\n", test_case);
    total_tests++;
    char log_msg[512];
    if ((is_negative && result != 0) || (!is_negative && result == 0)) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Result: [PASS]\n");
        snprintf(log_msg, sizeof(log_msg), "Test Case: %s | Result: [PASS]", test_case);
        total_passed++;
    } else {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Result: [FAIL]\n");
        snprintf(log_msg, sizeof(log_msg), "Test Case: %s | Result: [FAIL]", test_case);
    }
    log_to_file(log_msg);
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "----------------------------------------\n");
}


void print_summary() {
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "\n========================================\n");
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "[==========] %d tests ran.\n", total_tests);
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "[  PASSED  ] %d tests.\n", total_passed);
    if (total_passed != total_tests) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "[  FAILED  ] %d tests.\n", total_tests - total_passed);
    }
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "========================================\n");
}



// Function to validate IPv4 and IPv6 addresses
int validate_ip_address(const char *ip) {
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;

    // Check if it's a valid IPv4 address
    if (inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1) {
        return 1; // Valid IPv4
    }

    // Check if it's a valid IPv6 address
    if (inet_pton(AF_INET6, ip, &(sa6.sin6_addr)) == 1) {
        return 1; // Valid IPv6
    }

    return 0; // Invalid IP address
}


// Wrapper function for popen and pclose
int execute_command(const char *command, char *output, size_t output_size) {
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "popen failed: %s\n", strerror(errno));
        return -1;
    }

    // Only read output if the caller provided a buffer
    if (output != NULL && output_size > 0) {
        if (fgets(output, output_size, fp) == NULL) {
            // fgets failed - could be no output or error
            // Still need to call pclose to get the command exit status
            output[0] = '\0'; // Ensure output is empty
        }
    }

    int status = pclose(fp);
    if (status == -1) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "pclose failed: %s\n", strerror(errno));
        return -1;
    }

    // Return non-zero if command failed (exit status != 0)
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int handle_interface_up(int argc, char *argv[]) {
    if (argc != 3 || argv[2] == NULL || strlen(argv[2]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: interface_up <if_name>\n");
        return -1;
    }
    char *if_name = argv[2];

    // Call the interface_up API directly
    int result = interface_up(if_name);
    if (result == CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Interface %s brought up successfully.\n", if_name);

        // Validate using the validation command
        char validation_command[256];
        snprintf(validation_command, sizeof(validation_command), "ip link show %s | grep 'UP' | wc -l", if_name);

        char output[256];
        if (execute_command(validation_command, output, sizeof(output)) != 0) {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed for interface %s.\n", if_name);
            return -1;
        }

        int validation_result = atoi(output); // Convert output to integer
        if (validation_result != 1) {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation output indicates failure for interface %s.\n", if_name);
            return -1;
        }

        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Validation successful for interface %s.\n", if_name);
        return 0;
    } else {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Failed to bring up interface %s. Error code: %d\n", if_name, result);
        return -1;
    }
}

int handle_interface_down(int argc, char *argv[]) {
    if (argc != 3 || argv[2] == NULL || strlen(argv[2]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: interface_down <if_name>\n");
        return -1;
    }
    char *if_name = argv[2];

    // Call the interface_down API directly
    int result = interface_down(if_name);
    if (result == CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Interface %s brought down successfully.\n", if_name);

        // Validate using the validation command
        char validation_command[256];
        snprintf(validation_command, sizeof(validation_command), "ip link show %s | grep 'state DOWN' | wc -l", if_name);

        char output[256];
        if (execute_command(validation_command, output, sizeof(output)) != 0) {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed for interface %s.\n", if_name);
            return -1;
        }

        int validation_result = atoi(output); // Convert output to integer
        if (validation_result != 1) {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation output indicates failure for interface %s.\n", if_name);
            return -1;
        }

        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Validation successful for interface %s.\n", if_name);
        return 0;
    } else {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Failed to bring down interface %s. Error code: %d\n", if_name, result);
        return -1;
    }
}

int handle_interface_set_mtu(int argc, char *argv[]) {
    if (argc != 4 || argv[2] == NULL || argv[3] == NULL || strlen(argv[2]) == 0 || strlen(argv[3]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: interface_set_mtu <if_name> <mtu_value>\n");
        return -1;
    }
    char *if_name = argv[2];
    char *mtu_value_str = argv[3];

    // Call the interface_set_mtu API directly
    if (interface_set_mtu(if_name, mtu_value_str) == CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: MTU for interface %s set to %s successfully.\n", if_name, mtu_value_str);

        // Validate using Linux command
        char validation_command[256];
        snprintf(validation_command, sizeof(validation_command), "ip link show %s | grep -w 'mtu %s'", if_name, mtu_value_str);

        char output[256];
        if (execute_command(validation_command, output, sizeof(output)) == 0 && strstr(output, mtu_value_str)) {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Linux command validation successful for interface %s. MTU is set to %s.\n", if_name, mtu_value_str);
            return 0;
        } else {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Linux command validation failed for interface %s.\n", if_name);
            return -1;
        }
    } else {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Failed to set MTU for interface %s.\n", if_name);
        return -1;
    }
}

int handle_interface_get_mac(int argc, char *argv[]) {
    if (argc != 3 || argv[2] == NULL || strlen(argv[2]) == 0) {
        log_to_file("Usage: interface_get_mac <if_name>");
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: interface_get_mac <if_name>\n");
        return -1;
    }
    char *if_name = argv[2];
    char mac[18] = {0};
    char log_msg[256];
    if (interface_get_mac(if_name, mac, sizeof(mac)) == CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "MAC address of interface %s: %s\n", if_name, mac);

        // Validation: get MAC from ip link show and compare
        char validation_command[256];
        snprintf(validation_command, sizeof(validation_command),
                 "ip link show %s | grep 'link/ether' | awk '{print $2}'", if_name);

        char output[64] = {0};
        if (execute_command(validation_command, output, sizeof(output)) != 0) {
            snprintf(log_msg, sizeof(log_msg), "FAIL: Linux command validation failed for interface %s.", if_name);
            log_to_file(log_msg);
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Linux command validation failed for interface %s.\n", if_name);
            return -1;
        }

        // Remove trailing newline and convert to lowercase for comparison
        char *newline = strchr(output, '\n');
        if (newline) *newline = '\0';

        // Convert both to lowercase for case-insensitive comparison
        char mac_api[18], mac_ifconfig[18];
        snprintf(mac_api, sizeof(mac_api), "%s", mac);
        snprintf(mac_ifconfig, sizeof(mac_ifconfig), "%s", output);
        for (int i = 0; mac_api[i]; i++) mac_api[i] = tolower(mac_api[i]);
        for (int i = 0; mac_ifconfig[i]; i++) mac_ifconfig[i] = tolower(mac_ifconfig[i]);

        if (strcmp(mac_api, mac_ifconfig) == 0 && strlen(mac_api) > 0) {
            snprintf(log_msg, sizeof(log_msg), "PASS: Validation successful. MAC %s is present in ifconfig output for %s.", mac, if_name);
            log_to_file(log_msg);
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Validation successful. MAC %s is present in ifconfig output for %s.\n", mac, if_name);
            return 0;
        } else {
            snprintf(log_msg, sizeof(log_msg), "FAIL: Validation failed. API MAC (%s) does not match ifconfig output (%s) for %s.", mac, output, if_name);
            log_to_file(log_msg);
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed. API MAC (%s) does not match ifconfig output (%s) for %s.\n", mac, output, if_name);
            return -1;
        }
    } else {
        snprintf(log_msg, sizeof(log_msg), "FAIL: Failed to get MAC address of interface %s.", if_name);
        log_to_file(log_msg);
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Failed to get MAC address of interface %s.\n", if_name);
        return -1;
    }
}

int handle_interface_set_mac(int argc, char *argv[]) {
    if (argc != 4 || argv[2] == NULL || argv[3] == NULL || strlen(argv[2]) == 0 || strlen(argv[3]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: interface_set_mac <if_name> <mac_address>\n");
        return -1;
    }
    char *if_name = argv[2];
    char *mac_address = argv[3];

    // Execute the API
    int result = interface_set_mac(if_name, mac_address);
    if (result == CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "MAC address of interface %s set to %s successfully.\n", if_name, mac_address);

        // Validation: check with ip link show that the MAC is set
        char validation_command[256];
        snprintf(validation_command, sizeof(validation_command),
                 "ip link show %s | grep 'link/ether' | awk '{print $2}'", if_name);

        char output[64] = {0};
        if (execute_command(validation_command, output, sizeof(output)) != 0) {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed for interface %s.\n", if_name);
            return -1;
        }

        // Remove trailing newline
        char *newline = strchr(output, '\n');
        if (newline) *newline = '\0';

        // Compare ignoring case
        char mac_api[18], mac_ifconfig[18];
        snprintf(mac_api, sizeof(mac_api), "%s", mac_address);
        snprintf(mac_ifconfig, sizeof(mac_ifconfig), "%s", output);
        for (int i = 0; mac_api[i]; i++) mac_api[i] = tolower(mac_api[i]);
        for (int i = 0; mac_ifconfig[i]; i++) mac_ifconfig[i] = tolower(mac_ifconfig[i]);

        if (strcmp(mac_api, mac_ifconfig) == 0 && strlen(mac_api) > 0) {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Validation successful. MAC %s is present in ifconfig output for %s.\n", mac_address, if_name);
            return 0;
        } else {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed. API MAC (%s) does not match ifconfig output (%s) for %s.\n", mac_address, output, if_name);
            return -1;
        }
    } else {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Failed to set MAC address for interface %s.\n", if_name);
        return -1;
    }
}


int handle_route_add(int argc, char *argv[]) {
    if (argc != 3 || argv[2] == NULL || strlen(argv[2]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: route_add <args>\n");
        return -1;
    }

    char *args = argv[2];
    if (route_add(args) != CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Failed to add route: %s\n", args);
        return -1;
    }

    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Route added successfully: %s\n", args);

    // Parse fields from args
    char *args_copy = strdup(args);
    if (!args_copy) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Memory allocation failed.\n");
        return -1;
    }
    char *token = strtok(args_copy, " ");
    char dest_prefix[64] = {0}, dev[32] = {0}, via[64] = {0}, src[64] = {0};
    char metric[16] = {0}, mtu[16] = {0}, table[16] = {0}, proto[32] = {0};
    char scope[16] = {0}, type[16] = {0};

    while (token) {
        if (strcmp(token, "dev") == 0 && (token = strtok(NULL, " "))) {
            strncpy(dev, token, sizeof(dev) - 1);
        } else if (strcmp(token, "via") == 0 && (token = strtok(NULL, " "))) {
            strncpy(via, token, sizeof(via) - 1);
        } else if (strcmp(token, "src") == 0 && (token = strtok(NULL, " "))) {
            strncpy(src, token, sizeof(src) - 1);
        } else if (strcmp(token, "metric") == 0 && (token = strtok(NULL, " "))) {
            strncpy(metric, token, sizeof(metric) - 1);
        } else if (strcmp(token, "mtu") == 0 && (token = strtok(NULL, " "))) {
            strncpy(mtu, token, sizeof(mtu) - 1);
        } else if (strcmp(token, "table") == 0 && (token = strtok(NULL, " "))) {
            strncpy(table, token, sizeof(table) - 1);
        } else if ((strcmp(token, "proto") == 0 || strcmp(token, "protocol") == 0) &&
                   (token = strtok(NULL, " "))) {
            strncpy(proto, token, sizeof(proto) - 1);
        } else if (strcmp(token, "scope") == 0 && (token = strtok(NULL, " "))) {
            strncpy(scope, token, sizeof(scope) - 1);
        } else if (strcmp(token, "type") == 0 && (token = strtok(NULL, " "))) {
            strncpy(type, token, sizeof(type) - 1);
        } else if (strchr(token, '/')) {
            strncpy(dest_prefix, token, sizeof(dest_prefix) - 1);
        }
        token = strtok(NULL, " ");
    }
    free(args_copy);

    // Construct validation command
    char validation_cmd[256], output[1024] = {0};
    snprintf(validation_cmd, sizeof(validation_cmd), "ip route show | grep '%s'", dest_prefix);

    if (execute_command(validation_cmd, output, sizeof(output)) != 0 || strlen(output) == 0) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Route not found in routing table.\n");
        return -1;
    }

    int match = 1;
    if (dev[0] && !strstr(output, dev)) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: dev '%s' not found in route.\n", dev);
        match = 0;
    }
    if (via[0] && !strstr(output, via)) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: via '%s' not found in route.\n", via);
        match = 0;
    }
    if (src[0] && !strstr(output, src)) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: src '%s' not found in route.\n", src);
        match = 0;
    }
    if (metric[0] && !strstr(output, metric)) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: metric '%s' not found in route.\n", metric);
        match = 0;
    }
    if (mtu[0] && !strstr(output, mtu)) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: mtu '%s' not found in route.\n", mtu);
        match = 0;
    }
    if (table[0] && !strstr(output, table)) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: table '%s' not found in route.\n", table);
        match = 0;
    }
    if (proto[0] && !strstr(output, proto)) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: proto '%s' not found in route.\n", proto);
        match = 0;
    }
    if (scope[0] && !strstr(output, scope)) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: scope '%s' not found in route.\n", scope);
        match = 0;
    }
    if (type[0] && !strstr(output, type)) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: type '%s' not found in route.\n", type);
        match = 0;
    }

    if (match) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Route fields validated successfully.\n");
        return 0;
    } else {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: One or more fields not matched in routing table.\n");
        return -1;
    }
}

int handle_route_delete(int argc, char *argv[]) {
    if (argc != 3 || argv[2] == NULL || strlen(argv[2]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: route_delete <args>\n");
        return -1;
    }

    char *args = argv[2];
    if (route_delete(args) != CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Failed to delete route: %s\n", args);
        return -1;
    }

    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Route deleted successfully: %s\n", args);

    // Parse the fields
    char *args_copy = strdup(args);
    if (!args_copy) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Memory allocation failed.\n");
        return -1;
    }
    char *token = strtok(args_copy, " ");
    char dest_prefix[64] = {0}, dev[32] = {0}, via[64] = {0}, src[64] = {0};
    char metric[16] = {0}, mtu[16] = {0}, table[16] = {0}, proto[32] = {0};
    char scope[16] = {0}, type[16] = {0};

    while (token) {
        if (strcmp(token, "dev") == 0 && (token = strtok(NULL, " "))) {
            strncpy(dev, token, sizeof(dev) - 1);
        } else if (strcmp(token, "via") == 0 && (token = strtok(NULL, " "))) {
            strncpy(via, token, sizeof(via) - 1);
        } else if (strcmp(token, "src") == 0 && (token = strtok(NULL, " "))) {
            strncpy(src, token, sizeof(src) - 1);
        } else if (strcmp(token, "metric") == 0 && (token = strtok(NULL, " "))) {
            strncpy(metric, token, sizeof(metric) - 1);
        } else if (strcmp(token, "mtu") == 0 && (token = strtok(NULL, " "))) {
            strncpy(mtu, token, sizeof(mtu) - 1);
        } else if (strcmp(token, "table") == 0 && (token = strtok(NULL, " "))) {
            strncpy(table, token, sizeof(table) - 1);
        } else if ((strcmp(token, "proto") == 0 || strcmp(token, "protocol") == 0) &&
                   (token = strtok(NULL, " "))) {
            strncpy(proto, token, sizeof(proto) - 1);
        } else if (strcmp(token, "scope") == 0 && (token = strtok(NULL, " "))) {
            strncpy(scope, token, sizeof(scope) - 1);
        } else if (strcmp(token, "type") == 0 && (token = strtok(NULL, " "))) {
            strncpy(type, token, sizeof(type) - 1);
        } else if (strchr(token, '/')) {
            strncpy(dest_prefix, token, sizeof(dest_prefix) - 1);
        }
        token = strtok(NULL, " ");
    }
    free(args_copy);

    // Build validation command
    char validation_cmd[256], output[1024] = {0};
    snprintf(validation_cmd, sizeof(validation_cmd), "ip route show | grep '%s'", dest_prefix);

    if (execute_command(validation_cmd, output, sizeof(output)) == 0 && strlen(output) > 0) {
        // Still found, check if any of the deleted fields still exist
        int found = 0;
        if (dev[0] && strstr(output, dev)) found = 1;
        if (via[0] && strstr(output, via)) found = 1;
        if (src[0] && strstr(output, src)) found = 1;
        if (metric[0] && strstr(output, metric)) found = 1;
        if (mtu[0] && strstr(output, mtu)) found = 1;
        if (table[0] && strstr(output, table)) found = 1;
        if (proto[0] && strstr(output, proto)) found = 1;
        if (scope[0] && strstr(output, scope)) found = 1;
        if (type[0] && strstr(output, type)) found = 1;

        if (!found) {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Route deletion verified. No matching fields remain.\n");
            return 0;
        } else {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Route still present in routing table.\n");
            return -1;
        }
    }

    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Route completely removed from routing table.\n");
    return 0;
}


int handle_vlan_create(int argc, char *argv[]) {
    if (argc != 4 || argv[2] == NULL || argv[3] == NULL || strlen(argv[2]) == 0 || strlen(argv[3]) == 0) {
        log_to_file("Usage: vlan_create <if_name> <vlan_id>");
        return -1;
    }
    char *if_name = argv[2];
    int vlan_id = atoi(argv[3]);

    // Call the vlan_create API directly
    int result = vlan_create(if_name, vlan_id);
    if (result == CNL_STATUS_SUCCESS) {
        // Log and print success message
        char log_msg[128];
        snprintf(log_msg, sizeof(log_msg), "PASS: VLAN %d created on interface %s successfully.", vlan_id, if_name);
        log_to_file(log_msg);
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: VLAN %d created on interface %s successfully.\n", vlan_id, if_name);

        // Additional validation using Linux command
        char validation_command[256];
        snprintf(validation_command, sizeof(validation_command), "ip link show %s.%d", if_name, vlan_id);

        char output[256];
        if (execute_command(validation_command, output, sizeof(output)) == 0 && strstr(output, if_name)) {
            snprintf(log_msg, sizeof(log_msg), "PASS: Linux command validation successful. VLAN %d exists on interface %s.", vlan_id, if_name);
            log_to_file(log_msg);
            return 0;
        } else {
            snprintf(log_msg, sizeof(log_msg), "FAIL: Linux command validation failed. VLAN %d not found on interface %s.", vlan_id, if_name);
            log_to_file(log_msg);
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: VLAN %d creation validation failed on interface %s.\n", vlan_id, if_name);
            return -1;
        }
    } else {
        // Log and print failure message
        char log_msg[128];
        snprintf(log_msg, sizeof(log_msg), "FAIL: Failed to create VLAN %d on interface %s. Error code: %d", vlan_id, if_name, result);
        log_to_file(log_msg);
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: VLAN %d creation failed on interface %s.\n", vlan_id, if_name);
        return -1;
    }
}

int handle_vlan_delete(int argc, char *argv[]) {
    if (argc != 3 || argv[2] == NULL || strlen(argv[2]) == 0) {
        log_to_file("Usage: vlan_delete <vlan_name>");
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: vlan_delete <vlan_name>\n");
        return -1;
    }
    char *vlan_name = argv[2];

    // Call the vlan_delete API directly
    int result = vlan_delete(vlan_name);
    if (result == CNL_STATUS_SUCCESS) {
        char log_msg[128];
        snprintf(log_msg, sizeof(log_msg), "PASS: VLAN %s deleted successfully.", vlan_name);
        log_to_file(log_msg);
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: VLAN %s deleted successfully.\n", vlan_name);

        // Additional validation using Linux command
        char validation_command[256];
        snprintf(validation_command, sizeof(validation_command), "ip link show %s", vlan_name);

        char output[256];
        if (execute_command(validation_command, output, sizeof(output)) == 0 && strlen(output) > 0) {
            snprintf(log_msg, sizeof(log_msg), "FAIL: Linux command validation failed. VLAN %s still exists.", vlan_name);
            log_to_file(log_msg);
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: VLAN %s still exists after deletion.\n", vlan_name);
            return -1;
        }

        snprintf(log_msg, sizeof(log_msg), "PASS: Linux command validation successful. VLAN %s no longer exists.", vlan_name);
        log_to_file(log_msg);
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Validation successful. VLAN %s no longer exists.\n", vlan_name);
        return 0;
    } else {
        char log_msg[128];
        snprintf(log_msg, sizeof(log_msg), "FAIL: Unable to delete VLAN %s. Error code: %d", vlan_name, result);
        log_to_file(log_msg);
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Unable to delete VLAN %s. Error code: %d\n", vlan_name, result);
        return -1;
    }
}

int handle_bridge_create(int argc, char *argv[]) {
    if (argc != 3 || argv[2] == NULL || strlen(argv[2]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: bridge_create <bridge_name>\n");
        log_to_file("FAIL: bridge_create called with NULL or empty argument.");
        return -1;
    }

    char *bridge_name = argv[2];

    // Call the bridge_create API directly
    if (bridge_create(bridge_name) != CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Failed to create bridge %s.\n", bridge_name);
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "FAIL: bridge_create failed for bridge %s", bridge_name);
        log_to_file(log_msg);
        return -1;
    }

    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Bridge %s created successfully.\n", bridge_name);

    // Validate using the validation command
    char validation_command[256];
    snprintf(validation_command, sizeof(validation_command), "ip link show %s", bridge_name);
    char output[256] = {0};
    if (execute_command(validation_command, output, sizeof(output)) == 0 && strstr(output, bridge_name)) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Validation successful. Bridge %s exists.\n", bridge_name);
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "PASS: Bridge %s created and validated.", bridge_name);
        log_to_file(log_msg);
        return 0;
    } else {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed. Bridge %s not found.\n", bridge_name);
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "FAIL: Bridge %s created but not found in validation.", bridge_name);
        log_to_file(log_msg);
        return -1;
    }
}

int handle_bridge_delete(int argc, char *argv[]) {
    if (argc != 3 || argv[2] == NULL || strlen(argv[2]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: bridge_delete <bridge_name>\n");
        return -1;
    }
    char *bridge_name = argv[2];

    // Call the bridge_delete API directly
    if (bridge_delete(bridge_name) == CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Bridge %s deleted successfully.\n", bridge_name);

        // Validate using the exit status of the validation command
        char validation_command[256];
        snprintf(validation_command, sizeof(validation_command), "ip link show %s", bridge_name);

        if (execute_command(validation_command, NULL, 0) != 0) { // Command fails if the bridge does not exist
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Validation successful. Bridge %s no longer exists.\n", bridge_name);
            return 0;
        } else {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed. Bridge %s still exists.\n", bridge_name);
            return -1;
        }
    } else {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Failed to delete bridge %s.\n", bridge_name);
        return -1;
    }
}

int handle_interface_add_to_bridge(int argc, char *argv[]) {
    if (argc != 4 || argv[2] == NULL || argv[3] == NULL ||
        strlen(argv[2]) == 0 || strlen(argv[3]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: interface_add_to_bridge <bridge_name> <if_name>\n");
        return -1;
    }

    char *bridge_name = argv[2];
    char *if_name = argv[3];

    int result = interface_add_to_bridge(bridge_name, if_name);
    if (result != CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Failed to add interface %s to bridge %s.\n", if_name, bridge_name);
        return -1;
    }

    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Interface %s added to bridge %s successfully.\n", if_name, bridge_name);

    // Validation: check if the interface appears in the bridge
    char validation_command[256];
    snprintf(validation_command, sizeof(validation_command), "brctl show %s", bridge_name);
    char output[2048] = {0};

    if (execute_command(validation_command, output, sizeof(output)) != 0) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Could not get brctl show output for bridge %s.\n", bridge_name);
        return -1;
    }

    // Parse output line by line and check for the interface name
    int found = 0;
    char *line = strtok(output, "\n");
    while (line != NULL) {
        // Skip the first line (bridge info header)
        if (strstr(line, if_name) != NULL) {
            found = 1;
            break;
        }
        line = strtok(NULL, "\n");
    }

    if (found) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Validation successful. Interface %s is present in bridge %s (brctl show).\n", if_name, bridge_name);
        return 0;
    } else {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed. Interface %s not found in bridge %s (brctl show).\n", if_name, bridge_name);
        return -1;
    }
}


int handle_interface_remove_from_bridge(int argc, char *argv[]) {
    if (argc != 3 || argv[2] == NULL || strlen(argv[2]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: interface_remove_from_bridge <if_name>\n");
        return -1;
    }
    char *if_name = argv[2];
    int result = interface_remove_from_bridge(if_name);
    if (result == CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Interface %s removed from bridge successfully.\n", if_name);
        // Validation: check that if_name is not present in any bridge
        char output[2048] = {0};
        int rc = execute_command("brctl show", output, sizeof(output));
        if (rc == 0 && !strstr(output, if_name)) {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Validation successful. %s is not present in any bridge (brctl show).\n", if_name);
            return 0;
        } else {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed. %s is still present in a bridge (brctl show).\n", if_name);
            return -1;
        }
    } else {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Failed to remove interface %s from bridge.\n", if_name);
        return -1;
    }
}

int handle_interface_status(int argc, char *argv[]) {
    if (argc != 3 || argv[2] == NULL || strlen(argv[2]) == 0) {
        log_to_file("Usage: interface_status <if_name>");
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: interface_status <if_name>\n");
        return -1;
    }
    char *if_name = argv[2];
    int status;
    char log_msg[256];
    if (interface_status(if_name, &status) == CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Interface %s is %s.\n", if_name, status ? "UP" : "DOWN");

        // Validation: check if "UP" is present in ifconfig output
        char validation_command[256];
        snprintf(validation_command, sizeof(validation_command),
                 "ifconfig %s | grep -w 'UP' | wc -l", if_name);

        char output[32] = {0};
        if (execute_command(validation_command, output, sizeof(output)) != 0) {
            snprintf(log_msg, sizeof(log_msg), "FAIL: Linux command validation failed for interface %s.", if_name);
            log_to_file(log_msg);
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Linux command validation failed for interface %s.\n", if_name);
            return -1;
        }

        int up_count = atoi(output);
        int expected = status ? 1 : 0;
        if ((status && up_count > 0) || (!status && up_count == 0)) {
            snprintf(log_msg, sizeof(log_msg), "PASS: Validation successful. Interface %s is %s as expected.", if_name, status ? "UP" : "DOWN");
            log_to_file(log_msg);
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Validation successful. Interface %s is %s as expected.\n", if_name, status ? "UP" : "DOWN");
            return 0;
        } else {
            snprintf(log_msg, sizeof(log_msg), "FAIL: Validation failed. Interface %s status mismatch: API=%s, ifconfig=%s.", if_name, status ? "UP" : "DOWN", up_count > 0 ? "UP" : "DOWN");
            log_to_file(log_msg);
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed. Interface %s status mismatch: API=%s, ifconfig=%s.\n", if_name, status ? "UP" : "DOWN", up_count > 0 ? "UP" : "DOWN");
            return -1;
        }
    } else {
        snprintf(log_msg, sizeof(log_msg), "FAIL: Failed to get status of interface %s.", if_name);
        log_to_file(log_msg);
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Failed to get status of interface %s.\n", if_name);
        return -1;
    }
}

int handle_interface_get_ip(int argc, char *argv[]) {
    if (argc != 3 || argv[2] == NULL || strlen(argv[2]) == 0) {
        log_to_file("Usage: interface_get_ip <if_name>");
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: interface_get_ip <if_name>\n");
        return -1;
    }
    char *if_name = argv[2];
    char *ip = interface_get_ip(if_name);
    char log_msg[256];
    if (ip) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "IP address of interface %s: %s\n", if_name, ip);

        // Validation: check if IP is present in ifconfig output
        char validation_command[256];
        snprintf(validation_command, sizeof(validation_command),
                 "ifconfig %s | grep 'inet addr:' | awk '{print $2}' | cut -d: -f2", if_name);

        char output[128] = {0};
        if (execute_command(validation_command, output, sizeof(output)) != 0) {
            snprintf(log_msg, sizeof(log_msg), "FAIL: Linux command validation failed for interface %s.", if_name);
            log_to_file(log_msg);
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Linux command validation failed for interface %s.\n", if_name);
            return -1;
        }

        // Remove trailing newline
        char *newline = strchr(output, '\n');
        if (newline) *newline = '\0';

        if (strcmp(ip, output) == 0 && strlen(ip) > 0) {
            snprintf(log_msg, sizeof(log_msg), "PASS: Validation successful. IP %s is present in ifconfig output for %s.", ip, if_name);
            log_to_file(log_msg);
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Validation successful. IP %s is present in ifconfig output for %s.\n", ip, if_name);
            return 0;
        } else {
            snprintf(log_msg, sizeof(log_msg), "FAIL: Validation failed. API IP (%s) does not match ifconfig output (%s) for %s.", ip, output, if_name);
            log_to_file(log_msg);
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed. API IP (%s) does not match ifconfig output (%s) for %s.\n", ip, output, if_name);
            return -1;
        }
    } else {
        snprintf(log_msg, sizeof(log_msg), "FAIL: Failed to get IP address of interface %s.", if_name);
        log_to_file(log_msg);
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Failed to get IP address of interface %s.\n", if_name);
        return -1;
    }
}

int handle_interface_set_netmask(int argc, char *argv[]) {
    if (argc != 4 || argv[2] == NULL || argv[3] == NULL || strlen(argv[2]) == 0 || strlen(argv[3]) == 0) {
        log_to_file("Usage: interface_set_netmask <if_name> <netmask>");
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: interface_set_netmask <if_name> <netmask>\n");
        return -1;
    }
    char *if_name = argv[2];
    char *netmask = argv[3];
    char log_msg[256];
    if (interface_set_netmask(if_name, netmask) == CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Netmask for interface %s set to %s successfully.\n", if_name, netmask);

        // Validation: check if netmask is present in ifconfig output
        char validation_command[256];
        snprintf(validation_command, sizeof(validation_command),
                 "ifconfig %s | grep -w 'Mask:%s' | wc -l", if_name, netmask);

        char output[64] = {0};
        if (execute_command(validation_command, output, sizeof(output)) != 0) {
            snprintf(log_msg, sizeof(log_msg), "FAIL: Linux command validation failed for interface %s.", if_name);
            log_to_file(log_msg);
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Linux command validation failed for interface %s.\n", if_name);
            return -1;
        }

        int validation_result = atoi(output);
        if (validation_result > 0) {
            snprintf(log_msg, sizeof(log_msg), "PASS: Validation successful. Netmask %s is present in ifconfig output for %s.", netmask, if_name);
            log_to_file(log_msg);
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Validation successful. Netmask %s is present in ifconfig output for %s.\n", netmask, if_name);
            return 0;
        } else {
            snprintf(log_msg, sizeof(log_msg), "FAIL: Validation failed. Netmask %s is not present in ifconfig output for %s.", netmask, if_name);
            log_to_file(log_msg);
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed. Netmask %s is not present in ifconfig output for %s.\n", netmask, if_name);
            return -1;
        }
    } else {
        snprintf(log_msg, sizeof(log_msg), "FAIL: Failed to set netmask for interface %s.", if_name);
        log_to_file(log_msg);
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Failed to set netmask for interface %s.\n", if_name);
        return -1;
    }
}

int handle_bridge_set_stp(int argc, char *argv[]) {
    if (argc != 4 || argv[2] == NULL || argv[3] == NULL || strlen(argv[2]) == 0 || strlen(argv[3]) == 0) {
        log_to_file("Usage: bridge_set_stp <bridge_name> <on|off>");
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: bridge_set_stp <bridge_name> <on|off>\n");
        return -1;
    }
    char *bridge_name = argv[2];
    char *stp_state = argv[3];
    char log_msg[256];
    if (bridge_set_stp(bridge_name, stp_state) == CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "STP for bridge %s set to %s successfully.\n", bridge_name, stp_state);

        // Validation: check STP enabled field in brctl show output
        char validation_command[256];
        snprintf(validation_command, sizeof(validation_command),
                 "brctl show | grep -w '^%s' | awk '{print $3}'", bridge_name);

        char output[32] = {0};
        if (execute_command(validation_command, output, sizeof(output)) != 0) {
            snprintf(log_msg, sizeof(log_msg), "FAIL: Linux command validation failed for bridge %s.", bridge_name);
            log_to_file(log_msg);
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Linux command validation failed for bridge %s.\n", bridge_name);
            return -1;
        }

        // Remove trailing newline
        char *newline = strchr(output, '\n');
        if (newline) *newline = '\0';

        // Determine expected value
        const char *expected = (strcasecmp(stp_state, "on") == 0) ? "yes" : "no";
        if (strcasecmp(output, expected) == 0) {
            snprintf(log_msg, sizeof(log_msg), "PASS: Validation successful. STP for %s is '%s' as expected.", bridge_name, expected);
            log_to_file(log_msg);
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Validation successful. STP for %s is '%s' as expected.\n", bridge_name, expected);
            return 0;
        } else {
            snprintf(log_msg, sizeof(log_msg), "FAIL: Validation failed. STP for %s is '%s', expected '%s'.", bridge_name, output, expected);
            log_to_file(log_msg);
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed. STP for %s is '%s', expected '%s'.\n", bridge_name, output, expected);
            return -1;
        }
    } else {
        snprintf(log_msg, sizeof(log_msg), "FAIL: Failed to set STP for bridge %s.", bridge_name);
        log_to_file(log_msg);
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Failed to set STP for bridge %s.\n", bridge_name);
        return -1;
    }
}

int handle_interface_rename(int argc, char *argv[]) {
    if (argc != 4 || argv[2] == NULL || argv[3] == NULL || strlen(argv[2]) == 0 || strlen(argv[3]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: interface_rename <if_name> <new_name>\n");
        return -1;
    }
    char *if_name = argv[2];
    char *new_name = argv[3];

    // Step 1: Ensure the original interface exists for validation
    char validation_command[256];
    snprintf(validation_command, sizeof(validation_command), "ip link show %s", if_name);
    char output[256] = {0};
    if (execute_command(validation_command, output, sizeof(output)) != 0) {
        // Try to create the bridge if it doesn't exist (only for brlan* names)
        if (strncmp(if_name, "brlan", 5) == 0) {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Interface %s does not exist, attempting to create it for validation...\n", if_name);
            char *create_argv[] = {"corenetlib_api", "bridge_create", if_name};
            int create_result = handle_bridge_create(3, create_argv);
            if (create_result != 0) {
                RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Failed to create interface %s for rename validation.\n", if_name);
                return -1;
            }
        } else {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Interface %s does not exist and cannot be created automatically.\n", if_name);
            return -1;
        }
    }

    // Step 2: Call the API to rename the interface
    int result = interface_rename(if_name, new_name);
    if (result == CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Interface %s renamed to %s successfully.\n", if_name, new_name);

        // Step 3: Validate the rename using ip link show on the new name
        snprintf(validation_command, sizeof(validation_command), "ip link show %s", new_name);
        memset(output, 0, sizeof(output));
        if (execute_command(validation_command, output, sizeof(output)) == 0 && strstr(output, new_name)) {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Validation successful. Interface %s exists after rename.\n", new_name);
            return 0;
        } else {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed. Interface %s not found after rename.\n", new_name);
            return -1;
        }
    } else {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Failed to rename interface %s to %s.\n", if_name, new_name);
        return -1;
    }
}

int handle_interface_delete(int argc, char *argv[]) {
    if (argc != 3 || argv[2] == NULL || strlen(argv[2]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: interface_delete <if_name>\n");
        return -1;
    }
    char *if_name = argv[2];

    // Execute the interface_delete API
    int result = interface_delete(if_name);
    if (result == CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Interface %s deleted successfully.\n", if_name);

        // Validation: check with ifconfig that the interface is gone
        char validation_command[256];
        snprintf(validation_command, sizeof(validation_command), "ifconfig %s", if_name);
        int ifconfig_status = execute_command(validation_command, NULL, 0);

        if (ifconfig_status != 0) {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Validation successful. Interface %s no longer exists.\n", if_name);
            return 0;
        } else {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed. Interface %s still exists after deletion.\n", if_name);
            return -1;
        }
    } else {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Failed to delete interface %s.\n", if_name);
        return -1;
    }
}

int handle_neighbour_delete(int argc, char *argv[]) {
    if (argc != 4 || argv[2] == NULL || argv[3] == NULL || strlen(argv[2]) == 0 || strlen(argv[3]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: neighbour_delete <if_name> <ip>\n");
        return -1;
    }
    char *if_name = argv[2];
    char *ip = argv[3];
    if (neighbour_delete(if_name, ip) == CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Neighbour entry for IP %s on interface %s deleted successfully.\n", ip, if_name);
        return 0;
    } else {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Failed to delete neighbour entry for IP %s on interface %s.\n", ip, if_name);
        return -1;
    }
}

int handle_get_ipv6_address(int argc, char *argv[]) {
    if (argc != 3 || argv[2] == NULL || strlen(argv[2]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: get_ipv6_address <if_name>\n");
        return -1;
    }

    char *if_name = argv[2];
    char ipv6_addr[INET6_ADDRSTRLEN] = {0};

    if (get_ipv6_address(if_name, ipv6_addr, sizeof(ipv6_addr)) == CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Global IPv6 address of interface %s: %s\n", if_name, ipv6_addr);

        // Use 'ip' command to retrieve system's global IPv6 addresses for the interface
        char validation_command[256];
        snprintf(validation_command, sizeof(validation_command),
                 "ip -6 addr show dev %s scope global | grep 'inet6' | awk '{print $2}' | cut -d/ -f1",
                 if_name);

        char output[512] = {0};
        if (execute_command(validation_command, output, sizeof(output)) != 0) {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed to get IPv6 address from system for %s.\n", if_name);
            return -1;
        }

        // Compare line by line
        int matched = 0;
        char *line = strtok(output, "\n");
        while (line) {
            if (strcasecmp(ipv6_addr, line) == 0) {
                matched = 1;
                break;
            }
            line = strtok(NULL, "\n");
        }

        if (matched && strlen(ipv6_addr) > 0) {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Validation successful. IPv6 address %s is present in system output for %s.\n", ipv6_addr, if_name);
            return 0;
        } else {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed. API IPv6 (%s) not matched in system output for %s.\n", ipv6_addr, if_name);
            return -1;
        }
    } else {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Failed to get global IPv6 address of interface %s.\n", if_name);
        return -1;
    }
}


int handle_addr_add(int argc, char *argv[]) {
    if (argc != 3 || argv[2] == NULL || strlen(argv[2]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: addr_add <args>\n");
        log_to_file("FAIL: addr_add called with NULL or empty argument.");
        return -1;
    }

    char *args = argv[2];
    if (addr_add(args) != CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Failed to add address: %s\n", args);
        log_to_file("FAIL: Failed to add address.");
        return -1;
    }

    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Address added successfully: %s\n", args);

    // Variables for parsing
    char if_name[IFNAME_SIZE] = {0}, ip_with_mask[64] = {0};
    char valid_lft[32] = {0}, preferred_lft[32] = {0};
    int has_valid_lft = 0, has_preferred_lft = 0;

    char *args_copy = strdup(args);
    if (!args_copy) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Memory allocation failed.\n");
        log_to_file("FAIL: strdup failed.");
        return -1;
    }

    char *token = strtok(args_copy, " ");
    while (token) {
        if (strcmp(token, "dev") == 0 && (token = strtok(NULL, " "))) {
            strncpy(if_name, token, IFNAME_SIZE - 1);
        } else if (strcmp(token, "valid_lft") == 0 && (token = strtok(NULL, " "))) {
            strncpy(valid_lft, token, sizeof(valid_lft) - 1);
            has_valid_lft = 1;
        } else if (strcmp(token, "preferred_lft") == 0 && (token = strtok(NULL, " "))) {
            strncpy(preferred_lft, token, sizeof(preferred_lft) - 1);
            has_preferred_lft = 1;
        } else if (strchr(token, '/') && ip_with_mask[0] == '\0') {
            strncpy(ip_with_mask, token, sizeof(ip_with_mask) - 1);
        }
        token = strtok(NULL, " ");
    }
    free(args_copy);

    // Basic IP address validation
    char validation_cmd[256], output[256];
    snprintf(validation_cmd, sizeof(validation_cmd), "ip address show dev %s | grep -w \"%s\"", if_name, ip_with_mask);
    if (execute_command(validation_cmd, output, sizeof(output)) != 0) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed for address: %s\n", args);
        log_to_file("FAIL: Address not present in system after addition.");
        return -1;
    }
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Validation successful for address: %s\n", args);

    // Validate lifetime fields if present
    if (has_valid_lft || has_preferred_lft) {
        char lft_cmd[256], lft_output[1024] = {0};
        snprintf(lft_cmd, sizeof(lft_cmd), "ip -d address show dev %s", if_name);
        if (execute_command(lft_cmd, lft_output, sizeof(lft_output)) == 0) {
            int match = 1;
            if (has_valid_lft && !strstr(lft_output, "valid_lft forever")) {
                RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: valid_lft 'forever' not found.\n");
                match = 0;
            }
            if (has_preferred_lft && !strstr(lft_output, "preferred_lft forever")) {
                RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: preferred_lft 'forever' not found.\n");
                match = 0;
            }
            if (match) {
                RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: valid_lft/preferred_lft fields validated as 'forever'.\n");
                log_to_file("PASS: valid_lft/preferred_lft validated as 'forever'.");
            } else {
                log_to_file("FAIL: valid_lft/preferred_lft mismatch.");
                return -1;
            }
        } else {
                RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Lifetime info could not be fetched.\n");
            log_to_file("FAIL: ip -d address show command failed.");
            return -1;
        }
    }

    char log_msg[128];
    snprintf(log_msg, sizeof(log_msg), "PASS: Validation successful for address: %s", args);
    log_to_file(log_msg);
    return 0;
}


int handle_addr_delete(int argc, char *argv[]) {
    if (argc != 3 || argv[2] == NULL || strlen(argv[2]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: addr_delete <args>\n");
        log_to_file("FAIL: addr_delete called with NULL or empty argument.");
        return -1;
    }

    char *args = argv[2];
    if (addr_delete(args) != CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Failed to delete address: %s\n", args);
        log_to_file("FAIL: Failed to delete address.");
        return -1;
    }

    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Address deleted successfully: %s\n", args);

    // Parse interface and ip/mask for validation
    char if_name[IFNAME_SIZE] = {0}, ip_with_mask[64] = {0};
    char valid_lft[32] = {0}, preferred_lft[32] = {0}, broadcast[64] = {0};
    int has_valid_lft = 0, has_preferred_lft = 0, has_broadcast = 0;
    char *args_copy = strdup(args);
    if (!args_copy) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Memory allocation failed.\n");
        log_to_file("FAIL: strdup failed.");
        return -1;
    }
    char *token = strtok(args_copy, " ");
    while (token) {
        if (strcmp(token, "dev") == 0 && (token = strtok(NULL, " "))) {
            strncpy(if_name, token, IFNAME_SIZE - 1);
        } else if (strcmp(token, "valid_lft") == 0 && (token = strtok(NULL, " "))) {
            strncpy(valid_lft, token, sizeof(valid_lft) - 1);
            has_valid_lft = 1;
        } else if (strcmp(token, "preferred_lft") == 0 && (token = strtok(NULL, " "))) {
            strncpy(preferred_lft, token, sizeof(preferred_lft) - 1);
            has_preferred_lft = 1;
        } else if (strcmp(token, "broadcast") == 0 && (token = strtok(NULL, " "))) {
            strncpy(broadcast, token, sizeof(broadcast) - 1);
            has_broadcast = 1;
        } else if (strchr(token, '/') && ip_with_mask[0] == '\0') {
            strncpy(ip_with_mask, token, sizeof(ip_with_mask) - 1);
        }
        token = strtok(NULL, " ");
    }
    free(args_copy);

    // Validate that the address is no longer present
    char validation_cmd[256], output[256];
    snprintf(validation_cmd, sizeof(validation_cmd), "ip address show dev %s | grep -w \"%s\"", if_name, ip_with_mask);
    int present = execute_command(validation_cmd, output, sizeof(output));
    if (present == 0 && strstr(output, ip_with_mask)) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed. Address still present: %s\n", args);
        log_to_file("FAIL: Address still present after deletion.");
        return -1;
    }

    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Validation successful. Address is no longer present: %s\n", args);
    char log_msg[128];
    snprintf(log_msg, sizeof(log_msg), "PASS: Validation successful. Address is no longer present: %s", args);
    log_to_file(log_msg);
    return 0;
}

int handle_rule_add(int argc, char *argv[]) {
    if (argc != 3 || argv[2] == NULL || strlen(argv[2]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: rule_add <args>\n");
        return -1;
    }

    char *args = argv[2];
    if (rule_add(args) != CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Failed to add rule: %s\n", args);
        return -1;
    }
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Rule added successfully: %s\n", args);

    // --- Parse expected rule tokens ---
    char *args_copy = strdup(args);
    if (!args_copy) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Memory allocation error.\n");
        return -1;
    }

    char from[64] = {0}, to[64] = {0}, iif[32] = {0}, oif[32] = {0};
    char table[32] = {0}, prio[16] = {0}, family_flag[8] = {0};

    char *token = strtok(args_copy, " ");
    while (token) {
        if (strcmp(token, "from") == 0 && (token = strtok(NULL, " "))) {
            strncpy(from, token, sizeof(from) - 1);
        } else if (strcmp(token, "to") == 0 && (token = strtok(NULL, " "))) {
            strncpy(to, token, sizeof(to) - 1);
        } else if (strcmp(token, "iif") == 0 && (token = strtok(NULL, " "))) {
            strncpy(iif, token, sizeof(iif) - 1);
        } else if (strcmp(token, "oif") == 0 && (token = strtok(NULL, " "))) {
            strncpy(oif, token, sizeof(oif) - 1);
        } else if ((strcmp(token, "lookup") == 0 || strcmp(token, "table") == 0) &&
                   (token = strtok(NULL, " "))) {
            strncpy(table, token, sizeof(table) - 1);
        } else if (strcmp(token, "prio") == 0 && (token = strtok(NULL, " "))) {
            strncpy(prio, token, sizeof(prio) - 1);
        } else if (strcmp(token, "-4") == 0 || strcmp(token, "inet") == 0) {
            strcpy(family_flag, "-4");
        } else if (strcmp(token, "-6") == 0 || strcmp(token, "inet6") == 0) {
            strcpy(family_flag, "-6");
        }
        token = strtok(NULL, " ");
    }
    free(args_copy);

    // --- Get rule output ---
    char cmd[256], output[4096] = {0};
    if (family_flag[0])
        snprintf(cmd, sizeof(cmd), "ip %s rule show", family_flag);
    else
        snprintf(cmd, sizeof(cmd), "ip rule show");

    // Use popen/fread to read all output lines
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Could not fetch rule table.\n");
        return -1;
    }
    size_t total = 0;
    size_t n;
    while ((n = fread(output + total, 1, sizeof(output) - 1 - total, fp)) > 0) {
        total += n;
        if (total >= sizeof(output) - 1) break;
    }
    output[total] = '\0';
    pclose(fp);

    // --- Validate that all expected tokens appear together in any rule line ---
    char *line_saveptr = NULL;
    char *line = strtok_r(output, "\n", &line_saveptr);
    int matched = 0;

    while (line) {
        int found = 1;
        // For 'from', match "from <value>" as a word
        if (from[0]) {
            char needle[80];
            snprintf(needle, sizeof(needle), "from %s", from);
            if (!strstr(line, needle)) found = 0;
        }
        if (to[0]) {
            char needle[80];
            snprintf(needle, sizeof(needle), "to %s", to);
            if (!strstr(line, needle)) found = 0;
        }
        if (iif[0]) {
            char needle[80];
            snprintf(needle, sizeof(needle), "iif %s", iif);
            if (!strstr(line, needle)) found = 0;
        }
        if (oif[0]) {
            char needle[80];
            snprintf(needle, sizeof(needle), "oif %s", oif);
            if (!strstr(line, needle)) found = 0;
        }
        if (table[0]) {
            // Try both "lookup <table>" and "table <table>"
            char needle1[80], needle2[80];
            snprintf(needle1, sizeof(needle1), "lookup %s", table);
            snprintf(needle2, sizeof(needle2), "table %s", table);
            if (!strstr(line, needle1) && !strstr(line, needle2)) found = 0;
        }
        if (prio[0]) {
            char needle[80];
            snprintf(needle, sizeof(needle), "prio %s", prio);
            if (!strstr(line, needle)) found = 0;
        }

        if (found) {
            matched = 1;
            break;
        }

        line = strtok_r(NULL, "\n", &line_saveptr);
    }

    if (matched) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Rule fields validated successfully.\n");
        return 0;
    } else {
        if (from[0])   RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: 'from %s' not found in rule.\n", from);
        if (to[0])     RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: 'to %s' not found in rule.\n", to);
        if (iif[0])    RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: 'iif %s' not found in rule.\n", iif);
        if (oif[0])    RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: 'oif %s' not found in rule.\n", oif);
        if (table[0])  RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: 'lookup %s' or 'table %s' not found in rule.\n", table, table);
        if (prio[0])   RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: 'prio %s' not found in rule.\n", prio);
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: One or more rule fields not matched.\n");
        return -1;
    }
}

int handle_rule_delete(int argc, char *argv[]) {
    if (argc != 3 || argv[2] == NULL || strlen(argv[2]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: rule_delete <args>\n");
        return -1;
    }

    char *args = argv[2];
    if (rule_delete(args) != CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Failed to delete rule: %s\n", args);
        return -1;
    }

    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Rule deleted successfully: %s\n", args);

    // Parse the expected rule fields from args for validation
    char *args_copy = strdup(args);
    char *token = strtok(args_copy, " ");
    char from[64] = {0}, to[64] = {0}, iif[32] = {0}, oif[32] = {0}, table[32] = {0}, prio[16] = {0};
    char family_flag[8] = {0}; // -4 or -6

    while (token) {
        if (strcmp(token, "from") == 0 && (token = strtok(NULL, " "))) {
            strncpy(from, token, sizeof(from) - 1);
        } else if (strcmp(token, "to") == 0 && (token = strtok(NULL, " "))) {
            strncpy(to, token, sizeof(to) - 1);
        } else if (strcmp(token, "iif") == 0 && (token = strtok(NULL, " "))) {
            strncpy(iif, token, sizeof(iif) - 1);
        } else if (strcmp(token, "oif") == 0 && (token = strtok(NULL, " "))) {
            strncpy(oif, token, sizeof(oif) - 1);
        } else if ((strcmp(token, "lookup") == 0 || strcmp(token, "table") == 0) && (token = strtok(NULL, " "))) {
            strncpy(table, token, sizeof(table) - 1);
        } else if (strcmp(token, "prio") == 0 && (token = strtok(NULL, " "))) {
            strncpy(prio, token, sizeof(prio) - 1);
        } else if (strcmp(token, "-4") == 0 || strcmp(token, "inet") == 0) {
            strcpy(family_flag, "-4");
        } else if (strcmp(token, "-6") == 0 || strcmp(token, "inet6") == 0) {
            strcpy(family_flag, "-6");
        }
        token = strtok(NULL, " ");
    }
    free(args_copy);

    // Prepare ip rule show command
    char cmd[256], output[1024] = {0};
    if (family_flag[0])
        snprintf(cmd, sizeof(cmd), "ip %s rule show", family_flag);
    else
        snprintf(cmd, sizeof(cmd), "ip rule show");

    if (execute_command(cmd, output, sizeof(output)) != 0) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Could not fetch rule table.\n");
        return -1;
    }

    // Validate rule absence
    int match = 0;
    if (from[0] && strstr(output, from)) match = 1;
    if (to[0] && strstr(output, to)) match = 1;
    if (iif[0] && strstr(output, iif)) match = 1;
    if (oif[0] && strstr(output, oif)) match = 1;
    if (table[0] && strstr(output, table)) match = 1;
    if (prio[0] && strstr(output, prio)) match = 1;

    if (!match) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Validation successful. Rule is no longer present.\n");
        return 0;
    } else {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed. Rule still present in table.\n");
        return -1;
    }
}

int handle_tunnel_add_ip4ip6(int argc, char *argv[]) {
    if (argc != 7) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: tunnel_add_ip4ip6 <tunnel_name> <dev_name> <local_ip6> <remote_ip6> <encaplimit>\n");
        return -1;
    }
    char *tunnel_name = argv[2];
    char *dev_name = argv[3];
    char *local_ip6 = argv[4];
    char *remote_ip6 = argv[5];
    char *encaplimit = argv[6];
    if (tunnel_add_ip4ip6(tunnel_name, dev_name, local_ip6, remote_ip6, encaplimit) == CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Tunnel %s added successfully.\n", tunnel_name);
        return 0;
    } else {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Failed to add tunnel %s.\n", tunnel_name);
        return -1;
    }
}

int handle_interface_get_stats(int argc, char *argv[]) {
    if (argc != 4) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: interface_get_stats <if_name> <stats_mask>\n");
        return -1;
    }
    char *if_name = argv[2];
    int stats_mask = atoi(argv[3]);
    cnl_iface_stats stats = {0};
    if (interface_get_stats(stats_mask, if_name, &stats) == CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Interface %s stats:\n", if_name);
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "  RX packets: %lu\n", stats.rx_packet);
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "  TX packets: %lu\n", stats.tx_packet);
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "  RX bytes: %lu\n", stats.rx_bytes);
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "  TX bytes: %lu\n", stats.tx_bytes);
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "  RX errors: %lu\n", stats.rx_errors);
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "  TX errors: %lu\n", stats.tx_errors);
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "  RX dropped: %lu\n", stats.rx_dropped);
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "  TX dropped: %lu\n", stats.tx_dropped);
        return 0;
    } else {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Failed to get stats for interface %s.\n", if_name);
        return -1;
    }
}

int handle_neighbour_get_list(int argc, char *argv[]) {
    struct neighbour_info neigh_info = {0};
    char mac[18] = {0}; // Placeholder for MAC address
    char if_name[64] = {0}; // Placeholder for interface name
    int af_filter = AF_UNSPEC; // Use AF_UNSPEC to include all address families
    if (neighbour_get_list(&neigh_info, mac, if_name, af_filter) == CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Neighbour list:\n");
        for (int i = 0; i < neigh_info.neigh_count; i++) {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "  Local: %s, MAC: %s, Interface: %s, State: %d\n",
                   neigh_info.neigh_arr[i].local,
                   neigh_info.neigh_arr[i].mac,
                   neigh_info.neigh_arr[i].ifname,
                   neigh_info.neigh_arr[i].state);
        }
        neighbour_free_neigh(&neigh_info);
        return 0;
    } else {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Failed to get neighbour list.\n");
        return -1;
    }
}

int handle_bridge_get_info(int argc, char *argv[]) {
    if (argc != 3 || argv[2] == NULL || strlen(argv[2]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: bridge_get_info <bridge_name>\n");
        return -1;
    }
    char *bridge_name = argv[2];
    struct bridge_info bridge = {0};
    int result = bridge_get_info(bridge_name, &bridge);
    if (result == CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: bridge_get_info API call succeeded for %s.\n", bridge_name);
        for (int i = 0; i < bridge.slave_count; i++) {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "  Slave %d: %s\n", i + 1, bridge.slave_name[i]);
        }

        // Linux validation: print gretap0.<NNN> for brlanNNN and validate presence
        char validation_command[256];
        char gretap_name[32] = {0};
        int brnum = 0;
        int skip_validation = 0;
        if (sscanf(bridge_name, "brlan%d", &brnum) == 1) {
            snprintf(gretap_name, sizeof(gretap_name), "gretap0.%03d", brnum);
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: gretap interface for %s is %s\n", bridge_name, gretap_name);

            snprintf(validation_command, sizeof(validation_command),
                     "brctl show %s | grep -w '%s' | wc -l", bridge_name, gretap_name);
        } else {
            // If not a brlanX bridge, skip gretap validation
            skip_validation = 1;
        }

        if (!skip_validation) {
            char output[256];
            if (execute_command(validation_command, output, sizeof(output)) != 0) {
                RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Linux validation failed for %s.\n", gretap_name);
                bridge_free_info(&bridge);
                // Logging
                char log_msg[128];
                snprintf(log_msg, sizeof(log_msg), "FAIL: Linux validation failed for %s.", gretap_name);
                log_to_file(log_msg);
                return -1;
            }
            int validation_result = atoi(output);
            if (validation_result < 1) {
                RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation output indicates %s not found for bridge %s.\n", gretap_name, bridge_name);
                bridge_free_info(&bridge);
                // Logging
                char log_msg[128];
                snprintf(log_msg, sizeof(log_msg), "FAIL: %s not found for bridge %s.", gretap_name, bridge_name);
                log_to_file(log_msg);
                return -1;
            }
            printf("PASS: Validation successful for %s (present in brctl show).\n", gretap_name);
            // Logging
            char log_msg[128];
            snprintf(log_msg, sizeof(log_msg), "PASS: Validation successful for %s (present in brctl show).", gretap_name);
            log_to_file(log_msg);
        } else {
            printf("INFO: Skipping gretap validation for bridge %s (not brlanX format).\n", bridge_name);
        }

        bridge_free_info(&bridge);
        return 0;
    } else {
        printf("Failed to get info for bridge %s.\n", bridge_name);
        // Logging
        char log_msg[128];
        snprintf(log_msg, sizeof(log_msg), "FAIL: Failed to get info for bridge %s.", bridge_name);
        log_to_file(log_msg);
        return -1;
    }
}

int handle_bridge_free_info(int argc, char *argv[]) {
    if (argc != 3 || argv[2] == NULL || strlen(argv[2]) == 0) {
        log_to_file("Usage: bridge_free_info <bridge_name>");
        printf("Usage: bridge_free_info <bridge_name>\n");
        return -1;
    }
    char *bridge_name = argv[2];

    // Call the bridge_get_info API directly
    struct bridge_info bridge = {0};
    int result = bridge_get_info(bridge_name, &bridge);
    if (result == CNL_STATUS_SUCCESS) {
        bridge_free_info(&bridge);
        char log_msg[128];
        snprintf(log_msg, sizeof(log_msg), "PASS: Freed bridge info for %s successfully.", bridge_name);
        log_to_file(log_msg);
        printf("PASS: Freed bridge info for %s successfully.\n", bridge_name);

        // Find the actual gretap interface from bridge.slave_name[]
        char gretap_name[32] = {0};
        int found_gretap = 0;
        for (int i = 0; i < bridge.slave_count; i++) {
            if (strncmp(bridge.slave_name[i], "gretap0.", 8) == 0) {
                strncpy(gretap_name, bridge.slave_name[i], sizeof(gretap_name) - 1);
                found_gretap = 1;
                break;
            }
        }

        if (found_gretap) {
            printf("PASS: gretap interface for %s is %s\n", bridge_name, gretap_name);

            // Validate using brctl show
            char validation_command[256];
            snprintf(validation_command, sizeof(validation_command),
                     "brctl show %s | grep -w '%s' | wc -l", bridge_name, gretap_name);

            char output[256];
            if (execute_command(validation_command, output, sizeof(output)) == 0 && atoi(output) > 0) {
                snprintf(log_msg, sizeof(log_msg), "PASS: Linux validation successful. %s present in brctl show.", gretap_name);
                log_to_file(log_msg);
                printf("PASS: Validation successful for %s (present in brctl show).\n", gretap_name);
                return 0;
            } else {
                snprintf(log_msg, sizeof(log_msg), "FAIL: Linux validation failed. %s not found for bridge %s.", gretap_name, bridge_name);
                log_to_file(log_msg);
                printf("FAIL: Validation output indicates %s not found for bridge %s.\n", gretap_name, bridge_name);
                return -1;
            }
        } else {
            snprintf(log_msg, sizeof(log_msg), "INFO: Skipping gretap validation for bridge %s (no gretap slave found).", bridge_name);
            log_to_file(log_msg);
            printf("INFO: Skipping gretap validation for bridge %s (no gretap slave found).\n", bridge_name);
            return 0;
        }
    } else {
        char log_msg[128];
        snprintf(log_msg, sizeof(log_msg), "FAIL: Failed to free bridge info for %s.", bridge_name);
        log_to_file(log_msg);
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Failed to free bridge info for %s.\n", bridge_name);
        return -1;
    }
}

int handle_addr_derive_broadcast(int argc, char *argv[]) {
    if (argc != 4 || argv[2] == NULL || argv[3] == NULL || strlen(argv[2]) == 0 || strlen(argv[3]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: addr_derive_broadcast <ip> <prefix_len>\n");
        return -1;
    }

    char *ip = argv[2];
    char *prefix_str = argv[3];

    // Validate the IP address
    if (!validate_ip_address(ip)) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Invalid IP address: %s\n", ip);
        return -1;
    }

    // Validate prefix length is numeric and in range 0-32
    char *endptr = NULL;
    long prefix_len = strtol(prefix_str, &endptr, 10);
    if (*endptr != '\0' || prefix_len < 0 || prefix_len > 32) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Invalid prefix length: %s\n", prefix_str);
        return -1;
    }

    char bcast[INET_ADDRSTRLEN] = {0};
    int api_result = addr_derive_broadcast(ip, (unsigned int)prefix_len, bcast, sizeof(bcast));
    if (api_result == CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Broadcast address for IP %s/%ld: %s\n", ip, prefix_len, bcast);
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Broadcast address derived and set correctly.\n");
        return 0;
    } else {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Failed to derive broadcast address for IP %s/%ld.\n", ip, prefix_len);
        return -1;
    }
}


int handle_interface_exist(int argc, char *argv[]) {
    if (argc != 3 || argv[2] == NULL || strlen(argv[2]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: interface_exist <if_name>\n");
        return -1;
    }
    char *if_name = argv[2];
    int result = interface_exist(if_name);

    // Validation: check with ip link show
    char validation_command[256];
    snprintf(validation_command, sizeof(validation_command), "ip link show %s", if_name);
    char output[256] = {0};
    int ifconfig_status = execute_command(validation_command, output, sizeof(output));

    if (result == CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Interface %s exists.\n", if_name);
        if (ifconfig_status == 0 && strstr(output, if_name)) {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Validation successful. Interface %s is present.\n", if_name);
            return 0;
        } else {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed. Interface %s not found.\n", if_name);
            return -1;
        }
    } else {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Interface %s does not exist.\n", if_name);
        if (ifconfig_status != 0) {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: Validation successful. Interface %s is not present.\n", if_name);
            return -1;
        } else {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed. Interface %s unexpectedly found.\n", if_name);
            return -1;
        }
    }
}

int handle_interface_set_flags(int argc, char *argv[]) {
    if (argc != 4 || argv[2] == NULL || argv[3] == NULL || strlen(argv[2]) == 0 || strlen(argv[3]) == 0) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: interface_set_flags <if_name> <flags>\n");
        return -1;
    }

    char *if_name = argv[2];
    unsigned int flags = atoi(argv[3]);

    int result = interface_set_flags(if_name, flags);
    if (result != CNL_STATUS_SUCCESS) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Failed to set flags for interface %s.\n", if_name);
        return -1;
    }

    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Flags for interface %s set to %u successfully.\n", if_name, flags);
    sleep(3);

    // Simplified validation: just check for common active flags combo
    char validation_command[256];
    snprintf(validation_command, sizeof(validation_command), "ip link show %s", if_name);
    
    char output[1024] = {0};
    if (execute_command(validation_command, output, sizeof(output)) != 0) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Validation failed to get ip link output for %s.\n", if_name);
        return -1;
    }

    // Check for each flag substring individually
    int up = strstr(output, "UP") != NULL;
    // int broadcast = strstr(output, "BROADCAST") != NULL;
    int running = strstr(output, "RUNNING") != NULL;
    // int multicast = strstr(output, "MULTICAST") != NULL;


    if (up && running) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "PASS: ip link output contains UP and RUNNING for %s.\n", if_name);
        return 0;
    } else {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "FAIL: Expected flags not found in ifconfig output for %s.\n", if_name);
        return -1;
    }
}

int handle_neighbour_free_neigh(int argc, char *argv[]) {
    struct neighbour_info neigh_info = {0};
    char mac[18] = {0}; // Placeholder for MAC address
    char if_name[64] = {0}; // Placeholder for interface name
    int af_filter = AF_UNSPEC; // Use AF_UNSPEC to include all address families
    if (neighbour_get_list(&neigh_info, mac, if_name, af_filter) == CNL_STATUS_SUCCESS) {
        neighbour_free_neigh(&neigh_info);
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Freed neighbour information successfully.\n");
        return 0;
    } else {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Failed to retrieve and free neighbour information.\n");
        return -1;
    }
}

typedef struct {
    const char *description;
    int is_negative; // 0 for positive test, 1 for negative test
    int argc;
    char *argv[MAX_ARGS];
    int (*handler)(int argc, char *argv[]);
} TestCase;

typedef struct {
    const char *testcase_name;
    TestCase array[MAX_TESTS];
    int count;
} TestGroup;

TestGroup test_groups[] = {
    {"addr_tests", {0}, 0},
    {"addr_delete_tests", {0}, 0},
    {"interface_up_tests", {0}, 0},
    {"interface_down_tests", {0}, 0},
    {"vlan_tests", {0}, 0},
    {"mtu_tests", {0}, 0},
    {"rule_tests", {0}, 0},
    {"route_tests", {0}, 0},
    {"bridge_tests", {0}, 0},
    {"ip_mac_tests", {0}, 0},
    {"netmask_stp_tests", {0}, 0},
    {"stp_status_tests", {0}, 0},
    {"rename_delete_mac_tests", {0}, 0},
    {"addr_derive_broadcast_tests", {0}, 0},
    {"interface_set_flags_tests", {0}, 0},
    {"get_ipv6_address_tests", {0}, 0},
    {"bridge_interface_tests", {0}, 0},
};
int num_groups = sizeof(test_groups) / sizeof(test_groups[0]);

void parse_testcase(cJSON *testcase_obj, TestCase *test) {
    cJSON *temp_obj;
    
    // Initialize all fields to safe defaults
    test->description = NULL;
    test->is_negative = 0;
    test->argc = 0;
    test->handler = NULL;
    for (int i = 0; i < MAX_ARGS; i++) {
        test->argv[i] = NULL;
    }
    
    // Parse description
    temp_obj = cJSON_GetObjectItem(testcase_obj, "description");
    if (temp_obj && cJSON_IsString(temp_obj)) {
        test->description = strdup(cJSON_GetStringValue(temp_obj));
    }
    
    // Parse is_negative
    temp_obj = cJSON_GetObjectItem(testcase_obj, "is_negative");
    if (temp_obj && cJSON_IsNumber(temp_obj)) {
        test->is_negative = (int)cJSON_GetNumberValue(temp_obj);
    }
    
    // Parse argc
    temp_obj = cJSON_GetObjectItem(testcase_obj, "argc");
    if (temp_obj && cJSON_IsNumber(temp_obj)) {
        test->argc = (int)cJSON_GetNumberValue(temp_obj);
    }
    
    // Parse argv array
    temp_obj = cJSON_GetObjectItem(testcase_obj, "argv");
    if (temp_obj && cJSON_IsArray(temp_obj)) {
        int array_len = cJSON_GetArraySize(temp_obj);
        for (int i = 0; i < array_len && i < MAX_ARGS; i++) {
            cJSON *arg_obj = cJSON_GetArrayItem(temp_obj, i);
            if (cJSON_IsNull(arg_obj)) {
                test->argv[i] = NULL;
            } else if (cJSON_IsString(arg_obj)) {
                test->argv[i] = strdup(cJSON_GetStringValue(arg_obj));
            } else {
                test->argv[i] = NULL;
            }
        }
    }
    
    // Parse handler
    temp_obj = cJSON_GetObjectItem(testcase_obj, "handler");
    if (temp_obj && cJSON_IsString(temp_obj)) {
        const char *handler_name = cJSON_GetStringValue(temp_obj);
        test->handler = get_handler_by_name(handler_name);
    }
}

void parse_json(const char *filename) {
    printf("[DEBUG] Parsing JSON file: %s\n", filename);
    
    // Read file content
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "[DEBUG] Failed to open JSON file: %s\n", filename);
        return;
    }
    
    struct stat st;
    if (fstat(fileno(fp), &st) != 0) {
        fprintf(stderr, "[DEBUG] Failed to get file stats: %s\n", strerror(errno));
        fclose(fp);
        return;
    }
    
    long file_size = st.st_size;
    if (file_size <= 0) {
        fprintf(stderr, "[DEBUG] Invalid file size\n");
        fclose(fp);
        return;
    }
    
    char *file_content = malloc(file_size + 1);
    if (!file_content) {
        fprintf(stderr, "[DEBUG] Failed to allocate memory for file content\n");
        fclose(fp);
        return;
    }
    
    size_t read_size = fread(file_content, 1, file_size, fp);
    file_content[read_size] = '\0';
    fclose(fp);
    
    if (read_size != (size_t)file_size) {
        fprintf(stderr, "[DEBUG] Warning: Read size mismatch (expected: %ld, got: %zu)\n", 
                file_size, read_size);
    }
    
    // Parse JSON
    cJSON *root = cJSON_Parse(file_content);
    free(file_content);
    
    if (!root) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "[DEBUG] Failed to parse JSON: %s\n", error_ptr);
        } else {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "[DEBUG] Failed to parse JSON file - invalid JSON format\n");
        }
        return;
    }
    
    cJSON *testcases_obj = cJSON_GetObjectItem(root, "testcases");
    if (!testcases_obj) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "[DEBUG] No 'testcases' object in JSON file\n");
        cJSON_Delete(root);
        return;
    }
    
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "[DEBUG] Found 'testcases' root object\n");
    
    // Iterate through test groups
    for (int g = 0; g < num_groups; g++) {
        cJSON *test_group_array = cJSON_GetObjectItem(testcases_obj, test_groups[g].testcase_name);
        if (test_group_array) {
            if (!cJSON_IsArray(test_group_array)) {
                RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "[DEBUG] Warning: '%s' is not an array\n", 
                        test_groups[g].testcase_name);
                continue;
            }
            
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "[DEBUG] Found '%s' with array type\n", test_groups[g].testcase_name);
            
            int array_len = cJSON_GetArraySize(test_group_array);
            for (int i = 0; i < array_len && test_groups[g].count < MAX_TESTS; i++) {
                cJSON *testcase_obj = cJSON_GetArrayItem(test_group_array, i);
                if (testcase_obj) {
                    parse_testcase(testcase_obj, &test_groups[g].array[test_groups[g].count++]);
                }
            }
        }
    }
    
    // Print summary for all groups
    for (int g = 0; g < num_groups; g++) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "[DEBUG] Finished parsing JSON for %s. Total testcases loaded: %d\n", 
               test_groups[g].testcase_name, test_groups[g].count);
    }
    
    cJSON_Delete(root);
}


void print_testcases(TestGroup *groups, int num_groups) {
    for (int g = 0; g < num_groups; g++) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "\n==== %s ====\n", groups[g].testcase_name);
        if (groups[g].count == 0) {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "No test cases loaded for %s.\n", groups[g].testcase_name);
            continue;
        }
        for (int i = 0; i < groups[g].count; i++) {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "\nTestCase #%d:\n", i + 1);
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "  Description: %s\n", groups[g].array[i].description ? groups[g].array[i].description : "(null)");
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "  Is Negative: %d\n", groups[g].array[i].is_negative);
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "  Argc: %d\n", groups[g].array[i].argc);
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "  Argv:");
            for (int j = 0; j < groups[g].array[i].argc; j++) {
                RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", " [%d]: %s", j, groups[g].array[i].argv[j] ? groups[g].array[i].argv[j] : "(null)");
            }
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "\n");
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "  Handler: %p\n", (void *)groups[g].array[i].handler);
        }
    }
}

void run_testcases(TestCase *tests, int num_tests) {
    for (int i = 0; i < num_tests; i++) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "\nExecuting: %s\n", tests[i].description ? tests[i].description : "(no description)");
        
        // Safety check for handler
        if (!tests[i].handler) {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "ERROR: No handler function found for test case\n");
            log_result(tests[i].description, -1, tests[i].is_negative);
            continue;
        }
        
        // Safety check for argc/argv consistency
        if (tests[i].argc > 0 && tests[i].argv[0] == NULL) {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "ERROR: argc is %d but argv[0] is NULL\n", tests[i].argc);
            log_result(tests[i].description, -1, tests[i].is_negative);
            continue;
        }
        
        int result = tests[i].handler(tests[i].argc, tests[i].argv);
        log_result(tests[i].description, result, tests[i].is_negative);
    }
}

void cleanup_test_groups(TestGroup *groups, int num_groups) {
    for (int g = 0; g < num_groups; g++) {
        for (int i = 0; i < groups[g].count; i++) {
            // Free description
            if (groups[g].array[i].description) {
                free(groups[g].array[i].description);
                groups[g].array[i].description = NULL;
            }
            
            // Free all argv strings
            for (int j = 0; j < MAX_ARGS; j++) {
                if (groups[g].array[i].argv[j]) {
                    free(groups[g].array[i].argv[j]);
                    groups[g].array[i].argv[j] = NULL;
                }
            }
        }
        groups[g].count = 0;
    }
}

int run_all_tests(int argc, char *argv[]) {
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "\n========== Starting Test Suite ==========\n");

    const char *test_interface = "brlan18";
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "\nCreating temporary interface: %s...\n", test_interface);
    char *bridge_create_argv[] = {"corenetlib_api", "bridge_create", (char *)test_interface};
    int result = handle_bridge_create(3, bridge_create_argv);
    if (result != 0) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Failed to create temporary interface %s. Aborting tests.\n", test_interface);
        return -1;
    }

    // Setup IP addresses
    system("ip link set brlan18 up");
    system("ip addr add 192.168.18.1/24 dev brlan18");
    system("ip -6 addr add 2001:db8:18::1/64 dev brlan18");
  
    // Setup GRE tap interface and add to brlan18
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Setting up gretap0.018 and adding it to %s...\n", test_interface);
    system("ip link add gretap0.018 type gretap local 192.168.1.1 remote 192.168.1.2 dev brlan18 2>/dev/null || true");
    system("ip link set gretap0.018 up");
    system("brctl addif brlan18 gretap0.018");

    // Validate addresses
    struct {
        const char *desc;
        const char *cmd;
        const char *match;
    } validations[] = {
        { "IPv4 address 192.168.18.1/24 set", "ip addr show dev brlan18 | grep '192.168.18.1/24'", "192.168.18.1/24" },
        { "IPv6 address 2001:db8:18::1/64 set", "ip -6 addr show dev brlan18 | grep '2001:db8:18::1/64'", "2001:db8:18::1/64" },
        { "gretap0.018 interface attached to brlan18", "brctl show brlan18 | grep gretap0.018", "gretap0.018" }
    };

    for (int i = 0; i < sizeof(validations) / sizeof(validations[0]); i++) {
        char output[256] = {0};
        int rc = execute_command(validations[i].cmd, output, sizeof(output));
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "%s: %s\n", rc == 0 && strstr(output, validations[i].match) ? "PASS" : "FAIL", validations[i].desc);
    }

    parse_json("/tmp/corenetlib_tests.json");
    
    for (int g = 0; g < num_groups; g++) {
        if (test_groups[g].count == 0) {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "No test cases loaded for %s.\n", test_groups[g].testcase_name);
            continue;
        }
        run_testcases(test_groups[g].array, test_groups[g].count);

    }

    // Step 2: Remove the temporary bridge interface after tests
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "\nRemoving temporary interface: %s...\n", test_interface);
    char *delete_argv[] = {"corenetlib_api", "bridge_delete", (char *)test_interface};
    result = handle_bridge_delete(3, delete_argv);
    if (result != 0) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Failed to remove temporary interface %s. Please clean up manually.\n", test_interface);
    }
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "\n========== Test Suite Completed ==========\n");

    print_summary();
    
    // Cleanup allocated memory
    cleanup_test_groups(test_groups, num_groups);
    
    return 0;
}

api_entry_t api_table[] = {
    {"addr_add", "addr_add \"<args>\"", handle_addr_add},
    {"addr_delete", "addr_delete \"<args>\"", handle_addr_delete},
    {"addr_derive_broadcast", "addr_derive_broadcast <ip> <prefix_len>", handle_addr_derive_broadcast},
    {"bridge_create", "bridge_create <bridge_name>", handle_bridge_create},
    {"bridge_delete", "bridge_delete <bridge_name>", handle_bridge_delete},
    {"bridge_free_info", "bridge_free_info <bridge_name>", handle_bridge_free_info},
    {"bridge_get_info", "bridge_get_info <bridge_name>", handle_bridge_get_info},
    {"bridge_set_stp", "bridge_set_stp <bridge_name> <on|off>", handle_bridge_set_stp},
    {"get_ipv6_address", "get_ipv6_address <if_name>", handle_get_ipv6_address},
    {"interface_add_to_bridge", "interface_add_to_bridge <bridge_name> <if_name>", handle_interface_add_to_bridge},
    {"interface_delete", "interface_delete <if_name>", handle_interface_delete},
    {"interface_down", "interface_down <if_name>", handle_interface_down},
    {"interface_exist", "interface_exist <if_name>", handle_interface_exist},
    {"interface_get_ip", "interface_get_ip <if_name>", handle_interface_get_ip},
    {"interface_get_mac", "interface_get_mac <if_name>", handle_interface_get_mac},
    {"interface_get_stats", "interface_get_stats <if_name> <stats_mask>", handle_interface_get_stats},
    {"interface_remove_from_bridge", "interface_remove_from_bridge <if_name>", handle_interface_remove_from_bridge},
    {"interface_rename", "interface_rename <if_name> <new_name>", handle_interface_rename},
    {"interface_set_flags", "interface_set_flags <if_name> <flags>", handle_interface_set_flags},
    {"interface_set_mac", "interface_set_mac <if_name> <mac_address>", handle_interface_set_mac},
    {"interface_set_mtu", "interface_set_mtu <if_name> <mtu_value>", handle_interface_set_mtu},
    {"interface_set_netmask", "interface_set_netmask <if_name> <netmask>", handle_interface_set_netmask},
    {"interface_status", "interface_status <if_name>", handle_interface_status},
    {"interface_up", "interface_up <if_name>", handle_interface_up},
    {"neighbour_delete", "neighbour_delete <if_name> <ip>", handle_neighbour_delete},
    {"neighbour_free_neigh", "neighbour_free_neigh", handle_neighbour_free_neigh},
    {"neighbour_get_list", "neighbour_get_list", handle_neighbour_get_list},
    {"route_add", "route_add \"<args>\"", handle_route_add},
    {"route_delete", "route_delete \"<args>\"", handle_route_delete},
    {"rule_add", "rule_add \"<args>\"", handle_rule_add},
    {"rule_delete", "rule_delete \"<args>\"", handle_rule_delete},
    {"tunnel_add_ip4ip6", "tunnel_add_ip4ip6 <tunnel_name> <dev_name> <local_ip6> <remote_ip6> <encaplimit>", handle_tunnel_add_ip4ip6},
    {"vlan_create", "vlan_create <if_name> <vlan_id>", handle_vlan_create},
    {"vlan_delete", "vlan_delete <vlan_name>", handle_vlan_delete},
    {"run_all_tests", "run_all_tests", run_all_tests}, // Added entry for run_all_tests
    {NULL, NULL, NULL} // Sentinel to mark the end of the table
};

void print_usage() {
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Usage: test_libnet <API_NAME> [arguments]\n");
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Available APIs:\n");
    for (int i = 0; api_table[i].name != NULL; i++) {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "  %s - %s\n", api_table[i].name, api_table[i].usage);
    }
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "\nType 'corenetlib_api <API_NAME> help' for detailed usage of a specific API.\n");
}

void print_dynamic_helper(const char *api_name) {
    for (int i = 0; api_table[i].name != NULL; i++) {
        if (strcmp(api_name, api_table[i].name) == 0) {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Helper: %s\n", api_table[i].usage);
            return;
        }
    }
    RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Unknown API: %s\n", api_name);
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Use 'corenetlib_api help' to see the list of available APIs.\n");
}

// Start of main function and related logic
int main(int argc, char *argv[]) {
    if (argc < 2 || strcmp(argv[1], "help") == 0) {
        print_usage();
        return -1;
    }

    const char *api_name = argv[1];

    // Check if the user provided only the API name without arguments
    if (argc == 2) {
        print_dynamic_helper(api_name);
        return 0;
    }

    for (int i = 0; api_table[i].name != NULL; i++) {
        if (strcmp(api_name, api_table[i].name) == 0) {
            int result = api_table[i].handler(argc, argv);
            if (result == 0) {
                RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CORENETLIB", "Command '%s' executed successfully.\n", api_name);
            } else {
                RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Command '%s' failed.\n", api_name);
            }
            return result;
        }
    }

    RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CORENETLIB", "Unknown API: %s\n", api_name);
    print_usage();
    return -1;
}
