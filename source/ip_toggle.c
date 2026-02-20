/*
 * Simple IP Address Toggle
 * Usage: ./ip_toggle <interface> <ip_address> [interval]
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "libnet.h"

int main(int argc, char **argv)
{
    char addr_args[256];
    int interval = 3;
    int cycle = 0;
    
    if (argc < 3) {
        printf("Usage: %s <interface> <ip_address> [interval_seconds]\n", argv[0]);
        printf("Example: %s eth0 192.168.1.100/24 2\n", argv[0]);
        return 1;
    }
    
    if (argc >= 4) {
        interval = atoi(argv[3]);
        if (interval <= 0) interval = 3;
    }
    
    printf("Toggling IP %s on interface %s every %d seconds\n", 
           argv[2], argv[1], interval);
    printf("Press Ctrl+C to stop\n\n");
    
    while (1) {
        // Add IP
        snprintf(addr_args, sizeof(addr_args), "dev %s %s", argv[1], argv[2]);
        printf("Cycle %d: Adding IP %s... ", ++cycle, argv[2]);
        
        if (addr_add(addr_args) == CNL_STATUS_SUCCESS) {
            printf("OK\n");
        } else {
            printf("FAILED\n");
        }
        
        sleep(interval);
        
        // Delete IP
        printf("Cycle %d: Removing IP %s... ", cycle, argv[2]);
        
        if (addr_delete(addr_args) == CNL_STATUS_SUCCESS) {
            printf("OK\n");
        } else {
            printf("FAILED\n");
        }
        
        sleep(interval);
    }
    
    return 0;
}
