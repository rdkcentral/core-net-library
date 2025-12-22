#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include "libnet.h"

// Structure to pass arguments to threads
typedef struct {
    char addr_args[256]; // Address arguments
    int thread_id;       // Thread ID for logging
} ThreadData;

// Thread function to delete an address
void* delete_addr_thread(void* arg) {
    ThreadData* data = (ThreadData*)arg;
    printf("Thread %d: Deleting address with args: %s\n", data->thread_id, data->addr_args);

    // Call addr_delete with the provided arguments
    libnet_status status = addr_delete(data->addr_args);
    if (status == CNL_STATUS_SUCCESS) {
        printf("Thread %d: Address deleted successfully.\n", data->thread_id);
    } else {
        printf("Thread %d: Failed to delete address.\n", data->thread_id);
    }

    return NULL;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <num_threads> <addr_args>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int num_threads = atoi(argv[1]);
    char* addr_args = argv[2];

    if (num_threads <= 0) {
        fprintf(stderr, "Invalid number of threads.\n");
        return EXIT_FAILURE;
    }

    // Allocate memory for thread data and thread handles
    pthread_t* threads = malloc(num_threads * sizeof(pthread_t));
    ThreadData* thread_data = malloc(num_threads * sizeof(ThreadData));
    if (!threads || !thread_data) {
        perror("Memory allocation failed");
        return EXIT_FAILURE;
    }

    // Create threads
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].thread_id = i + 1;
        strncpy(thread_data[i].addr_args, addr_args, sizeof(thread_data[i].addr_args) - 1);
        thread_data[i].addr_args[sizeof(thread_data[i].addr_args) - 1] = '\0';

        if (pthread_create(&threads[i], NULL, delete_addr_thread, &thread_data[i]) != 0) {
            perror("Failed to create thread");
            free(threads);
            free(thread_data);
            return EXIT_FAILURE;
        }
    }

    // Wait for all threads to finish
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    // Clean up
    free(threads);
    free(thread_data);

    printf("All threads completed.\n");
    return EXIT_SUCCESS;
}