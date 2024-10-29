#include <ndn-lite.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MAX_CHUNK_SIZE 1024
#define PREFIX_BUFFER_SIZE 100

typedef struct {
    FILE* file;
    char file_path[256];
    uint32_t next_chunk;
    uint32_t total_chunks;
    uint32_t received_chunks;
    bool transfer_complete;
} file_client_state_t;

static file_client_state_t client_state;
static ndn_name_t prefix;
static uint8_t prefix_buf[PREFIX_BUFFER_SIZE];

static void
on_data(const ndn_data_t* data)
{
    // Write received data chunk to file
    fwrite(data->content_value, 1, data->content_size, client_state.file);
    client_state.received_chunks++;
    
    // Check if transfer is complete
    if (client_state.received_chunks >= client_state.total_chunks) {
        client_state.transfer_complete = true;
        printf("File transfer complete!\n");
        fclose(client_state.file);
        return;
    }
    
    // Request next chunk
    ndn_interest_t interest;
    ndn_interest_init(&interest);
    
    // Add chunk number to name
    ndn_name_append_bytes_component(&interest.name, 
                                  (uint8_t*)&client_state.next_chunk,
                                  sizeof(uint32_t));
    
    // Send interest
    uint8_t interest_buf[1024];
    size_t interest_size = ndn_interest_tlv_encode(&interest, interest_buf);
    ndn_forwarder_express_interest(interest_buf, interest_size, on_data, NULL);
    
    client_state.next_chunk++;
}

int main(int argc, char *argv[])
{
    if (argc != 4) {
        printf("Usage: %s <prefix> <file_size> <output_path>\n", argv[0]);
        return -1;
    }
    
    // Initialize NDN-Lite
    ndn_lite_startup();
    
    // Initialize client state
    client_state.file = fopen(argv[3], "wb");
    if (!client_state.file) {
        printf("Cannot create output file %s\n", argv[3]);
        return -1;
    }
    
    strcpy(client_state.file_path, argv[3]);
    client_state.next_chunk = 0;
    client_state.received_chunks = 0;
    client_state.transfer_complete = false;
    
    size_t file_size = atoi(argv[2]);
    client_state.total_chunks = (file_size + MAX_CHUNK_SIZE - 1) / MAX_CHUNK_SIZE;
    
    // Set prefix
    ndn_name_from_string(&prefix, argv[1], strlen(argv[1]));
    
    // Send first interest
    ndn_interest_t interest;
    ndn_interest_init(&interest);
    memcpy(&interest.name, &prefix, sizeof(ndn_name_t));
    
    // Add chunk number to name
    ndn_name_append_bytes_component(&interest.name,
                                  (uint8_t*)&client_state.next_chunk,
                                  sizeof(uint32_t));
    
    // Send interest
    uint8_t interest_buf[1024];
    size_t interest_size = ndn_interest_tlv_encode(&interest, interest_buf, 1024);
    ndn_forwarder_express_interest(interest_buf, interest_size, on_data, NULL);
    
    client_state.next_chunk++;
    
    printf("Starting file transfer...\n");
    
    while (!client_state.transfer_complete) {
        usleep(10000);
    }
    
    return 0;
}