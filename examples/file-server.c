#include <ndn-lite.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MAX_CHUNK_SIZE 1024
#define PREFIX_BUFFER_SIZE 100

typedef struct {
    FILE* file;
    char file_path[256];
    size_t file_size;
    uint32_t chunk_size;
} file_server_state_t;

static file_server_state_t server_state;
static ndn_name_t prefix;
static uint8_t prefix_buf[PREFIX_BUFFER_SIZE];

static int
on_interest(const ndn_interest_t* interest, const ndn_name_t* interest_name)
{
    ndn_data_t data;
    uint8_t content_buf[MAX_CHUNK_SIZE];
    
    // Parse chunk number from interest name
    uint32_t chunk_no;
    ndn_name_component_t* comp = &interest_name->components[interest_name->components_size - 1];
    memcpy(&chunk_no, comp->value, sizeof(uint32_t));
    
    // Calculate offset and read file
    size_t offset = chunk_no * server_state.chunk_size;
    if (offset >= server_state.file_size) {
        return -1;
    }
    
    fseek(server_state.file, offset, SEEK_SET);
    size_t read_size = fread(content_buf, 1, server_state.chunk_size, server_state.file);
    
    // Prepare data packet
    ndn_data_init(&data);
    memcpy(&data.name, interest_name, sizeof(ndn_name_t));
    data.content = content_buf;
    data.content_size = read_size;
    
    // Sign and send data
    uint8_t data_buf[1024];
    size_t data_size = ndn_data_tlv_encode(&data, data_buf, 1024);
    ndn_forwarder_put_data(data_buf, data_size);
    
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        printf("Usage: %s <prefix> <file_path>\n", argv[0]);
        return -1;
    }
    
    // Initialize NDN-Lite
    ndn_lite_startup();
    
    // Initialize server state
    strcpy(server_state.file_path, argv[2]);
    server_state.file = fopen(argv[2], "rb");
    if (!server_state.file) {
        printf("Cannot open file %s\n", argv[2]);
        return -1;
    }
    
    // Get file size
    fseek(server_state.file, 0, SEEK_END);
    server_state.file_size = ftell(server_state.file);
    fseek(server_state.file, 0, SEEK_SET);
    server_state.chunk_size = MAX_CHUNK_SIZE;
    
    // Set prefix
    ndn_name_from_string(&prefix, argv[1], strlen(argv[1]));
    
    // Register prefix
    ndn_forwarder_register_prefix(&prefix, on_interest);
    
    printf("File server started. Serving %s under prefix %s\n", argv[2], argv[1]);
    printf("File size: %zu bytes\n", server_state.file_size);
    
    while(1) {
        usleep(10000);
    }
    
    return 0;
}