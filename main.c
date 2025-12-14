#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <openssl/sha.h>

#define BUFFER_SIZE 1024

const char BAD_SIGNATURE[65] = "531691aa574cf40aa726907d70149cd101740be326989c89a193b3c171ad28f3";

int get_sha256_checksum(int fd, char* output_hash)
{
    ssize_t bytes_read = 0;
    char read_buffer[BUFFER_SIZE];
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned long long file_size = 0;

    // Creating the sha256 object
    SHA256_CTX c;
    // Initializing it
    SHA256_Init(&c);
    
    // While we still have bytes to read from the file
    // Read up to 1 KB each time
    // Add the new bytes to our read buffer
    // Incremeting file_size with the amount of bytes_read
    while (1) 
    {
        bytes_read = read(fd, read_buffer, BUFFER_SIZE);

        if (bytes_read > 0)
        {
            SHA256_Update(&c, read_buffer, bytes_read);
            file_size += bytes_read;
        }
        else if (bytes_read == 0) 
        {
            break;
        }
        else
        {
            perror("read error");
            close(fd);
            return 1;
        }
    }

    // Store our raw binary digest (32 bytes)
    SHA256_Final(digest, &c);
    // DEBUG
    printf("File is %llu bytes large\n", file_size);

    /*
     * FOR LOOP 0 .. 31
     * Converting each byte from digest to 2 characters hexadecimal (padding with 0 if necessary)
     * Writing three characters to handle null terminator each time
     * NOTE: \0 terminator is being overwritten each time until we reach the end of digest
     */
    for (uint8_t i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
       snprintf(output_hash + (i * 2), 3, "%02x", digest[i]); 
    }
    
    output_hash[64] = 0;

    return 0;
 }

void check_sign(char* signature)
{
    if (strcmp(signature, BAD_SIGNATURE) == 0)
    {
        printf("DENY\n");
    }
    else
    {
        printf("ALLOW\n");
    }
}

/*
 * Performs: argument check and good usage
 * Returns: file descriptor integer 
 */
int setup(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s <file>\n", argv[0]);    
        return -1;
    }

    int fd = open(argv[1], O_RDONLY | O_LARGEFILE);
    if (fd == -1)
    {
        perror(argv[1]);
        return -1;
    }

    return fd;
}

int main(int argc, char* argv[])
{
    int fd = setup(argc, argv); 
    char checksum[65];

    if (fd < 0) { return 1; }

    if (get_sha256_checksum(fd, checksum) != 0)
    {
        fprintf(stderr, "Failed to calculate checksum\n");
        close(fd);
        return 1;
    }

    check_sign(checksum);

    printf("%s\n", checksum);
    printf("%s\n", BAD_SIGNATURE);

    close(fd);

    return 0;
}
