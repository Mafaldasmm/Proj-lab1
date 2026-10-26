// RCOM 2026/2027
//
// Application layer protocol implementation

#include "application_layer.h"
#include "link_layer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

////////////////////////////////////////////////
// PACKET CONSTANTS
////////////////////////////////////////////////
#define C_START 1
#define C_DATA 2
#define C_END 3

#define T_FILE_SIZE 0
#define T_FILE_NAME 1

// Data packet: C L2 L1 P1..Pk  -> header has 3 bytes
#define DATA_HEADER_SIZE 3
#define MAX_DATA_FIELD (MAX_PAYLOAD_SIZE - DATA_HEADER_SIZE)

////////////////////////////////////////////////
// BUILDING PACKETS
////////////////////////////////////////////////

// Control packet: C [T L V] [T L V]
//   T=0 -> file size (L bytes, big-endian)
//   T=1 -> file name
// Returns the packet size.
static int buildControlPacket(unsigned char *packet, unsigned char c,
                              long fileSize, const char *fileName)
{
    int pos = 0;
    packet[pos++] = c;

    // File size: use only the bytes needed (big-endian)
    unsigned char sizeBytes[sizeof(long)];
    int nSizeBytes = 0;
    long tmp = fileSize;
    do
    {
        sizeBytes[nSizeBytes++] = tmp & 0xFF;
        tmp >>= 8;
    } while (tmp > 0);

    packet[pos++] = T_FILE_SIZE;
    packet[pos++] = nSizeBytes;
    for (int i = nSizeBytes - 1; i >= 0; i--)
        packet[pos++] = sizeBytes[i];

    // File name
    int nameLen = strlen(fileName);
    if (nameLen > 255)
        nameLen = 255;
    packet[pos++] = T_FILE_NAME;
    packet[pos++] = nameLen;
    memcpy(packet + pos, fileName, nameLen);
    pos += nameLen;

    return pos;
}

// Data packet: C=2 L2 L1 P1..Pk  (k = 256 * L2 + L1)
// Returns the packet size.
static int buildDataPacket(unsigned char *packet, const unsigned char *data, int size)
{
    packet[0] = C_DATA;
    packet[1] = (size >> 8) & 0xFF; // L2
    packet[2] = size & 0xFF;        // L1
    memcpy(packet + DATA_HEADER_SIZE, data, size);
    return size + DATA_HEADER_SIZE;
}

////////////////////////////////////////////////
// PARSING PACKETS
////////////////////////////////////////////////

// Parse a control packet. Fills fileSize and fileName (if present).
// Returns 0 on success, -1 if malformed.
static int parseControlPacket(const unsigned char *packet, int size,
                              long *fileSize, char *fileName)
{
    int pos = 1; // Skip C
    *fileSize = -1;
    fileName[0] = '\0';

    while (pos + 2 <= size)
    {
        unsigned char t = packet[pos++];
        unsigned char l = packet[pos++];
        if (pos + l > size)
            return -1;

        if (t == T_FILE_SIZE)
        {
            long v = 0;
            for (int i = 0; i < l; i++)
                v = (v << 8) | packet[pos + i];
            *fileSize = v;
        }
        else if (t == T_FILE_NAME)
        {
            memcpy(fileName, packet + pos, l);
            fileName[l] = '\0';
        }
        // Unknown T -> ignored
        pos += l;
    }
    return (*fileSize >= 0) ? 0 : -1;
}

////////////////////////////////////////////////
// TRANSMITTER
////////////////////////////////////////////////
static void sendFile(LinkLayer llParameters, const char *filename)
{
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
    {
        perror(filename);
        return;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    printf("[App Tx] File %s, %ld bytes\n", filename, fileSize);

    if (llOpenTx(llParameters) < 0)
    {
        printf("[App Tx] llOpenTx failed\n");
        fclose(file);
        return;
    }

    unsigned char packet[MAX_PAYLOAD_SIZE];
    int ok = TRUE;

    // START packet
    int size = buildControlPacket(packet, C_START, fileSize, filename);
    if (llSend(packet, size) < 0)
    {
        printf("[App Tx] Failed to send START packet\n");
        ok = FALSE;
    }

    // DATA packets
    unsigned char fragment[MAX_DATA_FIELD];
    long totalSent = 0;
    int nPackets = 0;

    while (ok)
    {
        int n = fread(fragment, 1, MAX_DATA_FIELD, file);
        if (n <= 0)
            break; // End of file

        size = buildDataPacket(packet, fragment, n);
        if (llSend(packet, size) < 0)
        {
            printf("[App Tx] Failed to send DATA packet %d\n", nPackets);
            ok = FALSE;
            break;
        }
        totalSent += n;
        nPackets++;
        printf("\r[App Tx] Sent %ld / %ld bytes", totalSent, fileSize);
        fflush(stdout);
    }
    printf("\n");

    // END packet
    if (ok)
    {
        size = buildControlPacket(packet, C_END, fileSize, filename);
        if (llSend(packet, size) < 0)
        {
            printf("[App Tx] Failed to send END packet\n");
            ok = FALSE;
        }
    }

    fclose(file);

    if (ok)
        printf("[App Tx] File sent in %d data packets\n", nPackets);
    else
        printf("[App Tx] File transfer failed\n");

    llCloseTx();
}

////////////////////////////////////////////////
// RECEIVER
////////////////////////////////////////////////
static void receiveFile(LinkLayer llParameters, const char *filename)
{
    if (llOpenRx(llParameters) < 0)
    {
        printf("[App Rx] llOpenRx failed\n");
        return;
    }

    unsigned char packet[MAX_PAYLOAD_SIZE];
    FILE *file = NULL;
    long fileSize = -1;
    long totalReceived = 0;
    char name[256];
    int done = FALSE;

    while (!done)
    {
        int size = llReceive(packet);
        if (size < 0)
        {
            printf("[App Rx] llReceive failed\n");
            break;
        }
        if (size == 0)
            continue;

        switch (packet[0])
        {
        case C_START:
            if (parseControlPacket(packet, size, &fileSize, name) < 0)
            {
                printf("[App Rx] Malformed START packet\n");
                break;
            }
            printf("[App Rx] START: file \"%s\", %ld bytes -> saving as %s\n",
                   name, fileSize, filename);
            file = fopen(filename, "wb");
            if (file == NULL)
            {
                perror(filename);
                done = TRUE;
            }
            break;

        case C_DATA:
        {
            if (file == NULL)
            {
                printf("[App Rx] DATA packet before START, ignored\n");
                break;
            }
            int k = 256 * packet[1] + packet[2];
            if (k != size - DATA_HEADER_SIZE)
            {
                printf("[App Rx] DATA packet size mismatch (L=%d, got %d)\n",
                       k, size - DATA_HEADER_SIZE);
                break;
            }
            fwrite(packet + DATA_HEADER_SIZE, 1, k, file);
            totalReceived += k;
            printf("\r[App Rx] Received %ld / %ld bytes", totalReceived, fileSize);
            fflush(stdout);
            break;
        }

        case C_END:
        {
            long endSize;
            char endName[256];
            printf("\n");
            if (parseControlPacket(packet, size, &endSize, endName) == 0 &&
                (endSize != fileSize || strcmp(endName, name) != 0))
                printf("[App Rx] Warning: END packet differs from START\n");

            if (totalReceived == fileSize)
                printf("[App Rx] END: file received correctly (%ld bytes)\n", totalReceived);
            else
                printf("[App Rx] END: size mismatch (expected %ld, got %ld)\n",
                       fileSize, totalReceived);
            done = TRUE;
            break;
        }

        default:
            printf("[App Rx] Unknown packet type %d, ignored\n", packet[0]);
        }
    }

    if (file != NULL)
        fclose(file);

    llCloseRx();
}

////////////////////////////////////////////////
// MAIN FUNCTION
////////////////////////////////////////////////
void applicationLayer(const char *serialPort, const char *role, int baudRate,
                      int nTries, int timeout, const char *filename)
{
    LinkLayer llParameters = {
        .baudRate = baudRate,
        .nRetransmissions = nTries,
        .timeout = timeout,
    };
    strcpy(llParameters.serialPort, serialPort);

    if (strcmp(role, "tx") == 0)
        sendFile(llParameters, filename);
    else if (strcmp(role, "rx") == 0)
        receiveFile(llParameters, filename);
    else
        printf("Invalid role: %s. Must be 'tx' or 'rx'.\n", role);
}
