// RCOM 2026/2027
//
// Link layer protocol implementation

#include "link_layer.h"
#include "serial_port.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

// MISC
#define _POSIX_SOURCE 1 // POSIX compliant source

////////////////////////////////////////////////
// FRAME CONSTANTS
////////////////////////////////////////////////
#define FLAG 0x7E
#define ESC 0x7D     // Escape byte used in byte stuffing
#define ESC_XOR 0x20 // 0x7E -> 0x7D 0x5E ; 0x7D -> 0x7D 0x5D

// Address field
#define A_TX 0x03 // Commands sent by the Transmitter / replies sent by the Receiver
#define A_RX 0x01 // Commands sent by the Receiver / replies sent by the Transmitter

// Control field
#define C_SET 0x03
#define C_UA 0x07
#define C_DISC 0x0B
#define C_I(n) ((n) << 7)     // I frame: 0x00 (Ns=0) or 0x80 (Ns=1)
#define C_RR(n) (0xAA | (n))  // RR0 = 0xAA, RR1 = 0xAB
#define C_REJ(n) (0x54 | (n)) // REJ0 = 0x54, REJ1 = 0x55

#define IS_I_FRAME(c) ((c) == C_I(0) || (c) == C_I(1))

// Biggest possible frame: F A C BCC1 + (data + BCC2, all stuffed -> x2) + F
#define MAX_FRAME_SIZE (4 + 2 * (MAX_PAYLOAD_SIZE + 1) + 1)

////////////////////////////////////////////////
// GLOBAL STATE
////////////////////////////////////////////////
static LinkLayer connectionParameters;

static int txNs = 0;       // Tx: sequence number of the next I frame to send
static int rxExpected = 0; // Rx: sequence number of the I frame we expect

// Statistics
static int statFramesSent = 0;      // Tx: I frames sent (including retransmissions)
static int statRetransmissions = 0; // Tx: I frames retransmitted
static int statTimeouts = 0;        // Tx/Rx: timeouts (any command frame)
static int statRejReceived = 0;     // Tx: REJ received
static int statFramesReceived = 0;  // Rx: valid new I frames
static int statRejSent = 0;         // Rx: REJ sent
static int statDuplicates = 0;      // Rx: duplicated I frames
static long statBytesReceived = 0;  // Rx: payload bytes delivered to the application
static struct timeval startTime;    // Time when the connection was established

////////////////////////////////////////////////
// ALARM
////////////////////////////////////////////////
static volatile sig_atomic_t alarmFired = FALSE;

static void alarmHandler(int signal)
{
    alarmFired = TRUE; // Only set a flag: printf is not safe inside a signal handler
}

// Install the alarm handler WITHOUT SA_RESTART, so that a blocking
// read() is interrupted (returns -1 with errno = EINTR) when the alarm fires.
static int setupAlarm()
{
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = alarmHandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;

    if (sigaction(SIGALRM, &act, NULL) == -1)
    {
        perror("sigaction");
        return -1;
    }
    return 0;
}

// Start the retransmission timer for a frame of frameSize bytes that was just
// written. write() returns as soon as the bytes are queued, but at low baud
// rates a full I frame takes seconds to go through the line (10 bits per byte,
// 8-N-1), so that time is added to the timeout: the timer effectively counts
// from the moment the last byte of the frame leaves the serial port.
static void startAlarm(int frameSize)
{
    int txTime = (frameSize * 10 + connectionParameters.baudRate / 2) /
                 connectionParameters.baudRate; // rounded to whole seconds
    alarmFired = FALSE;
    alarm(connectionParameters.timeout + txTime);
}

static void stopAlarm()
{
    alarm(0);
    alarmFired = FALSE;
}

static double elapsedSeconds()
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return (now.tv_sec - startTime.tv_sec) + (now.tv_usec - startTime.tv_usec) / 1e6;
}

////////////////////////////////////////////////
// SENDING FRAMES
////////////////////////////////////////////////

// Build and send a supervision/unnumbered frame [FLAG, A, C, BCC1, FLAG].
// Returns 0 on success, -1 on error.
static int sendSupervisionFrame(unsigned char a, unsigned char c)
{
    unsigned char frame[5] = {FLAG, a, c, a ^ c, FLAG};

    if (writeBytesSerialPort(frame, 5) != 5)
    {
        printf("Error writing supervision frame\n");
        return -1;
    }
    return 0;
}

// Byte stuffing: append "byte" to "frame" at position *pos, escaping it if needed.
static void stuffByte(unsigned char *frame, int *pos, unsigned char byte)
{
    if (byte == FLAG || byte == ESC)
    {
        frame[(*pos)++] = ESC;
        frame[(*pos)++] = byte ^ ESC_XOR;
    }
    else
    {
        frame[(*pos)++] = byte;
    }
}

// Build an I frame [FLAG, A, C, BCC1, D1..Dn (stuffed), BCC2 (stuffed), FLAG].
// Returns the frame size.
static int buildIFrame(unsigned char *frame, const unsigned char *data, int size, int ns)
{
    int pos = 0;
    unsigned char a = A_TX;
    unsigned char c = C_I(ns);

    frame[pos++] = FLAG;
    frame[pos++] = a;
    frame[pos++] = c;
    frame[pos++] = a ^ c; // BCC1

    // BCC2 is computed over the ORIGINAL data (before stuffing)
    unsigned char bcc2 = 0;
    for (int i = 0; i < size; i++)
    {
        bcc2 ^= data[i];
        stuffByte(frame, &pos, data[i]);
    }
    stuffByte(frame, &pos, bcc2); // BCC2 may also need stuffing

    frame[pos++] = FLAG;
    return pos;
}

////////////////////////////////////////////////
// RECEIVING FRAMES (state machine)
////////////////////////////////////////////////
typedef enum
{
    START,    // Waiting for a FLAG
    FLAG_RCV, // FLAG received, waiting for A
    A_RCV,    // A received, waiting for C
    C_RCV,    // C received, waiting for BCC1
    DATA,     // BCC1 OK, reading data (if any) until the closing FLAG
    DATA_ESC  // ESC received inside data, next byte must be destuffed
} State;

// Read ONE complete frame with a valid header (BCC1), byte by byte.
//  - *a and *c receive the address and control fields.
//  - For I frames, "data" receives the destuffed data field INCLUDING BCC2
//    as its last byte, and *dataSize its size. An I frame whose data field
//    is too long (corrupted by noise) is returned with *dataSize = 0, so the
//    caller treats it as a data error and can answer with REJ right away.
//  - Supervision frames must have no data (otherwise they are discarded).
//  - Frames with a wrong BCC1 are ignored (we just keep reading).
// If useAlarm is TRUE, gives up when the alarm fires.
// Returns 0 when a frame was read, 1 on timeout, -1 on error.
static int readFrame(unsigned char *a, unsigned char *c,
                     unsigned char *data, int *dataSize, int useAlarm)
{
    State state = START;
    int size = 0;
    int overflow = FALSE;

    while (TRUE)
    {
        if (useAlarm && alarmFired)
            return 1;

        unsigned char byte;
        int res = readByteSerialPort(&byte);

        if (res < 0)
        {
            if (errno == EINTR)
                continue; // Interrupted by the alarm -> loop checks alarmFired
            perror("readByteSerialPort");
            return -1;
        }
        if (res == 0)
            continue; // No byte received

        switch (state)
        {
        case START:
            if (byte == FLAG)
                state = FLAG_RCV;
            break;

        case FLAG_RCV:
            if (byte == A_TX || byte == A_RX)
            {
                *a = byte;
                state = A_RCV;
            }
            else if (byte != FLAG) // Several FLAGs in a row are allowed
                state = START;
            break;

        case A_RCV:
            if (byte == FLAG)
                state = FLAG_RCV;
            else
            {
                *c = byte;
                state = C_RCV;
            }
            break;

        case C_RCV:
            if (byte == (*a ^ *c))
            {
                size = 0;
                overflow = FALSE;
                state = DATA; // Header OK
            }
            else if (byte == FLAG)
                state = FLAG_RCV;
            else
                state = START; // Wrong BCC1 -> ignore frame
            break;

        case DATA:
            if (byte == FLAG)
            {
                // End of frame
                if (IS_I_FRAME(*c))
                {
                    // Valid header: always hand the frame to the caller, which
                    // checks BCC2 (size < 2 means the data field is corrupted)
                    *dataSize = overflow ? 0 : size;
                    return 0;
                }
                if (size == 0) // Supervision frame: no data allowed
                {
                    *dataSize = 0;
                    return 0;
                }
                // Malformed frame: this FLAG may start the next frame
                state = FLAG_RCV;
            }
            else if (!IS_I_FRAME(*c))
                state = START; // Supervision frame with data -> discard
            else if (byte == ESC)
                state = DATA_ESC;
            else if (size < MAX_PAYLOAD_SIZE + 1)
                data[size++] = byte;
            else
                overflow = TRUE; // Too long: keep reading until the closing FLAG
            break;

        case DATA_ESC:
            if (byte == FLAG)
            {
                // Invalid escape sequence: corrupted data field
                *dataSize = 0;
                return 0;
            }
            if (size < MAX_PAYLOAD_SIZE + 1)
                data[size++] = byte ^ ESC_XOR; // Destuffing
            else
                overflow = TRUE;
            state = DATA;
            break;
        }
    }
}

// Send a command frame and wait for the expected reply, retransmitting
// on timeout (1 first attempt + up to nRetransmissions retransmissions).
// Used for SET -> UA and DISC -> DISC/UA.
// Returns 0 on success, -1 if all attempts failed.
static int sendCommandAndWait(unsigned char cmdA, unsigned char cmdC,
                              unsigned char replyA, unsigned char replyC,
                              const char *name)
{
    unsigned char data[MAX_PAYLOAD_SIZE + 1];

    for (int attempt = 0; attempt <= connectionParameters.nRetransmissions; attempt++)
    {
        if (attempt > 0)
            printf("Retransmitting %s (%d/%d)\n", name, attempt,
                   connectionParameters.nRetransmissions);

        if (sendSupervisionFrame(cmdA, cmdC) < 0)
            return -1;

        startAlarm(5);
        while (TRUE)
        {
            unsigned char a, c;
            int size;
            int r = readFrame(&a, &c, data, &size, TRUE);
            if (r < 0)
            {
                stopAlarm();
                return -1;
            }
            if (r == 1)
                break; // Timeout

            if (a == replyA && c == replyC)
            {
                stopAlarm();
                return 0;
            }
            // Other frame -> ignore and keep waiting
        }
        stopAlarm();
        statTimeouts++;
        printf("Timeout waiting for reply to %s\n", name);
    }
    return -1;
}

////////////////////////////////////////////////
// LLOPEN
////////////////////////////////////////////////
int llOpenTx(LinkLayer llParameters)
{
    connectionParameters = llParameters;
    txNs = 0;

    if (openSerialPort(llParameters.serialPort, llParameters.baudRate) < 0)
    {
        perror("openSerialPort");
        return -1;
    }
    printf("[Tx] Serial port %s opened\n", llParameters.serialPort);

    if (setupAlarm() < 0)
    {
        closeSerialPort();
        return -1;
    }

    // SET -> UA
    if (sendCommandAndWait(A_TX, C_SET, A_TX, C_UA, "SET") < 0)
    {
        printf("[Tx] No UA received. Giving up.\n");
        closeSerialPort();
        return -1;
    }

    gettimeofday(&startTime, NULL);
    printf("[Tx] Connection established (SET/UA)\n");
    return 0;
}

int llOpenRx(LinkLayer llParameters)
{
    connectionParameters = llParameters;
    rxExpected = 0;

    if (openSerialPort(llParameters.serialPort, llParameters.baudRate) < 0)
    {
        perror("openSerialPort");
        return -1;
    }
    printf("[Rx] Serial port %s opened\n", llParameters.serialPort);

    if (setupAlarm() < 0)
    {
        closeSerialPort();
        return -1;
    }

    // Wait for SET (no timeout on the receiver)
    printf("[Rx] Waiting for SET...\n");
    unsigned char data[MAX_PAYLOAD_SIZE + 1];
    while (TRUE)
    {
        unsigned char a, c;
        int size;
        if (readFrame(&a, &c, data, &size, FALSE) < 0)
        {
            closeSerialPort();
            return -1;
        }
        if (a == A_TX && c == C_SET)
            break;
    }

    // Reply with UA
    if (sendSupervisionFrame(A_TX, C_UA) < 0)
    {
        closeSerialPort();
        return -1;
    }

    gettimeofday(&startTime, NULL);
    printf("[Rx] Connection established (SET/UA)\n");
    return 0;
}

////////////////////////////////////////////////
// LLSEND
////////////////////////////////////////////////
int llSend(const unsigned char *buf, int bufSize)
{
    if (buf == NULL || bufSize <= 0 || bufSize > MAX_PAYLOAD_SIZE)
        return -1;

    unsigned char frame[MAX_FRAME_SIZE];
    int frameSize = buildIFrame(frame, buf, bufSize, txNs);

    unsigned char data[MAX_PAYLOAD_SIZE + 1];
    int timeouts = 0; // Only timeouts count towards the retransmission limit
    int firstSend = TRUE;

    while (timeouts <= connectionParameters.nRetransmissions)
    {
        if (!firstSend)
        {
            statRetransmissions++;
            printf("[Tx] Retransmitting I%d\n", txNs);
        }
        firstSend = FALSE;

        if (writeBytesSerialPort(frame, frameSize) != frameSize)
        {
            printf("[Tx] Error writing I frame\n");
            return -1;
        }
        statFramesSent++;

        startAlarm(frameSize);

        while (TRUE)
        {
            unsigned char a, c;
            int size;
            int r = readFrame(&a, &c, data, &size, TRUE);
            if (r < 0)
            {
                stopAlarm();
                return -1;
            }
            if (r == 1)
            {
                timeouts++;
                statTimeouts++;
                if (timeouts <= connectionParameters.nRetransmissions)
                    printf("[Tx] Timeout waiting for RR (I%d) -> retransmission %d/%d\n",
                           txNs, timeouts, connectionParameters.nRetransmissions);
                else
                    printf("[Tx] Timeout waiting for RR (I%d)\n", txNs);
                break; // Retransmit
            }
            if (a != A_TX)
                continue;

            if (c == C_RR(1 - txNs))
            {
                // Positive acknowledgement: frame accepted
                stopAlarm();
                txNs = 1 - txNs;
                return bufSize;
            }
            if (c == C_REJ(txNs))
            {
                // Negative acknowledgement: retransmit right away.
                // A REJ proves the link is alive, so it does not use up a try.
                statRejReceived++;
                printf("[Tx] REJ%d received -> retransmitting\n", txNs);
                break;
            }
            if (c == C_RR(txNs))
            {
                // The receiver is still answering old copies of the previous
                // frame (retransmissions queued in the line, e.g. after the
                // cable was disconnected). Our frame is queued behind them, so
                // restart the timer instead of retransmitting: sending yet
                // another copy would only make the queue longer.
                startAlarm(frameSize);
            }
            // Anything else (e.g. RR for the previous frame) -> keep waiting
        }
        stopAlarm();
    }

    printf("[Tx] llSend failed: maximum number of retransmissions reached\n");
    return -1;
}

////////////////////////////////////////////////
// LLRECEIVE
////////////////////////////////////////////////
int llReceive(unsigned char *packet)
{
    unsigned char data[MAX_PAYLOAD_SIZE + 1];

    while (TRUE)
    {
        unsigned char a, c;
        int size;
        if (readFrame(&a, &c, data, &size, FALSE) < 0)
            return -1;

        if (a != A_TX)
            continue;

        // The UA was lost and the Tx retransmitted SET -> answer UA again
        if (c == C_SET)
        {
            printf("[Rx] SET received again -> resending UA\n");
            sendSupervisionFrame(A_TX, C_UA);
            continue;
        }

        if (!IS_I_FRAME(c))
            continue; // Not an I frame -> ignore

        int ns = (c == C_I(1)) ? 1 : 0;
        int dataSize = size - 1; // Last byte is BCC2
        int dataOk = FALSE;

        if (size >= 2) // At least 1 data byte + BCC2
        {
            unsigned char calc = 0;
            for (int i = 0; i < dataSize; i++)
                calc ^= data[i];
            dataOk = (calc == data[size - 1]);
        }

        if (ns != rxExpected)
        {
            // Duplicate (our RR was lost): discard data, confirm again
            statDuplicates++;
            printf("[Rx] Duplicate I%d -> RR%d\n", ns, rxExpected);
            sendSupervisionFrame(A_TX, C_RR(rxExpected));
            continue;
        }

        if (!dataOk)
        {
            // New frame with error in the data field -> REJ
            statRejSent++;
            printf("[Rx] BCC2 error in I%d -> REJ%d\n", ns, ns);
            sendSupervisionFrame(A_TX, C_REJ(ns));
            continue;
        }

        // New frame, no errors -> accept it
        memcpy(packet, data, dataSize);
        rxExpected = 1 - rxExpected;
        statFramesReceived++;
        statBytesReceived += dataSize;
        sendSupervisionFrame(A_TX, C_RR(rxExpected));
        return dataSize;
    }
}

////////////////////////////////////////////////
// LLCLOSE
////////////////////////////////////////////////
int llCloseTx()
{
    int result = 0;

    // DISC (Tx) -> DISC (Rx)
    if (sendCommandAndWait(A_TX, C_DISC, A_RX, C_DISC, "DISC") < 0)
    {
        printf("[Tx] No DISC received from the receiver\n");
        result = -1;
    }
    else
    {
        // UA is a reply from the Transmitter -> A = 0x01
        sendSupervisionFrame(A_RX, C_UA);
        printf("[Tx] Connection closed (DISC/DISC/UA)\n");
    }

    printf("\n--- Statistics (Tx) ---\n"
           "I frames sent:       %d\n"
           "Retransmissions:     %d\n"
           "Timeouts:            %d\n"
           "REJ received:        %d\n"
           "Elapsed time:        %.3f s\n",
           statFramesSent, statRetransmissions, statTimeouts, statRejReceived,
           elapsedSeconds());

    sleep(1); // Let the last frame leave the serial port
    if (closeSerialPort() < 0)
    {
        perror("closeSerialPort");
        return -1;
    }
    return result;
}

int llCloseRx()
{
    unsigned char data[MAX_PAYLOAD_SIZE + 1];
    int result = 0;
    double transferTime = elapsedSeconds();

    // Wait for DISC from the Tx
    printf("[Rx] Waiting for DISC...\n");
    while (TRUE)
    {
        unsigned char a, c;
        int size;
        if (readFrame(&a, &c, data, &size, FALSE) < 0)
        {
            result = -1;
            break;
        }
        if (a == A_TX && c == C_DISC)
            break;

        // The last RR was lost and the Tx retransmitted the last I frame
        if (a == A_TX && IS_I_FRAME(c))
        {
            statDuplicates++;
            printf("[Rx] Duplicate I frame while closing -> RR%d\n", rxExpected);
            sendSupervisionFrame(A_TX, C_RR(rxExpected));
        }
    }

    if (result == 0)
    {
        // DISC (Rx command -> A = 0x01) -> UA (Tx reply -> A = 0x01)
        if (sendCommandAndWait(A_RX, C_DISC, A_RX, C_UA, "DISC") < 0)
        {
            printf("[Rx] No UA received after DISC\n");
            result = -1;
        }
        else
            printf("[Rx] Connection closed (DISC/DISC/UA)\n");
    }

    double bitrate = transferTime > 0 ? statBytesReceived * 8 / transferTime : 0;

    printf("\n--- Statistics (Rx) ---\n"
           "I frames accepted:   %d\n"
           "Duplicates:          %d\n"
           "REJ sent:            %d\n"
           "Bytes received:      %ld\n"
           "Transfer time:       %.3f s\n"
           "Received bitrate R:  %.1f bit/s\n"
           "Efficiency S = R/C:  %.4f\n",
           statFramesReceived, statDuplicates, statRejSent, statBytesReceived,
           transferTime, bitrate, bitrate / connectionParameters.baudRate);

    if (closeSerialPort() < 0)
    {
        perror("closeSerialPort");
        return -1;
    }
    return result;
}