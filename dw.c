#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "aircrack-ng/src/osdep/osdep.h"

#define uchar unsigned char

#define MAX_PACKET_LENGTH 4096
#define ETH_MAC_LENGTH 6
#define MAX_MAC_LIST_ENTRIES 256

/* XXX: globals... why? Why, globals... why!? */
static struct wif *_wi_in, *_wi_out;

int current_channel = 0;

char mac[257];                          // Space for the MACs read from file
FILE *list_file_fp;                     // File containing MACs list
char *list_file_name = NULL;            // File Name for file containing MACs list
long list_file_pos = 0;                 // List file position
int list_file_eof = 0;                  // EOF flag
int use_list = 0;                       // Flag for using list [0 -> nolist| 1->blacklist| 2->whitelist]

uchar mac_list[MAX_MAC_LIST_ENTRIES][ETH_MAC_LENGTH];           // Whitelist/Blacklist
int mac_list_length = 0;                                        // Actual mac_list length
uchar mac_parsed[ETH_MAC_LENGTH] = "\x00\x00\x00\x00\x00\x00"; // Space for parsed MACs


struct packet
{
    uchar *data;
    int length;
} packet;

int read_packet(uchar *buffer, size_t buffer_size)
{
    struct wif *wi = _wi_in; /* XXX */
    int return_code;

    return_code = wi_read(wi, buffer, buffer_size, NULL);

    if (return_code == -1)
    {
        switch (errno)
        {
        case EAGAIN:
            return 0;
        }

        perror("wi_read()");
        return -1;
    }

    return return_code;
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


//Returns pointer to the desired MAC Adresses inside a packet
//Type: s => Station
//      a => AP
//      b => BSSID
uchar *get_macs_from_packet(char type, uchar *packet)
{
    uchar *bssid, *station, *access_point;

    //Ad-Hoc Case!
    bssid = packet + 16;
    station = packet + 10;
    access_point = packet + 4;

    // ToDS packet
    if ((packet[1] & '\x01') && (!(packet[1] & '\x02')))
    {
        bssid = packet + 4;
        station = packet + 10;
        access_point = packet + 16;
    }

    // FromDS packet
    if ((!(packet[1] & '\x01')) && (packet[1] & '\x02'))
    {
        station = packet + 4;
        bssid = packet + 10;
        access_point = packet + 16;
    }

    // WDS packet
    if ((packet[1] & '\x01') && (packet[1] & '\x02'))
    {
        station = packet + 4;
        bssid = packet + 10;
        access_point = packet + 4;
    }

    switch(type)
    {
    case 's':
        return station;
    case 'a':
        return access_point;
    case 'b':
        return bssid;
    }

    return NULL;
}


// Very simple routine to convert hexadecimal input into a byte
char hex2char (char byte1, char byte2)
{
    char rv;

    if (byte1 == '0') { rv = 0; }
    if (byte1 == '1') { rv = 16; }
    if (byte1 == '2') { rv = 32; }
    if (byte1 == '3') { rv = 48; }
    if (byte1 == '4') { rv = 64; }
    if (byte1 == '5') { rv = 80; }
    if (byte1 == '6') { rv = 96; }
    if (byte1 == '7') { rv = 112; }
    if (byte1 == '8') { rv = 128; }
    if (byte1 == '9') { rv = 144; }
    if (byte1 == 'A' || byte1 == 'a') { rv = 160; }
    if (byte1 == 'B' || byte1 == 'b') { rv = 176; }
    if (byte1 == 'C' || byte1 == 'c') { rv = 192; }
    if (byte1 == 'D' || byte1 == 'd') { rv = 208; }
    if (byte1 == 'E' || byte1 == 'e') { rv = 224; }
    if (byte1 == 'F' || byte1 == 'f') { rv = 240; }

    if (byte2 == '0') { rv += 0; }
    if (byte2 == '1') { rv += 1; }
    if (byte2 == '2') { rv += 2; }
    if (byte2 == '3') { rv += 3; }
    if (byte2 == '4') { rv += 4; }
    if (byte2 == '5') { rv += 5; }
    if (byte2 == '6') { rv += 6; }
    if (byte2 == '7') { rv += 7; }
    if (byte2 == '8') { rv += 8; }
    if (byte2 == '9') { rv += 9; }
    if (byte2 == 'A' || byte2 == 'a') { rv += 10; }
    if (byte2 == 'B' || byte2 == 'b') { rv += 11; }
    if (byte2 == 'C' || byte2 == 'c') { rv += 12; }
    if (byte2 == 'D' || byte2 == 'd') { rv += 13; }
    if (byte2 == 'E' || byte2 == 'e') { rv += 14; }
    if (byte2 == 'F' || byte2 == 'f') { rv += 15; }

    return rv;
}

// Parsing input MAC adresses like 00:00:11:22:aa:BB or 00001122aAbB
uchar *parse_mac(char *input)
{
    uchar tmp[12] = "000000000000";
    int t;

    if (input[2] == ':')
    {
        memcpy(tmp, input, 2);
        memcpy(tmp+2, input+3, 2);
        memcpy(tmp+4, input+6, 2);
        memcpy(tmp+6, input+9, 2);
        memcpy(tmp+8, input+12, 2);
        memcpy(tmp+10, input+15, 2);
    }
    else
    {
        memcpy(tmp, input, 12);
    }

    for (t=0; t<ETH_MAC_LENGTH; t++)
    {
        mac_parsed[t] = hex2char(tmp[2*t], tmp[2*t+1]);
    }

    return mac_parsed;
}

void set_channel(int channel)
{
    wi_set_channel(_wi_in, channel);
    current_channel = channel;
}

int get_channel()
{
    return current_channel;
}


// Read mac from file
// New line removed
char *read_line_from_file()
{
    int max_length = 255;
    int length = 32;
    char *mac_string = NULL;
    unsigned int size = 0;
    int bytes_read = 0;

    /* open file for input */
    if ((list_file_fp = fopen(list_file_name, "r")) == NULL)
    {
        printf("Cannot open file \n");
        exit(1);
    }

    fseek(list_file_fp, list_file_pos, SEEK_SET);
    bytes_read = getline(&mac_string, &size, list_file_fp);

    if (bytes_read == -1)
    {
        rewind(list_file_fp);
        list_file_eof = 1;
        bytes_read = getline(&mac_string, &size, list_file_fp);
    }

    length = strlen(mac_string);

    if (length > max_length)
    {
        memcpy(mac, mac_string, max_length);
        mac[max_length + 1]= '\x00';
        length = strlen(mac);
    }
    else
    {
        memcpy(mac, mac_string, length);
    }

    mac[length-1]='\x00';

    list_file_pos = ftell(list_file_fp);
    fclose(list_file_fp);

    return (char*) &mac;
}

void load_list_file(char *filename)
{

    list_file_name = filename;
    uchar *parsed_mac;

    mac_list_length = 0;

    while (!list_file_eof)
    {
        parsed_mac = parse_mac(read_line_from_file());
        memcpy(mac_list[mac_list_length], parsed_mac, ETH_MAC_LENGTH);

        mac_list_length++;
        if ((unsigned int) mac_list_length >= sizeof (mac_list) / sizeof (mac_list[0]))
        {
            fprintf(stderr, "Exceeded max whitelist entries\n");
            exit(1);
        }
    }

    //Resetting file positions for next access
    list_file_pos = 0;
    list_file_eof = 0;
}

int is_whitelisted(uchar *mac)
{
    int t;
    for (t=0; t<mac_list_length; t++)
    {
        if (!memcmp(mac_list[t], mac, ETH_MAC_LENGTH))
            return 1;
    }

    return 0;
}

char help[] =   "dw <interface> <bssid> <channel> [option] \n"
                "Options:\n"
                " -w <filename> \n"
                "   Whitelist...\n"
                " -b <filename> \n"
                "   Blacklist...\n";

void print_help()
{
    printf(help);
}

/* main */
int main(int argc, const char *argv[])
{
    uchar bssid;
    int channel, t;
    char *list_file = NULL;
    //options

    if (geteuid() != 0)
    {
        printf("This program requires root privileges.\n");
        return 1;
    }

    if (argc < 4  || !memcmp(argv[1], "--help", 6) || !memcmp(argv[1], "-h", 2))
    {
        print_help();
        return 1;
    }

    bssid = (uchar *) parse_mac(argv[2]);
    channel = atoi(argv[3]);

    for(t=3; t < argc; t++)
    {

        if(!strcmp(argv[t], "-w") && argc >= t+1)
        {
            use_list = 1;
        }

        if(!strcmp(argv[t], "-b") && argc >= t+1)
        {
            use_list = 2;
        }

        if(use_list != 0)
        {
            list_file = argv[t+1];
            load_list_file(list_file);
        }

    }

    /* open the replay interface */
    _wi_out = wi_open((char*) argv[1]);
    if (!_wi_out)
        return 1;

    /* open the packet source */
    _wi_in = _wi_out;

    /* drop privileges */
    setuid(getuid());

    uchar packet_data[MAX_PACKET_LENGTH];

    while (1)
    {
        read_packet(packet_data, MAX_PACKET_LENGTH);
        //print_packet(packet_data, MAX_PACKET_LENGTH);

        printf(get_macs_from_packet('a', packet_data));
        printf(get_macs_from_packet('b', packet_data));
        printf(get_macs_from_packet('s', packet_data));
    }

    return 0;
}
