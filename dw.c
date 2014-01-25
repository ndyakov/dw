#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "aircrack-ng/src/osdep/osdep.h"

#define uchar unsigned char

#define MAX_PACKET_LENGTH 4096

static struct wif *_wi_in, *_wi_out;

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

void print_help()
{
    printf("dw <interface>");
}

int main(int argc, const char *argv[])
{
    if (geteuid() != 0)
    {
        printf("This program requires root privileges.\n");
        return 1;
    }

    if (argc < 2  || !memcmp(argv[1], "--help", 6))
    {
        printf("need help");
        return 1;
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
