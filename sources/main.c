#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "../includes/main.h"
#include "../includes/ptp.h"


int main() {

#ifdef TEST_MODE
    const uint8_t simulated_packet1[] = {
        // Ethernet header (destination, source, EtherType)
        0x01, 0x1B, 0x19, 0x00, 0x00, 0x00, // Destination MAC
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Source MAC
        0x88, 0xF7,                         // EtherType (PTP)
        // PTP Header and Timestamp Data
        0x08, 0x00,                         // Message Type and Version
        0x00, 0x2E,                         // Message Length
        // Some padding
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Sequence, padding
        // Origin Timestamp
        0x00, 0x00, 0x05, 0xDC, 0x00, 0x00, // 1500 seconds
        0x2F, 0xAF, 0x08, 0x00              // 800,000,000 nanoseconds
    };
    size_t packet_len1 = sizeof(simulated_packet1);

    const uint8_t simulated_packet2[] = {
        // Ethernet header (destination, source, EtherType)
        0x01, 0x1b, 0x19, 0x00, 0x00, 0x00, // Destination MAC
        0xe0, 0x73, 0xe7, 0x10, 0x8d, 0xf5, // Source MAC
        0x88, 0xf7,                         // EtherType (PTP)
        // PTP Header and Timestamp Data
        0x08, 0x02,                         // Message Type and Version
        0x00, 0x2c,                         // Message Length
        // Some padding
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Source Port Identity (Clock ID)
        0xe0, 0x73, 0xe7, 0xff, 0xfe, 0x10,
        0x8d, 0xf5,                         // Unique Clock Identifier
        0x00, 0x01,                         // Port Number
        // Sequence ID
        0x00, 0x01,
        // Control Field
        0x02, 0x00,
        // Correction Field
        0x00, 0x00, 0x67, 0x91, 0xe5, 0xe2,
        // Origin Timestamp
        0x05, 0xa0, 0x4e, 0x15                 // Seconds and Nanoseconds
    };

    size_t packet_len2 = sizeof(simulated_packet2);


        printf("Running in test mode...\n");
        parse_ptpv2_packet(simulated_packet2,packet_len2);
#else
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(ETH_DEVICE, BUFSIZ, PROMISC, CAPTURE_READ_TIMEOUT_MS, errbuf);
    if (!handle) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    printf("Listening for PTPv2 packets on enx98254a5c16f9...\n");
    pcap_loop(handle, PACKET_CAPTURE_LOOP_COUNT, packet_handler, NULL);

    pcap_close(handle);
    return EXIT_SUCCESS;
#endif
}


void packet_handler(char *user, const struct pcap_pkthdr *header, const char *packet) {
    (void)user; 
    const uint16_t ethertype = ntohs(*(uint16_t *)(packet + ETHERTYPE_OFFSET));
    if (ethertype == ETHERTYPE_PTP) { 
        //printf("\n");
        //printf("[%d] Captured a PTPv2 packet: Length = %d bytes\n", packet_index,header->len);
        packet_index++;

        parse_ptpv2_packet(packet, header->len);
    }
}