#include "../includes/ptp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

void parse_ptpv2_packet(const char *packet, int length) {
    int packet_length = length - 2;
    const ptpv2_packet_t *ptp_packet = ( ptpv2_packet_t *)(packet + ETHERNET_HEADER_SIZE);

    uint8_t message_type = ptp_packet->transport_specific_message_type & 0x0F;
    uint64_t timestamp_seconds = extract_origin_seconds(ptp_packet);
    uint32_t timestamp_nanoseconds = extract_origin_nanoseconds(ptp_packet);

    //printf("PTPv2 Message Type: 0x%02x\n", message_type);

    if(message_type == 0x08 || message_type == 0x00) { 
        if (timestamp_seconds != 0 || timestamp_nanoseconds != 0) {
            //printf("Origin Timestamp: %lu seconds, %u nanoseconds\n", timestamp_seconds, timestamp_nanoseconds);
            convert_to_tod(timestamp_seconds, timestamp_nanoseconds);
        }
    //print_hex_data(packet, packet_length, ptp_packet);
    }
}

void convert_to_tod(uint64_t seconds, uint32_t nanoseconds) {
    uint64_t hours = ((seconds / SECONDS_PER_HOUR) % HOURS_PER_DAY) + GMT_ISRAEL_OFFSET;
    uint64_t minutes = (seconds / SECONDS_PER_MINUTE) % MINUTES_PER_HOUR;
    uint64_t secs = seconds % SECONDS_PER_MINUTE;

    // printf("Time of Day (ToD): %02lu:%02lu:%02lu.%09u\n", hours, minutes, secs, nanoseconds);
    printf("Time of Day (ToD): %02lu:%02lu:%02lu.%09d\n", hours, minutes, secs, nanoseconds);
}

void print_hex_data(unsigned char* packet, int length, struct ptpv2_packet* ptp_packet) {
    printf("Raw Hex Data(RawHex)                : ");
    for (int i = length - 10; i < length ; ++i) {
        printf("%02x ", (unsigned char)packet[i]);
    }
    printf("\n");
    printf("Origin Timestamp Seconds(Raw Hex)   : ");
    for (size_t i = 0; i < sizeof(ptp_packet->origin_timestamp_seconds); ++i) {
        printf("%02X ", ((unsigned char *)&ptp_packet->origin_timestamp_seconds)[i]);
    }
    printf("\n");
    printf("OriginTimestamp NanoSeconds(Raw Hex): ");
    for (size_t i = 0; i < sizeof(ptp_packet->origin_timestamp_nanoseconds); ++i) {
        printf("%02X ", ((unsigned char *)&ptp_packet->origin_timestamp_nanoseconds)[i]);
    }
    printf("\n");
}

uint64_t extract_origin_seconds(const struct ptpv2_packet* ptp_packet) {
    uint64_t seconds = 0;
    for(int i = 0; i < ORIGIN_TIMESTAMP_SECONDS_LENGTH; i++) {
        seconds = (seconds << 8) | ptp_packet->origin_timestamp_seconds[i];
    }
    return seconds;
}

uint32_t extract_origin_nanoseconds(const struct ptpv2_packet* ptp_packet) {
    uint32_t nanoseconds = 0;
    for(int i = 0; i < ORIGIN_TIMESTAMP_NANOSECONDS_LENGTH; i++) {
        nanoseconds = (nanoseconds << 8) | ptp_packet->origin_timestamp_nanoseconds[i];
    }
    return nanoseconds;
}