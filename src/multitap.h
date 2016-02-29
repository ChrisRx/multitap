/**
 * multitap, a multithreaded network tap
 * Copyright (C) 2016 Chris Marshall
 *
 * This file is part of multitap.
 *
 * multitap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * multitap is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with multitap.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __MULTITAP_H
#define __MULTITAP_H

typedef struct {
    char *in_device;
    char *out_device;
    char *filter;
    pcap_t *pd;
    eth_t *eth_retrans;
    int ready;
} NetworkTap;

typedef struct {
    size_t size;
    size_t length;
    NetworkTap* array;
} NetworkTaps;

void taps_init(NetworkTaps *t, size_t initial_size);
void taps_append(NetworkTaps *t, NetworkTap element);
void taps_free(NetworkTaps *t);

#endif
