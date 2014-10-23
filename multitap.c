/**
 * multitap, a multithreaded network tap
 * Copyright (C) 2014 Chris Marshall
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

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <pcap.h>
#include <dnet.h>
#include <yaml.h>
#include <pthread.h>

#define STDBUF 1024

pthread_mutex_t mutex;

struct network_tap {
    char *in_device;
    char *out_device;
    char *filter;
    pcap_t *pd;
    eth_t *eth_retrans;
};

typedef struct {
  size_t size;
  size_t capacity;
  struct network_tap *data;
} NetworkTaps;

static NetworkTaps *taps;

void ntaps_init(NetworkTaps *t, size_t s) {
  t->data = (struct network_tap *)malloc(s * sizeof(struct network_tap));
  t->size = 0;
  t->capacity = s;
}

void ntaps_append(NetworkTaps *t, struct network_tap tap) {
  if (t->size == t->capacity) {
    t->capacity *= 2;
    t->data = (struct network_tap *)realloc(t->data, t->capacity
        * sizeof(struct network_tap));
  }
  t->data[t->size++] = tap;
}

void ntaps_free(NetworkTaps *t) {
  free(t->data);
  t->data = NULL;
  t->size = t->capacity = 0;
}

void signal_handler(int sign)
{
    pthread_mutex_lock (&mutex);
    int i;
    if (sign != 0)
        signal(sign, &signal_handler);

    // Loop through taps and close gracefully
    if (taps != NULL) {
      for (i=0; i < taps->size; i++) {
        if (taps->data[i].eth_retrans != NULL)
          eth_close(taps->data[i].eth_retrans);

        if (taps->data[i].pd != NULL)
          pcap_close(taps->data[i].pd);
      }
      ntaps_free(taps);
    }
    fprintf(stderr, "\n");
    exit(sign);
    pthread_mutex_unlock (&mutex);
}

static void fatal(const char *format, ...)
{

    pthread_mutex_lock (&mutex);

    char buf[STDBUF+1];
    va_list ap;

    va_start(ap, format);
    vsnprintf(buf, STDBUF, format, ap);
    fprintf(stderr, "ERROR: %s", buf);
    va_end(ap);

    pthread_mutex_unlock (&mutex);

    signal_handler(1);
}

static void msg(const char *format, ...)
{
    char buf[STDBUF+1];
    va_list ap;

    va_start(ap, format);
    vsnprintf(buf, STDBUF, format, ap);
    fprintf(stderr, "%s\n", buf);
    va_end(ap);
}

static int drop_privileges(void)
{
    unsigned long groupid = 0;
    unsigned long userid = 0;
    if (getuid() == 0) {
      /* process is running as root, drop privileges */
      if (setgid(groupid) != 0)
          fatal("setgid: Unable to drop group privileges: %s", strerror(errno));
      if (setuid(userid) != 0)
          fatal("setuid: Unable to drop user privileges: %S", strerror(errno));
    }
    return 0;
}

void packet_retrans(u_char *args, struct pcap_pkthdr *pkthdr, u_char *pkt)
{
    eth_t *eth_retrans = (eth_t *) args;
    eth_send(eth_retrans, pkt, pkthdr->caplen);
    return;
}

void *tap_create(void *targs)
{
    static int count;
    static int datalink;
    struct bpf_program fp;
    bpf_u_int32 netmask = 0xFFFFFF00;
    char errorbuf[PCAP_ERRBUF_SIZE];
    struct network_tap *tap = targs;

    tap->pd = pcap_open_live(tap->in_device, 65535, 1, 500, errorbuf);

    if(tap->pd == NULL)
    {
        fatal("start_sniffing(): interface %s open: %s\n", tap->in_device,
            errorbuf);
    }

    if(pcap_compile(tap->pd, &fp, tap->filter, 1, netmask) < 0)
    {
        fatal("start_sniffing() FSM compilation failed: \n\t%s\n"
                "PCAP command: %s\n", pcap_geterr(tap->pd), tap->filter);
    }

    if(pcap_setfilter(tap->pd, &fp) < 0)
        fatal("start_sniffing() setfilter: \n\t%s\n", pcap_geterr(tap->pd));

    datalink = pcap_datalink(tap->pd);

    if(datalink < 0)
        fatal("OpenPcap() datalink grab: \n\t%s\n", pcap_geterr(tap->pd));

    if((tap->eth_retrans = eth_open(tap->out_device)) == NULL)
        fatal("init_retrans() eth_open failed\n");

    if (strcmp(tap->filter, "") == 0)
        tap->filter = "None";

    msg("Starting tap from %s to %s (filter: %s)", tap->in_device,
        tap->out_device, tap->filter);

    if(pcap_loop(tap->pd, count, (pcap_handler) packet_retrans,
        (u_char *) tap->eth_retrans) < 0)
    {
        fatal("pcap_loop: %s", pcap_geterr(tap->pd));
        signal_handler(0);
    }

    pthread_exit(NULL);
}

static void dump_mapping(yaml_parser_t *parser, NetworkTaps *taps) {
    yaml_event_t event;

    char *key = NULL, *value = NULL, **type_ptr;
    char *filter = "";
    struct network_tap tconfig;

    while (event.type != YAML_MAPPING_END_EVENT) {
        if (!yaml_parser_parse(parser, &event)) {
            printf("Parser error %d\n", parser->error);
            exit(1);
        }
        if (event.type == YAML_SCALAR_EVENT) {
            type_ptr = key == NULL ? &key : &value;

            *type_ptr = (char *) malloc(strlen((const char *)
                event.data.scalar.value) + 1);
            strcpy(*type_ptr, (const char *) event.data.scalar.value);

            if (value != NULL) {
                if (strcmp(key, "in") == 0) {
                    tconfig.in_device = value;
                }
                if (strcmp(key, "out") == 0) {
                    tconfig.out_device = value;
                }
                if (strcmp(key, "filter") == 0) {
                    filter = value;
                }
                key = value = NULL;
            }
        }
        if(event.type != YAML_MAPPING_END_EVENT)
            yaml_event_delete(&event);
    }
    yaml_event_delete(&event);
    if (tconfig.in_device == NULL || tconfig.out_device == NULL) {
        return;
    }
    tconfig.filter = filter;

    ntaps_append(taps, tconfig);
}

int read_config(char *filename, NetworkTaps *taps) {
    FILE *fh = fopen(filename, "r");
    yaml_parser_t parser;
    yaml_event_t  event;

    if(!yaml_parser_initialize(&parser))
        fputs("Failed to initialize parser!\n", stderr);

    if(fh == NULL)
        fputs("Failed to open file!\n", stderr);

    yaml_parser_set_input_file(&parser, fh);

    while (event.type != YAML_STREAM_END_EVENT) {
        if (!yaml_parser_parse(&parser, &event)) {
            printf("Parser error %d\n", parser.error);
            exit(1);
        }
        switch (event.type) {
            case YAML_STREAM_START_EVENT:
                break;
            case YAML_MAPPING_START_EVENT:
                dump_mapping(&parser, taps);
                break;
            default:
                break;
        }
        if(event.type != YAML_STREAM_END_EVENT)
            yaml_event_delete(&event);
    }
    yaml_event_delete(&event);
    yaml_parser_delete(&parser);
    fclose(fh);
    return 0;
}

int multitap_init(NetworkTaps *taps)
{
  int i;
  pthread_t threads[taps->size];
  for (i=0; i < taps->size; i++) {
      if (pthread_create(&threads[i], NULL, tap_create,
          (void *) &taps->data[i])) {
          fprintf(stderr, "ERROR; pthread_create() failed\n");
          exit(1);
      }
      usleep(100 * 1000);
  }

  /* Drop root privileges but wait for the threads to startup*/
  sleep(2);
  drop_privileges();

  for (i=0; i < taps->size; i++) {
      if (pthread_join(threads[i], NULL)) {
          fprintf(stderr, "ERROR; pthread_join() failed\n");
          exit(1);
      }
  }
  return 0;
}

int main(int argc, char *argv[])
{
    signal(SIGINT, &signal_handler);
    signal(SIGTERM, &signal_handler);

    if (argc != 2) {
        fprintf( stderr, "Not enough args\n" );
        exit(1);
    }
    NetworkTaps t;
    taps = &t;

    /* Initialize dynamic array */
    ntaps_init(taps, 1);

    /* Read in tap configuration from yaml */
    read_config(argv[1], taps);

    /* Initialize tap threads */
    multitap_init(taps);

    pthread_exit(NULL);
}
