/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "stack-parser.h"
#include "stack-netframe.h"
#include "ferret.h"
#include "stack-extract.h"
#include "util-base64.h"
#include "util-hamster.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>





void stream_to_server_unknown(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	frame->layer7_protocol = sess->layer7_proto = LAYER7_UNKNOWN_TCP;
}

void stream_from_server_unknown(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	frame->layer7_protocol = sess->layer7_proto = LAYER7_UNKNOWN_TCP;
}




