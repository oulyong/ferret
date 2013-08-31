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





void parse_ssl_request(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	UNUSEDPARM(px); UNUSEDPARM(length);
	sess->layer7_proto = LAYER7_SSL;
	frame->layer7_protocol = LAYER7_SSL;
}

void parse_ssl_response(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	UNUSEDPARM(px); UNUSEDPARM(length);
	sess->layer7_proto = LAYER7_SSL;
	frame->layer7_protocol = LAYER7_SSL;
}




