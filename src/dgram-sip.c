/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	SESSION INITIATION PROTOCOL

  This protocol starts a VoIP connection. We can find out the phone
  number of the person making the call, as well as information about
  who they are making calls to.

  With SIP will be the an embedded protocol that will tell us about
  the multi-media session that will be set up. We will need to decode
  that as well in order to then grab the audio session of the phone
  call.

*/
#include "platform.h"
#include "stack-parser.h"
#include "stack-netframe.h"
#include "ferret.h"
#include "stack-extract.h"
#include <string.h>
#include <ctype.h>

void copy_until_space(unsigned char *method, size_t sizeof_method, unsigned *r_method_length, const unsigned char *px, unsigned length, unsigned *r_offset);
void copy_until_colon(unsigned char *name, size_t sizeof_name, unsigned *r_name_length, const unsigned char *px, unsigned length, unsigned *r_offset);


typedef void (*HEADER_CALLBACK)(void *calldata, const unsigned char *name, size_t name_length, const unsigned char *value, size_t value_length);
struct Header
{
	unsigned state;

	unsigned char name[128];
	unsigned name_length;

	unsigned char value[1024];
	unsigned value_length;

	unsigned content_length;

	HEADER_CALLBACK callback;
	HEADER_CALLBACK content_callback;
	void *calldata;
};


void parse_header(const unsigned char *px, unsigned length, struct Header *req)
{
	unsigned offset;

	enum {
	HTTP_START,
	HTTP_METHOD_PRE,
	HTTP_METHOD,
	HTTP_METHOD_AFTER,
	HTTP_URL,
	HTTP_URL_AFTER,
	HTTP_VERSION,
	HTTP_CR,
	HTTP_LF,
	HTTP_CRLF,
	HTTP_NAME,
	HTTP_NAME_COLON,
	HTTP_NAME_AFTER,
	HTTP_VALUE,
	HTTP_CONTENT,
	HTTP_CONTENT_POST,
	HTTP_SKIP_TO_EOL,
	HTTP_DESYNCHRONIZED,
	};


	offset = 0;

	while (offset<length)
	switch (req->state) {
	case HTTP_START:
		memset(req, 0, sizeof(*req));
		req->state = HTTP_METHOD_PRE;
		break;
	case HTTP_METHOD_PRE:
		/* Clean up any whitespace before the designed header */
		while (offset<length && isspace(px[offset]))
			offset++;
		if (offset<length)
			req->state = HTTP_METHOD;
		break;
	case HTTP_METHOD:
		copy_until_space(req->value, sizeof(req->value), &req->value_length, px, length, &offset);
		if (offset<length && isspace(px[offset])) {
			req->callback(req->calldata, (const unsigned char*)"METHOD", 6, req->value, req->value_length);
			req->value_length = 0;
			req->state = HTTP_METHOD_AFTER;
		}
		break;
	case HTTP_METHOD_AFTER:
		while (offset<length && isspace(px[offset]) && px[offset] != '\n')
			offset++;
		if (offset<length)
			req->state = HTTP_URL;
		break;
	case HTTP_URL:
		copy_until_space(req->value, sizeof(req->value), &req->value_length, px, length, &offset);
		if (offset<length) {
			req->value_length = 0;
			req->state = HTTP_URL_AFTER;
		}
		break;
	case HTTP_URL_AFTER:
		while (offset<length && isspace(px[offset]) && px[offset] != '\n') {
			offset++;
		}

		if (offset<length)
			req->state = HTTP_VERSION;
		break;
	case HTTP_VERSION:
	case HTTP_SKIP_TO_EOL:
		while (offset<length && px[offset] != '\n')
			offset++;
		if (offset<length) {
			offset++; /*skip the LF*/
			req->state = HTTP_LF;
		}
		break;
	case HTTP_LF:
		while (offset<length && px[offset] == '\r')
			offset++;
		if (offset<length && px[offset] == '\n') {
			offset++;

			/*******************************************
			 * This is where whe handle the header once
			 * we have parsed it.
			 *******************************************/
			req->callback(req->calldata, 0, 0, 0, 0);
			/*******************************************
			 *******************************************/

			req->state = HTTP_CONTENT;
		} else {
			req->state = HTTP_NAME;
			req->value_length = 0;
			req->name_length = 0;
		}
		break;
	case HTTP_NAME:
		copy_until_colon(req->name, sizeof(req->name), &req->name_length, px, length, &offset);
		if (offset<length)
			req->state = HTTP_NAME_COLON;
		break;
	case HTTP_NAME_COLON:
		if (px[offset] == ':') {
			offset++;
			req->state = HTTP_NAME_AFTER;
		} else
			req->state = HTTP_SKIP_TO_EOL;
		break;
	case HTTP_NAME_AFTER:
		while (offset<length && isspace(px[offset]) && px[offset] != '\n')
			offset++;
		if (offset<length) {
			req->state = HTTP_VALUE;
			req->value_length = 0;
		}
		break;
	case HTTP_VALUE:
		while (offset<length && px[offset] != '\n') {
			if (req->value_length < sizeof(req->value))
				req->value_length = px[offset];
			offset++;
		}

		if (offset<length) {
			/* Clean trailing whitespace, such as the \r */
			if (offset<length) {
				while (req->value_length && isspace(req->value[req->value_length-1]))
					req->value_length--;
			}

			req->callback(req->calldata, req->name, req->name_length, req->value, req->value_length);

			req->state = HTTP_SKIP_TO_EOL;
		}
		break;
	case HTTP_CONTENT:
		if (req->content_length == 0)
			req->state = 0;
		else {
			unsigned len = length-offset;

			if (len > req->content_length)
				len = req->content_length;

			//parse_http_content(sess, frame, px+offset, len);
			offset += len;
			req->content_length -= len;
		}
		break;
	case HTTP_CONTENT_POST:
		if (req->content_length == 0)
			req->state = 0;
		else {
			unsigned len = length-offset;

			if (len > req->content_length)
				len = req->content_length;

			//parse_http_content_post(sess, frame, px+offset, len);
			offset += len;
			req->content_length -= len;
		}
		break;
	default:
		; //FRAMERR(frame, "bad\n");
	}
}

void parse_dgram_sip(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	UNUSEDPARM(ferret);UNUSEDPARM(frame);UNUSEDPARM(px);UNUSEDPARM(length);
}

