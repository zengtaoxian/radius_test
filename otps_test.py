#!/usr/bin/env python
# -*- coding: UTF-8 -*-

__author__ = 'zengtaoxian'

import binascii
import socket
import json
import struct
import hashlib
import time

REMOTE_IP_STR = 'remote_ip'
REMOTE_PORT_STR = 'remote_port'
SHARED_SECRET_STR = 'shared_secret'
ACTIVE_FILE_STR = 'active_file'

JSON_PATH = 'json/'

HOLD_TIME_STR = 'hold_time'
REQ_CODE_STR = 'req_code'
REQ_ATTR_STR = 'req_attr'
RESP_CODE_STR = 'resp_code'
RESP_ATTR_STR = "resp_attr"

TYPE_STR = 'type'
DESC_STR = 'desc'
VALUE_STR = 'value'
LEN_STR = 'len'
IGNORE_STR = 'ignore'

REQ_PKG_ID = 1

REQ_HEAD_FMT = '!BBH16s'
REQ_ATTR_FMT = '!BB'

RESP_HEAD_FMT = '!BBH16s'
RESP_ATTR_FMT = '!BB'

host = ''
port = 1813
addr = (host, port)
shared_secret = ''

type_map = {
    "char": "B",
    "short": "H",
    "int": "I",
    "string": "%ds",
    "stream": "unknow",
}

cfg_file = 'send.json'


def get_req_auth(data):
    m = hashlib.md5()
    m.update(data)
    m.update(shared_secret)
    return m.digest()


def create_attr(k, v):
    attr_desc = v[DESC_STR]
    attr_type = v[TYPE_STR]
    attr_value = v[VALUE_STR]

    res = type_map.get(attr_type)
    if res is not None:
        if res.find('%d') != -1:
            attr_len = v.get(LEN_STR, len(attr_value))
            fmt = res.replace('%d', str(attr_len))
            value = str(attr_value)
            print "\t%s(%d):%s" % (attr_desc, int(k), value)
        elif res == 'unknow':
            res_attr = ''
            res_len = 0
            for i in attr_value:
                tmp_attr, tmp_len = create_attr(k, i)
                res_attr += tmp_attr
                res_len += tmp_len

            return res_attr, res_len
        else:
            fmt = res
            value = int(attr_value)
            print "\t%s(%d):%d" % (attr_desc, int(k), value)

        return struct.pack(fmt, value), struct.calcsize(fmt)
    else:
        print "attr_type:%s is error." % (attr_type,)
        return '', 0


def parse_attr(k, v, body):
    attr_desc = v[DESC_STR]
    attr_type = v[TYPE_STR]
    attr_value = v[VALUE_STR]
    attr_ign = v.get(IGNORE_STR, 0)

    res = type_map.get(attr_type)
    if res is not None:
        val = None

        if res.find('%d') != -1:
            attr_len = v.get(LEN_STR, len(attr_value))
            fmt = res.replace('%d', str(attr_len))
            val_size = struct.calcsize(fmt)

            val, = struct.unpack(fmt, body[:val_size])
            val_list = [x for x in val if x != '\x00']
            val = ''.join(val_list)

            print "\t%s(%d):%s" % (attr_desc, int(k), val)

            if not attr_ign:
                if val != attr_value:
                    print "not match, val:%s, attr_value:%s" % (val, attr_value)
                    exit(-1)

            return val_size
        elif res == 'unknow':
            for i in attr_value:
                parse_len = parse_attr(k, i, body)
                body = body[parse_len:]
        else:
            fmt = res
            val_size = struct.calcsize(fmt)
            val, = struct.unpack(fmt, body[:val_size])
            print "\t%s(%d):%d" % (attr_desc, int(k), val)

            attr_value = int(attr_value)
            if not attr_ign:
                if val != attr_value:
                    print "[not match, val:%s, attr_value:%s]" % (val, attr_value)
                    exit(-1)

            return val_size


def create_tlv_attr(k, v):
    av, al = create_attr(k, v)
    tlv = ''
    if av:
        tlv = struct.pack(REQ_ATTR_FMT, int(k), al + 2)
        tlv += av
    return tlv


def parse_tlv_attr(attr, tlv):
    tlv_head_len = struct.calcsize(RESP_ATTR_FMT)

    tlv_head = tlv[0:tlv_head_len]
    tlv_type, tlv_len = struct.unpack(RESP_ATTR_FMT, tlv_head)

    key = str(tlv_type)
    v = attr.get(key, '')
    if not v:
        print 'type:%s is not support' % (key,)
        return tlv[tlv_len:]

    tlv_body = tlv[tlv_head_len:tlv_head_len + tlv_len - 2]
    parse_attr(key, v, tlv_body)

    return tlv[tlv_len:]


def parse_active(af):
    with open(af, 'r') as f:
        try:
            req_msg = ''

            json_data = json.load(f)

            # hold_time
            hold_time = json_data.get(HOLD_TIME_STR, 0)

            # req_code
            req_code = json_data[REQ_CODE_STR]
            code_type = str(req_code[TYPE_STR])
            code_desc = str(req_code[DESC_STR])
            code_value = int(req_code[VALUE_STR])

            req_pkg_id = REQ_PKG_ID

            print "[%d]==========%s(%d)=========>%r" % (req_pkg_id, code_desc, code_value, peer_addr)

            # req_attr
            req_attr = json_data[REQ_ATTR_STR]
            for k, v in req_attr.items():
                tlv_attr = create_tlv_attr(k, v)
                req_msg += tlv_attr

            attr_len = len(req_msg)
            total_len = struct.calcsize(REQ_HEAD_FMT) + attr_len

            orig_msg = struct.pack(REQ_HEAD_FMT, code_value, req_pkg_id, total_len, '') + req_msg
            req_auth = get_req_auth(orig_msg)
            send_msg = struct.pack(REQ_HEAD_FMT, code_value, req_pkg_id, total_len, req_auth) + req_msg

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(peer_addr)

            sock.sendall(send_msg)

            response = sock.recv(1024)
            resp_head_len = struct.calcsize(RESP_HEAD_FMT)
            resp_head = response[0:resp_head_len]
            resp_body = response[resp_head_len:]

            resp_code, resp_pkg_id, resp_len, resp_auth = struct.unpack(RESP_HEAD_FMT, resp_head)

            # resp_code
            resp_code = json_data[RESP_CODE_STR]
            code_type = str(resp_code[TYPE_STR])
            code_desc = str(resp_code[DESC_STR])
            code_value = int(resp_code[VALUE_STR])

            print "[%d]<==========%s(%d)=========%r" % (resp_pkg_id, code_desc, code_value, peer_addr)

            # resp_attr
            resp_attr = json_data.get(RESP_ATTR_STR, None)
            if not None:
                while resp_body:
                    resp_body = parse_tlv_attr(resp_attr, resp_body)

            sock.close()

            time.sleep(hold_time)
        except Exception, e:
            print Exception, ":", e
            exit(-1)


if __name__ == '__main__':
    with open(cfg_file, 'r') as f:
        try:
            json_data = json.load(f)
            remote_ip = json_data[REMOTE_IP_STR]
            remote_port = json_data[REMOTE_PORT_STR]
            shared_secret = json_data.get(SHARED_SECRET_STR, '')
            active_file = json_data[ACTIVE_FILE_STR]

            peer_addr = (remote_ip, remote_port)

            for af in active_file:
                parse_active(JSON_PATH + af)

        except Exception, e:
            print Exception, ":", e
            exit(-1)
