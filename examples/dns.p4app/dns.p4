/*
 * HEADERS
 */

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}


header_type udp_t {
    fields {
        srcPort: 16;
        dstPort: 16;
        length_: 16;
        checksum: 16;
    }
}


header_type dns_header_t {
    fields {
        trans_id: 16;
        is_res: 1;
        op_code: 4;
        authoritative: 1;
        truncated: 1;
        rec_desired: 1;
        rec_available: 1;
        reserved: 1;
        authenticated: 1;
        not_authenticated: 1;
        reply_code: 4;
        num_questions: 16;
        num_answers: 16;
        num_authorities: 16;
        num_additional: 16;
    }
}

header_type dns_query_t {
    fields {
        len: 8;
        label: 64;
        term: 8;
        type: 16;
        class: 16;
    }
}

header_type dns_answer_t {
    fields {
        name: 16;
        type: 16;
        class: 16;
        ttl: 32;
        len: 16;
        data: 32;
    }
}

header_type ingr_meta_t {
    fields {
        tmp_mac: 48;
        tmp_ip: 32;
        tmp_port: 16;
    }
}

/*
 * PARSER
 */
parser start {
    return parse_ethernet;
}

#define ETHERTYPE_IPV4 0x0800

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

header ipv4_t ipv4;

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

#define IP_PROT_UDP 0x11

parser parse_ipv4 {
    extract(ipv4);
    return select(ipv4.protocol) {
        IP_PROT_UDP : parse_udp;
        default : ingress;
    }
}

header udp_t udp;

parser parse_udp {
    extract(udp);
    return select(udp.dstPort) {
        53: parse_dns;
        default : ingress;
    }
}

header dns_header_t dns_header;
header dns_query_t dns_query;
header dns_answer_t dns_answer;

parser parse_dns {
    extract(dns_header);
    extract(dns_query);
    return select(dns_header.num_answers) {
        0: ingress;
        default: parse_dns_answer;
    }
}

parser parse_dns_answer {
    extract(dns_answer);
    return ingress;
}

metadata ingr_meta_t ingr_meta;

/*
 * INGRESS
 */

action a1 () { modify_field(standard_metadata.egress_spec, 2); }
table t1 { actions { a1; } default_action: a1; }

action a2 () { modify_field(standard_metadata.egress_spec, 1); }
table t2 { actions { a2; } default_action: a2; }

action rev_udp() {
    standard_metadata.egress_spec = standard_metadata.ingress_port;
    ingr_meta.tmp_mac = ethernet.dstAddr;
    ethernet.dstAddr = ethernet.srcAddr;
    ethernet.srcAddr = ingr_meta.tmp_mac;

    ingr_meta.tmp_ip = ipv4.dstAddr;
    ipv4.dstAddr = ipv4.srcAddr;
    ipv4.srcAddr = ingr_meta.tmp_ip;

    ingr_meta.tmp_port = udp.dstPort;
    udp.dstPort = udp.srcPort;
    udp.srcPort = ingr_meta.tmp_port;

    udp.checksum = 0;
}

action answerDNS(ip) {
    rev_udp();
    dns_header.is_res = 1;
    dns_header.op_code = 0;
    dns_header.authoritative = 0;
    dns_header.truncated = 0;
    dns_header.rec_desired = 1;
    dns_header.rec_available = 1;
    dns_header.reserved = 0;
    dns_header.authenticated = 0;
    dns_header.not_authenticated = 0;
    dns_header.reply_code = 0; // No error

    dns_header.num_answers = 1;

    add_header(dns_answer);
    dns_answer.name = 0xc00c;
    dns_answer.type = 1;
    dns_answer.class = 1;
    dns_answer.ttl = 233;
    dns_answer.len = 4;
    dns_answer.data = ip;

    udp.length_ = udp.length_ + 16;
    ipv4.totalLen = ipv4.totalLen + 16;
}

action notfoundDNS() {
    rev_udp();
    dns_header.is_res = 1;
    dns_header.op_code = 0;
    dns_header.reply_code = 3; // No such name
}

table dns_host {
    reads { dns_query.label: exact; }
    actions {
        answerDNS;
        notfoundDNS;
    }
    default_action: notfoundDNS;
    size: 128;
}

control ingress {
    if (valid(dns_query)) {
        apply(dns_host);
    }
    else {
        if (standard_metadata.ingress_port == 1)
            apply(t1);
        else
            apply(t2);
    }
}
