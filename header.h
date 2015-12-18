// Since we are using char, which has a vlue of 8 bits we need to combine/ remove some of the options so that the packet is the correct length, we can deal with the nitty gritty later.
struct ipheader {
 unsigned char	    iph_ver;
// unsigned char	    iph_ihl;
 unsigned char      iph_tos;
 unsigned short int iph_len;
 unsigned short int iph_ident;
// unsigned char      iph_flag;
 unsigned short int iph_offset;
 unsigned char      iph_ttl;
 unsigned char      iph_protocol;
 unsigned short int iph_chksum;
 unsigned int       iph_sourceip;
 unsigned int       iph_destip;
};
// For this project we will be spamming dns requests. The length of a dns request is 70 in total with 34 coming from the udp packet. That means there will be 26 bytes of data sent in the request

struct udpheader{
 unsigned short int udph_srcport;
 unsigned short int udph_destport;
 unsigned short int udph_len;
 unsigned short int udph_chksum;
// unsigned char *message;
};

struct miscHeader{
 unsigned char randA[4];
 unsigned char randB[4];
 unsigned char randC[4];
 unsigned char randD[4];

};
struct dnsrequest{
 unsigned short int dns_transid;
 unsigned short int dns_flags;
 unsigned short int dns_questions;
 unsigned short int dns_answerRR;
 unsigned short int dns_authorityRR;
 unsigned short int dns_additionalRR;
 unsigned char dns_wierdvalue;
 // the type and class are the last 4 bytes
 unsigned char dns_request[8];

 unsigned short int dns_type;
 unsigned short int dns_class;

};
