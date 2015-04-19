#include "dns-head.h"
int arr[5] = {1, 2, 5, 28, 15};

int dns_server_count = 0;
/*
 * Perform a DNS query by sending a packet
 * */
void ngethostbyname(unsigned char *host , int query_type/*decides the resource record you want to retirve*/)
{
	unsigned char buf[65536],*qname,*reader;
	bzero(buf, sizeof(buf));
	char str[INET6_ADDRSTRLEN+1];
	int i , j , stop , s;

	struct sockaddr_in a;
	struct sockaddr_in6 b;

	struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server
	struct sockaddr_in dest;

	struct DNS_HEADER *dns = NULL;
	struct QUESTION *qinfo = NULL;

	//printf("Resolving %s" , host);

	s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries

	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);
	dest.sin_addr.s_addr = inet_addr(dns_servers[0]); //dns servers

	if(connect(s, (struct sockaddr *)&dest, sizeof(dest)) == -1)
		printf("connect() failed\n");

	//Set the DNS structure to standard queries
	dns = (struct DNS_HEADER *)&buf;

	dns->id = (unsigned short) htons(getpid());
	dns->qr = 0; //This is a query
	dns->opcode = 0; //This is a standard query
	dns->aa = 0; //Not Authoritative
	dns->tc = 0; //This message is not truncated
	dns->rd = 1; //Recursion Desired
	dns->ra = 0; //Recursion not available! hey we dont have it (lol)
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); //we have only 1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;

	//point to the query portion
	qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];

	ChangetoDnsNameFormat(qname , host);
	qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it

	qinfo->qtype = htons( query_type ); //type of the query , A , MX , CNAME , NS etc
	qinfo->qclass = htons(1); //its internet

	//printf("\nSending Packet...\n");
	if(write(s, (char *)buf, sizeof(struct DNS_HEADER) + (strlen((const char *)qname)+1) + sizeof(struct QUESTION)) == 1)
		printf("write() failed");
	//printf("Done\n");

	//printf("Receiving answer...\n");
	if(read(s, (char *)buf, 65536) == 1)
		printf("read() failed");
	//printf("Done\n");
	printf("\n\n");

	dns = (struct DNS_HEADER*) buf;

	//move ahead of the dns header and the query field
	reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];

	//Start reading answers
	stop=0;

	for(i=0;i<ntohs(dns->ans_count);i++) {
		answers[i].name=ReadName(reader,buf,&stop);
		reader = reader + stop;

		answers[i].resource = (struct R_DATA*)(reader);
		reader = reader + sizeof(struct R_DATA);

		if(ntohs(answers[i].resource->type) == 1) { //if its an ipv4 address
			answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
			for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
				answers[i].rdata[j]=reader[j];
			answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
			reader = reader + ntohs(answers[i].resource->data_len);
		}

		else if(ntohs(answers[i].resource->type) == 28) { //if its an ipv6 address
			answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
			for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
				answers[i].rdata[j]=reader[j];
			answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
			reader = reader + ntohs(answers[i].resource->data_len);
		}

		else if(ntohs(answers[i].resource->type) == 2) {
			answers[i].rdata = ReadName(reader, buf, &stop);
			reader = reader + ntohs(answers[i].resource->data_len);
		}

		else if(ntohs(answers[i].resource->type) == 5) {
			answers[i].rdata = ReadName(reader, buf, &stop);
			reader += stop;
		}

		else if(ntohs(answers[i].resource->type) == 6)
			printf("This is SOA");

		else if(ntohs(answers[i].resource->type) == 15) {
			answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
			reader += 2;
			answers[i].rdata = ReadName(reader, buf, &stop);
			reader = reader + ntohs(answers[i].resource->data_len) - 2;
		}

		else
			printf("This is else part\n");

	}

	//read authorities
	for(i=0;i<ntohs(dns->auth_count);i++)
	{
		auth[i].name=ReadName(reader,buf,&stop);
		reader+=stop;

		auth[i].resource=(struct R_DATA*)(reader);
		reader+=sizeof(struct R_DATA);

		auth[i].rdata=ReadName(reader,buf,&stop);
		reader+=stop;
	}

	//read additional
	for(i=0;i<ntohs(dns->add_count);i++)
		{
		addit[i].name=ReadName(reader,buf,&stop);
		reader+=stop;

		addit[i].resource=(struct R_DATA*)(reader);
		reader+=sizeof(struct R_DATA);

		if(ntohs(addit[i].resource->type)==1)
			{
			addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
			for(j=0;j<ntohs(addit[i].resource->data_len);j++)
				addit[i].rdata[j]=reader[j];

			addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
			reader+=ntohs(addit[i].resource->data_len);
			}
		else if(ntohs(addit[i].resource->type) == 28) //if its an ipv4 address
			{
			addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));

			for(j=0 ; j<ntohs(addit[i].resource->data_len) ; j++)
				{
				addit[i].rdata[j]=reader[j];
				}

			addit[i].rdata[ntohs(addit[i].resource->data_len)] = '\0';
			reader = reader + ntohs(addit[i].resource->data_len);
			}
		else if(ntohs(addit[i].resource->type) == 2) {
			printf("This is NS");
		}
		else if(ntohs(addit[i].resource->type) == 5) {
			printf("This is CNAME");
		}
		else if(ntohs(addit[i].resource->type) == 6) {
			printf("This is SOA");
		}
		else if(ntohs(addit[i].resource->type) == 15) {
			printf("This is MX");
		}
		else {
			printf("This is else in additional");
		}
	}

	//print answers
	//printf("\nAnswer Records : %d \n" , ntohs(dns->ans_count) );
	for(i=0 ; i < ntohs(dns->ans_count) ; i++)
		{
		printf("Name : %s ",answers[0].name);

		if( ntohs(answers[i].resource->type) == T_A) { //IPv4 address
			long *p;
			p=(long*)answers[i].rdata;
			a.sin_addr.s_addr=(*p); //working without ntohl
			printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
		}
		else if( ntohs(answers[i].resource->type) == 28) { //IPv6 address
			strcpy((char *)b.sin6_addr.s6_addr,(char *)answers[i].rdata);
			inet_ntop(AF_INET6, &b.sin6_addr, str, sizeof(str));
			printf("has IPv6 address : %s",str);
		}

		else if(ntohs(answers[i].resource->type)==2) {
			printf("has nameserver: %s",answers[i].rdata);
		}

		else if(ntohs(answers[i].resource->type)==5) {
			printf("has alias name : %s",answers[i].rdata);
		}

		else if(ntohs(answers[i].resource->type)==15) {
			//Canonical name for an alias
			printf("has mail exchange : %s",answers[i].rdata);
		}

		printf("\n");
		}

	//print authorities
	//printf("\nAuthoritive Records : %d \n" , ntohs(dns->auth_count) );
	for( i=0 ; i < ntohs(dns->auth_count) ; i++) {
		printf("Name : %s ",auth[i].name);
		if(ntohs(auth[i].resource->type)==5) {
			printf("has nameserver : %s",auth[i].rdata);
		}
		printf(" ");
	}

	//print additional resource records
	//printf("\nAdditional Records : %d \n" , ntohs(dns->add_count) );
	for(i=0; i < ntohs(dns->add_count) ; i++)
		{
		printf("Name : %s ",addit[i].name);
		if(ntohs(addit[i].resource->type)==1)
			{
			long *p;
			p=(long*)addit[i].rdata;
			a.sin_addr.s_addr=(*p);
			printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
			}
		else if( ntohs(addit[i].resource->type) == 28) //IPv6 address
			{
			strcpy((char *)b.sin6_addr.s6_addr,(char *)addit[i].rdata);
			inet_ntop(AF_INET6, &b.sin6_addr, str, sizeof(str));
			printf("has IPv6 address : %s",str);
			}
		printf("\n");
		}
	return;
}

/*
 *
 * */
u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
	unsigned char *name;
	unsigned int p=0,jumped=0,offset;
	int i , j;

	*count = 1;
	name = (unsigned char*)malloc(256);

	name[0]='\0';

	//read the names in 3www6google3com format
	while(*reader!=0)
		{
		if(*reader>=192)
			{
			offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
			reader = buffer + offset - 1;
			jumped = 1; //we have jumped to another location so counting wont go up!
			}
		else
			{
			name[p++]=*reader;
			}

		reader = reader+1;

		if(jumped==0)
			{
			*count = *count + 1; //if we havent jumped to another location then we can count up
			}
		}

	name[p]='\0'; //string complete
	if(jumped==1) {
		*count = *count + 1; //number of steps we actually moved forward in the packet
	}

	//now convert 3www6google3com0 to www.google.com
	for(i=0;i<(int)strlen((const char*)name);i++)
		{
		p=name[i];
		for(j=0;j<(int)p;j++)
			{
			name[i]=name[i+1];
			i=i+1;
			}
		name[i]='.';
		}
	name[i-1]='\0'; //remove the last dot
	return name;
}

/*
 * Get the DNS servers from /etc/resolv.conf file on Linux
 * */
void get_dns_servers()
{
	FILE *fp;
	char line[200] , *p;
	if((fp = fopen("/etc/resolv.conf" , "r")) == NULL)
		{
		printf("Failed opening /etc/resolv.conf file \n");
		}

	while(fgets(line , 200 , fp))
		{
		if(line[0] == '#')
			{
			continue;
			}
		if(strncmp(line , "nameserver" , 10) == 0)
			{
			p = strtok(line , " ");
			p = strtok(NULL , " ");

			//p now is the dns ip :)
			//????
			}
		}

	strcpy(dns_servers[0] , "8.8.8.8");
	strcpy(dns_servers[1] , "208.67.220.220");
}

/*
 * This will convert www.google.com to 3www6google3com
 * got it :)
 * */
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host)
{
	int lock = 0 , i;
	strcat((char*)host,".");

	for(i = 0 ; i < strlen((char*)host) ; i++)
		{
		if(host[i]=='.')
			{
			*dns++ = i-lock;
			for(;lock<i;lock++)
				{
				*dns++=host[lock];
				}
			lock++; //or lock=i+1;
			}
		}
	*dns++='\0';
}
void set_dns_server(unsigned char* arg)
{
    strcpy(dns_servers[0] , arg);
}
