#include "dns-head.h"
#include<ctype.h> 
int main( int argc , char *argv[])
{
    unsigned char hostname[100];
    int i=1, check=-1, j=0;
    char *dns_serv=NULL;
    char *domain_list[5];
    for(;i<argc;i++)
    {
	if(!strcmp(argv[i],"-s"))
	{
		check=0;	
		dns_serv=argv[i+1];
		i++;	
	}	   
	else
	{
		domain_list[j++]=argv[i];
	}
    } 
    //Get the DNS servers from the resolv.conf file
    if(check==0)
    {
	set_dns_server(dns_serv);
    }
    else
    {
    	get_dns_servers();
    } 
    //Get the hostname from the terminal
    i=0;
    while(j!=0)
    {
	char *p = (char*)malloc(strlen(domain_list[i]));
	strcpy(p,domain_list[i]);
	//Now get the ip of this hostname , A record
	for(i = 0; i < 5; i++)
	ngethostbyname(p , arr[i]);	
	i++;
	j--;
	free(p);
    }
    
 return 0;
}
 

