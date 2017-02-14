#include<bios.h>
#include<stdio.h>
#include<setjmp.h>
#include<string.h>
#include<stdlib.h>
#include<dos.h>
#define MAX_PACKET 200
static unsigned char buff[1000];
static unsigned char mac[7];

static unsigned char buff2[1000];
static unsigned char mac2[7];
unsigned char tp[2]={0x06,0x08};
unsigned handle;
unsigned handle2;
int length,i;
int packets=0;

int packets2=0;

static unsigned char iip[2]={1,0};
static unsigned char arpi[50][2];
static unsigned char arpm[50][6];
static int ilist=0;
static int mlist=0;

static unsigned char iip2[2]={2,0};
static unsigned char arpi2[50][2];
static unsigned char arpm2[50][6];
static int ilist2=0;
static int mlist2=0;

void pack_packet(unsigned char *ptr,unsigned char *mdest,unsigned char *diip,unsigned char *cotnt)
{
    int i=0;
    for(i=0;i<6;i++)
        ptr[i]=mdest[i];
    for(i=6;i<12;i++)
        ptr[i]=mac[i-6];
    ptr[12]=tp[0];
    ptr[13]=tp[1];
    ptr[14]=diip[0];
    ptr[15]=diip[1];
    ptr[16]=iip[0];
    ptr[17]=iip[1];
    for(i=18;i<=strlen(cotnt)+18;i++)
        ptr[i]=cotnt[i-18];
}

void pack_packet2(unsigned char *ptr,unsigned char *mdest,unsigned char *diip,unsigned char *cotnt)
{
    int i=0;
    for(i=0;i<6;i++)
        ptr[i]=mdest[i];
    for(i=6;i<12;i++)
        ptr[i]=mac2[i-6];
    ptr[12]=tp[0];
    ptr[13]=tp[1];
    ptr[14]=diip[0];
    ptr[15]=diip[1];
    ptr[16]=iip2[0];
    ptr[17]=iip2[1];
    for(i=18;i<=strlen(cotnt)+18;i++)
        ptr[i]=cotnt[i-18];
}

int search_arp(unsigned char *siip)
{
    int i;
    for(i=0;i<ilist;i++)
    {
        if(arpi[i][0]==siip[0] && arpi[i][1]==siip[1])
            return i;
    }
    return -1;
}

int search_arp2(unsigned char *siip)
{
    int i;
    for(i=0;i<ilist2;i++)
    {
        if(arpi2[i][0]==siip[0] && arpi2[i][1]==siip[1])
            return i;
    }
    return -1;
}

void add_arp(unsigned char *niip,unsigned char *nmac)
{

    int i;
    if(search_arp(niip)!=-1)
        return;
    arpi[ilist][0]=niip[0];
    arpi[ilist][1]=niip[1];
    ilist++;
    for(i=0;i<6;i++)
    {
        arpm[mlist][i]=nmac[i];
    }
    mlist++;
}

void add_arp2(unsigned char *niip,unsigned char *nmac)
{

    int i;
    if(search_arp2(niip)!=-1)
        return;
    arpi2[ilist2][0]=niip[0];
    arpi2[ilist2][1]=niip[1];
    ilist2++;
    for(i=0;i<6;i++)
    {
        arpm2[mlist2][i]=nmac[i];
    }
    mlist2++;
}

int get_driver()
{
	int data;
	union REGS inregs,outregs;
	struct SREGS segregs;
	char far *ptr;
	inregs.h.ah=0x1;
	inregs.h.al=255;
	int86x(0x60,&inregs,&outregs,&segregs);
	ptr=MK_FP(segregs.ds,outregs.x.si);
	if(outregs.x.cflag!=0)
	{
		printf("Driver carry flag , errorno : %x , %x\n",outregs.x.cflag,outregs.h.dh);
		return outregs.h.dh;;
	}
	printf("Driver class : %x\n",outregs.h.ch);
	printf("Driver type : %x\n",outregs.x.dx);
	printf("Driver number : %x\n",outregs.h.cl);
	printf("Driver name : %s\n",ptr);
	return outregs.h.dh;
}

int get_driver2()
{
	int data;
	union REGS inregs,outregs;
	struct SREGS segregs;
	char far *ptr;
	inregs.h.ah=0x1;
	inregs.h.al=255;
	int86x(0x70,&inregs,&outregs,&segregs);
	ptr=MK_FP(segregs.ds,outregs.x.si);
	if(outregs.x.cflag!=0)
	{
		printf("Driver carry flag , errorno : %x , %x\n",outregs.x.cflag,outregs.h.dh);
		return outregs.h.dh;;
	}
	printf("Driver class : %x\n",outregs.h.ch);
	printf("Driver type : %x\n",outregs.x.dx);
	printf("Driver number : %x\n",outregs.h.cl);
	printf("Driver name : %s\n",ptr);
	return outregs.h.dh;
}

int getAddress()
{
	int len;
	int ptr,p,err,i;
	unsigned char far *src=farmalloc(6);
	union REGS inregs,outregs;
	struct SREGS segregs;
	inregs.h.ah=0x6;
	inregs.x.di=FP_OFF(src);
	inregs.x.cx=6;
	segregs.es=FP_SEG(src);
	int86x(0x60,&inregs,&outregs,&segregs);
	err=outregs.h.dh;
	for(i=0;i<6;i++)
		mac[i]=src[i];
	mac[6]='\0';
	printf("\nMAC address : ");
	for(i=0;i<6;i++)
		printf("%02x:",src[i] & 0xff);
	return err;
}

int getAddress2()
{
	int len;
	int ptr,p,err,i;
	unsigned char far *src=farmalloc(6);
	union REGS inregs,outregs;
	struct SREGS segregs;
	inregs.h.ah=0x6;
	inregs.x.di=FP_OFF(src);
	inregs.x.cx=6;
	segregs.es=FP_SEG(src);
	int86x(0x70,&inregs,&outregs,&segregs);
	err=outregs.h.dh;
	for(i=0;i<6;i++)
		mac2[i]=src[i];
	mac2[6]='\0';
	printf("\nMAC address2 : ");
	for(i=0;i<6;i++)
		printf("%02x:",src[i] & 0xff);
	return err;
}

int compare_mac()
{
	int i,flag=0;
	for(i=0;i<6;i++)
	{
		if((buff[i]) != mac[i])
			return 1;
	}
	return flag;
}

int compare_mac2()
{
	int i,flag=0;
	for(i=0;i<6;i++)
	{
		if((buff2[i]) != mac2[i])
			return 1;
	}
	return flag;
}

int compare_arp()
{
    unsigned char rip[2];
    unsigned char rmac[6];
    int i=0,flag=0;
    for(i=0;i<6;i++)
        if(buff[i]!=0xff)
            return 0;
    if(buff[18]!='#' || buff[19]!='#' || buff[20]!='#' )
        return 0;
    rip[0]=buff[16];
    rip[1]=buff[17];
    for(i=0;i<6;i++)
        rmac[i]=buff[i+6];
    add_arp(rip,rmac);
    return 1;
}

int compare_arp2()
{
    unsigned char rip[2];
    unsigned char rmac[6];
    int i=0,flag=0;
    for(i=0;i<6;i++)
        if(buff2[i]!=0xff)
            return 0;
    if(buff2[18]!='#' || buff2[19]!='#' || buff2[20]!='#' )
        return 0;
    rip[0]=buff2[16];
    rip[1]=buff2[17];
    for(i=0;i<6;i++)
        rmac[i]=buff2[i+6];
    add_arp2(rip,rmac);
    return 1;
}


void display_arp()
{
    int i,j;
    printf("\n\nARP List :\n");
    for(i=0;i<ilist;i++)
    {
         printf("%x.%x\t",arpi[i][0],arpi[i][1]);
         for(j=0;j<6;j++)
            printf("%02x:",arpm[i][j]);
         printf("\n");
    }
    printf("\n");
}

void display_arp2()
{
    int i,j;
    printf("\n\nARP List :\n");
    for(i=0;i<ilist2;i++)
    {
         printf("%x.%x\t",arpi2[i][0],arpi2[i][1]);
         for(j=0;j<6;j++)
            printf("%02x:",arpm2[i][j]);
         printf("\n");
    }
    printf("\n");
}

void send_packet(unsigned char *ptr,unsigned char *dip)
{
	int i=0;
	union REGS inregs,outregs;
	struct SREGS segreg;
	unsigned char pack[70];
	int dmac=search_arp(dip);
	if(dmac==-1)
	{
		printf("\nNo match\n");
		return;  /*send to router*/
	}
	pack_packet(pack,arpm[dmac],dip,ptr);
	inregs.h.ah=0x4;
	inregs.x.cx=70;
	segreg.ds=FP_SEG(pack);
	inregs.x.si=FP_OFF(pack);
	int86x(0x60,&inregs,&outregs,&segreg);
	if(outregs.x.cflag)
		printf("Error sending packet\n\n");
}

void send_packet2(unsigned char *ptr,unsigned char *dip)
{
	int i=0;
	union REGS inregs,outregs;
	struct SREGS segreg;
	unsigned char pack[70];
	int dmac=search_arp2(dip);
	if(dmac==-1)
	{
		printf("\nNo match\n");
		return;  /*send to router*/
	}
	pack_packet2(pack,arpm2[dmac],dip,ptr);
	inregs.h.ah=0x4;
	inregs.x.cx=70;
	segreg.ds=FP_SEG(pack);
	inregs.x.si=FP_OFF(pack);
	int86x(0x70,&inregs,&outregs,&segreg);
	if(outregs.x.cflag)
		printf("Error sending packet\n\n");
}

void send_arp_broadcast()
{
    int i=0;
	union REGS inregs,outregs;
	struct SREGS segreg;
	unsigned char pack[70];
	for(i=0;i<6;i++)
        pack[i]=0xff;
    for(i=6;i<12;i++)
        pack[i]=mac[i-6];
    pack[12]=tp[0];
    pack[13]=tp[1];
    pack[14]=0xff;
    pack[15]=0xff;
    pack[16]=iip[0];
    pack[17]=iip[1];
    pack[18]='#';
    pack[19]='#';
    pack[20]='#';
	inregs.h.ah=0x4;
	inregs.x.cx=70;
	segreg.ds=FP_SEG(pack);
	inregs.x.si=FP_OFF(pack);
	int86x(0x60,&inregs,&outregs,&segreg);
	if(outregs.x.cflag)
		printf("Error sending ARP broadcast packet\n\n");
}

void send_arp_broadcast2()
{
    int i=0;
	union REGS inregs,outregs;
	struct SREGS segreg;
	unsigned char pack[70];
	for(i=0;i<6;i++)
        pack[i]=0xff;
    for(i=6;i<12;i++)
        pack[i]=mac2[i-6];
    pack[12]=tp[0];
    pack[13]=tp[1];
    pack[14]=0xff;
    pack[15]=0xff;
    pack[16]=iip2[0];
    pack[17]=iip2[1];
    pack[18]='#';
    pack[19]='#';
    pack[20]='#';
	inregs.h.ah=0x4;
	inregs.x.cx=70;
	segreg.ds=FP_SEG(pack);
	inregs.x.si=FP_OFF(pack);
	int86x(0x70,&inregs,&outregs,&segreg);
	if(outregs.x.cflag)
		printf("Error sending ARP broadcast packet\n\n");
}

static int print_packet(unsigned len)
{
	int i=0;
	printf("\nDestination MAC : ");
	for(i=0;i<6;i++)
	{
		printf("%02X:",buff[i]);
	}
	printf("\nSource MAC : ");
	for(i=6;i<12;i++)
		printf("%02X:",buff[i]);
	printf("\nSource IIP : %x.%x\nContent : ",buff[16],buff[17]);
	for(i=18;i<len;i++)
	{
		if(buff[i]=='\0')
			break;
		printf("%c",buff[i]);
	}
	printf("\n\n");
	return 0;
}

void forward_packet2()
{
   	int i=0;
	union REGS inregs,outregs;
	struct SREGS segreg;
	unsigned char dip[2];
	int dmac;
	dip[0]=buff2[14];
	dip[1]=buff2[15];
	dmac=search_arp(dip);
	if(dmac==-1)
	{
		printf("\nNo match\n");
		return;  /*send to router*/
	}
	for(i=0;i<6;i++)
        buff2[i]=arpm[dmac][i];
	inregs.h.ah=0x4;
	inregs.x.cx=70;
	segreg.ds=FP_SEG(buff2);
	inregs.x.si=FP_OFF(buff2);
	int86x(0x60,&inregs,&outregs,&segreg);
	if(outregs.x.cflag)
		printf("Error sending packet\n\n");
}

void forward_packet()
{
   	int i=0;
	union REGS inregs,outregs;
	struct SREGS segreg;
	unsigned char dip[2];
	int dmac;
	dip[0]=buff[14];
	dip[1]=buff[15];
	dmac=search_arp2(dip);
	if(dmac==-1)
	{
		printf("\nNo match\n");
		return;  /*send to router*/
	}
	for(i=0;i<6;i++)
        buff[i]=arpm2[dmac][i];
	inregs.h.ah=0x4;
	inregs.x.cx=70;
	segreg.ds=FP_SEG(buff);
	inregs.x.si=FP_OFF(buff);
	int86x(0x70,&inregs,&outregs,&segreg);
	if(outregs.x.cflag)
		printf("Error sending packet\n\n");
}

static int print_packet2(unsigned len)
{
	int i=0;
	printf("\nDestination MAC : ");
	for(i=0;i<6;i++)
	{
		printf("%02X:",buff2[i]);
	}
	printf("\nSource MAC : ");
	for(i=6;i<12;i++)
		printf("%02X:",buff2[i]);
	printf("\nSource IIP : %x.%x\nContent : ",buff2[16],buff2[17]);
	for(i=18;i<len;i++)
	{
		if(buff2[i]=='\0')
			break;
		printf("%c",buff2[i]);
	}
	printf("\n\n");
	return 0;
}

static void handle_packet(unsigned len)
{
    int i=0;
    if(compare_arp()==1)
        return;
    if(compare_mac()==1)
	return;
	forward_packet();
    print_packet(len);
}

static void handle_packet2(unsigned len)
{
    int i=0;
    if(compare_arp2()==1)
        return;
    if(compare_mac2()==1)
	return;
	forward_packet2();
    print_packet2(len);
}

static void interrupt receiver(unsigned bp,unsigned di,unsigned si,
					unsigned ds,unsigned es,unsigned dx,
					unsigned cx,unsigned bx,unsigned ax)
{
	unsigned turn=ax;
	if(turn==0)
	{
		es=FP_SEG(buff);
		di=FP_OFF(buff);
	}
	if(turn!=0)
	{
		handle_packet(cx);
	}
	packets++;
}

static void interrupt receiver2(unsigned bp,unsigned di,unsigned si,
					unsigned ds,unsigned es,unsigned dx,
					unsigned cx,unsigned bx,unsigned ax)
{
	unsigned turn=ax;
	if(turn==0)
	{
		es=FP_SEG(buff2);
		di=FP_OFF(buff2);
	}
	if(turn!=0)
	{
		handle_packet2(cx);
	}
	packets2++;
}

int access_type()
{
	static void * (far *r)() = &receiver;
	union REGS inregs,outregs;
	struct SREGS segregs;
	inregs.h.ah=0x2;
	inregs.x.bx=0x63;
	inregs.x.cx=0x0;
	inregs.h.al=0x1;
	inregs.h.dl=0x0;
	inregs.x.si=FP_OFF(tp);
	segregs.ds=FP_SEG(tp);
	segregs.es=FP_SEG(&receiver);
	inregs.x.di=FP_OFF(&receiver);
	int86x(0x60,&inregs,&outregs,&segregs);
	/*r();*/
	if(outregs.x.cflag!=0)
	{
		printf("\n\nClear flag, Error : %x %x\n",outregs.x.cflag,outregs.h.dh);
		return 0;
	}
	handle=outregs.x.ax;
	printf("\n\nInitialized listener.\n");
	printf("Handle : %x\n",outregs.x.ax);
	return outregs.x.ax;
}

int access_type2()
{
	static void * (far *r)() = &receiver2;
	union REGS inregs,outregs;
	struct SREGS segregs;
	inregs.h.ah=0x2;
	inregs.x.bx=0x63;
	inregs.x.cx=0x0;
	inregs.h.al=0x1;
	inregs.h.dl=0x0;
	inregs.x.si=FP_OFF(tp);
	segregs.ds=FP_SEG(tp);
	segregs.es=FP_SEG(&receiver2);
	inregs.x.di=FP_OFF(&receiver2);
	int86x(0x70,&inregs,&outregs,&segregs);
	/*r();*/
	if(outregs.x.cflag!=0)
	{
		printf("\n\nClear flag, Error : %x %x\n",outregs.x.cflag,outregs.h.dh);
		return 0;
	}
	handle2=outregs.x.ax;
	printf("\n\nInitialized listener.\n");
	printf("Handle : %x\n",outregs.x.ax);
	return outregs.x.ax;
}

void set_receive_mode()
{
	union REGS inregs,outregs;
	inregs.x.bx=handle;
	inregs.x.cx=6;
	inregs.h.ah=20;
	int86(0x60,&inregs,&outregs);
	if(outregs.x.cflag!=0)
	{
		printf("Error setting  receiver mode.\n\n");
	}
	printf("\n\nReceive mode changed to all\n");
}

void set_receive_mode2()
{
	union REGS inregs,outregs;
	inregs.x.bx=handle2;
	inregs.x.cx=6;
	inregs.h.ah=20;
	int86(0x70,&inregs,&outregs);
	if(outregs.x.cflag!=0)
	{
		printf("Error setting  receiver mode.\n\n");
	}
	printf("\n\nReceive mode changed to all\n");
}

int release_type(int h)
{
	union REGS inregs,outregs;
	inregs.h.ah=0x3;
	inregs.x.bx=handle;
	int86(0x60,&inregs,&outregs);
	if(outregs.x.cflag!=0)
	{
		printf("Error stopping receiver\n");
		return outregs.x.dh;
	}
	printf("\nClosed handle : %x\n\n",handle);
	return 0;
}

int release_type2(int h)
{
	union REGS inregs,outregs;
	inregs.h.ah=0x3;
	inregs.x.bx=handle2;
	int86(0x70,&inregs,&outregs);
	if(outregs.x.cflag!=0)
	{
		printf("Error stopping receiver\n");
		return outregs.x.dh;
	}
	printf("\nClosed handle : %x\n\n",handle);
	return 0;
}

main()
{
	clrscr();
	printf("Driver Test ...\n\n");
	get_driver();
	get_driver2();
	getAddress();
	getAddress2();
	access_type();
	access_type2();
	set_receive_mode();
	set_receive_mode2();
	send_arp_broadcast();
	send_arp_broadcast2();
	while(1)
	{
		char ptr[30];
		int i=0;
		unsigned char dip[2]={1,2};
		/*printf("\nSend : \n");*/
		while(1)
		{
		send_arp_broadcast();
		send_arp_broadcast2();
			ptr[i++]=getche();
			if(ptr[i-1]=='0')
			{
				ptr[i-1]='\0';
				break;
			}
		}
		if(strcmp(ptr,"arp")==0)
		{
			display_arp();
			continue;
		}
		if(strcmp(ptr,"arp2")==0)
		{
			display_arp2();
			continue;
		}
		if(strcmp(ptr,"exit")==0)
			break;
		/*send_packet(ptr,dip);
		fflush(stdin);
		fflush(stdout);*/
	}
	getch();
	release_type(handle);
	release_type2(handle);
	printf("Total packets received : %d\n",packets);
	getch();
	return;
}
