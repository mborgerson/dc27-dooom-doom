//
// Copyright(C) 2005-2014 Simon Howard
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// DESCRIPTION:
//     Networking module which uses SDL_net
//

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "doomtype.h"
#include "i_system.h"
#include "m_argv.h"
#include "m_misc.h"
#include "net_defs.h"
#include "net_io.h"
#include "net_packet.h"
#include "net_sdl.h"
#include "z_zone.h"

//
// NETWORKING
//

#if XBOX
#include "../../net.h"
#else
#include <SDL_net.h>
#endif

#define DEFAULT_PORT 2342
#define MAX_SOCKETS 32
#define MAX_PACKET_SIZE 1500

static boolean initted = false;
static int port = DEFAULT_PORT;

#define IS_TCP 0

#ifdef IS_TCP
TCPsocket tcpsocket;
TCPsocket serverconnections[MAX_SOCKETS];
SDLNet_SocketSet clientsocketSet;
SDLNet_SocketSet serversocketSet;
#else
static UDPsocket udpsocket;
static UDPpacket *recvpacket;
#endif

typedef struct
{
    net_addr_t net_addr;
    IPaddress sdl_addr;
} addrpair_t;

static addrpair_t **addr_table;
static int addr_table_size = -1;

// Initializes the address table

static void NET_SDL_InitAddrTable(void)
{
    addr_table_size = 16;

    addr_table = Z_Malloc(sizeof(addrpair_t *) * addr_table_size,
                          PU_STATIC, 0);
    memset(addr_table, 0, sizeof(addrpair_t *) * addr_table_size);
}

static boolean AddressesEqual(IPaddress *a, IPaddress *b)
{
    return a->host == b->host
        && a->port == b->port;
}

// Finds an address by searching the table.  If the address is not found,
// it is added to the table.

static net_addr_t *NET_SDL_FindAddress(IPaddress *addr)
{
    addrpair_t *new_entry;
    int empty_entry = -1;
    int i;

    if (addr_table_size < 0)
    {
        NET_SDL_InitAddrTable();
    }

    for (i=0; i<addr_table_size; ++i)
    {
        if (addr_table[i] != NULL
         && AddressesEqual(addr, &addr_table[i]->sdl_addr))
        {
            return &addr_table[i]->net_addr;
        }

        if (empty_entry < 0 && addr_table[i] == NULL)
            empty_entry = i;
    }

    // Was not found in list.  We need to add it.

    // Is there any space in the table? If not, increase the table size

    if (empty_entry < 0)
    {
        addrpair_t **new_addr_table;
        int new_addr_table_size;

        // after reallocing, we will add this in as the first entry
        // in the new block of memory

        empty_entry = addr_table_size;
        
        // allocate a new array twice the size, init to 0 and copy 
        // the existing table in.  replace the old table.

        new_addr_table_size = addr_table_size * 2;
        new_addr_table = Z_Malloc(sizeof(addrpair_t *) * new_addr_table_size,
                                  PU_STATIC, 0);
        memset(new_addr_table, 0, sizeof(addrpair_t *) * new_addr_table_size);
        memcpy(new_addr_table, addr_table, 
               sizeof(addrpair_t *) * addr_table_size);
        Z_Free(addr_table);
        addr_table = new_addr_table;
        addr_table_size = new_addr_table_size;
    }

    // Add a new entry
    
    new_entry = Z_Malloc(sizeof(addrpair_t), PU_STATIC, 0);

    new_entry->sdl_addr = *addr;
    new_entry->net_addr.refcount = 0;
    new_entry->net_addr.handle = &new_entry->sdl_addr;
    new_entry->net_addr.module = &net_sdl_module;

    addr_table[empty_entry] = new_entry;

    return &new_entry->net_addr;
}

static void NET_SDL_FreeAddress(net_addr_t *addr)
{
    int i;
    
    for (i=0; i<addr_table_size; ++i)
    {
        if (addr == &addr_table[i]->net_addr)
        {
            Z_Free(addr_table[i]);
            addr_table[i] = NULL;
            return;
        }
    }

    I_Error("NET_SDL_FreeAddress: Attempted to remove an unused address!");
}


net_addr_t *NET_SDL_ResolveAddress(const char *address)
{
    IPaddress ip;
    char *addr_hostname;
    int addr_port;
    int result;
    char *colon;

    colon = strchr(address, ':');

    addr_hostname = M_StringDuplicate(address);
    if (colon != NULL)
    {
	addr_hostname[colon - address] = '\0';
	addr_port = atoi(colon + 1);
    }
    else
    {
	addr_port = DEFAULT_PORT;
    }
    
    result = SDLNet_ResolveHost(&ip, addr_hostname, addr_port);

    free(addr_hostname);

    if (result)
    {
        // unable to resolve

        return NULL;
    }
    else
    {
        return NET_SDL_FindAddress(&ip);
    }
}


void NET_SDL_AddrToString(net_addr_t *addr, char *buffer, int buffer_len)
{
    IPaddress *ip;
    uint32_t host;
    uint16_t port;

    ip = (IPaddress *) addr->handle;
    host = SDLNet_Read32(&ip->host);
    port = SDLNet_Read16(&ip->port);

    M_snprintf(buffer, buffer_len, "%i.%i.%i.%i",
               (host >> 24) & 0xff, (host >> 16) & 0xff,
               (host >> 8) & 0xff, host & 0xff);


    // If we are using the default port we just need to show the IP address,
    // but otherwise we need to include the port. This is important because
    // we use the string representation in the setup tool to provided an
    // address to connect to.
    if (port != DEFAULT_PORT)
    {
        char portbuf[10];
        M_snprintf(portbuf, sizeof(portbuf), ":%i", port);
        M_StringConcat(buffer, portbuf, buffer_len);
    }
}


static boolean NET_SDL_InitClient(void)
{
#ifdef IS_TCP
    int p;
    Uint16 port = 0;
    const char* host = "127.0.0.1";

    if (initted)
        return true;

    //!
    // @category net
    // @arg <n>
    //
    // Use the specified UDP port for communications, instead of 
    // the default (2342).
    //
    
    p = M_CheckParmWithArgs("-port", 1);
    if (p > 0)
        port = atoi(myargv[p+1]);


    p = M_CheckParmWithArgs("-connect", 1);
    if (p > 0)
        host = myargv[p+1];

    //printf("host %s port %d\n", host, port);

    SDLNet_Init();

    //udpsocket = SDLNet_UDP_Open(0);
    IPaddress ip;
    if(SDLNet_ResolveHost(&ip,host,port)==-1) {
        printf("NET_SDL_InitClient: SDLNet_ResolveHost ERROR");
    }

    //printf("opening %s %d\n", host, ip.port);
    tcpsocket = SDLNet_TCP_Open(&ip);

    //printf("attempt made\n");
    if (tcpsocket == NULL)
    {
        I_Error("NET_SDL_InitClient: Unable to open a socket host: %x!", ip.host);
        
        //printf("NET_SDL_InitClient: Unable to open a socket host: %x!\n", ip.host);
    }
    
    //recvpacket = SDLNet_AllocPacket(1500);

#ifdef DROP_PACKETS
    srand(time(NULL));
#endif
    serversocketSet = NULL;
    clientsocketSet = SDLNet_AllocSocketSet(MAX_SOCKETS);
    SDLNet_TCP_AddSocket( clientsocketSet, tcpsocket );

    initted = true;

    return true;
#else
    int p;

    if (initted)
        return true;

    //!
    // @category net
    // @arg <n>
    //
    // Use the specified UDP port for communications, instead of 
    // the default (2342).
    //

    p = M_CheckParmWithArgs("-port", 1);
    if (p > 0)
        port = atoi(myargv[p+1]);

    SDLNet_Init();

    udpsocket = SDLNet_UDP_Open(0);

    if (udpsocket == NULL)
    {
        I_Error("NET_SDL_InitClient: Unable to open a socket!");
    }
    
    recvpacket = SDLNet_AllocPacket(1500);

#ifdef DROP_PACKETS
    srand(time(NULL));
#endif

    initted = true;

    return true;
#endif
}

static boolean NET_SDL_InitServer(void)
{
#ifdef IS_TCP
    int p;
    Uint16 port = DEFAULT_PORT;

    if (initted)
        return true;

    p = M_CheckParmWithArgs("-port", 1);
    if (p > 0)
        port = atoi(myargv[p+1]);

    SDLNet_Init();

    //udpsocket = SDLNet_UDP_Open(port);

    IPaddress ip;
    if(SDLNet_ResolveHost(&ip,NULL,port)==-1) {
        printf("NET_SDL_InitServer: SDLNet_ResolveHost ERROR");
    }

    //printf("opening server socket\n");
    tcpsocket = SDLNet_TCP_Open(&ip);

    if (tcpsocket == NULL)
    {
        I_Error("NET_SDL_InitServer: Unable to bind to port %i", port);
    }

    //recvpacket = SDLNet_AllocPacket(1500);
#ifdef DROP_PACKETS
    srand(time(NULL));
#endif

    clientsocketSet = NULL;
    serversocketSet = SDLNet_AllocSocketSet(MAX_SOCKETS);    
    SDLNet_TCP_AddSocket( serversocketSet, tcpsocket );

    for(int i = 0; i < MAX_SOCKETS; i++) {
        serverconnections[i] = NULL;
    }


    initted = true;

    return true;
#else
    int p;
    Uint16 port = DEFAULT_PORT;

    if (initted)
        return true;

    p = M_CheckParmWithArgs("-port", 1);
    if (p > 0)
        port = atoi(myargv[p+1]);

    SDLNet_Init();

    udpsocket = SDLNet_UDP_Open(port);

    if (udpsocket == NULL)
    {
        I_Error("NET_SDL_InitServer: Unable to bind to port %i", port);
    }

    recvpacket = SDLNet_AllocPacket(1500);
#ifdef DROP_PACKETS
    srand(time(NULL));
#endif

    initted = true;

    return true;
#endif
}

static void NET_SDL_SendPacket(net_addr_t *addr, net_packet_t *packet)
{

#ifdef IS_TCP
    if(serversocketSet == NULL) { //is client
        if (!SDLNet_TCP_Send(tcpsocket, packet->data, packet->len))
        {
            I_Error("NET_SDL_SendPacket: Error transmitting packet: %s",
                    SDLNet_GetError());
        }
    }
    else {
        for (int i = 0; i < MAX_SOCKETS; i++)
        {
            TCPsocket conn = serverconnections[i];
            if(conn != NULL) {
                //printf("sending data to %d\n", i);
                net_addr_t* conn_addr = NET_SDL_FindAddress(SDLNet_TCP_GetPeerAddress(conn));
                if(conn_addr == addr) {
                    if (!SDLNet_TCP_Send(conn, packet->data, packet->len))
                    {
                        I_Error("NET_SDL_SendPacket: Error transmitting packet: %s",
                                SDLNet_GetError());
                    }
                }
            }
        }
    }
#else
    UDPpacket sdl_packet;
    IPaddress ip;
   
    if (addr == &net_broadcast_addr)
    {
        SDLNet_ResolveHost(&ip, NULL, port);
        ip.host = INADDR_BROADCAST;
    }
    else
    {
        ip = *((IPaddress *) addr->handle);
    }

#if 0
    {
        static int this_second_sent = 0;
        static int lasttime;

        this_second_sent += packet->len + 64;

        if (I_GetTime() - lasttime > TICRATE)
        {
            printf("%i bytes sent in the last second\n", this_second_sent);
            lasttime = I_GetTime();
            this_second_sent = 0;
        }
    }
#endif

#ifdef DROP_PACKETS
    if ((rand() % 4) == 0)
        return;
#endif

    sdl_packet.channel = 0;
    sdl_packet.data = packet->data;
    sdl_packet.len = packet->len;
    sdl_packet.address = ip;

    if (!SDLNet_UDP_Send(udpsocket, -1, &sdl_packet))
    {
        I_Error("NET_SDL_SendPacket: Error transmitting packet: %s",
                SDLNet_GetError());
    }
#endif

}

static boolean NET_SDL_RecvPacket(net_addr_t **addr, net_packet_t **packet)
{
#ifdef IS_TCP
    int length_recv = -1;
    char peer_host_name_buffer[80];
    
    //printf("receiving packet\n");

    if(serversocketSet == NULL) { //is client
        if(clientsocketSet == NULL) {
            //printf("clientsocketSet not init\n");
            return false; //error, clientsocketSet not init
        }
        int numClientActiveConnections = SDLNet_CheckSockets( clientsocketSet, 5 );

        //printf("client trying to recv packet\n");
        if(numClientActiveConnections > 0) {
            //printf("client has connections\n");
            //if(SDLNet_SocketReady(tcpsocket) == 0)
            //    return false;
            //printf("client recv packet\n");
            
            //SDLNet_TCP_AddSocket( clientsocketSet, newConnection );
            char data[MAX_PACKET_SIZE];
	        memset( data, 0, MAX_PACKET_SIZE );
   
            length_recv = SDLNet_TCP_Recv(tcpsocket, data, MAX_PACKET_SIZE);

            if (length_recv < 0)
            {
                I_Error("NET_SDL_RecvPacket: Error receiving packet: %s",
                        SDLNet_GetError());
            }
            //printf("received %d bytes\n", length_recv);
            // no packets received

            if (length_recv == 0) {
                return false;
            }

            // Put the data into a new packet structure

            *packet = NET_NewPacket(length_recv); //result == size of msg received
            memcpy((*packet)->data, data, length_recv);
            (*packet)->len = length_recv;

            // Address

            net_addr_t* peer_ip = NET_SDL_FindAddress(SDLNet_TCP_GetPeerAddress(tcpsocket));

	        memset( peer_host_name_buffer, 0, 80 );
            NET_SDL_AddrToString(peer_ip, peer_host_name_buffer, 80);        
            //printf("peer_hostname %s\n", peer_host_name_buffer); 
            for(int i = 0; i < 80; i++) {
                char c = peer_host_name_buffer[i];
                if(c == ':') {
                    //printf("found value, splitting\n");
                    peer_host_name_buffer[i] = '\0';
                    break;
                }
            }


            //peer_ip_string = strtok(&peer_host_name_buffer, ':');   
            //printf("peer_ip_string%s\n", peer_host_name_buffer);
    
            *addr = NET_SDL_ResolveAddress(peer_host_name_buffer);
            //if(*addr != NULL) 
            //    printf("recv packet from %s\n", NET_AddrToString(*addr));

            return true;

        }

    }
    else { //is server

        int numServerActiveConnections = SDLNet_CheckSockets( serversocketSet, 5 );

        if(numServerActiveConnections > 0) {
            //printf("active conn\n");
            
            TCPsocket newConnection = SDLNet_TCP_Accept( tcpsocket );
            if(newConnection != NULL) {
                //printf("adding new connection\n");
                int i = 0;
                for(i = 0; i < MAX_SOCKETS; i++)
                {
                    if(serverconnections[i] == NULL) {
                        //printf("adding newconn to %d\n", i);
                        serverconnections[i] = newConnection;
                        SDLNet_TCP_AddSocket( serversocketSet, newConnection );
                        break;
                    }
                }
                if(i >= MAX_SOCKETS)
                    printf("no free sockets to add\n");
            }

            //printf("server receiving packet\n");

            char data[MAX_PACKET_SIZE];
	        memset( data, 0, MAX_PACKET_SIZE );

            for(int i = 0; i < MAX_SOCKETS; i++)
            {
                TCPsocket conn = serverconnections[i];
                if(conn == NULL || SDLNet_SocketReady(conn) == 0) {
                    continue;
                }

                length_recv = SDLNet_TCP_Recv(conn, data, MAX_PACKET_SIZE);
            
                //printf("received packets %d\n", length_recv);
                if (length_recv < 0)
                {
                    I_Error("NET_SDL_RecvPacket: Error receiving packet: %s",
                            SDLNet_GetError());
                }

                //printf("received %d bytes\n", length_recv);
            
                *addr = NET_SDL_ResolveAddress(peer_host_name_buffer);

                // no packets received
                if (length_recv == 0) {
                    //printf("empty packets %d\n", i);
                    serverconnections[i] = NULL;
                    //if(conn != NULL) {
                    //   SDLNet_TCP_DelSocket( serversocketSet, conn );
                    //}
                    return false;
                }



                //init packet
                *packet = NET_NewPacket(length_recv); //result == size of msg received
                //set length
                (*packet)->len = length_recv;
                //set addr            
                *addr = NET_SDL_FindAddress(SDLNet_TCP_GetPeerAddress(conn));
                //if(*addr != NULL) 
                //    printf("recv packet from %s\n", NET_AddrToString(*addr));

                memcpy((*packet)->data, data, length_recv);

                return true;
            }
        }

    }

    return false;
#else
    int result;
    result = SDLNet_UDP_Recv(udpsocket, recvpacket);

    if (result < 0)
    {
        I_Error("NET_SDL_RecvPacket: Error receiving packet: %s",
                SDLNet_GetError());
    }

    // no packets received

    if (result == 0)
        return false;

    // Put the data into a new packet structure

    *packet = NET_NewPacket(recvpacket->len);
    memcpy((*packet)->data, recvpacket->data, recvpacket->len);
    (*packet)->len = recvpacket->len;

    // Address

    *addr = NET_SDL_FindAddress(&recvpacket->address);

    return true;
#endif
}

// Complete module

net_module_t net_sdl_module =
{
    NET_SDL_InitClient,
    NET_SDL_InitServer,
    NET_SDL_SendPacket,
    NET_SDL_RecvPacket,
    NET_SDL_AddrToString,
    NET_SDL_FreeAddress,
    NET_SDL_ResolveAddress,
};

