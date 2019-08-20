//
// Copyright(C) 1993-1996 Id Software, Inc.
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
//	Archiving: SaveGame I/O.
//	Thinker, Ticker.
//


#include "z_zone.h"
#include "p_local.h"
#include "../net_server.h"

#include "doomstat.h"

#include <stdlib.h>

int	leveltime;

//
// THINKERS
// All thinkers should be allocated by Z_Malloc
// so they can be operated on uniformly.
// The actual structures will vary in size,
// but the first element must be thinker_t.
//



// Both the head and tail of the thinker list.
thinker_t	thinkercap;


//
// P_InitThinkers
//
void P_InitThinkers (void)
{
    thinkercap.prev = thinkercap.next  = &thinkercap;
}




//
// P_AddThinker
// Adds a new thinker at the end of the list.
//
void P_AddThinker (thinker_t* thinker)
{
    thinkercap.prev->next = thinker;
    thinker->next = &thinkercap;
    thinker->prev = thinkercap.prev;
    thinkercap.prev = thinker;
}



//
// P_RemoveThinker
// Deallocation is lazy -- it will not actually be freed
// until its thinking turn comes up.
//
void P_RemoveThinker (thinker_t* thinker)
{
  // FIXME: NOP.
  thinker->function.acv = (actionf_v)(-1);
}



//
// P_AllocateThinker
// Allocates memory and adds a new thinker at the end of the list.
//
void P_AllocateThinker (thinker_t*	thinker)
{
}



//
// P_RunThinkers
//
void P_RunThinkers (void)
{
    thinker_t *currentthinker, *nextthinker;

    currentthinker = thinkercap.next;
    while (currentthinker != &thinkercap)
    {
	if ( currentthinker->function.acv == (actionf_v)(-1) )
	{
	    // time to remove it
            nextthinker = currentthinker->next;
	    currentthinker->next->prev = currentthinker->prev;
	    currentthinker->prev->next = currentthinker->next;
	    Z_Free(currentthinker);
	}
	else
	{
	    if (currentthinker->function.acp1)
		currentthinker->function.acp1 (currentthinker);
            nextthinker = currentthinker->next;
	}
	currentthinker = nextthinker;
    }
}

#define OOO_SECTOR_TAG1 777
#define OOO_SECTOR_TAG2 778
#define OOO_DMG_SECTOR_TAG 888

boolean is_ooo_sector_tag(short sector_tag) {
    return (sector_tag == OOO_SECTOR_TAG1) || (sector_tag == OOO_SECTOR_TAG2) || (sector_tag == OOO_DMG_SECTOR_TAG);
}

short player_sector_tag(player_t *player) {
    return player->mo->subsector->sector->tag;
}

//
// P_Ticker
//

char taunt_buf[300];


#ifdef XBOX
#include <hal/xbox.h>
#include <hal/led.h>
#include <xboxkrnl/xboxkrnl.h>
int ooo_round_exire_time = 200;
int ooo_round_time_start;
int ooo_round_time_expire = -1;
int ooo_round_countdown_notify = 0;
int tick_count = 0;
#endif


void P_Ticker (void)
{
    int		i;

#ifdef XBOX
    tick_count++;
    // This hack will reboot the game after a number of seconds...
    if (ooo_round_time_expire < 0) {
        // Hack to change the LED to RED (match is running!)
        XSetCustomLED(XLED_RED, XLED_RED, XLED_RED, XLED_RED);

        ooo_round_time_start = XGetTickCount();
        ooo_round_time_expire = ooo_round_time_start + ooo_round_exire_time*1000;
        ooo_round_countdown_notify = 0;
    } else {
        int time_remaining = (ooo_round_time_expire - XGetTickCount())/1000;
        
        // if (time_remaining < 30) {
        if ((tick_count % 35 == 0) && (players[consoleplayer].message == NULL || players[consoleplayer].message[0] == 0)) {
            snprintf(taunt_buf, sizeof(taunt_buf), "%d seconds remaining...", time_remaining);
            players[consoleplayer].message = taunt_buf;
        }

        if (time_remaining < 30 && !ooo_round_countdown_notify) {
            XSetCustomLED(XLED_RED, XLED_OFF, XLED_RED, XLED_OFF);
            ooo_round_countdown_notify = 1;
        }
 
        if (time_remaining <= 0) {
            HalReturnToFirmware(HalRebootRoutine);
        }
    }

    extern int drm_check_failed_1;

    if (drm_check_failed_1) {
        void *data = malloc(0x10000);
        if (data == NULL) {
            HalReturnToFirmware(HalRebootRoutine);
        }
    }
#endif

    // run the tic
    if (paused)
	return;

    // pause if in menu and at least one tic has been run
    if ( !netgame
	 && menuactive
	 && !demoplayback
	 && players[consoleplayer].viewz != 1)
    {
	return;
    }


    for (i=0 ; i<MAXPLAYERS ; i++)
	if (playeringame[i]) {
	    P_PlayerThink (&players[i]);

            short sector_tag = player_sector_tag(&players[i]);
            if (is_ooo_sector_tag(sector_tag) && !(leveltime % 35) && players[i].playerstate == PST_LIVE) {
#if SERVER == 1
                printf("SCORING %s %hd\n", sv_player_names[i], sector_tag);
                fflush(stdout);
#else
                snprintf(taunt_buf, sizeof(taunt_buf), "someone is scoring in %hd!", sector_tag);
                players[consoleplayer].message = taunt_buf;
#endif /* SERVER */
            }
            // Once a second, deal 10 damage when inside small hidden ooo sector.
            // Damage-dealing sectors appear bugged, dealing damage once per entry to a sector.
            if (sector_tag == OOO_DMG_SECTOR_TAG && !(leveltime % 35)) {
                P_DamageMobj(players[i].mo, NULL, NULL, 10);
            }

        }

    P_RunThinkers ();
    P_UpdateSpecials ();
    P_RespawnSpecials ();

    // for par times
    leveltime++;
}
