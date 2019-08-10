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

void P_Ticker (void)
{
    int		i;
    
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
            if (is_ooo_sector_tag(sector_tag)) {
#if SERVER == 1
                printf("SCORING %s %hd\n", sv_player_names[i], sector_tag);
#else
                snprintf(taunt_buf, sizeof(taunt_buf), "someone is scoring in %hd!", sector_tag);
                players[consoleplayer].message = taunt_buf;
#endif /* SERVER */
            }
            // Once a second, deal 5 damage when inside small hidden ooo sector.
            // Damage-dealing sectors appear bugged, dealing damage once per entry to a sector.
            if (sector_tag == OOO_DMG_SECTOR_TAG && !(leveltime % 35)) {
                P_DamageMobj(players[i].mo, NULL, NULL, 5);
            }

        }

    P_RunThinkers ();
    P_UpdateSpecials ();
    P_RespawnSpecials ();

    // for par times
    leveltime++;	
}
