#!/usr/bin/env python
"""Apply all PREFIX_* renames via MCP API."""

import requests

# Mapping of (address, new_name) for PREFIX_* functions - first 50
renames = [
    ("0x6fc8e750", "SetAIActionMode1B"),
    ("0x6fc8fb90", "ScheduleEvent7OnMode3"),
    ("0x6fc98b00", "SpawnTreasureOnAnimComplete"),
    ("0x6fc890a0", "CanStartSpecialAttack"),
    ("0x6fc8e6c0", "GetStateMode7"),
    ("0x6fc90290", "SpawnInitialMinion"),
    ("0x6fca1f30", "BroadcastStatUpdates"),
    ("0x6fc8f1e0", "ApplySpecialAuraStat"),
    ("0x6fc8f200", "BrokenFunc6fc8f200"),
    ("0x6fc9ca70", "CountValidPlayer"),
    ("0x6fc992d0", "HandleNpcWaypointInteraction"),
    ("0x6fc926f0", "ScheduleSequenceEvent"),
    ("0x6fc695c0", "GetActiveClientCount"),
    ("0x6fc95d10", "HandleObjectInteraction"),
    ("0x6fc99620", "HandleRepairInteraction"),
    ("0x6fc95b60", "ProcessEntityMessageThunk"),
    ("0x6fc6c090", "SendDisconnectError"),
    ("0x6fc6e920", "SendItemActionResult"),
    ("0x6fc6e420", "SendItemSpellIconUpdate"),
    ("0x6fc6e640", "SendNPCMovePacket"),
    ("0x6fc6edb0", "SendPacket0x15"),
    ("0x6fc6e9b0", "SendPacket0x50"),
    ("0x6fc6e4a0", "SendPacket42ItemRemove"),
    ("0x6fc6e910", "SendPacket5"),
    ("0x6fc6f080", "SendPacket84"),
    ("0x6fc6f180", "SendPartyRelationPacket"),
    ("0x6fc6ea00", "SendQuestStatusPacket"),
    ("0x6fc6ed50", "SendShrineInteractPacket"),
    ("0x6fc6e6a0", "SendUnitTargetPacket"),
    ("0x6fc654e0", "SetEventCallbackTable"),
    ("0x6fc91fb0", "HandleDeathSequence"),
    ("0x6fc8e6d0", "GetCharacterTierValue"),
    ("0x6fc95cc0", "DispatchEventFunction"),
    ("0x6fc89f00", "DispatchEventHandler"),
    ("0x6fc89820", "GetSkipSummonEndFlag"),
    ("0x6fc989a0", "ProcessObjectRoomEvent"),
    ("0x6fca1550", "ValidateAndCallHandler"),
    ("0x6fc9a1e0", "ActivatePortalPair"),
    ("0x6fc6f2f0", "BroadcastPacket8E"),
    ("0x6fc9cca0", "CheckPlayerExistsInGame"),
    ("0x6fc657c0", "CreateGame"),
    ("0x6fc67010", "DestroyGame"),
    ("0x6fc9aad0", "FreeArenaData"),
    ("0x6fc95180", "FreeMonsterUnits"),
    ("0x6fc9bb40", "FreeObjectUnits"),
    ("0x6fcb20f0", "FreePartyData"),
    ("0x6fc86520", "FreePlayerUnits"),
    ("0x6fcd6de0", "FreeTileUnits"),
    ("0x6fcd5620", "FreeTriggerData"),
    ("0x6fcddad0", "FreeUnitLists"),
]

successful = 0
failed = 0

for i, (address, new_name) in enumerate(renames, 1):
    try:
        url = "http://127.0.0.1:8089/rename_function_by_address"
        payload = {
            "function_address": address,
            "new_name": new_name
        }
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            result = response.json()
            if "result" in result and "Successfully" in result.get("result", ""):
                successful += 1
                print("[%3d] OK %s -> %s" % (i, address, new_name))
            else:
                failed += 1
                print("[%3d] SKIP %s -> %s" % (i, address, new_name))
        else:
            failed += 1
            print("[%3d] ERR %s -> %s (HTTP %d)" % (i, address, new_name, response.status_code))
    except Exception as e:
        failed += 1
        print("[%3d] ERR %s -> %s (%s)" % (i, address, new_name, str(e)[:30]))

print(f"\nBatch 1: {successful}/{len(renames)} completed")
