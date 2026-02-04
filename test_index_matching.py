#!/usr/bin/env python3
"""
Test script to verify OID index extraction and matching logic
without needing Docker rebuilds.

Usage: python3 test_index_matching.py
"""

def extract_index_from_oid(oid_str, base_oid):
    """
    Extract index from OID - mimics agent logic
    """
    base_oid_parts = base_oid.split('.')
    full_oid_parts = oid_str.split('.')
    suffix_parts = full_oid_parts[len(base_oid_parts):]
    index = '.'.join(suffix_parts) if suffix_parts else oid_str.split('.')[-1]
    return index

def extract_modem_index(compound_index):
    """
    Extract modem index from compound index (first part)
    """
    return compound_index.split('.')[0] if '.' in compound_index else compound_index

# Simulate real SNMP walk results from the CMTS
print("="*80)
print("SIMULATING SNMP WALKS FROM CMTS")
print("="*80)

# Base OIDs
OID_D3_MAC = '1.3.6.1.4.1.4491.2.1.20.1.3.1.2'
OID_MD_IF_INDEX = '1.3.6.1.4.1.4491.2.1.20.1.3.1.5'
OID_US_CH_ID = '1.3.6.1.4.1.4491.2.1.20.1.4.1.3'

# Simulate SNMP walk results (based on actual CMTS responses)
mac_walk_results = [
    (f'{OID_D3_MAC}.22', '0x90324bc817b3'),
    (f'{OID_D3_MAC}.24', '0x90324bc813df'),
    (f'{OID_D3_MAC}.25', '0x90324bc81aff'),
]

md_if_walk_results = [
    # MD-IF-INDEX bulk walk returns nothing, but individual gets work!
    # Simulating individual snmpget results:
    # (f'{OID_MD_IF_INDEX}.22', '536871013'),
    # (f'{OID_MD_IF_INDEX}.24', '536871015'),
    # (f'{OID_MD_IF_INDEX}.25', '536871017'),
]

# Simulate individual gets after bulk walk fails
md_if_individual_gets = {
    '22': 536871013,  # cable-mac 100
    '24': 536871015,  # cable-mac 102
    '25': 536871017,  # cable-mac 104
}

us_ch_walk_results = [
    (f'{OID_US_CH_ID}.22.843071491', '843071491'),
    (f'{OID_US_CH_ID}.24.843071493', '843071493'),
    (f'{OID_US_CH_ID}.25.843071495', '843071495'),
]

print("\n1. MAC Address OID Walk Results:")
for oid, value in mac_walk_results:
    index = extract_index_from_oid(oid, OID_D3_MAC)
    print(f"   OID: {oid}")
    print(f"   Index: {index}")
    print(f"   Value: {value}")
    print()

print("\n2. MD-IF-INDEX OID Walk Results:")
if md_if_walk_results:
    for oid, value in md_if_walk_results:
        index = extract_index_from_oid(oid, OID_MD_IF_INDEX)
        modem_idx = extract_modem_index(index)
        print(f"   OID: {oid}")
        print(f"   Raw Index: {index}")
        print(f"   Modem Index: {modem_idx}")
        print(f"   Value: {value}")
        print()
else:
    print("   No results (MD-IF-INDEX OID not supported on this CMTS)")

print("\n3. US Channel OID Walk Results:")
for oid, value in us_ch_walk_results:
    index = extract_index_from_oid(oid, OID_US_CH_ID)
    modem_idx = extract_modem_index(index)
    print(f"   OID: {oid}")
    print(f"   Raw Index: {index}")
    print(f"   Modem Index: {modem_idx}")
    print(f"   Value: {value}")
    print()

# Build maps like the agent does
print("="*80)
print("BUILDING INDEX MAPS")
print("="*80)

mac_map = {}
for oid, value in mac_walk_results:
    index = extract_index_from_oid(oid, OID_D3_MAC)
    mac_map[index] = value

md_if_map = {}
for oid, value in md_if_walk_results:
    index = extract_index_from_oid(oid, OID_MD_IF_INDEX)
    modem_idx = extract_modem_index(index)
    md_if_map[modem_idx] = int(value)

# If bulk walk returned nothing, simulate individual gets
if not md_if_map and md_if_individual_gets:
    print("\n  Bulk walk failed, using individual gets...")
    for modem_idx, value in md_if_individual_gets.items():
        md_if_map[modem_idx] = value

us_ch_map = {}
for oid, value in us_ch_walk_results:
    index = extract_index_from_oid(oid, OID_US_CH_ID)
    modem_idx = extract_modem_index(index)
    us_ch_map[modem_idx] = int(value)

print(f"\nMAC map keys:        {list(mac_map.keys())}")
print(f"MD-IF-INDEX map keys: {list(md_if_map.keys())}")
print(f"US Channel map keys:  {list(us_ch_map.keys())}")

# Test matching
print("\n" + "="*80)
print("TESTING INDEX MATCHING")
print("="*80)

modems = []
for index, mac in mac_map.items():
    modem = {
        'mac_address': mac,
        'cmts_index': index,
    }
    
    # Test MD-IF-INDEX matching
    if index in md_if_map:
        md_if_index = md_if_map[index]
        modem['md_if_index'] = md_if_index
        modem['upstream_interface'] = f"ifIndex.{md_if_index}"
        print(f"\n✓ Modem {index}: MD-IF-INDEX matched! Value: {md_if_index}")
    else:
        print(f"\n✗ Modem {index}: No MD-IF-INDEX match")
    
    # Test US channel matching
    if index in us_ch_map:
        us_ch_id = us_ch_map[index]
        modem['upstream_channel_id'] = us_ch_id
        print(f"✓ Modem {index}: US Channel matched! Value: {us_ch_id}")
    else:
        print(f"✗ Modem {index}: No US Channel match")
    
    modems.append(modem)

# Show final modem data
print("\n" + "="*80)
print("FINAL MODEM DATA")
print("="*80)

import json
for modem in modems:
    print(json.dumps(modem, indent=2))

# Summary
print("\n" + "="*80)
print("SUMMARY")
print("="*80)
print(f"Total modems: {len(modems)}")
print(f"Modems with MD-IF-INDEX: {sum(1 for m in modems if 'md_if_index' in m)}")
print(f"Modems with US Channel: {sum(1 for m in modems if 'upstream_channel_id' in m)}")

if all('upstream_channel_id' in m for m in modems):
    print("\n✓✓✓ SUCCESS! All modems have upstream_channel_id field!")
else:
    print("\n✗✗✗ FAILED! Not all modems have upstream_channel_id field")
    print("    Check the index extraction logic above.")
