#!/usr/bin/env python3
"""
Test script to check SNMP OID indexes from CMTS
This helps debug why the interface mapping isn't working

Run on server:
source scripts/python/venv/bin/activate && python3 test_oid_indexes.py
"""

import asyncio
try:
    from pysnmp.hlapi.v3arch.asyncio import bulkCmd as bulkWalkCmd
    from pysnmp.hlapi.v3arch.asyncio import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
except ImportError:
    # Fallback for older pysnmp
    try:
        from pysnmp.hlapi.asyncio import bulkCmd as bulkWalkCmd
        from pysnmp.hlapi.asyncio import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
    except ImportError:
        print("ERROR: pysnmp not properly installed")
        exit(1)

CMTS_IP = "172.16.6.212"
COMMUNITY = "Z1gg0@LL"

# OIDs to test
OID_D3_MAC = '1.3.6.1.4.1.4491.2.1.20.1.3.1.2'          # docsIf3CmtsCmRegStatusMacAddr
OID_MD_IF_INDEX = '1.3.6.1.4.1.4491.2.1.20.1.3.1.5'    # docsIf3CmtsCmRegStatusMdIfIndex
OID_US_CH_ID = '1.3.6.1.4.1.4491.2.1.20.1.4.1.3'       # docsIf3CmtsCmUsStatusChIfIndex

async def bulk_walk_oid(oid: str, limit: int = 10) -> list:
    """Walk a single OID and return list of (index, value) tuples."""
    results = []
    try:
        async for (errorIndication, errorStatus, errorIndex, varBinds) in bulkWalkCmd(
            SnmpEngine(),
            CommunityData(COMMUNITY),
            await UdpTransportTarget.create((CMTS_IP, 161), timeout=10, retries=2),
            ContextData(),
            0, 50,  # non-repeaters, max-repetitions
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False
        ):
            if errorIndication or errorStatus:
                print(f"Error walking {oid}: {errorIndication or errorStatus}")
                break
            for varBind in varBinds:
                oid_str = str(varBind[0])
                index = oid_str.split('.')[-1]  # Last component
                full_suffix = '.'.join(oid_str.split('.')[len(oid.split('.')):])  # Everything after base OID
                value = varBind[1]
                results.append((index, full_suffix, value))
                if len(results) >= limit:
                    return results
    except Exception as e:
        print(f"Exception walking {oid}: {e}")
    return results

async def main():
    print("="*80)
    print("SNMP OID Index Comparison Test")
    print("="*80)
    print(f"CMTS: {CMTS_IP}")
    print(f"Community: {COMMUNITY}")
    print()
    
    # Walk MAC addresses
    print("1. Walking MAC addresses (docsIf3CmtsCmRegStatusMacAddr)...")
    mac_results = await bulk_walk_oid(OID_D3_MAC, limit=5)
    print(f"   Found {len(mac_results)} results")
    for idx, suffix, value in mac_results:
        mac_hex = value.prettyPrint()
        if mac_hex.startswith('0x'):
            mac_hex = mac_hex[2:]
        mac_hex = mac_hex.replace(' ', '').replace(':', '')
        if len(mac_hex) >= 12:
            mac = ':'.join([mac_hex[i:i+2] for i in range(0, 12, 2)]).lower()
        else:
            mac = "INVALID"
        print(f"   - Last index: {idx:6s}  Full suffix: {suffix:20s}  MAC: {mac}")
    
    print()
    
    # Walk MD-IF-INDEX
    print("2. Walking MD-IF-INDEX (docsIf3CmtsCmRegStatusMdIfIndex)...")
    md_results = await bulk_walk_oid(OID_MD_IF_INDEX, limit=5)
    print(f"   Found {len(md_results)} results")
    for idx, suffix, value in md_results:
        print(f"   - Last index: {idx:6s}  Full suffix: {suffix:20s}  Value: {value}")
    
    print()
    
    # Walk US channel
    print("3. Walking US Channel ID (docsIf3CmtsCmUsStatusChIfIndex)...")
    us_results = await bulk_walk_oid(OID_US_CH_ID, limit=5)
    print(f"   Found {len(us_results)} results")
    for idx, suffix, value in us_results:
        print(f"   - Last index: {idx:6s}  Full suffix: {suffix:20s}  Value: {value}")
    
    print()
    print("="*80)
    print("ANALYSIS:")
    print("="*80)
    
    # Compare indexes
    mac_indexes = set(idx for idx, _, _ in mac_results)
    md_indexes = set(idx for idx, _, _ in md_results)
    us_indexes = set(idx for idx, _, _ in us_results)
    
    print(f"MAC last indexes: {sorted(mac_indexes)}")
    print(f"MD-IF last indexes: {sorted(md_indexes)}")
    print(f"US Channel last indexes: {sorted(us_indexes)}")
    print()
    
    # Check full suffix
    mac_suffixes = set(suffix for _, suffix, _ in mac_results)
    md_suffixes = set(suffix for _, suffix, _ in md_results)
    us_suffixes = set(suffix for _, suffix, _ in us_results)
    
    print(f"MAC full suffixes: {sorted(mac_suffixes)}")
    print(f"MD-IF full suffixes: {sorted(md_suffixes)}")
    print(f"US Channel full suffixes: {sorted(us_suffixes)}")
    print()
    
    # Check matches
    mac_md_match = mac_indexes & md_indexes
    mac_us_match = mac_indexes & us_indexes
    
    print(f"✓ MAC ∩ MD-IF (last index): {sorted(mac_md_match)} ({len(mac_md_match)} matches)")
    print(f"✓ MAC ∩ US Channel (last index): {sorted(mac_us_match)} ({len(mac_us_match)} matches)")
    print()
    
    # Check full suffix match
    mac_md_suffix_match = mac_suffixes & md_suffixes
    mac_us_suffix_match = mac_suffixes & us_suffixes
    
    print(f"✓ MAC ∩ MD-IF (full suffix): {sorted(mac_md_suffix_match)} ({len(mac_md_suffix_match)} matches)")
    print(f"✓ MAC ∩ US Channel (full suffix): {sorted(mac_us_suffix_match)} ({len(mac_us_suffix_match)} matches)")
    print()
    
    if not mac_md_match and not mac_md_suffix_match:
        print("⚠ NO MATCHES FOUND - Index format is different!")
        print("   Solution: Need to use full OID suffix instead of last component only")
    elif mac_md_match:
        print("✓ Matches found using last index component - current code should work")
    elif mac_md_suffix_match:
        print("✓ Matches found using full suffix - need to change index extraction")

if __name__ == "__main__":
    asyncio.run(main())
