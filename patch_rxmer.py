#!/usr/bin/env python3
"""Patch agent.py to fix pnm_ofdm_rxmer to trigger capture first."""

with open('agent.py', 'r') as f:
    content = f.read()

old_handler = '''    def _handle_pnm_ofdm_rxmer(self, params: dict) -> dict:
        """Get OFDM RxMER data via pysnmp SNMP walk."""
        modem_ip = params.get('modem_ip')
        community = params.get('community', 'your-cm-community')
        
        if not modem_ip:
            return {'success': False, 'error': 'modem_ip required'}
        
        try:
            # docsPnmCmDsOfdmRxMerMean OID (MER values per channel)
            OID_RXMER_MEAN = '1.3.6.1.4.1.4491.2.1.27.1.2.5.1.3'
            
            result = self._snmp_walk(modem_ip, OID_RXMER_MEAN, community)
            
            if not result.get('success') or not result.get('results'):
                return {'success': False, 'error': 'No RxMER data available'}
            
            subcarriers = []
            mer_values = []
            
            for r in result['results']:
                try:
                    # Extract channel index from OID (last element)
                    oid_parts = r['oid'].split('.')
                    channel_idx = int(oid_parts[-1])
                    mer_raw = int(r['value'])
                    mer_db = mer_raw / 100.0  # Convert to dB (value is in 1/100 dB)
                    
                    subcarriers.append(channel_idx)
                    mer_values.append(mer_db)
                except (ValueError, IndexError):
                    pass
            
            if not subcarriers:
                return {'success': False, 'error': 'No RxMER data available'}
            
            return {
                'success': True,
                'data': {
                    'mac_address': params.get('mac_address'),
                    'subcarriers': subcarriers,
                    'mer_values': mer_values
                }
            }
        except Exception as e:
            self.logger.error(f"OFDM RxMER error: {e}")
            return {'success': False, 'error': str(e)}'''

new_handler = '''    def _handle_pnm_ofdm_rxmer(self, params: dict) -> dict:
        """Get OFDM RxMER data - trigger capture first, then read data."""
        import time
        
        modem_ip = params.get('modem_ip')
        community = params.get('community', 'your-cm-community')
        ofdm_channel = params.get('ofdm_channel', 0)  # Default to first OFDM channel
        
        if not modem_ip:
            return {'success': False, 'error': 'modem_ip required'}
        
        try:
            # OIDs for RxMER capture control
            OID_RXMER_ENABLE = f'1.3.6.1.4.1.4491.2.1.27.1.2.5.1.1.{ofdm_channel}'  # docsPnmCmDsOfdmRxMerEnable
            OID_RXMER_MEAN = '1.3.6.1.4.1.4491.2.1.27.1.2.5.1.3'  # docsPnmCmDsOfdmRxMerMean
            OID_RXMER_DATA = f'1.3.6.1.4.1.4491.2.1.27.1.2.5.1.5.{ofdm_channel}'  # docsPnmCmDsOfdmRxMerData (per-subcarrier)
            
            # Step 1: Trigger RxMER capture
            self.logger.info(f"Triggering RxMER capture for {modem_ip} channel {ofdm_channel}")
            trigger_result = self._set_modem(modem_ip, OID_RXMER_ENABLE, '1', 'i', community)
            
            if not trigger_result.get('success'):
                self.logger.warning(f"RxMER trigger failed: {trigger_result.get('error')}, trying to read existing data")
            else:
                # Step 2: Wait for capture to complete
                time.sleep(2)
            
            # Step 3: Try to read per-subcarrier RxMER data first
            self.logger.info(f"Reading RxMER data from {modem_ip}")
            result = self._snmp_walk(modem_ip, OID_RXMER_DATA, community)
            
            if result.get('success') and result.get('results'):
                # Parse per-subcarrier data (binary blob)
                self.logger.info(f"Got per-subcarrier RxMER data ({len(result['results'])} entries)")
                # TODO: Parse binary RxMER data format
            
            # Fallback: Read RxMER mean table
            result = self._snmp_walk(modem_ip, OID_RXMER_MEAN, community)
            
            if not result.get('success') or not result.get('results'):
                return {'success': False, 'error': 'No RxMER data available after capture'}
            
            subcarriers = []
            mer_values = []
            
            for r in result['results']:
                try:
                    oid_parts = r['oid'].split('.')
                    channel_idx = int(oid_parts[-1])
                    mer_raw = int(r['value'])
                    mer_db = mer_raw / 100.0
                    
                    subcarriers.append(channel_idx)
                    mer_values.append(mer_db)
                except (ValueError, IndexError):
                    pass
            
            if not subcarriers:
                return {'success': False, 'error': 'No RxMER data available'}
            
            return {
                'success': True,
                'data': {
                    'mac_address': params.get('mac_address'),
                    'subcarriers': subcarriers,
                    'mer_values': mer_values
                }
            }
        except Exception as e:
            self.logger.error(f"OFDM RxMER error: {e}")
            return {'success': False, 'error': str(e)}'''

if old_handler in content:
    content = content.replace(old_handler, new_handler)
    with open('agent.py', 'w') as f:
        f.write(content)
    print("SUCCESS: Updated _handle_pnm_ofdm_rxmer to trigger capture first")
else:
    print("ERROR: Could not find old handler")
    exit(1)
