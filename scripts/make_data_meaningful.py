#!/usr/bin/env python3
"""
Make Data Items Meaningful
===========================
Systematically analyzes and improves data item definitions in Ghidra by:
1. Inspecting memory content to detect actual types (strings, pointers, arrays)
2. Analyzing cross-references to understand usage patterns
3. Applying proper types and meaningful names
4. Documenting critical global variables

Usage:
    python make_data_meaningful.py --top 50
    python make_data_meaningful.py --address 0x035b829c
    python make_data_meaningful.py --segment .data
"""

import sys
import json
import re
from pathlib import Path

# Add parent directory to path for bridge imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import bridge_mcp_ghidra as bridge
except ImportError as e:
    print(f"Error: Could not import bridge_mcp_ghidra: {e}")
    print("Make sure bridge_mcp_ghidra.py is in the parent directory")
    sys.exit(1)


class DataAnalyzer:
    """Analyzes and improves data item definitions"""
    
    def __init__(self):
        self.improvements = []
    
    def is_valid_import_name(self, name):
        """Check if PTR_ name is actually descriptive (import thunk)"""
        if name.startswith('PTR_'):
            # Extract function name between PTR_ and final _address
            parts = name.split('_')
            if len(parts) >= 3:  # PTR_FunctionName_address
                func_name = '_'.join(parts[1:-1])
                # If function name is meaningful and not just hex, it's valid
                if len(func_name) > 3 and not func_name.replace('0x', '').replace('x', '').isdigit():
                    # Known Windows API functions are valid
                    known_apis = ['IsBadCodePtr', 'LeaveCriticalSection', 'EnterCriticalSection', 
                                  'wsprintfA', 'GetLastError', 'SetLastError', 'malloc', 'free',
                                  'memcpy', 'memset', 'strlen', 'strcpy', 'strcmp']
                    return any(api in func_name for api in known_apis)
        return False
        
    def analyze_memory_content(self, address, size=64):
        """Inspect memory to detect actual type"""
        result = bridge.inspect_memory_content(address, length=size)
        
        # Parse JSON result - bridge returns list of lines
        try:
            if isinstance(result, list):
                result = '\n'.join(result)
            data = json.loads(result)
        except:
            return None
        
        # Detect type based on content
        if data.get('is_likely_string', False):
            return {
                'type': 'string',
                'suggested_type': data.get('suggested_type', 'char[]'),
                'value': data.get('detected_string', ''),
                'confidence': 'high' if data.get('printable_ratio', 0) > 0.8 else 'medium'
            }
        
        # Check for pointer array (many addresses in sequence)
        hex_dump = data.get('hex_dump', '')
        # Look for patterns like "XX XX XX 6F" (addresses ending in Diablo 2 memory range)
        pointer_pattern = re.findall(r'[0-9A-F]{2}\s+[0-9A-F]{2}\s+[0-9A-F]{2}\s+6[FO]', hex_dump)
        if len(pointer_pattern) >= 4:  # At least 4 pointers
            return {
                'type': 'pointer_array',
                'suggested_type': 'void*[]',
                'count': len(pointer_pattern),
                'confidence': 'high'
            }
        
        # Check for numeric array (low printable ratio, consistent patterns)
        if data.get('printable_ratio', 0) < 0.2:
            return {
                'type': 'numeric_array',
                'suggested_type': 'undefined[]',
                'confidence': 'low'
            }
        
        return None
    
    def analyze_xref_usage(self, address, limit=10):
        """Analyze how data is used via cross-references"""
        result = bridge.get_xrefs_to(address, limit=limit)
        
        # Parse result - bridge returns list of lines
        try:
            if isinstance(result, list):
                result = '\n'.join(result)
            xrefs = json.loads(result) if isinstance(result, str) else result
        except:
            return None
        
        # Analyze patterns
        patterns = {
            'read_only': all(x.get('type') == 'READ' for x in xrefs if isinstance(x, dict)),
            'data_access': all(x.get('type') in ['READ', 'DATA'] for x in xrefs if isinstance(x, dict)),
            'write_access': any(x.get('type') == 'WRITE' for x in xrefs if isinstance(x, dict)),
            'function_names': [x.get('function_name', 'Unknown') for x in xrefs[:5] if isinstance(x, dict)]
        }
        
        # Derive naming hints from functions
        name_hints = []
        for func_name in patterns['function_names']:
            if 'Initialize' in func_name:
                name_hints.append('initialization_data')
            elif 'Table' in func_name or 'Array' in func_name:
                name_hints.append('table_or_array')
            elif 'Global' in func_name or 'Data' in func_name:
                name_hints.append('global_data')
            elif 'Monster' in func_name:
                name_hints.append('monster_related')
            elif 'Player' in func_name:
                name_hints.append('player_related')
            elif 'Skill' in func_name:
                name_hints.append('skill_related')
        
        return {
            'patterns': patterns,
            'name_hints': list(set(name_hints)),
            'xref_count': len(xrefs)
        }
    
    def suggest_improvements(self, data_item):
        """Suggest improvements for a data item"""
        address = data_item.get('address', '')
        # Ensure address has 0x prefix
        if address and not address.startswith('0x'):
            address = '0x' + address
            
        name = data_item.get('name', '')
        dtype = data_item.get('type', '')
        xref_count = data_item.get('xref_count', 0)
        
        improvements = []
        
        # Check if name is generic
        is_generic = any(prefix in name for prefix in ['DAT_', 'DWORD_', 'undefined'])
        # Also check PTR_ names, but exclude valid import names
        if name.startswith('PTR_') and not self.is_valid_import_name(name):
            is_generic = True
        
        if is_generic:
            improvements.append({
                'type': 'rename',
                'reason': f'Generic name "{name}" should be meaningful',
                'priority': 'high' if xref_count > 50 else 'medium'
            })
        
        # Check type
        if 'undefined' in dtype:
            improvements.append({
                'type': 'retype',
                'reason': f'Type "{dtype}" should be properly defined',
                'priority': 'high' if xref_count > 50 else 'medium'
            })
        
        # Analyze memory content
        memory_analysis = self.analyze_memory_content(address)
        if memory_analysis:
            improvements.append({
                'type': 'apply_type',
                'suggested_type': memory_analysis.get('suggested_type'),
                'detected': memory_analysis.get('type'),
                'confidence': memory_analysis.get('confidence'),
                'priority': 'high'
            })
        
        # Analyze usage patterns
        usage_analysis = self.analyze_xref_usage(address)
        if usage_analysis:
            name_hints = usage_analysis.get('name_hints', [])
            if name_hints:
                improvements.append({
                    'type': 'naming_hint',
                    'hints': name_hints,
                    'xref_functions': usage_analysis['patterns']['function_names'][:3],
                    'priority': 'medium'
                })
        
        return improvements
    
    def process_top_items(self, limit=50):
        """Process top N most-referenced data items"""
        print(f"\n{'='*80}")
        print(f"Analyzing Top {limit} Most-Referenced Data Items")
        print(f"{'='*80}\n")
        
        # Get data items sorted by XREFs
        result = bridge.list_data_items_by_xrefs(limit=limit, format='json')
        
        # Bridge returns list of lines, need to join them
        try:
            if isinstance(result, list):
                result = '\n'.join(result)
            items = json.loads(result)
            if not isinstance(items, list):
                print(f"Error: Expected list, got {type(items)}")
                return
        except Exception as e:
            print(f"Error: Could not parse data items: {e}")
            print(f"Result type: {type(result)}")
            return
        
        for idx, item in enumerate(items, 1):
            address = item.get('address', '')
            name = item.get('name', '')
            dtype = item.get('type', '')
            xref_count = item.get('xref_count', 0)
            
            print(f"\n[{idx}/{limit}] {name} @ {address}")
            print(f"  Type: {dtype} | XREFs: {xref_count}")
            
            # Analyze and suggest improvements
            improvements = self.suggest_improvements(item)
            
            if improvements:
                print(f"  Improvements needed: {len(improvements)}")
                for improvement in improvements:
                    imp_type = improvement.get('type')
                    priority = improvement.get('priority', 'medium')
                    print(f"    [{priority.upper()}] {imp_type}:", end='')
                    
                    if imp_type == 'apply_type':
                        print(f" {improvement.get('detected')} -> {improvement.get('suggested_type')}")
                    elif imp_type == 'naming_hint':
                        hints = improvement.get('hints', [])
                        funcs = improvement.get('xref_functions', [])
                        print(f" Consider names related to: {', '.join(hints)}")
                        if funcs:
                            print(f"      Used by: {', '.join(funcs[:3])}")
                    elif imp_type == 'rename':
                        print(f" {improvement.get('reason')}")
                        # If we have naming hints, show them
                        naming_hints = [i for i in improvements if i.get('type') == 'naming_hint']
                        if naming_hints:
                            hints = naming_hints[0].get('hints', [])
                            funcs = naming_hints[0].get('xref_functions', [])
                            if hints:
                                print(f"      Context hints: {', '.join(hints)}")
                            if funcs:
                                print(f"      Used by: {', '.join(funcs[:3])}")
                    else:
                        print(f" {improvement.get('reason')}")
                
                self.improvements.append({
                    'item': item,
                    'improvements': improvements
                })
            else:
                print("  ✓ Looks good")
    
    def generate_action_plan(self):
        """Generate prioritized action plan"""
        print(f"\n\n{'='*80}")
        print("ACTION PLAN - Prioritized Improvements")
        print(f"{'='*80}\n")
        
        # Group by priority
        high_priority = [i for i in self.improvements 
                        if any(imp['priority'] == 'high' for imp in i['improvements'])]
        medium_priority = [i for i in self.improvements 
                          if any(imp['priority'] == 'medium' for imp in i['improvements']) 
                          and i not in high_priority]
        
        print(f"HIGH PRIORITY ({len(high_priority)} items):")
        print("-" * 80)
        for item_data in high_priority[:10]:  # Top 10
            item = item_data['item']
            print(f"\n{item['name']} @ {item['address']} ({item['xref_count']} XREFs)")
            for imp in item_data['improvements']:
                if imp['priority'] == 'high':
                    imp_type = imp['type']
                    if imp_type == 'rename':
                        print(f"  → {imp_type}: {imp.get('reason')}")
                        # Show naming hints if available
                        naming_hints = [i for i in item_data['improvements'] if i.get('type') == 'naming_hint']
                        if naming_hints:
                            hints = naming_hints[0].get('hints', [])
                            funcs = naming_hints[0].get('xref_functions', [])
                            if hints:
                                print(f"     Suggestion: Consider '{', '.join(hints)}' context")
                            if funcs:
                                print(f"     Functions: {', '.join(funcs[:3])}")
                    elif imp_type == 'retype':
                        print(f"  → {imp_type}: {imp.get('reason')}")
                    else:
                        print(f"  → {imp_type}: {imp.get('reason') or imp.get('detected')}")
        
        print(f"\n\nMEDIUM PRIORITY ({len(medium_priority)} items):")
        print("-" * 80)
        for item_data in medium_priority[:5]:  # Top 5
            item = item_data['item']
            print(f"\n{item['name']} @ {item['address']} ({item['xref_count']} XREFs)")
            for imp in item_data['improvements']:
                if imp['priority'] == 'medium':
                    print(f"  → {imp['type']}")
        
        # Summary
        print(f"\n\n{'='*80}")
        print("SUMMARY")
        print(f"{'='*80}")
        print(f"Total items analyzed: {len(self.improvements)}")
        print(f"High priority fixes: {len(high_priority)}")
        print(f"Medium priority fixes: {len(medium_priority)}")
        print(f"\nRecommended approach:")
        print("1. Fix high priority items first (most-referenced with undefined types)")
        print("2. Focus on items with clear type detection (strings, pointer arrays)")
        print("3. Use naming hints from cross-reference analysis")
        print("4. Document critical globals using DATA_DOCUMENTATION_TEMPLATE.md")
    
    def apply_fixes(self, dry_run=True):
        """Apply fixes to items that need improvement"""
        print(f"\n{'='*80}")
        print(f"APPLYING FIXES {'(DRY RUN - No changes will be made)' if dry_run else '(LIVE MODE)'}")
        print(f"{'='*80}\n")
        
        if not self.improvements:
            print("No improvements to apply.")
            return
        
        fixes_applied = 0
        fixes_failed = 0
        fixes_would_apply = 0
        
        for item_data in self.improvements:
            item = item_data['item']
            address = item.get('address', '')
            if address and not address.startswith('0x'):
                address = '0x' + address
            name = item.get('name', '')
            
            for improvement in item_data['improvements']:
                imp_type = improvement.get('type')
                priority = improvement.get('priority', 'medium')
                
                # Only apply high priority fixes
                if priority != 'high':
                    continue
                
                if imp_type == 'retype':
                    # Fix undefined types
                    if 'undefined4' in item.get('type', ''):
                        new_type = 'dword'
                        print(f"[{'DRY RUN' if dry_run else 'APPLY'}] {name} @ {address}")
                        print(f"  Changing type: undefined4 → {new_type}")
                        
                        if dry_run:
                            fixes_would_apply += 1
                        else:
                            try:
                                result = bridge.apply_data_type(address, new_type)
                                if isinstance(result, list):
                                    result = '\n'.join(result)
                                if 'success' in result.lower() or 'applied' in result.lower():
                                    print(f"  ✓ Type changed successfully")
                                    fixes_applied += 1
                                else:
                                    print(f"  ✗ Failed: {result[:100]}")
                                    fixes_failed += 1
                            except Exception as e:
                                print(f"  ✗ Error: {e}")
                                fixes_failed += 1
                    
                elif imp_type == 'rename':
                    # Get naming hints
                    naming_hints = [i for i in item_data['improvements'] if i.get('type') == 'naming_hint']
                    if naming_hints:
                        hints = naming_hints[0].get('hints', [])
                        print(f"[INFO] {name} @ {address}")
                        print(f"  Needs renaming - Context: {', '.join(hints)}")
                        print(f"  Note: Automatic renaming not implemented (requires human judgment)")
                    else:
                        print(f"[INFO] {name} @ {address}")
                        print(f"  Needs renaming but no context hints available")
        
        print(f"\n{'='*80}")
        print(f"SUMMARY: {'DRY RUN COMPLETE' if dry_run else 'FIXES APPLIED'}")
        print(f"{'='*80}")
        if dry_run:
            print(f"Fixes that would be applied: {fixes_would_apply}")
        else:
            print(f"Fixes successfully applied: {fixes_applied}")
            print(f"Fixes failed: {fixes_failed}")
        print(f"\nNote: Renaming requires manual intervention with meaningful names.")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Make Ghidra data items meaningful')
    parser.add_argument('--top', type=int, default=50, 
                       help='Analyze top N items by XREF count (default: 50)')
    parser.add_argument('--address', 
                       help='Analyze specific address')
    parser.add_argument('--segment', 
                       help='Analyze items in specific segment (.data, .rdata)')
    parser.add_argument('--apply-fixes', action='store_true',
                       help='Apply automatic fixes (types only, not names)')
    parser.add_argument('--dry-run', action='store_true', default=True,
                       help='Show what would be changed without applying (default: True)')
    parser.add_argument('--no-dry-run', action='store_true',
                       help='Actually apply changes (use with --apply-fixes)')
    
    args = parser.parse_args()
    
    # Determine dry run mode
    dry_run = args.dry_run and not args.no_dry_run
    
    # Test connection
    print("Connecting to Ghidra...")
    try:
        bridge.check_connection()
        print("✓ Connected to Ghidra\n")
    except Exception as e:
        print(f"✗ Error connecting to Ghidra: {e}")
        return 1
    
    # Create analyzer
    analyzer = DataAnalyzer()
    
    # Process based on arguments
    if args.address:
        print(f"Analyzing single address: {args.address}")
        # TODO: Implement single address analysis
    elif args.segment:
        print(f"Analyzing segment: {args.segment}")
        # TODO: Implement segment analysis
    else:
        analyzer.process_top_items(args.top)
        analyzer.generate_action_plan()
        
        # Apply fixes if requested
        if args.apply_fixes:
            analyzer.apply_fixes(dry_run=dry_run)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
