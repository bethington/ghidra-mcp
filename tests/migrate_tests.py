#!/usr/bin/env python3
"""
Migration script for transitioning from old test structure to new pytest-based structure.

This script helps identify, archive, and migrate tests from the old structure
to the new organized test suite.
"""

import os
import shutil
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple


class TestMigrator:
    """Handles migration from old test structure to new pytest structure."""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.old_tests_dir = project_root / "tests"
        self.old_scripts_dir = project_root / "scripts"
        self.migration_log = []
        
    def analyze_old_structure(self) -> Dict[str, List[str]]:
        """Analyze the old test structure and categorize files."""
        analysis = {
            'deprecated_tests': [],
            'valuable_tests': [],
            'scripts_to_archive': [],
            'scripts_to_keep': [],
            'files_to_remove': []
        }
        
        # Analyze old tests directory
        if self.old_tests_dir.exists():
            for file_path in self.old_tests_dir.glob("*.py"):
                if file_path.name in [
                    "comprehensive_mcp_test.py",
                    "enhanced_comprehensive_test.py", 
                    "final_summary_test.py",
                    "endpoint_diagnostics.py"
                ]:
                    analysis['deprecated_tests'].append(str(file_path))
                elif file_path.name in [
                    "test_data_types.py",
                    "test_struct_enum_creation.py",
                    "test_steps_8_9.py"
                ]:
                    analysis['valuable_tests'].append(str(file_path))
                else:
                    analysis['files_to_remove'].append(str(file_path))
        
        # Analyze scripts directory
        if self.old_scripts_dir.exists():
            for file_path in self.old_scripts_dir.glob("test_*.py"):
                if file_path.name in [
                    "test_mcp_tools_endpoints.py",
                    "test_mcp_tools_functional.py", 
                    "test_mcp_tools_unit.py"
                ]:
                    analysis['scripts_to_archive'].append(str(file_path))
                else:
                    analysis['scripts_to_keep'].append(str(file_path))
                    
        return analysis
    
    def create_archive(self, analysis: Dict[str, List[str]]) -> Path:
        """Create archive directory for old test files."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_dir = self.project_root / f"tests_archive_{timestamp}"
        archive_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        (archive_dir / "old_tests").mkdir(exist_ok=True)
        (archive_dir / "old_scripts").mkdir(exist_ok=True)
        (archive_dir / "deprecated").mkdir(exist_ok=True)
        
        return archive_dir
    
    def archive_files(self, analysis: Dict[str, List[str]], archive_dir: Path):
        """Archive old test files."""
        # Archive deprecated tests
        for file_path in analysis['deprecated_tests']:
            src = Path(file_path)
            dst = archive_dir / "deprecated" / src.name
            if src.exists():
                shutil.copy2(src, dst)
                self.migration_log.append(f"Archived deprecated: {src.name}")
        
        # Archive old scripts
        for file_path in analysis['scripts_to_archive']:
            src = Path(file_path)
            dst = archive_dir / "old_scripts" / src.name
            if src.exists():
                shutil.copy2(src, dst)
                self.migration_log.append(f"Archived script: {src.name}")
                
        # Archive valuable tests for reference
        for file_path in analysis['valuable_tests']:
            src = Path(file_path)
            dst = archive_dir / "old_tests" / src.name
            if src.exists():
                shutil.copy2(src, dst)
                self.migration_log.append(f"Archived valuable test: {src.name}")
    
    def generate_migration_report(self, analysis: Dict[str, List[str]], archive_dir: Path):
        """Generate a migration report."""
        report = {
            'migration_date': datetime.now().isoformat(),
            'project_root': str(self.project_root),
            'archive_location': str(archive_dir),
            'analysis': analysis,
            'migration_log': self.migration_log,
            'new_structure': {
                'unit_tests': str(self.project_root / "tests" / "unit"),
                'integration_tests': str(self.project_root / "tests" / "integration"),
                'functional_tests': str(self.project_root / "tests" / "functional"),
                'fixtures': str(self.project_root / "tests" / "fixtures"),
                'config': str(self.project_root / "tests" / "conftest.py")
            },
            'recommendations': [
                "Review archived valuable tests for unique test cases",
                "Port any missing test scenarios to new structure",
                "Update CI/CD pipelines to use new test runner",
                "Remove archived files after confirming migration success",
                "Train team on new pytest-based testing approach"
            ]
        }
        
        report_file = archive_dir / "migration_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        # Also create a readable markdown report
        md_report = archive_dir / "MIGRATION_REPORT.md"
        with open(md_report, 'w') as f:
            f.write("# Test Structure Migration Report\n\n")
            f.write(f"**Migration Date:** {report['migration_date']}\n")
            f.write(f"**Archive Location:** {archive_dir}\n\n")
            
            f.write("## Files Processed\n\n")
            for category, files in analysis.items():
                if files:
                    f.write(f"### {category.replace('_', ' ').title()}\n")
                    for file_path in files:
                        f.write(f"- {Path(file_path).name}\n")
                    f.write("\n")
            
            f.write("## New Test Structure\n\n")
            f.write("The new test structure follows pytest best practices:\n\n")
            f.write("```\n")
            f.write("tests/\n")
            f.write("├── unit/           # Fast, isolated unit tests\n")
            f.write("├── integration/    # API endpoint integration tests\n")
            f.write("├── functional/     # End-to-end workflow tests\n")
            f.write("├── fixtures/       # Shared test utilities\n")
            f.write("└── conftest.py     # Pytest configuration\n")
            f.write("```\n\n")
            
            f.write("## Next Steps\n\n")
            for i, rec in enumerate(report['recommendations'], 1):
                f.write(f"{i}. {rec}\n")
            
        return report_file
    
    def run_migration(self, dry_run: bool = False) -> Path:
        """Run the complete migration process."""
        print("🔍 Analyzing old test structure...")
        analysis = self.analyze_old_structure()
        
        print("\n📊 Analysis Results:")
        for category, files in analysis.items():
            if files:
                print(f"  {category}: {len(files)} files")
        
        if dry_run:
            print("\n🔬 DRY RUN - No files will be moved or archived")
            return None
        
        print("\n📦 Creating archive...")
        archive_dir = self.create_archive(analysis)
        
        print("📁 Archiving files...")
        self.archive_files(analysis, archive_dir)
        
        print("📋 Generating migration report...")
        report_file = self.generate_migration_report(analysis, archive_dir)
        
        print(f"\n✅ Migration completed!")
        print(f"   Archive location: {archive_dir}")
        print(f"   Report: {report_file}")
        
        return archive_dir


def main():
    """Main entry point for migration script."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Migrate old test structure to new pytest structure")
    parser.add_argument("--dry-run", action="store_true", help="Analyze without making changes")
    parser.add_argument("--project-root", type=Path, default=Path.cwd(), help="Project root directory")
    
    args = parser.parse_args()
    
    migrator = TestMigrator(args.project_root)
    archive_dir = migrator.run_migration(dry_run=args.dry_run)
    
    if not args.dry_run:
        print("\n📚 Next steps:")
        print("1. Review the migration report")
        print("2. Test the new test structure: python run_tests.py --unit")
        print("3. Port any unique test cases from archived files")
        print("4. Update your CI/CD pipelines")
        print("5. Remove archived files once migration is confirmed successful")


if __name__ == "__main__":
    main()