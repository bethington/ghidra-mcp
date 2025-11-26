#!/usr/bin/env python3
"""
Continuous Self-Improvement Loop for Ghidra MCP Tooling

This script orchestrates a perpetual improvement cycle that:
1. Documents functions in Ghidra (RE work)
2. Identifies friction and missing capabilities
3. Modifies the actual tool source code
4. Tests changes
5. Deploys to Ghidra if tests pass
6. Repeats indefinitely

The system improves both:
- The binary documentation IN Ghidra
- The MCP tools themselves that interface WITH Ghidra

Usage:
    python continuous_improvement.py                    # Run with Claude Code
    python continuous_improvement.py --standalone      # Run standalone (limited)
    python continuous_improvement.py --dry-run         # Preview without changes
"""

import json
import os
import sys
import time
import subprocess
import hashlib
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Tuple
from enum import Enum
import logging
import shutil

# Configuration
REPO_ROOT = Path(__file__).parent.parent
BRIDGE_FILE = REPO_ROOT / "bridge_mcp_ghidra.py"
JAVA_PLUGIN = REPO_ROOT / "src" / "main" / "java" / "com" / "xebyte" / "GhidraMCPPlugin.java"
DEPLOY_SCRIPT = REPO_ROOT / "deploy-to-ghidra.ps1"
STATE_FILE = REPO_ROOT / "workflows" / ".improvement_state.json"
LOG_DIR = REPO_ROOT / "workflows" / "logs"

GHIDRA_SERVER = os.environ.get("GHIDRA_SERVER", "http://127.0.0.1:8089")

# Set up logging
LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / f"improvement_{datetime.now():%Y%m%d}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ChangeType(Enum):
    """Types of changes that can be made to tooling."""
    ADD_ENDPOINT = "add_endpoint"           # Add new REST endpoint to Java
    ADD_MCP_TOOL = "add_mcp_tool"           # Add new MCP tool to Python bridge
    MODIFY_ENDPOINT = "modify_endpoint"     # Change existing Java endpoint
    MODIFY_MCP_TOOL = "modify_mcp_tool"     # Change existing Python tool
    REMOVE_ENDPOINT = "remove_endpoint"     # Remove Java endpoint
    REMOVE_MCP_TOOL = "remove_mcp_tool"     # Remove Python tool
    FIX_BUG = "fix_bug"                     # Bug fix
    OPTIMIZE = "optimize"                   # Performance improvement


@dataclass
class ToolChange:
    """Represents a proposed or completed change to tooling."""
    id: str
    change_type: ChangeType
    description: str
    rationale: str
    target_file: str                        # "bridge" or "plugin"
    code_diff: Optional[str] = None         # The actual code change
    status: str = "proposed"                # proposed, implemented, tested, deployed, rejected
    test_results: Optional[Dict] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    implemented_at: Optional[str] = None
    deployed_at: Optional[str] = None


@dataclass
class ImprovementState:
    """Persistent state across improvement sessions."""
    session_count: int = 0
    functions_documented: int = 0
    tools_added: int = 0
    tools_removed: int = 0
    tools_modified: int = 0
    bugs_fixed: int = 0
    last_session: Optional[str] = None
    pending_changes: List[Dict] = field(default_factory=list)
    completed_changes: List[Dict] = field(default_factory=list)
    friction_history: List[Dict] = field(default_factory=list)
    tool_usage_stats: Dict[str, Dict] = field(default_factory=dict)

    def save(self):
        """Save state to disk."""
        def serialize(obj):
            if isinstance(obj, Enum):
                return obj.value
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

        with open(STATE_FILE, 'w') as f:
            json.dump(asdict(self), f, indent=2, default=serialize)

    @classmethod
    def load(cls) -> 'ImprovementState':
        """Load state from disk."""
        if STATE_FILE.exists():
            with open(STATE_FILE) as f:
                data = json.load(f)
                return cls(**data)
        return cls()


class SourceCodeManager:
    """Manages modifications to the actual source code files."""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.backups: Dict[str, str] = {}

    def backup_file(self, filepath: Path) -> str:
        """Create a backup of a file before modification."""
        backup_dir = REPO_ROOT / "workflows" / "backups"
        backup_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = backup_dir / f"{filepath.name}.{timestamp}.bak"

        if not self.dry_run:
            shutil.copy2(filepath, backup_path)

        self.backups[str(filepath)] = str(backup_path)
        logger.info(f"Backed up {filepath.name} to {backup_path.name}")
        return str(backup_path)

    def restore_file(self, filepath: Path) -> bool:
        """Restore a file from its backup."""
        backup_path = self.backups.get(str(filepath))
        if backup_path and Path(backup_path).exists():
            if not self.dry_run:
                shutil.copy2(backup_path, filepath)
            logger.info(f"Restored {filepath.name} from backup")
            return True
        return False

    def read_file(self, filepath: Path) -> str:
        """Read file contents."""
        return filepath.read_text(encoding='utf-8')

    def write_file(self, filepath: Path, content: str) -> bool:
        """Write content to file."""
        if self.dry_run:
            logger.info(f"[DRY RUN] Would write {len(content)} chars to {filepath.name}")
            return True

        filepath.write_text(content, encoding='utf-8')
        logger.info(f"Wrote {len(content)} chars to {filepath.name}")
        return True

    def get_file_hash(self, filepath: Path) -> str:
        """Get MD5 hash of file for change detection."""
        content = filepath.read_bytes()
        return hashlib.md5(content).hexdigest()


class PythonBridgeModifier:
    """Handles modifications to bridge_mcp_ghidra.py"""

    def __init__(self, source_manager: SourceCodeManager):
        self.source_manager = source_manager
        self.bridge_path = BRIDGE_FILE

    def add_mcp_tool(self, tool_name: str, tool_code: str) -> bool:
        """
        Add a new MCP tool to the bridge.

        Args:
            tool_name: Name of the new tool
            tool_code: Complete tool code including @mcp.tool() decorator
        """
        self.source_manager.backup_file(self.bridge_path)

        content = self.source_manager.read_file(self.bridge_path)

        # Find the end of the tools section (before if __name__ == "__main__")
        insert_marker = 'if __name__ == "__main__":'
        if insert_marker not in content:
            # Alternative: insert before the last function
            insert_marker = '\n\n# ====='  # Common section separator

        # Insert the new tool
        insert_pos = content.find(insert_marker)
        if insert_pos == -1:
            # Append at end
            new_content = content + "\n\n" + tool_code
        else:
            new_content = content[:insert_pos] + tool_code + "\n\n" + content[insert_pos:]

        return self.source_manager.write_file(self.bridge_path, new_content)

    def modify_mcp_tool(self, tool_name: str, new_code: str) -> bool:
        """
        Replace an existing MCP tool with new code.
        """
        self.source_manager.backup_file(self.bridge_path)

        content = self.source_manager.read_file(self.bridge_path)

        # Find the tool definition
        tool_pattern = f"@mcp.tool()\ndef {tool_name}"
        start = content.find(tool_pattern)
        if start == -1:
            # Try without decorator on same line
            tool_pattern = f"def {tool_name}"
            start = content.find(tool_pattern)
            if start == -1:
                logger.error(f"Tool {tool_name} not found in bridge")
                return False
            # Back up to find decorator
            decorator_start = content.rfind("@mcp.tool()", 0, start)
            if decorator_start != -1 and start - decorator_start < 100:
                start = decorator_start

        # Find the end of the function (next function or decorator)
        next_func = content.find("\n@mcp.tool()", start + 1)
        next_def = content.find("\ndef ", start + len(tool_pattern))

        if next_func == -1:
            next_func = len(content)
        if next_def == -1:
            next_def = len(content)

        end = min(next_func, next_def)

        # Replace
        new_content = content[:start] + new_code + content[end:]

        return self.source_manager.write_file(self.bridge_path, new_content)

    def remove_mcp_tool(self, tool_name: str) -> bool:
        """Remove an MCP tool from the bridge."""
        # Similar to modify but replace with empty string
        self.source_manager.backup_file(self.bridge_path)

        content = self.source_manager.read_file(self.bridge_path)

        # Find and remove (simplified - real implementation would be more careful)
        tool_pattern = f"@mcp.tool()\ndef {tool_name}"
        start = content.find(tool_pattern)
        if start == -1:
            return False

        # Find end
        next_func = content.find("\n@mcp.tool()", start + 1)
        if next_func == -1:
            next_func = content.find("\nif __name__", start + 1)
        if next_func == -1:
            next_func = len(content)

        new_content = content[:start] + content[next_func:]

        return self.source_manager.write_file(self.bridge_path, new_content)


class JavaPluginModifier:
    """Handles modifications to GhidraMCPPlugin.java"""

    def __init__(self, source_manager: SourceCodeManager):
        self.source_manager = source_manager
        self.plugin_path = JAVA_PLUGIN

    def add_endpoint(self, endpoint_name: str, handler_code: str) -> bool:
        """
        Add a new REST endpoint to the Java plugin.

        Args:
            endpoint_name: URL path (e.g., "/my_endpoint")
            handler_code: Java code for the endpoint handler
        """
        self.source_manager.backup_file(self.plugin_path)

        content = self.source_manager.read_file(self.plugin_path)

        # Find where endpoints are registered (look for createContext pattern)
        # Insert before the server.start() call
        insert_marker = "server.start();"
        insert_pos = content.find(insert_marker)

        if insert_pos == -1:
            logger.error("Could not find server.start() in plugin")
            return False

        # Build the endpoint registration code
        endpoint_code = f'''
        server.createContext("{endpoint_name}", exchange -> {{
            {handler_code}
        }});

        '''

        new_content = content[:insert_pos] + endpoint_code + content[insert_pos:]

        return self.source_manager.write_file(self.plugin_path, new_content)


class DeploymentManager:
    """Handles building and deploying changes to Ghidra."""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

    def build_java(self) -> Tuple[bool, str]:
        """Build the Java plugin using Maven."""
        if self.dry_run:
            logger.info("[DRY RUN] Would run: mvn clean package assembly:single")
            return True, "Dry run - build skipped"

        try:
            result = subprocess.run(
                ["mvn", "clean", "package", "assembly:single", "-q"],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                timeout=300
            )
            if result.returncode == 0:
                logger.info("Maven build successful")
                return True, result.stdout
            else:
                logger.error(f"Maven build failed: {result.stderr}")
                return False, result.stderr
        except subprocess.TimeoutExpired:
            return False, "Build timed out"
        except Exception as e:
            return False, str(e)

    def deploy_to_ghidra(self) -> Tuple[bool, str]:
        """Run the deploy-to-ghidra.ps1 script."""
        if self.dry_run:
            logger.info("[DRY RUN] Would run: deploy-to-ghidra.ps1")
            return True, "Dry run - deploy skipped"

        if not DEPLOY_SCRIPT.exists():
            return False, "Deploy script not found"

        try:
            result = subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(DEPLOY_SCRIPT)],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                logger.info("Deployment successful")
                return True, result.stdout
            else:
                logger.error(f"Deployment failed: {result.stderr}")
                return False, result.stderr
        except Exception as e:
            return False, str(e)

    def restart_bridge(self) -> bool:
        """Signal that the bridge needs to be restarted."""
        # In MCP context, this would be handled by Claude Code
        logger.info("Bridge restart required - changes will take effect on next MCP session")
        return True


class TestRunner:
    """Runs tests to validate changes."""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

    def run_unit_tests(self) -> Tuple[bool, Dict]:
        """Run Python unit tests."""
        if self.dry_run:
            return True, {"status": "dry_run", "passed": 0, "failed": 0}

        try:
            result = subprocess.run(
                [sys.executable, "workflows/test_workflow.py", "--quick"],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                timeout=60
            )

            passed = "OK" in result.stdout or result.returncode == 0
            return passed, {
                "status": "passed" if passed else "failed",
                "output": result.stdout,
                "errors": result.stderr
            }
        except Exception as e:
            return False, {"status": "error", "error": str(e)}

    def run_integration_tests(self) -> Tuple[bool, Dict]:
        """Run integration tests against Ghidra."""
        if self.dry_run:
            return True, {"status": "dry_run", "passed": 0, "failed": 0}

        try:
            result = subprocess.run(
                [sys.executable, "workflows/test_workflow.py", "--integration"],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                timeout=120
            )

            passed = "OK" in result.stdout or result.returncode == 0
            return passed, {
                "status": "passed" if passed else "failed",
                "output": result.stdout,
                "errors": result.stderr
            }
        except Exception as e:
            return False, {"status": "error", "error": str(e)}

    def run_smoke_test(self) -> Tuple[bool, Dict]:
        """Quick smoke test against Ghidra server."""
        import requests

        if self.dry_run:
            return True, {"status": "dry_run"}

        try:
            response = requests.get(f"{GHIDRA_SERVER}/get_metadata", timeout=5)
            if response.status_code == 200:
                return True, {"status": "connected", "response": response.text[:200]}
            return False, {"status": "error", "code": response.status_code}
        except Exception as e:
            return False, {"status": "connection_failed", "error": str(e)}


class ContinuousImprovementLoop:
    """
    Main orchestrator for continuous self-improvement.

    This is designed to be called by Claude Code, which provides the
    intelligence for:
    - Analyzing decompiled code to understand function purpose
    - Deciding on good names for functions/variables
    - Identifying what tools are missing or problematic
    - Generating code for new tools
    """

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.state = ImprovementState.load()
        self.source_manager = SourceCodeManager(dry_run)
        self.bridge_modifier = PythonBridgeModifier(self.source_manager)
        self.plugin_modifier = JavaPluginModifier(self.source_manager)
        self.deployment_manager = DeploymentManager(dry_run)
        self.test_runner = TestRunner(dry_run)

        # Import Ghidra client
        sys.path.insert(0, str(REPO_ROOT))
        from workflows.re_improvement_workflow import GhidraClient
        self.ghidra_client = GhidraClient()

        # Import Ghidra manager for process control
        from workflows.ghidra_manager import GhidraManager, GhidraConfig, GhidraState
        self.ghidra_manager = GhidraManager()
        self.GhidraState = GhidraState

    def check_ghidra_connection(self) -> bool:
        """Verify Ghidra is available."""
        return self.ghidra_client.is_available()

    def ensure_ghidra_running(self, project: str = None, binary: str = None) -> Tuple[bool, str]:
        """
        Ensure Ghidra is running with MCP available.

        If Ghidra is not running or MCP is not available, this will:
        1. Start Ghidra with the specified project/binary
        2. Wait for MCP server to become available

        Args:
            project: Path to .gpr project file
            binary: Binary to open in the project

        Returns:
            Tuple of (success, message)
        """
        return self.ghidra_manager.ensure_running(project=project, binary=binary)

    def restart_ghidra(self, project: str = None, binary: str = None, force: bool = False) -> Tuple[bool, str]:
        """
        Restart Ghidra completely.

        Args:
            project: Path to .gpr project file
            binary: Binary to open
            force: Force kill existing instance

        Returns:
            Tuple of (success, message)
        """
        return self.ghidra_manager.restart(project=project, binary=binary, force_close=force)

    def get_ghidra_state(self) -> str:
        """Get current Ghidra state as a string."""
        state = self.ghidra_manager.get_state(force_check=True)
        return state.value

    def health_check(self) -> Dict[str, Any]:
        """
        Perform comprehensive health check.

        Returns dict with state, mcp_available, program_loaded, and recommendations.
        """
        return self.ghidra_manager.health_check()

    def get_next_function_to_document(self) -> Optional[Dict]:
        """Find the next undocumented function to work on."""
        result = self.ghidra_client.call("searchFunctions", {"query": "FUN_", "limit": 1})
        if result.get("success") and result.get("data"):
            lines = result["data"].strip().split('\n')
            for line in lines:
                if ' @ ' in line:
                    name, addr = line.split(' @ ')
                    return {"name": name.strip(), "address": addr.strip()}
        return None

    def get_function_analysis(self, func_name: str) -> Dict[str, Any]:
        """Get comprehensive analysis of a function for Claude to interpret."""
        analysis = {
            "name": func_name,
            "decompiled": None,
            "disassembly": None,
            "variables": None,
            "callees": None,
            "callers": None,
            "strings": [],
            "constants": []
        }

        # Decompile
        result = self.ghidra_client.call("decompile", {"name": func_name}, timeout=60)
        if result.get("success"):
            analysis["decompiled"] = result["data"]

        # Disassemble
        result = self.ghidra_client.call("disassemble_function", {"name": func_name})
        if result.get("success"):
            analysis["disassembly"] = result["data"]

        # Variables
        result = self.ghidra_client.call("function_variables", {"name": func_name})
        if result.get("success"):
            analysis["variables"] = result["data"]

        # Callees
        result = self.ghidra_client.call("function_callees", {"name": func_name})
        if result.get("success"):
            analysis["callees"] = result["data"]

        # Callers
        result = self.ghidra_client.call("function_callers", {"name": func_name})
        if result.get("success"):
            analysis["callers"] = result["data"]

        return analysis

    def apply_documentation(self, func_address: str,
                           new_name: str = None,
                           prototype: str = None,
                           plate_comment: str = None,
                           variable_renames: Dict[str, str] = None,
                           variable_types: Dict[str, str] = None) -> Dict[str, bool]:
        """Apply documentation to a function."""
        results = {}

        if new_name:
            # First need to get the current name
            funcs = self.ghidra_client.call("searchFunctions",
                                            {"query": func_address[-8:], "limit": 1})
            if funcs.get("success") and funcs.get("data"):
                lines = funcs["data"].strip().split('\n')
                for line in lines:
                    if ' @ ' in line:
                        old_name = line.split(' @ ')[0].strip()
                        result = self.ghidra_client.call("rename_function", {
                            "old_name": old_name,
                            "new_name": new_name
                        }, method="POST")
                        results["rename"] = result.get("success", False)
                        break

        if prototype:
            result = self.ghidra_client.call("set_function_prototype", {
                "function_address": func_address,
                "prototype": prototype
            }, method="POST")
            results["prototype"] = result.get("success", False)

        if plate_comment:
            func_name = new_name or func_address
            result = self.ghidra_client.call("set_plate_comment", {
                "function_name": func_name,
                "comment": plate_comment
            }, method="POST")
            results["plate_comment"] = result.get("success", False)

        if variable_types:
            result = self.ghidra_client.call("batch_set_variable_types", {
                "function_address": func_address,
                "variable_types": json.dumps(variable_types)
            }, method="POST", timeout=60)
            results["variable_types"] = result.get("success", False)

        return results

    def record_friction(self, description: str, context: Dict = None):
        """Record a friction point for later analysis."""
        friction = {
            "timestamp": datetime.now().isoformat(),
            "description": description,
            "context": context or {},
            "session": self.state.session_count
        }
        self.state.friction_history.append(friction)
        self.state.save()
        logger.info(f"Friction recorded: {description}")

    def propose_tool_change(self, change: ToolChange):
        """Add a tool change proposal."""
        self.state.pending_changes.append(asdict(change))
        self.state.save()
        logger.info(f"Change proposed: {change.description}")

    def implement_tool_change(self, change_id: str, code: str) -> bool:
        """
        Implement a proposed tool change.

        Args:
            change_id: ID of the change to implement
            code: The actual code to add/modify
        """
        # Find the change
        change_dict = None
        for c in self.state.pending_changes:
            if c["id"] == change_id:
                change_dict = c
                break

        if not change_dict:
            logger.error(f"Change {change_id} not found")
            return False

        change_type = ChangeType(change_dict["change_type"])
        target = change_dict["target_file"]

        success = False

        if target == "bridge":
            if change_type == ChangeType.ADD_MCP_TOOL:
                success = self.bridge_modifier.add_mcp_tool(
                    change_dict["description"].split(":")[0],  # Extract tool name
                    code
                )
            elif change_type == ChangeType.MODIFY_MCP_TOOL:
                success = self.bridge_modifier.modify_mcp_tool(
                    change_dict["description"].split(":")[0],
                    code
                )
            elif change_type == ChangeType.REMOVE_MCP_TOOL:
                success = self.bridge_modifier.remove_mcp_tool(
                    change_dict["description"].split(":")[0]
                )

        elif target == "plugin":
            if change_type == ChangeType.ADD_ENDPOINT:
                success = self.plugin_modifier.add_endpoint(
                    change_dict["description"],
                    code
                )

        if success:
            change_dict["status"] = "implemented"
            change_dict["implemented_at"] = datetime.now().isoformat()
            change_dict["code_diff"] = code[:500]  # Store first 500 chars
            self.state.save()
            logger.info(f"Change {change_id} implemented")

        return success

    def test_changes(self) -> Tuple[bool, Dict]:
        """Run tests after implementing changes."""
        results = {}

        # Unit tests first (fast)
        unit_passed, unit_results = self.test_runner.run_unit_tests()
        results["unit_tests"] = unit_results

        if not unit_passed:
            logger.error("Unit tests failed - rolling back")
            return False, results

        # Smoke test against Ghidra
        smoke_passed, smoke_results = self.test_runner.run_smoke_test()
        results["smoke_test"] = smoke_results

        if not smoke_passed:
            logger.warning("Smoke test failed - Ghidra may not be running")

        # Integration tests (if Ghidra is available)
        if smoke_passed:
            int_passed, int_results = self.test_runner.run_integration_tests()
            results["integration_tests"] = int_results

            if not int_passed:
                logger.error("Integration tests failed")
                return False, results

        return True, results

    def deploy_changes(self) -> Tuple[bool, str]:
        """Build and deploy changes to Ghidra."""
        # Check if Java changes need building
        if any(c.get("target_file") == "plugin"
               for c in self.state.pending_changes
               if c.get("status") == "implemented"):

            logger.info("Building Java plugin...")
            build_success, build_output = self.deployment_manager.build_java()
            if not build_success:
                return False, f"Build failed: {build_output}"

            logger.info("Deploying to Ghidra...")
            deploy_success, deploy_output = self.deployment_manager.deploy_to_ghidra()
            if not deploy_success:
                return False, f"Deploy failed: {deploy_output}"

        # Mark changes as deployed
        for change in self.state.pending_changes:
            if change.get("status") == "implemented":
                change["status"] = "deployed"
                change["deployed_at"] = datetime.now().isoformat()
                self.state.completed_changes.append(change)

        # Clear pending
        self.state.pending_changes = [
            c for c in self.state.pending_changes
            if c.get("status") != "deployed"
        ]
        self.state.save()

        return True, "Deployment successful"

    def rollback_changes(self):
        """Rollback all pending changes."""
        for filepath, backup_path in self.source_manager.backups.items():
            self.source_manager.restore_file(Path(filepath))

        # Mark changes as rejected
        for change in self.state.pending_changes:
            if change.get("status") == "implemented":
                change["status"] = "rejected"

        self.state.save()
        logger.info("Changes rolled back")

    def get_improvement_summary(self) -> Dict:
        """Get a summary of all improvements made."""
        return {
            "sessions": self.state.session_count,
            "functions_documented": self.state.functions_documented,
            "tools_added": self.state.tools_added,
            "tools_removed": self.state.tools_removed,
            "tools_modified": self.state.tools_modified,
            "bugs_fixed": self.state.bugs_fixed,
            "pending_changes": len(self.state.pending_changes),
            "completed_changes": len(self.state.completed_changes),
            "friction_points": len(self.state.friction_history)
        }

    def start_session(self):
        """Start a new improvement session."""
        self.state.session_count += 1
        self.state.last_session = datetime.now().isoformat()
        self.state.save()
        logger.info(f"Started session {self.state.session_count}")

    def end_session(self):
        """End the current session."""
        self.state.save()
        logger.info(f"Ended session {self.state.session_count}")
        logger.info(f"Summary: {json.dumps(self.get_improvement_summary(), indent=2)}")


# =============================================================================
# Claude Code Integration Functions
# =============================================================================

def get_loop_instance(dry_run: bool = False) -> ContinuousImprovementLoop:
    """Get a configured improvement loop instance."""
    return ContinuousImprovementLoop(dry_run=dry_run)


def ensure_ghidra(project: str = None, binary: str = None) -> Tuple[bool, str]:
    """
    Ensure Ghidra is running with MCP available.

    This is a convenience function that can be called before starting the loop.

    Args:
        project: Path to .gpr project file (e.g., "F:\\GhidraProjects\\PD2.gpr")
        binary: Binary to open (e.g., "D2Win.dll")

    Returns:
        Tuple of (success, message)

    Example:
        success, msg = ensure_ghidra(
            project=r"F:\GhidraProjects\PD2.gpr",
            binary="D2Win.dll"
        )
        if success:
            loop = get_loop_instance()
            loop.start_session()
    """
    from workflows.ghidra_manager import ensure_ghidra as _ensure
    return _ensure(project=project, binary=binary)


def restart_ghidra(project: str = None, binary: str = None, force: bool = False) -> Tuple[bool, str]:
    """
    Restart Ghidra completely.

    Args:
        project: Path to .gpr project file
        binary: Binary to open
        force: Force kill existing instance

    Returns:
        Tuple of (success, message)
    """
    from workflows.ghidra_manager import restart_ghidra as _restart
    return _restart(project=project, binary=binary, force=force)


def check_ghidra_status() -> Dict[str, Any]:
    """
    Check Ghidra status without starting anything.

    Returns:
        Dict with:
        - state: "not_running", "running_no_mcp", or "running_with_mcp"
        - mcp_available: Boolean
        - program_loaded: Name of loaded program or None
        - recommendations: List of suggested actions
    """
    from workflows.ghidra_manager import check_ghidra
    return check_ghidra()


def configure_ghidra_defaults(
    ghidra_path: str = None,
    project: str = None,
    binary: str = None
):
    """
    Configure default Ghidra settings for the improvement loop.

    These settings are saved and used when no arguments are provided
    to ensure_ghidra() or restart_ghidra().

    Args:
        ghidra_path: Path to Ghidra installation (e.g., "F:\\ghidra_11.4.2")
        project: Default project file (e.g., "F:\\GhidraProjects\\PD2.gpr")
        binary: Default binary to open (e.g., "D2Win.dll")

    Example:
        configure_ghidra_defaults(
            ghidra_path=r"F:\ghidra_11.4.2",
            project=r"F:\GhidraProjects\PD2.gpr",
            binary="D2Win.dll"
        )

        # Now these work without arguments:
        ensure_ghidra()
        restart_ghidra()
    """
    from workflows.ghidra_manager import configure_defaults
    return configure_defaults(ghidra_path=ghidra_path, project=project, binary=binary)


def document_next_function(loop: ContinuousImprovementLoop) -> Optional[Dict]:
    """
    Find and return analysis for the next function to document.

    Returns:
        Dict with function info and analysis, or None if no functions need work
    """
    func = loop.get_next_function_to_document()
    if not func:
        return None

    analysis = loop.get_function_analysis(func["name"])
    return {
        "function": func,
        "analysis": analysis
    }


def apply_function_documentation(loop: ContinuousImprovementLoop,
                                 address: str,
                                 name: str,
                                 prototype: str = None,
                                 comment: str = None,
                                 var_types: Dict[str, str] = None) -> Dict:
    """
    Apply documentation to a function.

    This is called by Claude Code after analyzing the function.
    """
    results = loop.apply_documentation(
        func_address=address,
        new_name=name,
        prototype=prototype,
        plate_comment=comment,
        variable_types=var_types
    )

    if any(results.values()):
        loop.state.functions_documented += 1
        loop.state.save()

    return results


def report_tool_friction(loop: ContinuousImprovementLoop,
                        tool_name: str,
                        issue: str,
                        suggested_fix: str = None):
    """
    Report friction with a tool.

    Called by Claude Code when encountering issues.
    """
    loop.record_friction(f"Tool {tool_name}: {issue}", {
        "tool": tool_name,
        "suggested_fix": suggested_fix
    })


def propose_new_tool(loop: ContinuousImprovementLoop,
                    tool_name: str,
                    description: str,
                    rationale: str,
                    target: str = "bridge") -> str:
    """
    Propose a new tool to be added.

    Returns the change ID for later implementation.
    """
    change = ToolChange(
        id=f"CHANGE-{loop.state.session_count:04d}-{len(loop.state.pending_changes):03d}",
        change_type=ChangeType.ADD_MCP_TOOL if target == "bridge" else ChangeType.ADD_ENDPOINT,
        description=f"{tool_name}: {description}",
        rationale=rationale,
        target_file=target
    )
    loop.propose_tool_change(change)
    return change.id


def implement_proposed_change(loop: ContinuousImprovementLoop,
                             change_id: str,
                             code: str) -> bool:
    """
    Implement a proposed change with actual code.

    Called by Claude Code after generating the code.
    """
    return loop.implement_tool_change(change_id, code)


def test_and_deploy(loop: ContinuousImprovementLoop) -> Tuple[bool, Dict]:
    """
    Test and deploy all pending changes.

    Returns success status and detailed results.
    """
    test_passed, test_results = loop.test_changes()

    if not test_passed:
        loop.rollback_changes()
        return False, {"status": "rolled_back", "tests": test_results}

    deploy_success, deploy_msg = loop.deploy_changes()

    return deploy_success, {
        "status": "deployed" if deploy_success else "deploy_failed",
        "tests": test_results,
        "deploy": deploy_msg
    }


# =============================================================================
# Standalone Execution (Limited without Claude)
# =============================================================================

def main():
    """Main entry point for standalone execution."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Continuous Self-Improvement Loop for Ghidra MCP"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without applying them"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show current improvement status"
    )
    parser.add_argument(
        "--standalone",
        action="store_true",
        help="Run in standalone mode (limited without Claude)"
    )

    args = parser.parse_args()

    loop = ContinuousImprovementLoop(dry_run=args.dry_run)

    if args.status:
        print("\n" + "=" * 60)
        print("CONTINUOUS IMPROVEMENT STATUS")
        print("=" * 60)
        print(json.dumps(loop.get_improvement_summary(), indent=2))

        if loop.state.friction_history:
            print("\nRecent Friction Points:")
            for f in loop.state.friction_history[-5:]:
                print(f"  - {f['description']}")

        if loop.state.pending_changes:
            print("\nPending Changes:")
            for c in loop.state.pending_changes:
                print(f"  - [{c['status']}] {c['description']}")

        return 0

    if args.standalone:
        print("\n" + "=" * 60)
        print("STANDALONE MODE")
        print("=" * 60)
        print("Note: Full improvement loop requires Claude Code integration.")
        print("In standalone mode, we can only report status and run tests.")
        print()

        # Check Ghidra connection
        if loop.check_ghidra_connection():
            print("[OK] Ghidra server is accessible")

            # Find next function
            func = loop.get_next_function_to_document()
            if func:
                print(f"\nNext function to document: {func['name']} @ {func['address']}")
                print("\nTo document this function, run with Claude Code:")
                print("  Claude> Analyze and document the function at", func['address'])
            else:
                print("\nNo undocumented functions found (all FUN_* functions documented)")
        else:
            print("[ERROR] Ghidra server is not accessible")

        return 0

    # Default: show usage
    print("\n" + "=" * 60)
    print("CONTINUOUS IMPROVEMENT LOOP")
    print("=" * 60)
    print("""
This system is designed to run with Claude Code for full functionality.

Usage with Claude Code:
    1. Start Claude Code in this directory
    2. Ask: "Run the continuous improvement loop"
    3. Claude will analyze functions and improve tooling

Standalone commands:
    python continuous_improvement.py --status      # View status
    python continuous_improvement.py --standalone  # Limited standalone mode
    python continuous_improvement.py --dry-run     # Preview mode

The loop will:
    1. Find undocumented functions
    2. Analyze with decompilation
    3. Apply documentation (names, types, comments)
    4. Record any friction or missing capabilities
    5. Propose and implement tool improvements
    6. Test changes
    7. Deploy to Ghidra
    8. Repeat
""")

    return 0


if __name__ == "__main__":
    sys.exit(main())
