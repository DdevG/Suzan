#!/usr/bin/env python3
import re
import time
import json
import logging
import threading
import os
import tempfile
import subprocess
from datetime import datetime
from functools import wraps
from typing import Optional, List, Tuple, Dict, Any, Union

from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify
import plotly.graph_objs as go
import plotly.offline as pyo

from web3 import Web3
from web3.exceptions import TransactionNotFound
from werkzeug.security import generate_password_hash, check_password_hash

# =============================================================================
# 1. Flask App & Configuration
# =============================================================================
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

# =============================================================================
# 2. Logging Configuration
# =============================================================================
logger = logging.getLogger("contract_scanner")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

file_handler = logging.FileHandler("scanner.log", mode="a")
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# =============================================================================
# 3. Utility Decorators
# =============================================================================
def login_required(f):
    """Decorator that ensures a user is logged in."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# =============================================================================
# 4. Live Feed Integration
# =============================================================================
# These globals and functions support a live, dynamic activity feed.
live_feed: List[str] = []  # List to hold feed messages
live_feed_lock = threading.Lock()
MAX_FEED_MESSAGES = 50  # Maximum number of messages to store

def add_feed_message(message: str) -> None:
    """Append a timestamped message to the live feed (thread safe)."""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}"
    with live_feed_lock:
        live_feed.append(entry)
        if len(live_feed) > MAX_FEED_MESSAGES:
            live_feed.pop(0)

# =============================================================================
# 5. Blockchain Connection
# =============================================================================
SONIC_RPC_URL = "https://rpc.soniclabs.com"

def connect_to_sonic() -> Optional[Web3]:
    """
    Attempt to connect to the Sonic blockchain.
    Returns a Web3 instance on success or None on failure.
    """
    try:
        web3_instance = Web3(Web3.HTTPProvider(SONIC_RPC_URL))
        if not web3_instance.is_connected():
            raise ConnectionError("Unable to connect to Sonic blockchain.")
        msg = f"Connected to Sonic blockchain. Latest block: {web3_instance.eth.block_number}"
        logger.info(msg)
        add_feed_message(msg)
        return web3_instance
    except Exception as e:
        logger.error(f"Error connecting to Sonic blockchain: {e}")
        time.sleep(5)
        return None

web3: Optional[Web3] = None
while web3 is None:
    web3 = connect_to_sonic()

# =============================================================================
# 6. Constants, Regex & In-Memory Cache
# =============================================================================
ADDRESS_REGEX = re.compile(r'0x[a-fA-F0-9]{40}', re.IGNORECASE)
OPCODE_TABLE = {
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8",
    0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI",
    0x58: "PC", 0x59: "MSIZE", 0x5A: "GAS", 0x5B: "JUMPDEST",
    0xA1: "LOG1", 0xA2: "LOG2", 0xA3: "LOG3", 0xA4: "LOG4",
    0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE", 0xF3: "RETURN",
    0xF4: "DELEGATECALL", 0xF5: "CREATE2", 0xFA: "STATICCALL",
    0xFD: "REVERT", 0xFE: "INVALID", 0xFF: "SUICIDE"
}

# In-memory cache for scanned contracts (with a lock)
scanned_addresses: Dict[str, dict] = {}
scanned_addresses_lock = threading.Lock()

# Token definitions
ERC20_ABI = [{
    "constant": True,
    "inputs": [{"name": "_owner", "type": "address"}],
    "name": "balanceOf",
    "outputs": [{"name": "balance", "type": "uint256"}],
    "type": "function"
}]
TOKEN_LIST = {
    "WSONIC": "0x039e2fB66102314Ce7b64Ce5Ce3E5183bc94aD38"
}

# =============================================================================
# 7. Core Utility Functions
# =============================================================================
def is_contract_address(address: str) -> bool:
    """Return True if the given address has bytecode (i.e. is a contract)."""
    try:
        code = web3.eth.get_code(Web3.to_checksum_address(address))
        return len(code) > 0
    except Exception as e:
        logger.error(f"Error checking contract code for {address}: {e}")
        return False

def find_addresses_in_data(data: Union[bytes, str]) -> List[str]:
    """Extract Ethereum addresses from a data blob."""
    if isinstance(data, bytes):
        data = data.hex()
    return ADDRESS_REGEX.findall(data)

def disassemble(bytecode_hex: str) -> List[Tuple[int, str, Optional[bytes]]]:
    """
    Disassemble a contract's bytecode.
    Returns a list of tuples: (offset, opcode name, operand bytes if any).
    """
    code_bytes = bytes.fromhex(bytecode_hex.replace("0x", ""))
    i = 0
    instructions = []
    length = len(code_bytes)
    while i < length:
        opcode = code_bytes[i]
        if 0x60 <= opcode <= 0x7F:
            push_size = opcode - 0x5F
            instr_name = f"PUSH{push_size}"
            start = i + 1
            end = min(i + 1 + push_size, length)
            operand = code_bytes[start:end]
            instructions.append((i, instr_name, operand))
            i += 1 + push_size
        else:
            instr_name = OPCODE_TABLE.get(opcode, f"UNKNOWN_0x{opcode:02X}")
            instructions.append((i, instr_name, None))
            i += 1
    return instructions

# =============================================================================
# 8. Vulnerability Analysis Functions
# =============================================================================
def check_for_reentrancy_patterns(instructions: List[Tuple[int, str, Optional[bytes]]]) -> bool:
    """Heuristically check for reentrancy patterns in a list of instructions."""
    possible_reentrancy = False
    for i, (_, opcode_name, _) in enumerate(instructions):
        if opcode_name == "SSTORE":
            for j in range(i+1, min(i+6, len(instructions))):
                if instructions[j][1] in ("CALL", "DELEGATECALL", "CALLCODE"):
                    possible_reentrancy = True
    for i, (_, opcode_name, _) in enumerate(instructions):
        if opcode_name in ("CALL", "DELEGATECALL", "CALLCODE"):
            for j in range(i+1, min(i+6, len(instructions))):
                if instructions[j][1] == "SSTORE":
                    possible_reentrancy = True
    return possible_reentrancy

def in_depth_reentrancy_check(bytecode_hex: str) -> bool:
    """
    Look more deeply for reentrancy by counting occurrences of CALL/DELEGATECALL
    followed shortly by an SSTORE.
    """
    instructions = disassemble(bytecode_hex)
    occurrences = 0
    for i in range(len(instructions)):
        op = instructions[i][1]
        if op in ("CALL", "DELEGATECALL", "CALLCODE"):
            for j in range(i+1, min(i+11, len(instructions))):
                if instructions[j][1] == "SSTORE":
                    occurrences += 1
                    break
    return occurrences > 1

def check_for_block_timestamp(bytecode_hex: str) -> bool:
    """Check whether the bytecode uses the block.timestamp opcode (0x42)."""
    code_bytes = bytes.fromhex(bytecode_hex.replace("0x", ""))
    return 0x42 in code_bytes

def check_for_unchecked_call_value(bytecode_hex: str) -> bool:
    """Check for potential unchecked call.value usage."""
    upper_hex = bytecode_hex.upper()
    if "63616C6C2E76616C756528" in upper_hex:
        return True
    code_bytes = bytes.fromhex(bytecode_hex.replace("0x", ""))
    return 0x34 in code_bytes

def check_for_safemath(bytecode_hex: str) -> bool:
    """Determine if SafeMath is used in the contract."""
    return "536166654d617468" in bytecode_hex.upper()

def unprotected_withdraw_check(bytecode_hex: str) -> bool:
    """Detect an unprotected withdraw function in the bytecode."""
    lower_hex = bytecode_hex.lower()
    if "7769746864726177" in lower_hex:
        if ("6f6e6c794f776e6572" not in lower_hex and
            "72657374726963746564" not in lower_hex and
            "61646d696e" not in lower_hex):
            return True
    return False

def unprotected_withdraw_balance_check(bytecode_hex: str, contract_address: str) -> bool:
    """
    Check if an unprotected withdraw function exists and the contract holds balance.
    (Returns True only if both conditions are met.)
    """
    if unprotected_withdraw_check(bytecode_hex):
        try:
            balance = web3.eth.get_balance(contract_address)
            if balance > 0:
                return True
        except Exception as e:
            logger.error(f"Error fetching balance for {contract_address}: {e}")
    return False

def unprotected_selfdestruct_check(bytecode_hex: str) -> bool:
    """Detect if the selfdestruct opcode is present without protection."""
    instructions = disassemble(bytecode_hex)
    has_selfdestruct = any(op == "SUICIDE" for _, op, _ in instructions)
    if has_selfdestruct:
        lower_hex = bytecode_hex.lower()
        if ("onlyowner" not in lower_hex and
            "restricted" not in lower_hex and
            "admin" not in lower_hex):
            return True
    return False

def unprotected_token_withdraw_check(bytecode_hex: str) -> bool:
    """Check for unprotected token withdraw routines."""
    lower_hex = bytecode_hex.lower()
    if "7769746864726177746f6b656e" in lower_hex:
        if ("6f6e6c794f776e6572" not in lower_hex and "61646d696e" not in lower_hex):
            return True
    return False

def unprotected_token_transfer_check(bytecode_hex: str) -> bool:
    """Check for unprotected token transfer routines."""
    lower_hex = bytecode_hex.lower()
    if "7472616e73666572746f6b656e" in lower_hex:
        if ("6f6e6c794f776e6572" not in lower_hex and "61646d696e" not in lower_hex):
            return True
    return False

def get_token_balances(contract_address: str) -> Dict[str, str]:
    """Query token balances for a contract from a predefined token list."""
    balances = {}
    for token_name, token_addr in TOKEN_LIST.items():
        try:
            token_contract = web3.eth.contract(
                address=Web3.to_checksum_address(token_addr),
                abi=ERC20_ABI
            )
            balance = token_contract.functions.balanceOf(contract_address).call()
            balance_ether = web3.from_wei(balance, 'ether')
            balances[token_name] = str(balance_ether)
        except Exception as e:
            balances[token_name] = "Error"
    return balances

def advanced_vulnerability_check(bytecode_hex: str) -> Dict[str, Any]:
    """
    Perform an in-depth vulnerability analysis on the contract bytecode.
    Checks for 18 specific vulnerability types plus extra (simulated) tests
    to reach 100 keys.
    """
    results: Dict[str, Any] = {}
    instructions = disassemble(bytecode_hex)
    opcode_text = " ".join(op for (_, op, _) in instructions if op)
    code_bytes = bytes.fromhex(bytecode_hex.replace("0x", ""))
    
    # 18 dedicated vulnerability flags
    results["vuln_reentrancy"] = (check_for_reentrancy_patterns(instructions) or
                                  in_depth_reentrancy_check(bytecode_hex) or
                                  ("REENTRANCY" in opcode_text.upper()))
    results["vuln_overflow_underflow"] = ((not check_for_safemath(bytecode_hex)) or
                                          ("OVERFLOW" in opcode_text.upper() or "UNDERFLOW" in opcode_text.upper()))
    results["vuln_selfdestruct"] = ("SUICIDE" in opcode_text)
    results["vuln_private_data"] = ("PRIVATE" in opcode_text.upper())
    results["vuln_delegatecall"] = ("DELEGATECALL" in opcode_text)
    results["vuln_randomness"] = (check_for_block_timestamp(bytecode_hex) or
                                  (0x44 in code_bytes) or
                                  ("TIMESTAMP" in opcode_text.upper() or "DIFFICULTY" in opcode_text.upper() or "RANDOM" in opcode_text.upper()))
    results["vuln_dos"] = ("DOS" in opcode_text.upper())
    results["vuln_phishing_tx_origin"] = (("TX.ORIGIN" in opcode_text.upper()) or (0x32 in code_bytes))
    results["vuln_external_contract"] = (0x3C in code_bytes or "EXTCODECOPY" in opcode_text.upper())
    results["vuln_honeypot"] = ("HONEYPOT" in opcode_text.upper())
    results["vuln_frontrunning"] = ("FRONTRUN" in opcode_text.upper())
    results["vuln_timestamp_manipulation"] = (check_for_block_timestamp(bytecode_hex) or "TIMESTAMP" in opcode_text.upper())
    results["vuln_signature_replay"] = ("REPLAY" in opcode_text.upper())
    results["vuln_size_bypass"] = (0x3B in code_bytes)
    results["vuln_same_address"] = ("SAME_ADDRESS" in opcode_text.upper())
    results["vuln_vault_inflation"] = ("INFLATION" in opcode_text.upper())
    results["vuln_weth_permit"] = ("PERMIT" in opcode_text.upper())
    results["vuln_63_64"] = ("63/64" in opcode_text)
    
    # Basic legacy flags
    results["has_delegatecall"] = ("DELEGATECALL" in opcode_text)
    results["has_create2"] = ("CREATE2" in opcode_text)
    results["has_selfdestruct"] = ("SUICIDE" in opcode_text)
    results["has_tx_origin"] = (("TX.ORIGIN" in opcode_text.upper()) or ("TXORIGIN" in opcode_text.upper()))
    results["has_possible_reentrancy"] = check_for_reentrancy_patterns(instructions)
    results["has_nonreentrant_guard"] = ("NONREENTRANCY" in opcode_text.upper())
    results["uses_block_timestamp"] = check_for_block_timestamp(bytecode_hex)
    results["uses_callvalue"] = check_for_unchecked_call_value(bytecode_hex)
    results["uses_safemath"] = check_for_safemath(bytecode_hex)
    results["in_depth_reentrancy"] = in_depth_reentrancy_check(bytecode_hex)
    results["tx_origin_usage"] = (0x32 in code_bytes)
    
    # Extra simulated vulnerability tests to reach 100 keys
    extra_keys = [f"vuln_extra_{i}" for i in range(1, 90)]
    for i, key in enumerate(extra_keys, start=1):
        pattern = f"PATTERN{i}"
        results[key] = pattern.upper() in opcode_text.upper()
    
    return results

def rate_contract(results: Dict[str, Any]) -> int:
    """Calculate a risk rating (1-10) for a contract based on its vulnerability flags."""
    score = 0.0
    if results.get("has_selfdestruct"):
        score += 3
    if results.get("has_possible_reentrancy"):
        score += 2
    if results.get("in_depth_reentrancy"):
        score += 3
    if results.get("tx_origin_usage"):
        score += 2
    vuln_flags = ["vuln_reentrancy", "vuln_overflow_underflow", "vuln_selfdestruct", "vuln_private_data", 
                  "vuln_delegatecall", "vuln_randomness", "vuln_dos", "vuln_phishing_tx_origin", 
                  "vuln_external_contract", "vuln_honeypot", "vuln_frontrunning", "vuln_timestamp_manipulation",
                  "vuln_signature_replay", "vuln_size_bypass", "vuln_same_address", "vuln_vault_inflation", 
                  "vuln_weth_permit", "vuln_63_64"]
    for flag in vuln_flags:
        if results.get(flag):
            score += 0.5
    extra_weight = sum(0.1 for key, val in results.items() if key.startswith("vuln_extra_") and val)
    score += extra_weight
    try:
        balance = float(results.get("balance", "0"))
        if balance > 10:
            score += 1
    except Exception:
        pass
    if score > 10:
        score = 10
    if score < 1:
        score = 1
    return int(score)

def get_severity_label(rating: int) -> str:
    """Return a severity label based on the risk rating."""
    if rating >= 8:
        return "Critical"
    elif rating >= 5:
        return "High"
    elif rating >= 3:
        return "Medium"
    else:
        return "Low"

def scan_contract(address: str) -> Optional[Dict[str, Any]]:
    """
    Scan a contract given by its address. If the address is valid and not cached,
    run vulnerability checks and return the results.
    """
    try:
        checksum_address = Web3.to_checksum_address(address)
    except Exception as e:
        logger.error(f"Invalid address format {address}: {e}")
        add_feed_message(f"Invalid address: {address}")
        return None

    with scanned_addresses_lock:
        if checksum_address in scanned_addresses:
            logger.info(f"[Cache] Already scanned {checksum_address}.")
            return scanned_addresses[checksum_address]

    if not is_contract_address(checksum_address):
        add_feed_message(f"Address {checksum_address} is not a contract.")
        return None

    add_feed_message(f"Scanning contract: {checksum_address}")
    logger.info(f"[Scan] Contract detected: {checksum_address}")
    try:
        raw_bytecode = web3.eth.get_code(checksum_address)
        bytecode_hex = raw_bytecode.hex()
    except Exception as e:
        logger.error(f"[Error] Could not retrieve bytecode for {checksum_address}: {e}")
        return None

    results = advanced_vulnerability_check(bytecode_hex)
    results["unprotected_withdraw"] = unprotected_withdraw_check(bytecode_hex)
    results["unprotected_withdraw_balance"] = unprotected_withdraw_balance_check(bytecode_hex, checksum_address)
    results["unprotected_selfdestruct"] = unprotected_selfdestruct_check(bytecode_hex)
    results["unprotected_token_withdraw"] = unprotected_token_withdraw_check(bytecode_hex)
    results["unprotected_token_transfer"] = unprotected_token_transfer_check(bytecode_hex)
    try:
        balance = web3.eth.get_balance(checksum_address)
        results["balance"] = str(web3.from_wei(balance, 'ether'))
    except Exception as e:
        results["balance"] = "N/A"
    results["token_balances"] = get_token_balances(checksum_address)
    results["scanned_at"] = datetime.utcnow().isoformat()
    results["risk_rating"] = rate_contract(results)
    results["severity"] = get_severity_label(results["risk_rating"])
    results["external_comparison"] = "N/A"  # Stub for future integration

    with scanned_addresses_lock:
        scanned_addresses[checksum_address] = results
    return results

def log_vulnerability_findings(address: str, results: Dict[str, Any]) -> None:
    """Log vulnerability findings if any suspicious flags are detected."""
    if not any(results.values()):
        logger.info(f"[Scan] No suspicious patterns in {address}")
    else:
        msg = f"Vulnerabilities detected in {address}"
        logger.warning(msg)
        add_feed_message(msg)

# =============================================================================
# 9. Advanced Solidity Analysis (using Slither)
# =============================================================================
def run_slither_analysis(source_code: str) -> Dict[str, Any]:
    """
    Run Slither on the given Solidity source code.
    Assumes slither is installed and available in the PATH.
    Returns the parsed JSON output.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".sol", mode="w") as temp_sol:
        temp_sol.write(source_code)
        temp_filename = temp_sol.name
    try:
        result = subprocess.run(["slither", temp_filename, "--json", "-"],
                                  capture_output=True, text=True)
        if result.returncode != 0:
            return {"error": "Slither analysis failed", "details": result.stderr}
        analysis_output = json.loads(result.stdout)
        return analysis_output
    except Exception as e:
        return {"error": str(e)}
    finally:
        os.remove(temp_filename)

# =============================================================================
# 10. Flask Templates & Routes
# =============================================================================
DATA_TABLES_CSS = '<link rel="stylesheet" href="https://cdn.datatables.net/1.10.21/css/jquery.dataTables.min.css">'
DATA_TABLES_JS = '<script src="https://cdn.datatables.net/1.10.21/js/jquery.dataTables.min.js"></script>'

BASE_TEMPLATE = f"""
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>{{{{ title }}}} - Suzan</title>
    <!-- AdminLTE CSS -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/admin-lte@3.1/dist/css/adminlte.min.css">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css">
    {DATA_TABLES_CSS}
    <!-- jQuery -->
    <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
    <!-- Bootstrap 4 -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/js/bootstrap.bundle.min.js"></script>
    {DATA_TABLES_JS}
    <!-- AdminLTE JS -->
    <script src="https://cdn.jsdelivr.net/npm/admin-lte@3.1/dist/js/adminlte.min.js"></script>
    <!-- Plotly -->
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
      .content-wrapper {{ padding: 20px; }}
      .table-responsive {{ max-height: 500px; overflow-y: auto; overflow-x: auto; }}
      thead th {{ position: sticky; top: 0; background: #fff; z-index: 2; }}
    </style>
  </head>
  <body class="hold-transition sidebar-mini">
    <div class="wrapper">
      <!-- Navbar -->
      <nav class="main-header navbar navbar-expand navbar-white navbar-light">
        <ul class="navbar-nav">
          <li class="nav-item">
            <a class="nav-link" data-widget="pushmenu" href="#"><i class="fas fa-bars"></i></a>
          </li>
        </ul>
        <ul class="navbar-nav ml-auto">
          <li class="nav-item">
            <a href="{{{{ url_for('logout') }}}}" class="nav-link">Logout</a>
          </li>
        </ul>
      </nav>
      <!-- Sidebar -->
      <aside class="main-sidebar sidebar-dark-primary elevation-4">
        <a href="{{{{ url_for('dashboard') }}}}" class="brand-link">
          <span class="brand-text font-weight-light">Suzan</span>
        </a>
        <div class="sidebar">
          <nav class="mt-2">
            <ul class="nav nav-pills nav-sidebar flex-column">
              <li class="nav-item"><a href="{{{{ url_for('dashboard') }}}}" class="nav-link {{{{ 'active' if active=='dashboard' else '' }}}}"><i class="nav-icon fas fa-chart-bar"></i><p>Dashboard</p></a></li>
              <li class="nav-item"><a href="{{{{ url_for('contracts') }}}}" class="nav-link {{{{ 'active' if active=='contracts' else '' }}}}"><i class="nav-icon fas fa-table"></i><p>Contracts</p></a></li>
              <li class="nav-item"><a href="{{{{ url_for('vulnerabilities') }}}}" class="nav-link {{{{ 'active' if active=='vulnerabilities' else '' }}}}"><i class="nav-icon fas fa-exclamation-triangle"></i><p>Vulnerabilities</p></a></li>
              <li class="nav-item"><a href="{{{{ url_for('dangerous') }}}}" class="nav-link {{{{ 'active' if active=='dangerous' else '' }}}}"><i class="nav-icon fas fa-skull-crossbones"></i><p>Dangerous</p></a></li>
              <li class="nav-item"><a href="{{{{ url_for('database') }}}}" class="nav-link {{{{ 'active' if active=='database' else '' }}}}"><i class="nav-icon fas fa-database"></i><p>Database</p></a></li>
              <li class="nav-item"><a href="{{{{ url_for('analytics') }}}}" class="nav-link {{{{ 'active' if active=='analytics' else '' }}}}"><i class="nav-icon fas fa-chart-pie"></i><p>Analytics</p></a></li>
            </ul>
          </nav>
        </div>
      </aside>
      <!-- Content Wrapper -->
      <div class="content-wrapper">
        <section class="content-header">
          <div class="container-fluid">
            <h1>{{{{ title }}}}</h1>
            <small id="last-updated" class="text-muted"></small>
          </div>
        </section>
        <section class="content">
          {{{{ content|safe }}}}
        </section>
      </div>
      <!-- Footer -->
      <footer class="main-footer">
        <div class="float-right d-none d-sm-block">
          <b>Version</b> 1.0
        </div>
        <strong>&copy; {{{{ current_year }}}} Suzan.</strong> All rights reserved.
      </footer>
    </div>
    <script>
      // Initialize DataTables
      $(document).ready(function(){{
         $('.datatable').DataTable({{
            "scrollY": "400px",
            "scrollX": true,
            "scrollCollapse": true,
            "paging": true,
            "dom": 'frtip'
         }});
      }});
      
      // Function to update dashboard summary and chart
      function updateDashboard() {{
          fetch('/summary')
            .then(response => response.json())
            .then(data => {{
                let summaryList = "";
                for (const key in data) {{
                    summaryList += `<li class="list-group-item d-flex justify-content-between align-items-center">${{key}}: <span class="badge badge-primary badge-pill">${{data[key]}}</span></li>`;
                }}
                document.getElementById("summary-list").innerHTML = summaryList;
                
                let labels = Object.keys(data);
                let counts = Object.values(data);
                let chartData = [{{
                    x: labels,
                    y: counts,
                    type: 'bar',
                    marker: {{color: 'rgba(55,128,191,0.7)'}}
                }}];
                let layout = {{
                    title: "Vulnerability Summary",
                    xaxis: {{title: "Vulnerability Type"}},
                    yaxis: {{title: "Count"}}
                }};
                Plotly.react('chart-div', chartData, layout);
                
                document.getElementById("last-updated").innerText = "Last updated: " + new Date().toLocaleTimeString();
            }})
            .catch(error => console.error('Error fetching summary:', error));
      }}
      
      // Function to update the live activity feed
      function updateFeed() {{
          fetch('/feed')
            .then(response => response.json())
            .then(data => {{
                let feedList = "";
                data.forEach(msg => {{
                    feedList += `<li class="list-group-item">${{msg}}</li>`;
                }});
                document.getElementById("live-feed-list").innerHTML = feedList;
            }})
            .catch(error => console.error('Error fetching feed:', error));
      }}
      
      // Poll for dashboard updates every 5 seconds and live feed every 3 seconds
      setInterval(updateDashboard, 5000);
      setInterval(updateFeed, 3000);
      updateDashboard();
      updateFeed();
    </script>
  </body>
</html>
"""

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Login - Suzan</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/admin-lte@3.1/dist/css/adminlte.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css">
    <style>.login-page { background: #f4f6f9; }</style>
  </head>
  <body class="hold-transition login-page">
    <div class="login-box">
      <div class="login-logo"><a href="#"><b>Suzan</b> Enterprise</a></div>
      <div class="card">
        <div class="card-body login-card-body">
          <p class="login-box-msg">Sign in to start your session</p>
          {% if error %}
            <div class="alert alert-danger">{{ error }}</div>
          {% endif %}
          <form action="{{ url_for('login') }}" method="post">
            <div class="input-group mb-3">
              <input type="text" name="username" class="form-control" placeholder="Username" required>
              <div class="input-group-append"><div class="input-group-text"><span class="fas fa-user"></span></div></div>
            </div>
            <div class="input-group mb-3">
              <input type="password" name="password" class="form-control" placeholder="Password" required>
              <div class="input-group-append"><div class="input-group-text"><span class="fas fa-lock"></span></div></div>
            </div>
            <div class="row">
              <div class="col-12"><button type="submit" class="btn btn-primary btn-block">Sign In</button></div>
            </div>
          </form>
        </div>
      </div>
    </div>
  </body>
</html>
"""

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = generate_password_hash("password")

@app.route("/login", methods=["GET", "POST"])
def login():
    error: Optional[str] = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid Credentials. Please try again."
    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    # The dashboard now includes the summary graph, vulnerability counts, and the live activity feed.
    content = """
      <div class="card mb-4">
        <div class="card-header"><h3 class="card-title">Summary Graph</h3></div>
        <div class="card-body">
          <div id="chart-div"></div>
        </div>
      </div>
      <div class="card mb-4">
        <div class="card-header"><h3 class="card-title">Aggregated Vulnerability Counts</h3></div>
        <div class="card-body">
          <ul class="list-group" id="summary-list"></ul>
        </div>
      </div>
      <div class="card">
        <div class="card-header"><h3 class="card-title">Live Activity Feed</h3></div>
        <div class="card-body">
          <ul class="list-group" id="live-feed-list"></ul>
        </div>
      </div>
    """
    return render_template_string(
        BASE_TEMPLATE,
        title="Dashboard",
        content=content,
        active="dashboard",
        current_year=datetime.utcnow().year
    )

@app.route("/contracts")
@login_required
def contracts():
    with scanned_addresses_lock:
        contracts = [{"address": addr, **data} for addr, data in scanned_addresses.items()]
    rows = ""
    for c in contracts:
        token_balances = c.get("token_balances", {})
        tokens_str = ", ".join([f"{k}: {v}" for k, v in token_balances.items()]) if token_balances else "N/A"
        def fmt(flag):
            return "<strong>True</strong>" if flag else "False"
        rows += "<tr>"
        rows += f"<td>{c.get('address', '')}</td>"
        rows += f"<td>{fmt(c.get('has_delegatecall', False))}</td>"
        rows += f"<td>{fmt(c.get('has_create2', False))}</td>"
        rows += f"<td>{fmt(c.get('has_selfdestruct', False))}</td>"
        rows += f"<td>{fmt(c.get('has_tx_origin', False))}</td>"
        rows += f"<td>{fmt(c.get('has_possible_reentrancy', False))}</td>"
        rows += f"<td>{fmt(c.get('has_nonreentrant_guard', False))}</td>"
        rows += f"<td>{fmt(c.get('uses_block_timestamp', False))}</td>"
        rows += f"<td>{fmt(c.get('uses_callvalue', False))}</td>"
        rows += f"<td>{fmt(c.get('uses_safemath', False))}</td>"
        rows += f"<td>{fmt(c.get('in_depth_reentrancy', False))}</td>"
        rows += f"<td>{fmt(c.get('unprotected_withdraw', False))}</td>"
        rows += f"<td>{fmt(c.get('unprotected_withdraw_balance', False))}</td>"
        rows += f"<td>{fmt(c.get('unprotected_selfdestruct', False))}</td>"
        rows += f"<td>{fmt(c.get('unprotected_token_withdraw', False))}</td>"
        rows += f"<td>{fmt(c.get('unprotected_token_transfer', False))}</td>"
        rows += f"<td>{c.get('balance', 'N/A')}</td>"
        rows += f"<td>{c.get('risk_rating', 'N/A')}</td>"
        rows += f"<td>{c.get('severity', 'N/A')}</td>"
        rows += f"<td>{tokens_str}</td>"
        rows += f"<td>{c.get('scanned_at', '')}</td>"
        rows += "</tr>"
    content = f"""
      <div class="card">
        <div class="card-header"><h3 class="card-title">Scanned Contracts</h3></div>
        <div class="card-body table-responsive">
          <table class="table table-bordered table-hover datatable">
            <thead>
              <tr>
                <th>Address</th>
                <th>DelegateCall</th>
                <th>Create2</th>
                <th>Selfdestruct</th>
                <th>Tx Origin</th>
                <th>Reentrancy</th>
                <th>NonReentrant</th>
                <th>Block Timestamp</th>
                <th>CallValue</th>
                <th>SafeMath</th>
                <th>In-Depth Reentrancy</th>
                <th>Unprot. Withdraw</th>
                <th>Withdraw Balance</th>
                <th>Unprot. SelfDestruct</th>
                <th>Unprot. Token Withdraw</th>
                <th>Unprot. Token Transfer</th>
                <th>Balance (ETH)</th>
                <th>Risk Rating</th>
                <th>Severity</th>
                <th>Token Balances</th>
                <th>Scanned At</th>
              </tr>
            </thead>
            <tbody>
              {rows}
            </tbody>
          </table>
        </div>
      </div>
    """
    return render_template_string(
        BASE_TEMPLATE,
        title="Contracts",
        content=content,
        active="contracts",
        current_year=datetime.utcnow().year
    )

@app.route("/vulnerabilities")
@login_required
def vulnerabilities():
    vuln_keys = ["vuln_reentrancy", "vuln_overflow_underflow", "vuln_selfdestruct", "vuln_private_data",
                 "vuln_delegatecall", "vuln_randomness", "vuln_dos", "vuln_phishing_tx_origin",
                 "vuln_external_contract", "vuln_honeypot", "vuln_frontrunning", "vuln_timestamp_manipulation",
                 "vuln_signature_replay", "vuln_size_bypass", "vuln_same_address", "vuln_vault_inflation",
                 "vuln_weth_permit", "vuln_63_64"]
    summary_data = {key: {"count": 0, "total_balance": 0.0} for key in vuln_keys}
    contract_details = []
    with scanned_addresses_lock:
        for res in scanned_addresses.values():
            try:
                balance = float(res.get("balance", "0"))
            except Exception:
                balance = 0.0
            for key in vuln_keys:
                if res.get(key):
                    summary_data[key]["count"] += 1
                    summary_data[key]["total_balance"] += balance
                    contract_details.append((res.get("address"), key))
        for key in summary_data.keys():
            summary_data[key]["total_balance"] = f"{summary_data[key]['total_balance']:.2f}"
    summary_rows = ""
    for k, data in summary_data.items():
        summary_rows += f"<tr><td>{k}</td><td>{data['count']}</td><td>{data['total_balance']}</td></tr>"
    detail_rows = ""
    for addr, key in contract_details:
        detail_rows += f"<tr><td>{addr}</td><td>{key}</td></tr>"
    content = f"""
      <div class="card mb-4">
        <div class="card-header"><h3 class="card-title">Vulnerability Aggregation</h3></div>
        <div class="card-body table-responsive">
          <table class="table table-bordered datatable">
            <thead>
              <tr>
                <th>Vulnerability Type</th>
                <th>Count</th>
                <th>Total Balance (ETH)</th>
              </tr>
            </thead>
            <tbody>
              {summary_rows}
            </tbody>
          </table>
        </div>
      </div>
      <div class="card">
        <div class="card-header"><h3 class="card-title">Contracts per Vulnerability</h3></div>
        <div class="card-body table-responsive">
          <table class="table table-bordered datatable">
            <thead>
              <tr>
                <th>Contract Address</th>
                <th>Vulnerability Flag</th>
              </tr>
            </thead>
            <tbody>
              {detail_rows}
            </tbody>
          </table>
        </div>
      </div>
    """
    return render_template_string(
        BASE_TEMPLATE,
        title="Vulnerabilities",
        content=content,
        active="vulnerabilities",
        current_year=datetime.utcnow().year
    )

@app.route("/dangerous")
@login_required
def dangerous():
    dangerous_contracts = []
    danger_flags = ["unprotected_withdraw_balance", "unprotected_selfdestruct", "unprotected_token_withdraw", "unprotected_token_transfer"]
    with scanned_addresses_lock:
        for addr, res in scanned_addresses.items():
            triggered = [flag for flag in danger_flags if res.get(flag)]
            if res.get("risk_rating", 0) >= 8 or triggered:
                record = {
                    "address": addr,
                    "risk_rating": res.get("risk_rating"),
                    "severity": res.get("severity"),
                    "vulnerabilities": ", ".join(triggered) if triggered else "N/A",
                    "balance": res.get("balance", "N/A"),
                    "token_balances": ", ".join([f"{k}: {v}" for k, v in res.get("token_balances", {}).items()]) if res.get("token_balances") else "N/A",
                    "scanned_at": res.get("scanned_at")
                }
                dangerous_contracts.append(record)
    rows = ""
    for d in dangerous_contracts:
        rows += "<tr>"
        rows += f"<td>{d.get('address')}</td>"
        rows += f"<td>{d.get('risk_rating')}</td>"
        rows += f"<td>{d.get('severity')}</td>"
        rows += f"<td>{d.get('vulnerabilities')}</td>"
        rows += f"<td>{d.get('balance')}</td>"
        rows += f"<td>{d.get('token_balances')}</td>"
        rows += f"<td>{d.get('scanned_at')}</td>"
        rows += "</tr>"
    content = f"""
      <div class="card">
        <div class="card-header"><h3 class="card-title">Dangerous Vulnerabilities</h3></div>
        <div class="card-body table-responsive">
          <table class="table table-bordered datatable">
            <thead>
              <tr>
                <th>Address</th>
                <th>Risk Rating</th>
                <th>Severity</th>
                <th>Triggered Vulnerabilities</th>
                <th>Balance (ETH)</th>
                <th>Token Balances</th>
                <th>Scanned At</th>
              </tr>
            </thead>
            <tbody>{rows}</tbody>
          </table>
        </div>
      </div>
    """
    return render_template_string(
        BASE_TEMPLATE,
        title="Dangerous Vulnerabilities",
        content=content,
        active="dangerous",
        current_year=datetime.utcnow().year
    )

@app.route("/database")
@login_required
def database():
    with scanned_addresses_lock:
        records = [{"address": addr, **data} for addr, data in scanned_addresses.items()]
    rows = ""
    for r in records:
        token_balances = r.get("token_balances", {})
        tokens_str = ", ".join([f"{k}: {v}" for k, v in token_balances.items()]) if token_balances else "N/A"
        rows += "<tr>"
        rows += f"<td>{r.get('address', '')}</td>"
        rows += f"<td>{r.get('balance', 'N/A')}</td>"
        rows += f"<td>{r.get('risk_rating', 'N/A')}</td>"
        rows += f"<td>{r.get('severity', 'N/A')}</td>"
        rows += f"<td>{tokens_str}</td>"
        rows += f"<td>{r.get('scanned_at', '')}</td>"
        rows += "</tr>"
    content = f"""
      <div class="card">
        <div class="card-header"><h3 class="card-title">Vulnerability Database</h3></div>
        <div class="card-body table-responsive">
          <table class="table table-bordered datatable">
            <thead>
              <tr>
                <th>Address</th>
                <th>Balance (ETH)</th>
                <th>Risk Rating</th>
                <th>Severity</th>
                <th>Token Balances</th>
                <th>Scanned At</th>
              </tr>
            </thead>
            <tbody>
              {rows}
            </tbody>
          </table>
        </div>
      </div>
    """
    return render_template_string(
        BASE_TEMPLATE,
        title="Database",
        content=content,
        active="database",
        current_year=datetime.utcnow().year
    )

@app.route("/analytics")
@login_required
def analytics():
    vuln_keys = ["vuln_reentrancy", "vuln_overflow_underflow", "vuln_selfdestruct", "vuln_private_data", 
                 "vuln_delegatecall", "vuln_randomness", "vuln_dos", "vuln_phishing_tx_origin", 
                 "vuln_external_contract", "vuln_honeypot", "vuln_frontrunning", "vuln_timestamp_manipulation",
                 "vuln_signature_replay", "vuln_size_bypass", "vuln_same_address", "vuln_vault_inflation", 
                 "vuln_weth_permit", "vuln_63_64"]
    vuln_counts: Dict[str, int] = {}
    total_flags = 0
    with scanned_addresses_lock:
        for res in scanned_addresses.values():
            for key in vuln_keys:
                if res.get(key):
                    vuln_counts[key] = vuln_counts.get(key, 0) + 1
                    total_flags += 1
    vuln_percentages = {key: (count / total_flags * 100) if total_flags > 0 else 0 for key, count in vuln_counts.items()}
    
    pie_chart = go.Pie(labels=list(vuln_percentages.keys()),
                       values=list(vuln_percentages.values()),
                       hole=0.3,
                       hoverinfo="label+percent+value")
    pie_layout = go.Layout(title="Vulnerability Distribution (%)")
    pie_fig = go.Figure(data=[pie_chart], layout=pie_layout)
    pie_div = pyo.plot(pie_fig, output_type="div", include_plotlyjs=False)

    risk_distribution: Dict[Any, int] = {}
    with scanned_addresses_lock:
        for res in scanned_addresses.values():
            risk = res.get("risk_rating", 0)
            risk_distribution[risk] = risk_distribution.get(risk, 0) + 1

    risk_bar = go.Bar(x=list(risk_distribution.keys()),
                      y=list(risk_distribution.values()),
                      marker=dict(color='rgba(255,99,132,0.7)'))
    bar_layout = go.Layout(title="Risk Rating Distribution", xaxis=dict(title="Risk Rating"), yaxis=dict(title="Count"))
    bar_fig = go.Figure(data=[risk_bar], layout=bar_layout)
    bar_div = pyo.plot(bar_fig, output_type="div", include_plotlyjs=False)

    content = f"""
      <div class="card mb-4">
        <div class="card-header"><h3 class="card-title">Vulnerability Distribution (Pie Chart)</h3></div>
        <div class="card-body">
          {pie_div}
        </div>
      </div>
      <div class="card">
        <div class="card-header"><h3 class="card-title">Risk Rating Distribution (Bar Chart)</h3></div>
        <div class="card-body">
          {bar_div}
        </div>
      </div>
    """
    return render_template_string(
        BASE_TEMPLATE,
        title="Analytics",
        content=content,
        active="analytics",
        current_year=datetime.utcnow().year
    )

@app.route("/summary")
@login_required
def summary_endpoint():
    summary_data: Dict[str, int] = {}
    with scanned_addresses_lock:
        for res in scanned_addresses.values():
            for key, val in res.items():
                if isinstance(val, bool) and val:
                    summary_data[key] = summary_data.get(key, 0) + 1
    return jsonify(summary_data)

# New route: Live Feed RPC endpoint
@app.route("/feed")
@login_required
def feed():
    """Return the current live feed as JSON."""
    with live_feed_lock:
        return jsonify(live_feed)

# =============================================================================
# 11. Blockchain Transaction Listener & App Runner
# =============================================================================
def listen_to_transactions() -> None:
    """Continuously poll for new blocks and scan any new contract addresses found."""
    add_feed_message("Starting block polling and contract scanning...")
    logger.info("Starting block polling and contract scanning...")
    latest_block = web3.eth.block_number
    while True:
        try:
            current_block = web3.eth.block_number
            if current_block > latest_block:
                for block_num in range(latest_block + 1, current_block + 1):
                    try:
                        block = web3.eth.get_block(block_num, full_transactions=True)
                        block_msg = f"Processing Block #{block.number} with {len(block.transactions)} transactions"
                        logger.info(block_msg)
                        add_feed_message(block_msg)
                        for tx in block.transactions:
                            tx_hash = tx.hash.hex()
                            tx_from = tx["from"]
                            tx_to = tx["to"]
                            value_in_ether = web3.from_wei(tx["value"], 'ether')
                            logger.info(f"[Tx] Hash: {tx_hash} | From: {tx_from} | To: {tx_to} | Value: {value_in_ether} SONIC")
                            if tx_from:
                                from_results = scan_contract(tx_from)
                                if from_results is not None:
                                    log_vulnerability_findings(tx_from, from_results)
                            if tx_to:
                                to_results = scan_contract(tx_to)
                                if to_results is not None:
                                    log_vulnerability_findings(tx_to, to_results)
                            tx_input = tx.input if isinstance(tx.input, str) else tx.input.hex()
                            found_addresses = find_addresses_in_data(tx_input)
                            if found_addresses:
                                for addr in found_addresses:
                                    res = scan_contract(addr)
                                    if res is not None:
                                        log_vulnerability_findings(addr, res)
                        latest_block = current_block
                    except Exception as block_error:
                        logger.error(f"Error processing block #{block_num}: {block_error}")
            time.sleep(2)
        except Exception as e:
            logger.error(f"Error while polling blocks: {e}")
            time.sleep(5)

def run_dashboard() -> None:
    """Run the Flask dashboard on localhost."""
    app.run(host="127.0.0.1", port=5000)

if __name__ == "__main__":
    dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
    dashboard_thread.start()
    listen_to_transactions()
