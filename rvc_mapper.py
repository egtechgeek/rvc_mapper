#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RV-C / J1939 Mapper for CoachProxy/eRVin-style networks

New in this build
- Discovery mode: REQUEST known status PGNs (default 0x1FEDA), collect instances, save rvc_discovery.json
- Send Command mode: pick instance from rvc_map_v2.json and transmit ON/OFF/BRIGHT/DIM/SET_LEVEL (verb or set_level)
- MQTT publishing: Real-time publishing of decoded frames to MQTT broker
- Enhanced YAML decoder: Full rvc-spec.yml support with unit conversions
- Integrated rvc2mqtt functionality: Combines Perl and Python rvc2mqtt features

Also includes
- SocketCAN sniff (CSV/JSONL logs)
- YAML decoder (optional) for PGN fields with rvc-spec.yml support
- Ignore rules (rvc_ignore.json) + manager
- TP BAM reassembly (0xEC00/0xEB00)
- Burst Capture window
- Role Registry (rvc_roles.json): PANEL vs CONTROLLER
- Command style detection (verb vs set_level)
- Canonical Autolearn → rvc_map_v2.json (Instance+Action, merged across panels)
- MQTT publishing with rvc2mqtt format compatibility

Dependencies:
  sudo apt-get install -y python3-can python3-yaml python3-paho-mqtt
  pip install paho-mqtt
"""

import os
import sys
import time
import json
import csv
import argparse
import re
from datetime import datetime
import struct
import asyncio

import can
import yaml
from paho.mqtt.client import Client as MqttClient

# -------------------- Basic helpers --------------------

def parse_can_id(arb_id: int):
    priority = (arb_id >> 26) & 0x7
    dp       = (arb_id >> 24) & 0x1
    pf       = (arb_id >> 16) & 0xFF
    ps       = (arb_id >> 8)  & 0xFF
    sa       = (arb_id >> 0)  & 0xFF
    if pf < 240:
        pgn = (dp << 16) | (pf << 8) | 0x00
        da  = ps
    else:
        pgn = (dp << 16) | (pf << 8) | ps
        da  = 0xFF
    return {"priority": priority, "dp": dp, "pf": pf, "ps": ps, "sa": sa, "da": da, "pgn": pgn}

def phex(val: int, width: int = 5) -> str:
    return f"0x{val:0{width}X}"

def bytes_hex(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)

def sig_exact(fields: dict, data: bytes) -> str:
    return f"PGN={fields['pgn']:05X}|SA={fields['sa']:02X}|DA={fields['da']:02X}|LEN={len(data)}|DATA={bytes_hex(data)}"

def sig_masked(fields: dict, data: bytes, changed_idx):
    idx = ",".join(map(str, changed_idx)) if changed_idx else ""
    subset = " ".join(f"{data[i]:02X}" for i in changed_idx) if changed_idx else ""
    return f"MSK|PGN={fields['pgn']:05X}|SA={fields['sa']:02X}|DA={fields['da']:02X}|IDX={idx}|DATA={subset}"

PGN_TP_CM = 0x00EC00
PGN_TP_DT = 0x00EB00
DIMMER_COMMAND_PGNS = {0x001FEDB, 0x001FEDF}

PGN_NAMES = {
    0x00EA00: "REQUEST",
    0x00EE00: "ADDRESS_CLAIM",
    0x00EE01: "COMMANDED_ADDRESS",
    0x00FECA: "DM1_ACTIVE_DIAGNOSTICS",
    0x001FEDF: "WINDOW_SHADE_COMMAND",
    0x001FEDB: "DC_DIMMER_COMMAND_2",
    0x001FEDA: "DC_DIMMER_STATUS_3",
}

# -------------------- Delta tracker --------------------

class DeltaTracker:
    def __init__(self):
        self.last = {}  # (pgn, sa) -> bytes
    def delta(self, pgn: int, sa: int, data: bytes):
        key = (pgn, sa)
        prev = self.last.get(key)
        self.last[key] = data
        if prev is None or len(prev) != len(data):
            return list(range(len(data)))
        return [i for i, (a, b) in enumerate(zip(prev, data)) if a != b]

# -------------------- Logger --------------------

class Logger:
    def __init__(self, base_dir="logs"):
        os.makedirs(base_dir, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        self.csv_path = os.path.join(base_dir, f"rvc_log_{ts}.csv")
        self.jsonl_path = os.path.join(base_dir, f"rvc_log_{ts}.jsonl")
        self.csv_file = open(self.csv_path, "a", newline="")
        self.jsonl_file = open(self.jsonl_path, "a")
        self.csv_writer = csv.writer(self.csv_file)
        if os.stat(self.csv_path).st_size == 0:
            self.csv_writer.writerow([
                "time_iso", "arb_id_hex", "priority", "pgn_hex", "pgn_name",
                "sa_hex", "da_hex", "len", "data_hex", "changed_byte_idx", "decoded_json"
            ])
    def write(self, row: dict):
        self.csv_writer.writerow([
            row["time_iso"], row["arb_id_hex"], row["priority"], row["pgn_hex"], row.get("pgn_name", ""),
            row["sa_hex"], row["da_hex"], row["len"], row["data_hex"],
            " ".join(map(str, row.get("changed_byte_idx", []))),
            json.dumps(row.get("decoded", {}), ensure_ascii=False),
        ])
        self.jsonl_file.write(json.dumps(row) + "\n")
    def close(self):
        try:
            self.csv_file.close()
        finally:
            self.jsonl_file.close()

# -------------------- Enhanced YAML decoder --------------------

class YamlDecoder:
    def __init__(self):
        self.map = {}
        self.path = None
        self.api_version = 1
        self.compiled_decoders = {}
        self.compiled_wildcards = []
        
    @staticmethod
    def _norm_key(k):
        if isinstance(k, int): return k
        if isinstance(k, str):
            k = k.strip()
            if not k:
                raise ValueError("Empty key")
            ku = k.upper()
            if "#" in ku or "?" in ku:
                return ku
            if ku.startswith("0X"):
                return int(k, 16)
            if ku.startswith("Z"):
                return int(k[1:], 10)
            try:
                if all(c in "0123456789ABCDEF" for c in ku):
                    return int(ku, 16)
                return int(k, 10)
            except ValueError:
                return ku
        raise ValueError("Bad PGN key")
    
    @staticmethod
    def _normalize_lookup_key(k):
        if isinstance(k, int):
            return k
        if isinstance(k, str):
            k = k.strip()
            if not k:
                return None
            ku = k.upper()
            if "#" in ku or "?" in ku:
                return ku
            if ku.startswith("0X"):
                return int(ku, 16)
            if ku.startswith("Z"):
                try:
                    return int(ku[1:], 10)
                except ValueError:
                    return ku
            try:
                if all(c in "0123456789ABCDEF" for c in ku):
                    return int(ku, 16)
                return int(k, 10)
            except ValueError:
                return ku
        return None
        
    def load(self, path: str):
        with open(path, "r") as f:
            raw = yaml.safe_load(f) or {}
        
        # Extract API version
        self.api_version = raw.get("API_VERSION", 1)
        
        # Build decoder map with proper key normalization
        self.map = {}
        for k, v in raw.items():
            if k == "API_VERSION":
                continue
            if isinstance(v, dict) and "name" in v:
                key = self._norm_key(k)
                self.map[key] = v
                
        self.path = path
        self._compile_decoders()
        
    def _compile_decoders(self):
        """Pre-compile parameter decoders for better performance"""
        self.compiled_decoders = {}
        self.compiled_wildcards = []
        
        for dgn, d in self.map.items():
            if not isinstance(d, dict) or "name" not in d:
                continue
                
            # Resolve aliases and collect parameters
            params = []
            alias_key = self._normalize_lookup_key(d.get("alias"))
            if alias_key is not None and alias_key in self.map:
                alias_entry = self.map[alias_key]
                if isinstance(alias_entry, dict) and "parameters" in alias_entry:
                    params.extend(alias_entry["parameters"])
            if "parameters" in d:
                params.extend(d["parameters"])
                
            # Compile parameter readers
            readers = []
            for p in params:
                reader = self._compile_parameter_reader(p)
                if reader:
                    readers.append(reader)
                    
            compiled = {
                "name": d["name"],
                "readers": readers
            }

            if isinstance(dgn, int):
                self.compiled_decoders[dgn] = compiled
            elif isinstance(dgn, str):
                regex = self._wildcard_to_regex(dgn)
                if regex:
                    self.compiled_wildcards.append({"pattern": regex, "key": dgn, "decoder": compiled})
                else:
                    # treat as exact string match fallback
                    self.compiled_wildcards.append({"pattern": re.compile(f"^{re.escape(dgn)}$"), "key": dgn, "decoder": compiled})
    
    def _compile_parameter_reader(self, param):
        """Compile a parameter reader function"""
        name = param.get("name")
        if not name:
            return None
            
        byte_spec = param.get("byte")
        bit_spec = param.get("bit")
        typ = param.get("type", "uint")
        unit = param.get("unit")
        values = param.get("values")
        
        # Parse byte range
        if isinstance(byte_spec, int):
            start_byte, end_byte = byte_spec, byte_spec
        elif isinstance(byte_spec, str) and "-" in byte_spec:
            start_byte, end_byte = map(int, byte_spec.split("-"))
        elif byte_spec is None:
            return None
        else:
            start_byte, end_byte = int(byte_spec), int(byte_spec)
            
        # Parse bit range
        if isinstance(bit_spec, int):
            start_bit, end_bit = bit_spec, bit_spec
        elif isinstance(bit_spec, str) and "-" in bit_spec:
            start_bit, end_bit = map(int, bit_spec.split("-"))
        else:
            start_bit, end_bit = None, None
            
        def reader(data: bytes, result: dict):
            if start_byte >= len(data):
                return
                
            # Extract bytes (little-endian for RV-C)
            end_byte = min(end_byte, len(data) - 1)
            sub_data = data[start_byte:end_byte + 1]
            
            if not sub_data:
                return
                
            # Convert to integer (little-endian)
            val = int.from_bytes(sub_data, "little")
            
            # Apply bit masking if specified
            if start_bit is not None and end_bit is not None:
                mask = ((1 << (end_bit - start_bit + 1)) - 1) << start_bit
                val = (val & mask) >> start_bit
                
            # Apply unit conversions
            if unit:
                val = self._convert_unit(val, unit, typ)
                
            # Store result
            result[name] = val
            
            # Add Fahrenheit conversion for Celsius
            if unit and unit.lower() == "deg c" and isinstance(val, (int, float)):
                result[name + " F"] = round((val * 9 / 5) + 32, 1)
                
            # Add value definitions
            if values and isinstance(val, int) and val in values:
                result[f"{name} definition"] = values[val]
                
        return reader
    
    @staticmethod
    def _wildcard_to_regex(pattern: str):
        if not isinstance(pattern, str):
            return None
        expr = pattern.upper().replace("#", "[0-9A-F]").replace("?", "[0-9A-F]")
        return re.compile(f"^{expr}$")
    
    def _convert_unit(self, value, unit, typ):
        """Convert units based on RV-C specification"""
        unit_lower = unit.lower()
        
        if unit_lower == "pct":
            return "n/a" if value == 255 else value / 2
        elif unit_lower in ("deg c", "deg c"):
            if typ == "uint8":
                return "n/a" if value == 255 else value - 40
            elif typ == "uint16":
                return "n/a" if value == 65535 else round(value * 0.03125 - 273, 1)
        elif unit_lower == "v":
            if typ == "uint8":
                return "n/a" if value == 255 else value
            elif typ == "uint16":
                return "n/a" if value == 65535 else round(value * 0.05, 1)
        elif unit_lower == "a":
            if typ == "uint8":
                return "n/a" if value == 255 else value / 4
            elif typ == "uint16":
                return "n/a" if value == 65535 else round(value * 0.1, 1)
            elif typ == "uint32":
                return "n/a" if value == 4294967295 else round(value * 0.001 - 2000000, 2)
        elif unit_lower == "hz":
            if typ == "uint8":
                return value
            elif typ == "uint16":
                return round(value / 128, 1)
        elif unit_lower == "sec":
            if typ == "uint8":
                if 240 < value < 251:
                    return ((value - 240) + 4) * 60
                return value
            elif typ == "uint16":
                return value * 2
        elif unit_lower == "bitmap":
            return format(value, "08b")
            
        return value
        
    def has(self, pgn: int) -> bool:
        if pgn in self.compiled_decoders:
            return True
        key = f"{pgn:05X}"
        return any(entry["pattern"].match(key) for entry in self.compiled_wildcards)
        
    def name_for(self, pgn: int):
        decoder = self._find_decoder(pgn)
        return decoder["name"] if decoder else None
        
    def decode(self, pgn: int, data: bytes) -> dict:
        decoder = self._find_decoder(pgn)
        if not decoder:
            return {}
            
        result = {
            "dgn": f"{pgn:05X}",
            "data": data.hex().upper(),
            "name": decoder["name"]
        }
        
        if not decoder["readers"]:
            result["DECODER PENDING"] = 1
            return result
            
        for reader in decoder["readers"]:
            reader(data, result)
            
        return result
    
    def _find_decoder(self, pgn: int):
        decoder = self.compiled_decoders.get(pgn)
        if decoder:
            return decoder
        key = f"{pgn:05X}"
        for entry in self.compiled_wildcards:
            if entry["pattern"].match(key):
                return entry["decoder"]
        return None

# -------------------- Ignore rules --------------------

class IgnoreRules:
    def __init__(self, path="rvc_ignore.json"):
        self.path = path
        self.rules = []
        self.mtime = 0.0
        self.load()
        if not self.rules:
            self.rules = [
                {"type":"pgn","pgn":0x00EE00},  # Address Claim
                {"type":"pgn","pgn":0x00EA00},  # Request
                {"type":"pgn","pgn":0x00FECA},  # DM1
            ]
            self.save()
    def load(self):
        try:
            if os.path.exists(self.path):
                with open(self.path, "r") as f:
                    raw = json.load(f) or {}
                self.rules = list(raw.get("rules", []))
                self.mtime = os.path.getmtime(self.path)
            else:
                self.rules = []; self.mtime = 0.0; self.save()
        except Exception:
            self.rules = []; self.mtime = 0.0
    def save(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f: json.dump({"rules": self.rules}, f, indent=2)
        os.replace(tmp, self.path); self.mtime = os.path.getmtime(self.path)
    def maybe_reload(self):
        try:
            if os.path.exists(self.path):
                m = os.path.getmtime(self.path)
                if m > self.mtime: self.load()
        except Exception: pass
    def add_rule(self, rule: dict):
        self.rules.append(rule); self.save()
    def remove_rule(self, idx: int):
        if 0 <= idx < len(self.rules):
            del self.rules[idx]; self.save()
    def list_rules(self): return list(self.rules)
    def matches(self, fields: dict, data: bytes) -> bool:
        s = sig_exact(fields, data)
        for r in self.rules:
            t = r.get("type")
            if t == "signature" and r.get("signature") == s: return True
            if t == "pgn" and int(r.get("pgn",-1)) == fields["pgn"]: return True
            if t == "sa"  and int(r.get("sa",-1))  == fields["sa"]:  return True
            if t == "da"  and int(r.get("da",-1))  == fields["da"]:  return True
            if t == "pgn_sa" and int(r.get("pgn",-1)) == fields["pgn"] and int(r.get("sa",-1)) == fields["sa"]:
                return True
        return False

# -------------------- TP reassembly (BAM) --------------------

class TPReassembler:
    """BAM only (broadcast). Collapses TP.CM/TP.DT into one logical message."""
    def __init__(self, timeout_sec=5):
        self.sessions = {}  # key: (sa, target_pgn) -> dict
        self.timeout = timeout_sec
    def _expire(self):
        now = time.time()
        dead = [k for k,v in self.sessions.items() if now - v["start"] > self.timeout]
        for k in dead: del self.sessions[k]
    def feed(self, fields: dict, data: bytes):
        self._expire()
        pgn = fields["pgn"]
        if pgn == PGN_TP_CM and len(data) >= 8:
            control = data[0]
            if control == 0x20:  # BAM
                total = data[1] | (data[2] << 8)
                npkt  = data[3]
                tgt   = data[5] | (data[6] << 8) | (data[7] << 16)
                key = (fields["sa"], tgt)
                self.sessions[key] = {"start": time.time(), "total": total, "npkt": npkt, "buf": bytearray(), "next_sn": 1}
            return None
        if pgn == PGN_TP_DT and len(data) >= 1:
            sn = data[0]; payload = data[1:]
            for key, sess in list(self.sessions.items()):
                sa, tgt = key
                if sa != fields["sa"]: continue
                if sn != sess["next_sn"]:
                    del self.sessions[key]; return None
                sess["buf"].extend(payload)
                sess["next_sn"] += 1
                if len(sess["buf"]) >= sess["total"] or (sess["next_sn"] - 1) >= sess["npkt"]:
                    assembled = bytes(sess["buf"][:sess["total"]])
                    del self.sessions[key]
                    return (tgt, assembled)
            return None
        return None

# -------------------- Legacy masked store (optional) --------------------

class AutoLearnStore:
    def __init__(self, path="rvc_map.json"):
        self.path = path
        self.map = {}
        self.mtime = 0.0
        self.load()
    def load(self):
        try:
            if os.path.exists(self.path):
                with open(self.path, "r") as f:
                    self.map = json.load(f)
                self.mtime = os.path.getmtime(self.path)
            else:
                self.map = {}; self.mtime = 0.0
        except Exception:
            self.map = {}; self.mtime = 0.0
    def maybe_reload(self):
        try:
            if os.path.exists(self.path):
                m = os.path.getmtime(self.path)
                if m > self.mtime: self.load()
        except Exception: pass
    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f: json.dump(self.map, f, indent=2)
        os.replace(tmp, self.path); self.mtime = os.path.getmtime(self.path)
    def get(self, signature: str): return self.map.get(signature)
    def set(self, signature: str, friendly: str):
        self.map[signature] = friendly; self.save()

# -------------------- Roles + Canonical map v2 --------------------

VERB_MAP = {0x11: "ON", 0x06: "OFF", 0x13: "BRIGHT", 0x14: "DIM"}

def classify_command_1FEDB(data: bytes):
    """Returns (style, action, level_opt) for dimmer-style command PGNs (e.g., 1FEDB/1FEDF)."""
    if len(data) < 4: return (None, None, None)
    b2 = data[2]; b3 = data[3]
    if b3 == 0x01:
        return ("set_level", "SET_LEVEL", int(b2))
    if b3 == 0x03:
        if b2 == 0x00:
            return ("set_level", "OFF", 0)
        return ("set_level", "SET_LEVEL", int(b2))
    if b3 in VERB_MAP:
        return ("verb", VERB_MAP[b3], None)
    return (None, None, None)

def extract_instance_for_1FEDx(pgn: int, data: bytes):
    return int(data[0]) if len(data) >= 1 else None

class RoleRegistry:
    def __init__(self, path="rvc_roles.json"):
        self.path = path
        self.roles = {}  # "9B":"panel", "8E":"controller"
        self._load()
    def _load(self):
        try:
            if os.path.exists(self.path):
                with open(self.path, "r") as f:
                    self.roles = json.load(f) or {}
        except Exception:
            self.roles = {}
    def _save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f: json.dump(self.roles, f, indent=2)
        os.replace(tmp, self.path)
    def learn_from_frame(self, pgn: int, sa: int):
        role = None
        if pgn == 0x001FEDB: role = "panel"
        elif pgn == 0x001FEDA: role = "controller"
        if role:
            key = f"{sa:02X}"
            if self.roles.get(key) != role:
                self.roles[key] = role
                self._save()
    def role_of(self, sa: int):
        return self.roles.get(f"{sa:02X}")

class CanonicalMapV2:
    """
    rvc_map_v2.json:
    {
      "schema": 2,
      "lights": {
        "inst_1C": {
          "name": "kitchen_overhead",
          "controller": "8E",
          "entries": {
            "ON":  {"panels":["9B","9D"], "styles_seen":["verb","set_level"], "last_seen":"..."},
            "OFF": {"panels":["9B"], "styles_seen":["verb"], "last_seen":"..."},
            "SET_LEVEL": {"panels":["9F"], "styles_seen":["set_level"], "last_level": 152, "last_seen":"..."}
          }
        }
      }
    }
    """
    def __init__(self, path="rvc_map_v2.json"):
        self.path = path
        self.doc = {"schema": 2, "lights": {}}
        self.mtime = 0.0
        self._load()
    def _load(self):
        try:
            if os.path.exists(self.path):
                with open(self.path, "r") as f:
                    self.doc = json.load(f) or {"schema": 2, "lights": {}}
                self.mtime = os.path.getmtime(self.path)
            else:
                self._save()
        except Exception:
            self.doc = {"schema": 2, "lights": {}}
            self.mtime = 0.0
    def _save(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f: json.dump(self.doc, f, indent=2)
        os.replace(tmp, self.path)
        try:
            self.mtime = os.path.getmtime(self.path)
        except Exception:
            self.mtime = 0.0
    def upsert(self, instance: int, action: str, *, panel_sa: int=None, controller_sa: int=None,
               style: str=None, level: int=None, friendly_name: str=None, payload: bytes=None,
               pgn: int = None):
        key = f"inst_{instance:02X}"
        lights = self.doc.setdefault("lights", {})
        rec = lights.setdefault(key, {"name": None, "controller": None, "entries": {}})
        if friendly_name and not rec.get("name"):
            rec["name"] = friendly_name
        if controller_sa is not None:
            rec["controller"] = f"{controller_sa:02X}"
        ent = rec["entries"].setdefault(action, {"panels": [], "styles_seen": [], "last_seen": None})
        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        ent["last_seen"] = now
        if panel_sa is not None:
            p = f"{panel_sa:02X}"
            if p not in ent["panels"]:
                ent["panels"].append(p)
        if style and style not in ent["styles_seen"]:
            ent["styles_seen"].append(style)
        if action == "SET_LEVEL" and level is not None:
            ent["last_level"] = int(level)
        if payload is not None:
            ent["last_payload"] = payload.hex().upper()
        if pgn is None:
            pgn = 0x001FEDB
        ent["pgn"] = f"0x{pgn:05X}"
        self._save()
    def maybe_reload(self):
        try:
            if os.path.exists(self.path):
                m = os.path.getmtime(self.path)
                if m > self.mtime:
                    self._load()
        except Exception:
            pass

# -------------------- rvc_map.json helper functions --------------------

def load_rvc_map_json(path="rvc_map.json"):
    """Load rvc_map.json if it exists, return dict or None"""
    try:
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f) or {"schema": 2, "lights": []}
        return {"schema": 2, "lights": []}
    except Exception:
        return None

def save_rvc_map_json(doc, path="rvc_map.json"):
    """Save rvc_map.json"""
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(doc, f, indent=2)
        os.replace(tmp, path)
        return True
    except Exception:
        return False

def get_rvc_map_category_counts(path="rvc_map.json"):
    """Return a dict of category names and their counts from rvc_map.json"""
    doc = load_rvc_map_json(path)
    if doc is None:
        return {}
    counts = {}
    # Count lights (filter out shades)
    lights = doc.get("lights", [])
    if isinstance(lights, list):
        lights_only = [l for l in lights if l.get("category") != "shade"]
        shades_only = [l for l in lights if l.get("category") == "shade"]
        if lights_only:
            counts["lights"] = len(lights_only)
        if shades_only:
            counts["shades"] = len(shades_only)
    elif isinstance(lights, dict):
        counts["lights"] = len(lights)
    # Count commands subcategories
    commands = doc.get("commands", {})
    if isinstance(commands, dict):
        for cmd_type in commands.keys():
            cmd_data = commands.get(cmd_type, {})
            if isinstance(cmd_data, dict) and "commands" in cmd_data:
                counts[f"commands.{cmd_type}"] = len(cmd_data.get("commands", {}))
            elif isinstance(cmd_data, dict) and "locations" in cmd_data:
                # Count actions in locations (for shades_generic, etc.)
                locations = cmd_data.get("locations", [])
                total_actions = 0
                for loc in locations:
                    if isinstance(loc, dict):
                        actions = loc.get("actions", [])
                        if isinstance(actions, list):
                            total_actions += len(actions)
                if total_actions > 0:
                    counts[f"commands.{cmd_type}"] = total_actions
            elif isinstance(cmd_data, dict) and "panels" in cmd_data:
                panels = cmd_data.get("panels", [])
                if isinstance(panels, list) and panels:
                    counts[f"commands.{cmd_type}"] = len(panels)
    # Count statuses
    statuses = doc.get("statuses", {})
    if isinstance(statuses, dict):
        counts["statuses"] = len(statuses)
    return counts

def get_all_categories_list():
    """Return a list of all available category names from rvc_map.json"""
    counts = get_rvc_map_category_counts()
    categories = []
    # Add base categories first
    if "lights" in counts:
        categories.append("lights")
    if "shades" in counts:
        categories.append("shades")
    # Add command categories
    for cat_name in sorted(counts.keys()):
        if cat_name.startswith("commands."):
            categories.append(cat_name)
    # Add statuses
    if "statuses" in counts:
        categories.append("statuses")
    return categories

def upsert_rvc_map_light(instance: int, action: str, *, panel_sa: int=None, controller_sa: int=None,
                         style: str=None, level: int=None, friendly_name: str=None, payload: bytes=None,
                         pgn: int = None, category: str=None, compatibility: dict=None, path="rvc_map.json"):
    """Upsert a light action in rvc_map.json format"""
    doc = load_rvc_map_json(path)
    if doc is None:
        doc = {"schema": 2, "lights": []}
    
    key = f"inst_{instance:02X}"
    lights = doc.setdefault("lights", [])
    if not isinstance(lights, list):
        lights = []
        doc["lights"] = lights
    
    # Find existing light entry
    light_entry = None
    for light in lights:
        if light.get("instance") == key:
            light_entry = light
            break
    
    # Create new entry if not found
    if light_entry is None:
        light_entry = {
            "instance": key,
            "category": category or "light",  # Use provided category, default to "light"
            "name": friendly_name or None,
            "controller": f"{controller_sa:02X}" if controller_sa is not None else None,
            "panels": [],
            "actions": []
        }
        # Add compatibility info if provided
        if compatibility:
            light_entry["compatibility"] = compatibility
        lights.append(light_entry)
    else:
        # Update category if provided and not already set
        if category and not light_entry.get("category"):
            light_entry["category"] = category
        # Update compatibility if provided and not already set
        if compatibility and not light_entry.get("compatibility"):
            light_entry["compatibility"] = compatibility
    
    # Update name if provided and not set
    if friendly_name and not light_entry.get("name"):
        light_entry["name"] = friendly_name
    
    # Update controller if provided
    if controller_sa is not None:
        light_entry["controller"] = f"{controller_sa:02X}"
    
    # Update panels
    if panel_sa is not None:
        panel_str = f"{panel_sa:02X}"
        if "panels" not in light_entry:
            light_entry["panels"] = []
        if panel_str not in light_entry["panels"]:
            light_entry["panels"].append(panel_str)
    
    # Find or create action entry
    action_entry = None
    for act in light_entry.get("actions", []):
        if act.get("name") == action:
            action_entry = act
            break
    
    if action_entry is None:
        action_entry = {
            "name": action,
            "pgn": f"0x{(pgn or 0x001FEDB):05X}",
            "styles": [],
            "payload": payload.hex().upper() if payload else None,
            "seen": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "panels": []
        }
        light_entry.setdefault("actions", []).append(action_entry)
    else:
        # Update seen timestamp
        action_entry["seen"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    
    # Update styles
    if style and "styles" in action_entry:
        if style not in action_entry["styles"]:
            action_entry["styles"].append(style)
    elif style:
        action_entry["styles"] = [style]
    
    # Update payload
    if payload is not None:
        action_entry["payload"] = payload.hex().upper()
    
    # Update level for SET_LEVEL
    if action == "SET_LEVEL" and level is not None:
        action_entry["level"] = int(level)
    
    # Update panels in action
    if panel_sa is not None:
        panel_str = f"{panel_sa:02X}"
        if "panels" not in action_entry:
            action_entry["panels"] = []
        if panel_str not in action_entry["panels"]:
            action_entry["panels"].append(panel_str)
    
    save_rvc_map_json(doc, path)

# -------------------- Request & Command builders --------------------

def build_request_frame(pgn: int, sa: int = 0x80, da: int = 0xFF, priority: int = 6):
    PF_REQUEST = 0xEA; DP = 0
    arb = ((priority & 7) << 26) | (DP << 24) | (PF_REQUEST << 16) | ((da & 0xFF) << 8) | (sa & 0xFF)
    payload = bytes([pgn & 0xFF, (pgn >> 8) & 0xFF, (pgn >> 16) & 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    return can.Message(arbitration_id=arb, is_extended_id=True, data=payload)

def build_pgn_frame(pgn: int, data: bytes, sa: int = 0x80, priority: int = 6):
    """Build a generic 29-bit extended-id J1939/RV-C frame for a given PGN (PDU2 assumed if PF>=240)."""
    dp  = (pgn >> 16) & 0x01
    pf  = (pgn >> 8)  & 0xFF
    ps  = (pgn >> 0)  & 0xFF
    if pf < 240:
        # PDU1; ps would be DA, but all RV-C we use here are PDU2 (pf >= 240)
        pass
    arb = ((priority & 7) << 26) | (dp << 24) | (pf << 16) | (ps << 8) | (sa & 0xFF)
    return can.Message(arbitration_id=arb, is_extended_id=True, data=data[:8].ljust(8, b'\xFF'))

def build_dimmer_command_frame(instance: int, action: str, *, style: str = "verb", level: int = None,
                               sa: int = 0x80, priority: int = 6, pgn: int = 0x001FEDB):
    """
    Compose 1FEDB (DC_DIMMER_COMMAND_2) per two styles:
      - style='verb' uses action mapping: ON(0x11) OFF(0x06) BRIGHT(0x13) DIM(0x14)
      - style='set_level' uses byte3=0x01 (or 0x03 with level=0 for OFF), byte2=level(0..200)
    """
    b = bytearray([0xFF]*8)
    b[0] = instance & 0xFF
    b[1] = 0xFF
    b[4] = 0xFF
    b[5] = 0x00
    b[6] = 0xFF
    b[7] = 0xFF

    style_u = style.lower()
    act_u = action.upper()

    if style_u == "set_level":
        if act_u == "OFF":
            b[2] = 0x00
            b[3] = 0x03  # panel-style OFF payload
        elif act_u == "SET_LEVEL":
            if level is None:
                raise ValueError("SET_LEVEL requires --level 0..200")
            if not (0 <= int(level) <= 200):
                raise ValueError("level must be 0..200 (0.5% steps to 100%)")
            brightness = max(0, min(int(level), 200))
            b[2] = brightness & 0xFF
            b[3] = 0x00  # direct set-level command
            b[4] = 0xFF
        elif act_u in ("ON","BRIGHT","DIM"):
            # emulate by pushing a level; ON -> 200, BRIGHT -> 200, DIM -> 32 (approx)
            if act_u == "ON":
                lvl = 200
            elif act_u == "BRIGHT":
                lvl = 200
            else:  # DIM
                lvl = 32
            b[2] = lvl & 0xFF
            b[3] = 0x01
        else:
            raise ValueError(f"Unsupported action for set_level: {action}")
    else:
        if act_u not in ("ON","OFF","BRIGHT","DIM"):
            if act_u == "SET_LEVEL":
                raise ValueError("Use style 'set_level' for SET_LEVEL")
            raise ValueError(f"Unsupported action: {action}")
        code = {"ON":0x11,"OFF":0x06,"BRIGHT":0x13,"DIM":0x14}[act_u]
        b[2] = 0x00
        b[3] = code
        b[5] = 0x00

    return build_pgn_frame(pgn, bytes(b), sa=sa, priority=priority)

# -------------------- MQTT Publisher --------------------

class MqttPublisher:
    def __init__(self, host="localhost", port=1883, client_id="rvc_mapper"):
        self.host = host
        self.port = port
        self.client_id = client_id
        self.client = None
        self.connected = False
        
    def connect(self):
        try:
            self.client = MqttClient(client_id=self.client_id)
            self.client.connect(self.host, self.port, 60)
            self.client.loop_start()
            self.connected = True
            return True
        except Exception as e:
            print(f"Failed to connect to MQTT broker: {e}")
            return False
            
    def disconnect(self):
        if self.client:
            self.client.loop_stop()
            self.client.disconnect()
            self.connected = False
            
    def publish(self, topic, payload, retain=False):
        if not self.connected or not self.client:
            return False
        try:
            result = self.client.publish(topic, payload, retain=retain)
            return result.rc == 0
        except Exception as e:
            print(f"MQTT publish error: {e}")
            return False
            
    def publish_decoded_frame(self, decoded_result, timestamp=None):
        """Publish decoded frame to MQTT in rvc2mqtt format"""
        if not self.connected:
            return False
            
        name = decoded_result.get("name", "UNKNOWN")
        instance = decoded_result.get("instance")
        
        # Build topic: RVC/<name>[/instance]
        topic = f"RVC/{name}"
        if instance is not None:
            topic += f"/{instance}"
            
        # Add timestamp if provided
        if timestamp is not None:
            decoded_result["timestamp"] = timestamp
            
        # Publish as JSON
        payload = json.dumps(decoded_result, separators=(",", ":"))
        return self.publish(topic, payload)

# -------------------- App --------------------

class RvcMapperApp:
    def __init__(self, channel="can0", mqtt_host="localhost", mqtt_port=1883):
        self.channel = channel
        self.decoder = YamlDecoder()
        self.show_decoded = True
        self.show_raw = True
        self.ignore = IgnoreRules()
        self.roles  = RoleRegistry()
        self.cmap   = CanonicalMapV2()
        self.mqtt = MqttPublisher(host=mqtt_host, port=mqtt_port)
        self.mqtt_enabled = False

    def _role_tag(self, sa: int):
        r = self.roles.role_of(sa)
        return f"[{r.upper()}]" if r else ""

    def _open_can_bus(self):
        """Safely open CAN bus, return None if unavailable (allows testing without CAN interface)"""
        try:
            return can.ThreadSafeBus(interface="socketcan", channel=self.channel)
        except Exception as e:
            print(f"  ! Cannot open CAN channel '{self.channel}': {e}")
            print("  ! Continuing without CAN interface (for testing/debugging)")
            return None

    def prompt(self, msg, default=None, parse=None):
        sdef = f" [{default}]" if default is not None else ""
        s = input(f"{msg}{sdef}: ").strip()
        if not s and default is not None:
            if parse:
                try:
                    to_parse = default if isinstance(default, str) else str(default)
                    return parse(to_parse)
                except Exception as e:
                    print(f"  ! Invalid default value: {e}")
                    return None
            return default
        if parse:
            try: return parse(s)
            except Exception as e:
                print(f"  ! Invalid input: {e}")
                return None
        return s

    # ---------- Menu ----------
    def menu(self):
        while True:
            print("\n=== RV-C / J1939 Mapper ===")
            print(f"Channel: {self.channel} | YAML: {self.decoder.path or '(none)'} | Decoded: {self.show_decoded} | Raw: {self.show_raw}")
            
            # Build category counts string
            cat_parts = [f"Ignore rules: {len(self.ignore.rules)}", f"Roles known: {len(self.roles.roles)}"]
            cat_parts.append(f"Map v2 lights: {len(self.cmap.doc.get('lights',{}))}")
            
            # Add rvc_map.json category counts (load on demand)
            v1_counts = get_rvc_map_category_counts()
            for cat_name, count in sorted(v1_counts.items()):
                cat_parts.append(f"Map {cat_name}: {count}")
            
            print(" | ".join(cat_parts))
            print(f"MQTT: {'Connected' if self.mqtt.connected else 'Disconnected'} | Enabled: {self.mqtt_enabled}")
            print("1) Sniff")
            print("2) Raw Capture (filtered dump)")
            print("3) Burst Capture (3s window)")
            print("4) Discovery (REQUEST + aggregate instances)")
            print("5) Send Command (from rvc_map_v2.json or rvc_map.json)")
            print("6) View Command Payload")
            print("7) Send REQUEST (manual)")
            print("8) Load YAML mapping")
            print("9) Autolearn (canonical Instance+Action)")
            print("10) Ignore Manager")
            print("11) Settings")
            print("12) MQTT Settings")
            print("13) Quit")
            choice = input("Select> ").strip()
            if choice == "1": self.action_sniff()
            elif choice == "2": self.action_raw_capture()
            elif choice == "3": self.action_burst()
            elif choice == "4": self.action_discovery()
            elif choice == "5": self.action_send_command()
            elif choice == "6": self.action_view_payload()
            elif choice == "7": self.action_request()
            elif choice == "8": self.action_load_yaml()
            elif choice == "9": self.action_autolearn()
            elif choice == "10": self.action_ignore_mgr()
            elif choice == "11": self.action_settings()
            elif choice == "12": self.action_mqtt_settings()
            elif choice == "13": print("Bye."); return
            else: print("  ! Invalid selection.")

    # ---------- Settings ----------
    def action_settings(self):
        while True:
            print("\n--- Settings ---")
            print(f"1) Change channel (current: {self.channel})")
            print(f"2) Toggle show decoded (current: {self.show_decoded})")
            print(f"3) Toggle show raw (current: {self.show_raw})")
            print("4) Back")
            c = input("Select> ").strip()
            if c == "1":
                ch = self.prompt("Enter SocketCAN channel", default=self.channel)
                if ch: self.channel = ch
            elif c == "2": self.show_decoded = not self.show_decoded
            elif c == "3": self.show_raw = not self.show_raw
            elif c == "4": return
            else: print("  ! Invalid selection.")

    # ---------- MQTT Settings ----------
    def action_mqtt_settings(self):
        while True:
            print("\n--- MQTT Settings ---")
            print(f"1) Connect to MQTT broker (current: {self.mqtt.host}:{self.mqtt.port})")
            print(f"2) Disconnect from MQTT broker")
            print(f"3) Toggle MQTT publishing (current: {self.mqtt_enabled})")
            print(f"4) Change MQTT host (current: {self.mqtt.host})")
            print(f"5) Change MQTT port (current: {self.mqtt.port})")
            print("6) Back")
            c = input("Select> ").strip()
            if c == "1":
                if self.mqtt.connect():
                    print("  ✓ Connected to MQTT broker")
                    # Publish API version
                    self.mqtt.publish("RVC/API_VERSION", str(self.decoder.api_version), retain=True)
                else:
                    print("  ! Failed to connect to MQTT broker")
            elif c == "2":
                self.mqtt.disconnect()
                print("  ✓ Disconnected from MQTT broker")
            elif c == "3":
                self.mqtt_enabled = not self.mqtt_enabled
                print(f"  ✓ MQTT publishing {'enabled' if self.mqtt_enabled else 'disabled'}")
            elif c == "4":
                host = self.prompt("Enter MQTT host", default=self.mqtt.host)
                if host:
                    self.mqtt.host = host
                    if self.mqtt.connected:
                        self.mqtt.disconnect()
            elif c == "5":
                port = self.prompt("Enter MQTT port", default=str(self.mqtt.port), parse=int)
                if port is not None:
                    self.mqtt.port = port
                    if self.mqtt.connected:
                        self.mqtt.disconnect()
            elif c == "6":
                return
            else:
                print("  ! Invalid selection.")

    # ---------- YAML ----------
    def action_load_yaml(self):
        path = self.prompt("YAML file path", default="rvc_map.yaml")
        if not path: return
        try:
            self.decoder.load(path)
            print(f"  ✓ Loaded YAML: {path} (PGNs: {len(self.decoder.map)})")
        except Exception as e:
            print(f"  ! Failed to load YAML: {e}")

    # ---------- REQUEST (manual) ----------
    def action_request(self):
        bus = self._open_can_bus()
        if bus is None:
            return
        def to_int(x): return int(x, 0)
        raw_pgn = self.prompt("PGN/DGN to request (e.g., 0x1FEDA)", parse=None)
        if raw_pgn is None: return
        raw_pgn = raw_pgn.strip()
        if not raw_pgn:
            return
        try:
            pgn = int(raw_pgn, 0)
        except ValueError:
            print("  ! Invalid PGN/DGN value.")
            return

        data_str = input("Data bytes to send (blank for REQUEST): ").strip()

        sa = self.prompt("Our source address", default="0x80", parse=to_int)
        if sa is None: return
        pr = self.prompt("Priority (0..7)", default="6", parse=int)
        if pr is None: return

        if data_str:
            try:
                data_bytes = bytearray.fromhex(data_str)
            except ValueError as e:
                print(f"  ! Invalid data bytes: {e}")
                return
            msg = build_pgn_frame(pgn, bytes(data_bytes), sa=sa, priority=pr)
            bus.send(msg)
            print(f"  > Sent {phex(pgn)} data=[{bytes_hex(bytes(data_bytes))}] from SA {phex(sa,2)} (prio {pr})")
            return

        da = self.prompt("Destination address (0xFF=broadcast)", default="0xFF", parse=to_int)
        if da is None: return
        try:
            msg = build_request_frame(pgn, sa=sa, da=da, priority=pr)
            bus.send(msg)
            named = PGN_NAMES.get(pgn) or self.decoder.name_for(pgn) or ""
            print(f"  > Sent REQUEST for {phex(pgn)}{(' ('+named+')') if named else ''} to DA {phex(da,2)} from SA {phex(sa,2)} (prio {pr})")
            print("  i Listening 3s for immediate responses...")
            reasm = TPReassembler()
            t_end = time.time() + 3.0
            while time.time() < t_end:
                rx = bus.recv(timeout=0.5)
                if not (rx and rx.is_extended_id): continue
                f = parse_can_id(rx.arbitration_id); data = bytes(rx.data)
                self.roles.learn_from_frame(f["pgn"], f["sa"])
                out = reasm.feed(f, data)
                if out is not None:
                    tgt, assembled = out
                    f2 = dict(f); f2["pgn"] = tgt; data = assembled
                    if self.ignore.matches(f2, data): continue
                    self._print_line(f2, data, prefix="    RX (TP) "); continue
                if f["pgn"] in (PGN_TP_CM, PGN_TP_DT): continue
                if self.ignore.matches(f, data): continue
                self._print_line(f, data, prefix="    RX ")
        except Exception as e:
            print(f"  ! Failed to send/receive: {e}")

    def _print_line(self, f, data, prefix=""):
        name = PGN_NAMES.get(f["pgn"]) or self.decoder.name_for(f["pgn"]) or "PGN"
        line = f"{prefix}{name} {phex(f['pgn'])} SA {phex(f['sa'],2)}{self._role_tag(f['sa'])} -> DA {phex(f['da'],2)} len={len(data)}"
        if self.show_raw: line += f" data=[{bytes_hex(data)}]"
        if self.show_decoded and self.decoder.has(f["pgn"]):
            try:
                dec = self.decoder.decode(f["pgn"], data)
                if dec: line += f" -> {dec}"
            except Exception as e:
                line += f" -> {{'_decode_error':'{e}'}}"
        print(line)

    # ---------- SNIFF ----------
    def action_sniff(self):
        def parse_opt_hex(s):
            s = s.strip(); return None if not s else int(s, 0)
        src = self.prompt("Filter Source Address (blank=any)", parse=parse_opt_hex, default="")
        dst = self.prompt("Filter Destination Address (blank=any)", parse=parse_opt_hex, default="")
        pfn = self.prompt("Filter PF byte (blank=any)", parse=parse_opt_hex, default="")
        pgn = self.prompt("Filter PGN/DGN (blank=any)", parse=parse_opt_hex, default="")
        src = None if src == "" else src
        dst = None if dst == "" else dst
        pfn = None if pfn == "" else pfn
        pgn = None if pgn == "" else pgn

        bus = self._open_can_bus()
        if bus is None:
            return

        tracker = DeltaTracker()
        logger = Logger(base_dir="logs")
        reasm = TPReassembler()

        print(f"\n[i] Sniffing on {self.channel}. Logs:\n    CSV   {logger.csv_path}\n    JSONL {logger.jsonl_path}")
        print(f"[i] Ignore rules loaded: {len(self.ignore.rules)} | Roles: {len(self.roles.roles)}")
        print("[i] Ctrl+C to stop.\n")

        try:
            while True:
                self.ignore.maybe_reload()
                rx = bus.recv(timeout=1.0)
                if not (rx and rx.is_extended_id): continue
                f = parse_can_id(rx.arbitration_id); data = bytes(rx.data)
                self.roles.learn_from_frame(f["pgn"], f["sa"])

                out = reasm.feed(f, data)
                if out is not None:
                    tgt, assembled = out
                    f2 = dict(f); f2["pgn"] = tgt; data2 = assembled
                    if not self._passes_filters(f2, src, dst, pfn, pgn): continue
                    if self.ignore.matches(f2, data2): continue
                    changed = tracker.delta(f2["pgn"], f2["sa"], data2)
                    self._log_and_print(logger, f2, data2, changed, tag="(TP)")
                    continue

                if f["pgn"] in (PGN_TP_CM, PGN_TP_DT): continue
                if not self._passes_filters(f, src, dst, pfn, pgn): continue
                if self.ignore.matches(f, data): continue
                changed = tracker.delta(f["pgn"], f["sa"], data)
                self._log_and_print(logger, f, data, changed)
        except KeyboardInterrupt:
            print("\n[i] Stopping...")
        finally:
            logger.close()

    def _passes_filters(self, f, src, dst, pfn, pgn):
        if src is not None and f["sa"] != src: return False
        if dst is not None and f["da"] != dst: return False
        if pfn is not None and ((f["pgn"] >> 8) & 0xFF) != pfn: return False
        if pgn is not None and f["pgn"] != pgn: return False
        return True

    def _log_and_print(self, logger, f, data, changed, tag=""):
        pgn_name = PGN_NAMES.get(f["pgn"]) or self.decoder.name_for(f["pgn"]) or ""
        decoded = {}
        if self.show_decoded and self.decoder.has(f["pgn"]):
            try: decoded = self.decoder.decode(f["pgn"], data)
            except Exception as e: decoded = {"_decode_error": str(e)}
        row = {
            "time_iso": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
            "arb_id_hex": f"0x{((f['priority']<<26) | (f['dp']<<24) | (f['pf']<<16) | (f['ps']<<8) | f['sa']):08X}",
            "priority": f["priority"], "pgn_hex": phex(f["pgn"]),
            "pgn_name": pgn_name, "sa_hex": phex(f["sa"],2), "da_hex": phex(f["da"],2),
            "len": len(data), "data_hex": bytes_hex(data),
            "changed_byte_idx": changed, "decoded": decoded
        }
        logger.write(row)
        
        # Publish to MQTT if enabled and we have decoded data
        if self.mqtt_enabled and self.mqtt.connected and decoded and not decoded.get("_decode_error"):
            timestamp = time.time()
            self.mqtt.publish_decoded_frame(decoded, timestamp)
        
        line = (f"{row['time_iso']}  {(pgn_name or 'PGN')} {row['pgn_hex']} {tag}  "
                f"SA {row['sa_hex']}{self._role_tag(f['sa'])} -> DA {row['da_hex']}  len={row['len']}")
        if self.show_raw: line += f"  data=[{row['data_hex']}]"
        line += f"  Δ={changed}"
        if self.show_decoded and decoded: line += f"  -> {decoded}"
        print(line)

    # ---------- Raw Capture ----------
    def action_raw_capture(self):
        def parse_opt_hex(s):
            s = s.strip()
            return None if not s else int(s, 0)

        pgn = self.prompt("Filter PGN/DGN (blank=any)", parse=parse_opt_hex, default="")
        sa = self.prompt("Filter Source Address (blank=any)", parse=parse_opt_hex, default="")
        da = self.prompt("Filter Destination Address (blank=any)", parse=parse_opt_hex, default="")
        duration = self.prompt("Capture window seconds (blank=5)", default="5", parse=lambda x: float(x) if x else 5.0)
        max_frames = self.prompt("Max frames (blank=0 for unlimited)", default="0", parse=lambda x: int(x, 0))

        if pgn == "":
            pgn = None
        if sa == "":
            sa = None
        if da == "":
            da = None

        bus = self._open_can_bus()
        if bus is None:
            return

        if duration is not None and duration <= 0:
            duration = None
        if max_frames is not None and max_frames < 0:
            max_frames = 0
        t_end = None if duration is None else time.time() + float(duration)
        captured = 0

        print(f"\n[i] Raw capture on {self.channel}. Ctrl+C to stop.")
        try:
            while True:
                if t_end is not None and time.time() >= t_end:
                    break
                if max_frames and captured >= max_frames:
                    break
                rx = bus.recv(timeout=0.5)
                if not (rx and rx.is_extended_id):
                    continue
                f = parse_can_id(rx.arbitration_id)
                if pgn is not None and f["pgn"] != pgn:
                    continue
                if sa is not None and f["sa"] != sa:
                    continue
                if da is not None and f["da"] != da:
                    continue
                data = bytes(rx.data)
                ts = datetime.utcnow().isoformat(timespec="milliseconds") + "Z"
                print(f"{ts}  {phex(rx.arbitration_id,8)}  PGN {phex(f['pgn'])}  SA {phex(f['sa'],2)} -> DA {phex(f['da'],2)}  len={len(data)}  data=[{bytes_hex(data)}]")
                captured += 1
        except KeyboardInterrupt:
            print("\n[i] Raw capture stopped by user.")
        finally:
            try:
                bus.shutdown()
            except Exception:
                pass
        print(f"\n[i] Captured {captured} frame(s).")

    # ---------- Burst Capture ----------
    def action_burst(self):
        window = self.prompt("Window seconds", default="3", parse=float)
        if window is None: return
        bus = self._open_can_bus()
        if bus is None:
            return
        input("Press Enter to START the window, then press your button...")
        reasm = TPReassembler()
        tracker = {}
        changed_union = {}
        seen_last = {}

        t_end = time.time() + float(window)
        print(f"[i] Capturing for {window}s...")

        while time.time() < t_end:
            rx = bus.recv(timeout=0.2)
            if not (rx and rx.is_extended_id): continue
            f = parse_can_id(rx.arbitration_id); data = bytes(rx.data)
            self.roles.learn_from_frame(f["pgn"], f["sa"])

            out = reasm.feed(f, data)
            if out is not None:
                tgt, assembled = out
                f = dict(f); f["pgn"] = tgt; data = assembled
            elif f["pgn"] in (PGN_TP_CM, PGN_TP_DT):
                continue

            if self.ignore.matches(f, data): continue

            key = (f["pgn"], f["sa"])
            if key not in tracker:
                tracker[key] = data
                seen_last[key] = data
                continue
            prev = seen_last[key]
            seen_last[key] = data
            idx = [i for i,(a,b) in enumerate(zip(prev, data)) if a != b] if len(prev)==len(data) else list(range(len(data)))
            if idx:
                changed_union.setdefault(key, set()).update(idx)

        if not changed_union:
            print("No changing PGN/SA pairs observed in the window.")
            return

        print("\n=== Burst result (changed PGN/SA in window) ===")
        for (pgn, sa), idxset in sorted(changed_union.items()):
            idxlist = sorted(idxset)
            print(f"{PGN_NAMES.get(pgn,'PGN')} {phex(pgn)}  SA {phex(sa,2)}{self._role_tag(sa)}  changed bytes {idxlist}")

    # ---------- Discovery ----------
    def action_discovery(self):
        def parse_list(s):
            s = s.strip()
            if not s: return []
            parts = [x.strip() for x in s.split(",") if x.strip()]
            return [int(x, 0) for x in parts]
        print("\n[i] DISCOVERY")
        default_pgNs = "0x1FEDA"
        pgns = self.prompt(f"PGNs to REQUEST (comma-separated hex; default {default_pgNs})", default=default_pgNs, parse=parse_list)
        if pgns is None: return
        if not pgns: pgns = [0x1FEDA]
        window = self.prompt("Listen window seconds after each REQUEST", default="2.5", parse=float)
        if window is None: return
        sa = self.prompt("Our source address", default="0x80", parse=lambda x:int(x,0))
        if sa is None: return
        pr = self.prompt("Priority (0..7)", default="6", parse=int)
        if pr is None: return

        bus = self._open_can_bus()
        if bus is None:
            return

        reasm = TPReassembler()
        discovered = {
            "time": datetime.utcnow().isoformat(timespec="seconds")+"Z",
            "channel": self.channel,
            "by_pgn": {},     # pgn_hex -> { "controllers": { "SAhex": [instances...] } }
            "address_claim": {}  # basic SA presence (optional future)
        }

        for pgn in pgns:
            msg = build_request_frame(pgn, sa=sa, da=0xFF, priority=pr)
            bus.send(msg)
            pname = PGN_NAMES.get(pgn) or self.decoder.name_for(pgn) or ""
            print(f"  > REQUEST {phex(pgn)}{(' ('+pname+')') if pname else ''} broadcast; listening {window}s...")
            t_end = time.time() + float(window)
            controllers = {}
            while time.time() < t_end:
                rx = bus.recv(timeout=0.3)
                if not (rx and rx.is_extended_id): continue
                f = parse_can_id(rx.arbitration_id); data = bytes(rx.data)
                self.roles.learn_from_frame(f["pgn"], f["sa"])

                out = reasm.feed(f, data)
                if out is not None:
                    tgt, assembled = out
                    f = dict(f); f["pgn"] = tgt; data = assembled
                elif f["pgn"] in (PGN_TP_CM, PGN_TP_DT):
                    continue

                if f["pgn"] != pgn:  # only responses to target PGN
                    continue
                if self.ignore.matches(f, data):
                    continue

                inst = extract_instance_for_1FEDx(f["pgn"], data)
                if inst is None:
                    continue
                sahex = f"{f['sa']:02X}"
                controllers.setdefault(sahex, set()).add(inst)

            # finalize
            controllers_sorted = {k: sorted(list(v)) for k,v in controllers.items()}
            discovered["by_pgn"][f"{pgn:05X}"] = {"controllers": controllers_sorted}

        path = "rvc_discovery.json"
        existing = {}
        try:
            with open(path, "r") as f:
                existing = json.load(f) or {}
        except FileNotFoundError:
            existing = {}
        except Exception as e:
            print(f"  ! Warning: could not load existing discovery file: {e}")
            existing = {}

        if isinstance(existing, dict) and "history" in existing:
            history = existing.get("history", [])
            history.append(discovered)
            merged = {"history": history}
        elif isinstance(existing, dict) and existing:
            merged = {
                "history": [existing, discovered]
            }
        else:
            merged = discovered

        with open(path, "w") as f:
            json.dump(merged, f, indent=2)

        print("\n=== Discovery Result ===")
        for pgn_hex, info in discovered["by_pgn"].items():
            pname = PGN_NAMES.get(int(pgn_hex,16)) or self.decoder.name_for(int(pgn_hex,16)) or ""
            print(f"{pgn_hex}{(' ('+pname+')') if pname else ''}:")
            ctrls = info.get("controllers", {})
            if not ctrls:
                print("  (no responders)")
            for sah, insts in ctrls.items():
                insts_s = ", ".join(f"0x{i:02X}" for i in insts)
                print(f"  CTRL SA {sah}: instances [{insts_s}]")
        print(f"\nSaved: {path}")

    def _collect_command_params(self):
        # Ask which map file to use
        print("\n--- Select Map File ---")
        print("[1] rvc_map_v2.json")
        print("[2] rvc_map.json")
        map_choice = input("Select map file [1]: ").strip() or "1"
        
        use_v1 = (map_choice == "2")
        doc = None  # Will be set for rvc_map.json
        
        # Load the selected map file and get categories
        if use_v1:
            doc = load_rvc_map_json()
            if doc is None:
                print("  ! Failed to load rvc_map.json")
                return None
            # Get categories from rvc_map.json
            categories = {}
            lights_list = doc.get("lights", [])
            if isinstance(lights_list, list) and lights_list:
                # Filter by category
                lights_only = [l for l in lights_list if l.get("category") != "shade"]
                shades_only = [l for l in lights_list if l.get("category") == "shade"]
                if lights_only:
                    categories["lights"] = len(lights_only)
                if shades_only:
                    categories["shades"] = len(shades_only)
            commands = doc.get("commands", {})
            if isinstance(commands, dict):
                for cmd_type, cmd_data in commands.items():
                    if isinstance(cmd_data, dict):
                        # Check for "commands" dictionary (locks, aquahot_electric, etc.)
                        if "commands" in cmd_data:
                            categories[f"commands.{cmd_type}"] = len(cmd_data.get("commands", {}))
                        # Check for "locations" array (shades_generic, etc.)
                        elif "locations" in cmd_data:
                            locations = cmd_data.get("locations", [])
                            if isinstance(locations, list) and locations:
                                # Count total actions across all locations
                                total_actions = 0
                                for loc in locations:
                                    if isinstance(loc, dict):
                                        actions = loc.get("actions", [])
                                        if isinstance(actions, list):
                                            total_actions += len(actions)
                                if total_actions > 0:
                                    categories[f"commands.{cmd_type}"] = total_actions
                        # Check for "panels" array (panel_lights_entegra, etc.)
                        elif "panels" in cmd_data:
                            panels = cmd_data.get("panels", [])
                            if isinstance(panels, list) and panels:
                                categories[f"commands.{cmd_type}"] = len(panels)
            statuses = doc.get("statuses", {})
            if isinstance(statuses, dict) and statuses:
                categories["statuses"] = len(statuses)
        else:
            self.cmap.maybe_reload()
            m = self.cmap.doc
            categories = {}
            lights = m.get("lights", {})
            if lights:
                categories["lights"] = len(lights)
            # rvc_map_v2.json only has lights currently
        
        if not categories:
            print("No categories found in selected map file.")
            return None
        
        # Show categories and let user select
        print("\n--- Select Category ---")
        cat_items = sorted(categories.items())
        for i, (cat_name, count) in enumerate(cat_items):
            print(f"[{i}] {cat_name}: {count}")
        try:
            cat_idx = int(input("Pick a category index: ").strip())
        except Exception:
            print("  ! Invalid index"); return None
        if not (0 <= cat_idx < len(cat_items)):
            print("  ! Index out of range"); return None
        
        selected_cat, cat_count = cat_items[cat_idx]
        
        # Handle different category types
        if selected_cat == "lights":
            # Handle lights category (same as before)
            if use_v1:
                lights_list = doc.get("lights", [])
                if not lights_list:
                    print("No lights in rvc_map.json.")
                    return None
                
                # Filter out shades
                lights_list = [l for l in lights_list if l.get("category") != "shade"]
                if not lights_list:
                    print("No lights (excluding shades) in rvc_map.json.")
                    return None
                
                items = []
                for light in lights_list:
                    key = light.get("instance", "")
                    name = light.get("name") or "(unnamed)"
                    controller = light.get("controller") or "--"
                    inst_hex_raw = key.split("_", 1)[-1] if "_" in key else key.replace("inst_", "")
                    try:
                        inst_val = int(inst_hex_raw, 16)
                    except ValueError:
                        inst_val = None
                    inst_display = f"{inst_val:02X}" if inst_val is not None else inst_hex_raw
                    items.append((key, name, inst_val, inst_display, controller, light))
                items.sort(key=lambda x: (x[1], x[3]))
                
                print("\n--- Lights (rvc_map.json) ---")
                for i, (key, name, inst_val, inst_display, ctrl, light) in enumerate(items):
                    print(f"[{i}] {name:<24} inst={inst_display} controller={ctrl}")
                try:
                    idx = int(input("Pick a light index: ").strip())
                except Exception:
                    print("  ! Invalid index"); return None
                if not (0 <= idx < len(items)):
                    print("  ! Index out of range"); return None
                key, name, inst_val, inst_display, ctrl, light = items[idx]
                if inst_val is None:
                    print("  ! Instance ID not available for this entry.")
                    return None
                inst = inst_val
                actions_list = light.get("actions", [])
                controller_sa = light.get("controller")
                
                entries = {}
                for act in actions_list:
                    act_name = act.get("name")
                    if act_name:
                        entries[act_name] = {
                            "styles_seen": act.get("styles", []),
                            "panels": act.get("panels", []),
                            "last_payload": act.get("payload"),
                            "pgn": act.get("pgn"),
                            "last_level": act.get("level"),
                            "last_seen": act.get("seen"),
                            "sequence": act.get("sequence")
                        }
            else:
                # rvc_map_v2.json lights
                m = self.cmap.doc
                lights = m.get("lights", {})
                if not lights:
                    print("No lights in rvc_map_v2.json.")
                    return None
                
                items = []
                for key, rec in lights.items():
                    name = rec.get("name") or "(unnamed)"
                    controller = rec.get("controller") or "--"
                    override_inst = rec.get("override_instance")
                    inst_val = None
                    if override_inst is not None:
                        try:
                            inst_val = int(override_inst, 0) if isinstance(override_inst, str) else int(override_inst)
                        except Exception:
                            inst_val = None
                    inst_hex_raw = key.split("_",1)[-1]
                    if inst_val is None:
                        try:
                            inst_val = int(inst_hex_raw, 16)
                        except ValueError:
                            inst_val = None
                    inst_display = f"{inst_val:02X}" if inst_val is not None else inst_hex_raw
                    items.append((key, name, inst_val, inst_display, controller))
                items.sort(key=lambda x: (x[1], x[3]))

                print("\n--- Lights (rvc_map_v2.json) ---")
                for i,(key,name,inst_val,inst_display,ctrl) in enumerate(items):
                    rec_item = lights.get(key, {})
                    cls = rec_item.get("instance_group") or ""
                    extra = f" class={cls}" if cls else ""
                    print(f"[{i}] {name:<24} inst={inst_display} controller={ctrl}{extra}")
                try:
                    idx = int(input("Pick a light index: ").strip())
                except Exception:
                    print("  ! Invalid index"); return None
                if not (0 <= idx < len(items)):
                    print("  ! Index out of range"); return None
                key,name,inst_val,inst_display,ctrl = items[idx]
                if inst_val is None:
                    print("  ! Instance ID not available for this entry.")
                    return None
                inst = inst_val
                rec = lights.get(key, {})
                entries = rec.get("entries", {})
                controller_sa = rec.get("controller")
        elif selected_cat == "shades":
            # Handle shades category (from lights array with category="shade")
            if use_v1:
                lights_list = doc.get("lights", [])
                if not lights_list:
                    print("No shades in rvc_map.json.")
                    return None
                
                # Filter to only shades
                shades_list = [l for l in lights_list if l.get("category") == "shade"]
                if not shades_list:
                    print("No shades in rvc_map.json.")
                    return None
                
                items = []
                for shade in shades_list:
                    key = shade.get("instance", "")
                    name = shade.get("name") or "(unnamed)"
                    controller = shade.get("controller") or "--"
                    inst_hex_raw = key.split("_", 1)[-1] if "_" in key else key.replace("inst_", "")
                    try:
                        inst_val = int(inst_hex_raw, 16)
                    except ValueError:
                        inst_val = None
                    inst_display = f"{inst_val:02X}" if inst_val is not None else inst_hex_raw
                    items.append((key, name, inst_val, inst_display, controller, shade))
                items.sort(key=lambda x: (x[1], x[3]))
                
                print("\n--- Shades (rvc_map.json) ---")
                for i, (key, name, inst_val, inst_display, ctrl, shade) in enumerate(items):
                    print(f"[{i}] {name:<24} inst={inst_display} controller={ctrl}")
                try:
                    idx = int(input("Pick a shade index: ").strip())
                except Exception:
                    print("  ! Invalid index"); return None
                if not (0 <= idx < len(items)):
                    print("  ! Index out of range"); return None
                key, name, inst_val, inst_display, ctrl, shade = items[idx]
                if inst_val is None:
                    print("  ! Instance ID not available for this entry.")
                    return None
                inst = inst_val
                actions_list = shade.get("actions", [])
                controller_sa = shade.get("controller")
                
                entries = {}
                for act in actions_list:
                    act_name = act.get("name")
                    if act_name:
                        entries[act_name] = {
                            "styles_seen": act.get("styles", []),
                            "panels": act.get("panels", []),
                            "last_payload": act.get("payload"),
                            "pgn": act.get("pgn"),
                            "last_level": act.get("level"),
                            "last_seen": act.get("seen"),
                            "sequence": act.get("sequence")
                        }
            else:
                # Shades are only in rvc_map.json, not rvc_map_v2.json
                print("  ! Shades are only available in rvc_map.json, not rvc_map_v2.json.")
                return None
        elif selected_cat.startswith("commands."):
            # Handle commands subcategory
            cmd_type = selected_cat.split(".", 1)[1]
            cmd_data = doc.get("commands", {}).get(cmd_type, {})
            
            # Check for different command structures
            if "commands" in cmd_data:
                # Standard structure: commands.commands.{name: {...}}
                commands_dict = cmd_data.get("commands", {})
                if not commands_dict:
                    print(f"No commands found in {selected_cat}.")
                    return None
                
                print(f"\n--- Commands: {cmd_type} ---")
                cmd_items = list(commands_dict.items())
                for i, (cmd_name, cmd_info) in enumerate(cmd_items):
                    print(f"[{i}] {cmd_name}")
                try:
                    cmd_idx = int(input("Pick a command index: ").strip())
                except Exception:
                    print("  ! Invalid index"); return None
                if not (0 <= cmd_idx < len(cmd_items)):
                    print("  ! Index out of range"); return None
                
                cmd_name, cmd_info = cmd_items[cmd_idx]
            elif "locations" in cmd_data:
                # Shades structure: commands.locations[{location: X, actions: [...]}]
                locations = cmd_data.get("locations", [])
                if not locations:
                    print(f"No locations found in {selected_cat}.")
                    return None
                
                print(f"\n--- Commands: {cmd_type} (Locations) ---")
                for i, loc in enumerate(locations):
                    loc_num = loc.get("location", i)
                    print(f"[{i}] Location {loc_num}")
                try:
                    loc_idx = int(input("Pick a location index: ").strip())
                except Exception:
                    print("  ! Invalid index"); return None
                if not (0 <= loc_idx < len(locations)):
                    print("  ! Index out of range"); return None
                
                selected_location = locations[loc_idx]
                actions_list = selected_location.get("actions", [])
                if not actions_list:
                    print(f"No actions found in location {selected_location.get('location', loc_idx)}.")
                    return None
                
                print(f"\n--- Actions for Location {selected_location.get('location', loc_idx)} ---")
                for i, action_item in enumerate(actions_list):
                    action_name = action_item.get("name", f"Action_{i}")
                    print(f"[{i}] {action_name}")
                try:
                    action_idx = int(input("Pick an action index: ").strip())
                except Exception:
                    print("  ! Invalid index"); return None
                if not (0 <= action_idx < len(actions_list)):
                    print("  ! Index out of range"); return None
                
                cmd_name = f"Location_{selected_location.get('location', loc_idx)}_{actions_list[action_idx].get('name', 'Action')}"
                cmd_info = actions_list[action_idx]
            elif "panels" in cmd_data:
                # Panel lights structure: commands.panels[{panel_id: X, name: "...", ...}]
                panels = cmd_data.get("panels", [])
                if not panels:
                    print(f"No panels found in {selected_cat}.")
                    return None
                
                print(f"\n--- Commands: {cmd_type} (Panels) ---")
                for i, panel in enumerate(panels):
                    panel_name = panel.get("name", f"Panel_{i}")
                    panel_id = panel.get("panel_id", i)
                    print(f"[{i}] {panel_name} (ID: {panel_id})")
                try:
                    panel_idx = int(input("Pick a panel index: ").strip())
                except Exception:
                    print("  ! Invalid index"); return None
                if not (0 <= panel_idx < len(panels)):
                    print("  ! Index out of range"); return None
                
                selected_panel = panels[panel_idx]
                cmd_name = selected_panel.get("name", f"Panel_{panel_idx}")
                cmd_info = selected_panel  # Panel has command_format structure
            else:
                print(f"  ! Unsupported command structure in {selected_cat}")
                return None
            
            # Commands have different structure - they may have lock/unlock, sequences, etc.
            # Extract available actions from the command
            entries = {}
            cmd_pgn = cmd_data.get("pgn", "0x1FEDB")
            if isinstance(cmd_pgn, str):
                try:
                    cmd_pgn = int(cmd_pgn, 0)
                except:
                    cmd_pgn = 0x001FEDB
            elif not isinstance(cmd_pgn, int):
                cmd_pgn = 0x001FEDB
            
            # Handle different command info structures
            if "lock" in cmd_info and "unlock" in cmd_info:
                entries["lock"] = {"last_payload": cmd_info["lock"].get("payload"), "pgn": cmd_pgn}
                entries["unlock"] = {"last_payload": cmd_info["unlock"].get("payload"), "pgn": cmd_pgn}
            elif "sequence" in cmd_info:
                # Single action with sequence - convert to format with pgn in each item
                seq_with_pgn = []
                for seq_item in cmd_info["sequence"]:
                    if isinstance(seq_item, dict):
                        seq_item_copy = dict(seq_item)
                        seq_item_copy["pgn"] = cmd_pgn
                        seq_with_pgn.append(seq_item_copy)
                    else:
                        seq_with_pgn.append(seq_item)
                entries["EXECUTE"] = {"sequence": seq_with_pgn, "pgn": cmd_pgn}
            elif "payload" in cmd_info:
                # Single payload action (from shades locations)
                action_name = cmd_info.get("name", "EXECUTE")
                entries[action_name] = {"last_payload": cmd_info.get("payload"), "pgn": cmd_pgn}
            elif "command_format" in cmd_info:
                # Panel lights structure - has command_format with payload_template
                # This would need level input, so we'll handle it as a special case
                entries["SET_LEVEL"] = {"command_format": cmd_info.get("command_format"), "pgn": cmd_pgn}
            elif isinstance(cmd_info, dict):
                # Check for action keys like ON_LOW, ON_HIGH, OFF, UP, DOWN, etc.
                for key in cmd_info.keys():
                    if key not in ("instance", "instances", "compatibility", "location", "name", "pgn", "description"):
                        if isinstance(cmd_info[key], list):
                            # Convert sequence items to include pgn
                            seq_with_pgn = []
                            for seq_item in cmd_info[key]:
                                if isinstance(seq_item, dict):
                                    seq_item_copy = dict(seq_item)
                                    seq_item_copy["pgn"] = cmd_pgn
                                    seq_with_pgn.append(seq_item_copy)
                                else:
                                    seq_with_pgn.append(seq_item)
                            entries[key] = {"sequence": seq_with_pgn, "pgn": cmd_pgn}
                        elif isinstance(cmd_info[key], dict) and "payload" in cmd_info[key]:
                            entries[key] = {"last_payload": cmd_info[key].get("payload"), "pgn": cmd_pgn}
            
            if not entries:
                print(f"  ! No sendable actions found for {cmd_name}")
                return None
            
            # For commands, we need to extract instance from the first payload or sequence
            inst = None
            inst_display = "??"
            name = cmd_name
            controller_sa = cmd_data.get("controller")
            key = f"cmd_{cmd_type}_{cmd_name}"
            
            # Try to get instance from first entry
            first_entry = list(entries.values())[0]
            if "last_payload" in first_entry and first_entry["last_payload"]:
                try:
                    payload_bytes = bytearray.fromhex(first_entry["last_payload"])
                    if payload_bytes:
                        inst = payload_bytes[0]
                        inst_display = f"{inst:02X}"
                except Exception:
                    pass
            elif "sequence" in first_entry and first_entry["sequence"]:
                seq = first_entry["sequence"]
                if isinstance(seq, list) and len(seq) > 0:
                    first_seq_item = seq[0]
                    if isinstance(first_seq_item, dict):
                        inst_str = first_seq_item.get("instance", "")
                        if inst_str:
                            try:
                                inst = int(inst_str, 0)
                                inst_display = f"{inst:02X}"
                            except Exception:
                                pass
        elif selected_cat == "statuses":
            print("  ! Statuses are read-only, cannot send commands.")
            return None
        else:
            print(f"  ! Category {selected_cat} not yet supported for sending commands.")
            return None

        selected_info = None
        selected_action = None
        entry_items = sorted(entries.items()) if entries else []
        if entry_items:
            print("\n--- Saved Actions ---")
            for i, (act, info) in enumerate(entry_items):
                styles = ", ".join(info.get("styles_seen", [])) or "--"
                panels = ", ".join(f"0x{p}" for p in info.get("panels", [])) or "--"
                last_level = info.get("last_level")
                lvl = f" last_level={last_level}" if last_level is not None else ""
                last_seen = info.get("last_seen") or "--"
                print(f"[{i}] {act:<10} styles=[{styles}] panels=[{panels}]{lvl} last_seen={last_seen}")
            choice = input("Pick a saved action index (blank to enter manually): ").strip()
            if choice:
                try:
                    ai = int(choice)
                    selected_action, selected_info = entry_items[ai]
                except (ValueError, IndexError):
                    print("  ! Invalid action selection"); return None

        recorded_payload = None
        payload_sequence = None
        payload_sequence_name = None
        use_recorded_payload = False
        selected_pgn = None
        if selected_info:
            recorded_payload = selected_info.get("last_payload")
            if recorded_payload:
                ans = input("Use recorded payload? (Y/n): ").strip().lower()
                use_recorded_payload = ans in ("", "y", "yes")
            else:
                # Check for sequence in rvc_map.json format
                sequence_candidate = selected_info.get("sequence") or selected_info.get("last_payload_sequence")
                if sequence_candidate:
                    ans = input("Use recorded payload sequence? (Y/n): ").strip().lower()
                    if ans in ("", "y", "yes"):
                        use_recorded_payload = True
                        payload_sequence = sequence_candidate
                        payload_sequence_name = selected_info.get("friendly_name")
            pgn_field = selected_info.get("pgn")
            if isinstance(pgn_field, str):
                try:
                    selected_pgn = int(pgn_field, 0)
                except ValueError:
                    selected_pgn = None
            elif isinstance(pgn_field, int):
                selected_pgn = pgn_field

        # Choose action & style
        if selected_info:
            action = selected_action
            print(f"Using saved action: {action}")
        else:
            # For commands and shades with saved actions, show available actions; for lights without saved actions, restrict to standard actions
            if entries:
                # Show available actions (for commands, shades with saved actions, etc.)
                available_actions = list(entries.keys())
                print(f"\nAvailable actions: {', '.join(available_actions)}")
                action = (input("Action: ").strip() or "").upper()
                if not action or action not in [a.upper() for a in available_actions]:
                    print("  ! Invalid action"); return None
                # Find matching case
                for a in available_actions:
                    if a.upper() == action:
                        action = a
                        break
            elif selected_cat == "lights" or selected_cat == "shades":
                # No saved actions, prompt for standard actions
                action = (input("Action (ON/OFF/BRIGHT/DIM/SET_LEVEL): ").strip() or "").upper()
                if action not in ("ON","OFF","BRIGHT","DIM","SET_LEVEL"):
                    print("  ! Unsupported action"); return None
            else:
                # Commands without saved actions - shouldn't happen, but handle it
                action = (input("Action: ").strip() or "").upper()
                if not action:
                    print("  ! Action required"); return None

        style = None
        level = None

        if use_recorded_payload:
            styles_seen = selected_info.get("styles_seen") if selected_info else None
            style = styles_seen[0] if styles_seen else None
            level = selected_info.get("last_level") if selected_info else None
        else:
            def parse_style(s):
                v = s.strip().lower()
                if v not in ("verb", "set_level"):
                    raise ValueError("style must be verb or set_level")
                return v

            if selected_info:
                styles_seen = selected_info.get("styles_seen") or []
                if action == "SET_LEVEL" and "set_level" in styles_seen:
                    default_style = "set_level"
                elif "verb" in styles_seen:
                    default_style = "verb"
                elif styles_seen:
                    default_style = styles_seen[0]
                else:
                    default_style = "set_level" if action == "SET_LEVEL" else "verb"
            else:
                default_style = "set_level" if action == "SET_LEVEL" else "verb"

            style = self.prompt("Style (verb/set_level)", default=default_style, parse=parse_style)
            if style is None:
                return None

            need_level = (action == "SET_LEVEL") or (style == "set_level" and action in ("ON", "BRIGHT", "DIM"))
            if need_level:
                def parse_level(s):
                    v = int(s, 0)
                    if not (0 <= v <= 200):
                        raise ValueError("level must be 0..200")
                    return v
                default_level = None
                if selected_info:
                    default_level = selected_info.get("last_level")
                default_level_str = str(default_level) if default_level is not None else None
                level = self.prompt("Level 0..200 (0.5% steps; 200=100%)", default=default_level_str, parse=parse_level)
                if level is None:
                    print("  ! Level required for this action"); return None

        if action == "SET_LEVEL":
            style = "set_level"
            if level is None:
                level = 0
            recorded_payload = None
            payload_sequence = None
            use_recorded_payload = False

        # Compose & send
        panels = []
        if selected_info:
            panels = [p.upper() for p in selected_info.get("panels", []) if isinstance(p, str)]
        panels = list(dict.fromkeys(panels))
        sa_override = None
        if not use_v1 and selected_cat == "lights":
            # Only try to get sa_override for lights in v2 format
            try:
                rec = lights.get(key, {})
                sa_override = rec.get("default_sa")
            except:
                pass
        if panels:
            print(f"Known panel SAs for this action: {', '.join('0x'+p for p in panels)}")
            sa_default = f"0x{panels[0]}"
        else:
            sa_default = "0x80"
        if sa_override is not None:
            if isinstance(sa_override, str):
                sa_default = sa_override
            else:
                try:
                    sa_default = f"0x{int(sa_override):02X}"
                except Exception:
                    pass
        if isinstance(controller_sa, str) and controller_sa:
            print(f"Last controller SA observed: 0x{controller_sa}")
        sa = self.prompt("Our source address", default=sa_default, parse=lambda x:int(x,0))
        if sa is None: return None
        pr = self.prompt("Priority (0..7)", default="6", parse=int)
        if pr is None: return None

        return {
            "inst": inst,
            "inst_display": inst_display,
            "name": name,
            "action": action,
            "style": style,
            "level": level,
            "sa": sa,
            "priority": pr,
            "controller_sa": controller_sa,
            "panels": panels,
            "key": key,
            "pgn": selected_pgn or 0x001FEDB,
            "payload_hex": recorded_payload if (use_recorded_payload and recorded_payload) else None,
            "payload_sequence": payload_sequence if use_recorded_payload and payload_sequence else None,
            "payload_sequence_name": payload_sequence_name,
            "override_instance": None,  # Not used for commands
            "selected_info": selected_info,
            "selected_cat": selected_cat  # Pass category info for later use
        }

    # ---------- Send Command (from rvc_map_v2.json) ----------
    def action_send_command(self):
        params = self._collect_command_params()
        if not params:
            return

        inst = params["inst"]
        action = params["action"]
        style = params["style"]
        level = params["level"]
        sa = params["sa"]
        pr = params["priority"]
        name = params["name"]
        payload_hex = params.get("payload_hex")
        payload_sequence = params.get("payload_sequence") or []
        pgn = params.get("pgn") or 0x001FEDB

        frames_prepared = []
        single_msg = None
        used_payload = None
        try:
            if payload_sequence:
                for entry in payload_sequence:
                    # Handle different sequence formats
                    entry_pgn = entry.get("pgn", pgn)
                    if isinstance(entry_pgn, str):
                        entry_pgn = int(entry_pgn, 0)
                    # Commands use "payload", lights use "data" or "last_payload"
                    data_hex = entry.get("payload") or entry.get("data") or entry.get("last_payload")
                    if not data_hex:
                        raise ValueError("Sequence entry missing data/payload field")
                    data_bytes = bytearray.fromhex(data_hex)
                    if len(data_bytes) < 8:
                        data_bytes.extend(b'\xFF' * (8 - len(data_bytes)))
                    else:
                        data_bytes = data_bytes[:8]
                    frames_prepared.append((entry_pgn, bytes(data_bytes)))
            elif payload_hex:
                data_bytes = bytearray.fromhex(payload_hex)
                if len(data_bytes) < 8:
                    data_bytes.extend(b'\xFF' * (8 - len(data_bytes)))
                elif len(data_bytes) > 8:
                    data_bytes = data_bytes[:8]
                if inst is not None and data_bytes[0] != (inst & 0xFF):
                    print(f"  ! Warning: recorded payload instance 0x{data_bytes[0]:02X} differs from selected 0x{inst:02X}; sending recorded byte.")
                single_msg = build_pgn_frame(pgn, bytes(data_bytes), sa=sa, priority=pr)
                used_payload = bytes(data_bytes)
            else:
                # For commands or when inst is None, we should have payload_hex or payload_sequence
                # If we get here, it means we need to build a dimmer command but inst might be None
                if inst is None:
                    print("  ! Cannot build command: instance ID required but not available.")
                    return
                single_msg = build_dimmer_command_frame(inst, action, style=style or "set_level",
                                                        level=level, sa=sa, priority=pr, pgn=pgn)
                used_payload = bytes(single_msg.data)
        except Exception as e:
            print(f"  ! Cannot build command: {e}")
            return

        bus = self._open_can_bus()
        if bus is None:
            return

        try:
            sequence_name = params.get("payload_sequence_name")
            if frames_prepared:
                messages = []
                for entry_pgn, data_bytes in frames_prepared:
                    msg = build_pgn_frame(entry_pgn, data_bytes, sa=sa, priority=pr)
                    messages.append((entry_pgn, data_bytes, msg))
                label = sequence_name or action
                print(f"  > Sending sequence ({len(messages)} frames) for name={name} action={label}")
                for idx, (entry_pgn, data_bytes, msg) in enumerate(messages, start=1):
                    bus.send(msg)
                    print(f"    Frame {idx}/{len(messages)} {phex(entry_pgn)} data=[{bytes_hex(data_bytes)}]")
                last_frame_inst = messages[-1][1][0] if messages else (inst & 0xFF)
            else:
                bus.send(single_msg)
                inst_str = f"0x{inst:02X}" if inst is not None else "??"
                print(f"  > Sent {phex(pgn)} to inst={inst_str} name={name} "
                      f"(action={action}{' style='+str(style) if style else ''}{' level='+str(level) if level is not None else ''})")
                print(f"    Data: [{bytes_hex(used_payload)}]")
                last_frame_inst = (inst & 0xFF) if inst is not None else used_payload[0] if used_payload else 0
                if style and style.lower() == "set_level" and inst is not None:
                    follow_payloads = [
                        bytes([inst & 0xFF, 0xFF, 0x00, 0x15, 0x00, 0x00, 0xFF, 0xFF]),
                        bytes([inst & 0xFF, 0xFF, 0x00, 0x04, 0x00, 0x00, 0xFF, 0xFF])
                    ]
                    for idx, data_bytes in enumerate(follow_payloads, start=1):
                        msg_follow = build_pgn_frame(pgn, data_bytes, sa=sa, priority=pr)
                        bus.send(msg_follow)
                        print(f"    Follow-up {idx}/2 {phex(pgn)} data=[{bytes_hex(data_bytes)}]")
                    last_frame_inst = inst & 0xFF
            # Optionally listen briefly for controller echo
            listen = self.prompt("Listen 1.5s for echo? (y/N)", default="N").strip().lower() == "y"
            if listen:
                reasm = TPReassembler()
                t_end = time.time() + 1.5
                while time.time() < t_end:
                    rx = bus.recv(timeout=0.25)
                    if not (rx and rx.is_extended_id): continue
                    f = parse_can_id(rx.arbitration_id); data = bytes(rx.data)
                    out = reasm.feed(f, data)
                    if out is not None:
                        tgt, assembled = out
                        f = dict(f); f["pgn"] = tgt; data = assembled
                    elif f["pgn"] in (PGN_TP_CM, PGN_TP_DT):
                        continue
                    if f["pgn"] != 0x001FEDA:  # expect status echo
                        continue
                    if extract_instance_for_1FEDx(f["pgn"], data) != last_frame_inst:
                        continue
                    print(f"    Echo {phex(f['pgn'])} SA {phex(f['sa'],2)}{self._role_tag(f['sa'])} data=[{bytes_hex(data)}]")
        except Exception as e:
            print(f"  ! Send failed: {e}")

    # ---------- View Command Payload ----------
    def action_view_payload(self):
        params = self._collect_command_params()
        if not params:
            return

        inst = params["inst"]
        action = params["action"]
        style = params["style"]
        level = params["level"]
        sa = params["sa"]
        pr = params["priority"]
        name = params["name"]
        payload_hex = params.get("payload_hex")
        pgn = params.get("pgn") or 0x001FEDB

        try:
            if payload_hex:
                data_bytes = bytearray.fromhex(payload_hex)
                if len(data_bytes) < 8:
                    data_bytes.extend(b'\xFF' * (8 - len(data_bytes)))
                elif len(data_bytes) > 8:
                    data_bytes = data_bytes[:8]
                if data_bytes[0] != (inst & 0xFF):
                    print(f"  ! Warning: recorded payload instance 0x{data_bytes[0]:02X} differs from selected 0x{inst:02X}; using recorded byte.")
                msg = build_pgn_frame(pgn, bytes(data_bytes), sa=sa, priority=pr)
                data_bytes = bytes(data_bytes)
            else:
                msg = build_dimmer_command_frame(inst, action, style=style or "set_level",
                                                 level=level, sa=sa, priority=pr, pgn=pgn)
                data_bytes = bytes(msg.data)
        except Exception as e:
            print(f"  ! Cannot build command: {e}")
            return

        fields = parse_can_id(msg.arbitration_id)

        print("\n--- Command Payload ---")
        print(f"Instance: 0x{inst:02X} ({name})")
        print(f"Action: {action}{'  Style: '+str(style) if style else ''}{'  Level: '+str(level) if level is not None else ''}")
        print(f"Source SA: {phex(sa,2)}  Priority: {pr}")
        print(f"Arbitration ID: 0x{msg.arbitration_id:08X} (PGN {phex(fields['pgn'])} -> DA {phex(fields['da'],2)})")
        print(f"Data bytes: [{bytes_hex(data_bytes)}]")
        print(f"Data hex: {data_bytes.hex().upper()}")

    # ---------- Autolearn (canonical Instance + Action) ----------
    def action_autolearn(self):
        legacy = AutoLearnStore("rvc_map.json")  # optional legacy store
        print("\n[i] AUTOLEARN (canonical)")
        print("    Learns from PANEL commands, confirms via CONTROLLER status,")
        print("    then stores one entry per (Instance, Action) in rvc_map_v2.json.")
        print("    Quick ignore: i (signature), ip (PGN), is (SA), id (DA), ips (PGN+SA)")
        print("    Press Enter to skip; Ctrl+C to stop.\n")

        # Load PGNs from rvc-spec.yaml and allow user to filter/select
        selected_pgns = None
        if self.decoder.map or self.decoder.compiled_decoders:
            print("--- Select PGNs to Learn From ---")
            print("Available options:")
            print("  [1] All PGNs")
            print("  [2] Filter by name pattern")
            print("  [3] Select specific PGNs")
            choice = input("Select option [1]: ").strip() or "1"
            
            # Build list of all PGNs with names
            # First, get from compiled_decoders (exact PGN matches)
            pgn_list = []
            pgn_set = set()
            for pgn, decoder in self.decoder.compiled_decoders.items():
                if isinstance(pgn, int):
                    name = decoder.get("name", "UNKNOWN")
                    pgn_list.append((pgn, name))
                    pgn_set.add(pgn)
            
            # Also check map for any string keys that can be converted to int
            for key, entry in self.decoder.map.items():
                if isinstance(key, int) and key not in pgn_set:
                    name = entry.get("name", "UNKNOWN")
                    pgn_list.append((key, name))
                    pgn_set.add(key)
                elif isinstance(key, str):
                    # Skip wildcards for selection
                    if "#" in key or "?" in key:
                        continue
                    try:
                        if key.upper().startswith("0X"):
                            pgn = int(key, 16)
                        else:
                            # Try hex first, then decimal
                            try:
                                pgn = int(key, 16)
                            except ValueError:
                                pgn = int(key, 10)
                        if pgn not in pgn_set:
                            name = entry.get("name", "UNKNOWN")
                            pgn_list.append((pgn, name))
                            pgn_set.add(pgn)
                    except ValueError:
                        continue
            
            # Sort alphabetically by name
            pgn_list.sort(key=lambda x: x[1].upper())
            
            if choice == "2":
                # Filter by name pattern
                pattern = input("Enter name pattern (case-insensitive, e.g., 'DIMMER', 'LOCK'): ").strip()
                if pattern:
                    pattern_upper = pattern.upper()
                    filtered = [(pgn, name) for pgn, name in pgn_list if pattern_upper in name.upper()]
                    if filtered:
                        print(f"\nFound {len(filtered)} matching PGNs:")
                        for i, (pgn, name) in enumerate(filtered, start=1):
                            print(f"  [{i}] {phex(pgn)} - {name}")
                        selected_pgns = {pgn for pgn, name in filtered}
                    else:
                        print(f"  ! No PGNs found matching '{pattern}'")
                        return
                else:
                    selected_pgns = None  # All PGNs
            elif choice == "3":
                # Select specific PGNs
                print(f"\nAvailable PGNs ({len(pgn_list)} total):")
                # Show in pages if too many
                page_size = 20
                selected_pgns = set()
                
                for page_start in range(0, len(pgn_list), page_size):
                    page_end = min(page_start + page_size, len(pgn_list))
                    page = pgn_list[page_start:page_end]
                    
                    print(f"\n--- PGNs {page_start+1}-{page_end} of {len(pgn_list)} ---")
                    for i, (pgn, name) in enumerate(page, start=page_start+1):
                        print(f"  [{i}] {phex(pgn)} - {name}")
                    
                    if page_end < len(pgn_list):
                        more = input(f"\nSelect PGNs (comma-separated indices, 'n' for next page, 'a' for all remaining, Enter to finish): ").strip()
                    else:
                        more = input(f"\nSelect PGNs (comma-separated indices, Enter to finish): ").strip()
                    
                    if more.lower() == 'n':
                        continue
                    elif more.lower() == 'a':
                        # Add all remaining
                        for pgn, name in pgn_list[page_end:]:
                            selected_pgns.add(pgn)
                        break
                    elif more:
                        try:
                            indices = [int(x.strip()) - 1 for x in more.split(",")]
                            for idx in indices:
                                if 0 <= idx < len(pgn_list):
                                    selected_pgns.add(pgn_list[idx][0])
                        except ValueError:
                            print("  ! Invalid selection, continuing...")
                    
                    if page_end >= len(pgn_list):
                        break
                
                if not selected_pgns:
                    print("  ! No PGNs selected, exiting")
                    return
                
                print(f"\n  ✓ Selected {len(selected_pgns)} PGN(s) for learning")
            else:
                # All PGNs
                selected_pgns = None
        else:
            print("  ! No YAML decoder loaded. Learning from all PGNs.")
            selected_pgns = None

        bus = self._open_can_bus()
        if bus is None:
            print("  ! Autolearn requires a CAN bus interface to receive messages.")
            print("  ! Please connect a CAN interface and try again.")
            return

        reasm = TPReassembler()
        delta = DeltaTracker()
        last_controller_for_inst = {}  # instance -> last controller SA seen (from 1FEDA)

        try:
            while True:
                self.ignore.maybe_reload(); legacy.maybe_reload(); self.cmap.maybe_reload()
                rx = bus.recv(timeout=1.0)
                if not (rx and rx.is_extended_id): continue
                f = parse_can_id(rx.arbitration_id)
                data = bytes(rx.data)

                # learn roles
                self.roles.learn_from_frame(f["pgn"], f["sa"])

                # TP reassembly
                out = reasm.feed(f, data)
                if out is not None:
                    tgt, assembled = out
                    f = dict(f); f["pgn"] = tgt; data = assembled
                elif f["pgn"] in (PGN_TP_CM, PGN_TP_DT):
                    continue

                if self.ignore.matches(f, data): continue

                # Controller echo updates cache; we don't learn duplicates from these
                if f["pgn"] == 0x001FEDA:
                    inst = extract_instance_for_1FEDx(f["pgn"], data)
                    if inst is not None:
                        last_controller_for_inst[inst] = f["sa"]
                    continue

                # Filter by selected PGNs if specified
                if selected_pgns is not None and f["pgn"] not in selected_pgns:
                    continue

                # Handle any PGN for learning (not just DIMMER_COMMAND_PGNS)
                # Try to extract instance - for 1FEDx PGNs use specialized function, otherwise try byte 0
                inst = None
                if f["pgn"] in DIMMER_COMMAND_PGNS:
                    inst = extract_instance_for_1FEDx(f["pgn"], data)
                elif len(data) >= 1:
                    # For other PGNs, try byte 0 as instance (common pattern)
                    inst = data[0] if data[0] != 0xFF else None
                
                # For 1FEDB/1FEDF, try to classify command
                style = None
                action = None
                level = None
                if f["pgn"] in DIMMER_COMMAND_PGNS:
                    style, action, level = classify_command_1FEDB(data)
                
                # If we couldn't extract instance or action, prompt user
                if inst is None:
                    sig = sig_exact(f, data)
                    pgn_name = PGN_NAMES.get(f["pgn"]) or self.decoder.name_for(f["pgn"]) or f"PGN {phex(f['pgn'])}"
                    print(f"\n--- Unrecognized {pgn_name} command ---")
                    print(f"PGN {phex(f['pgn'])} SA {phex(f['sa'],2)}  data=[{bytes_hex(data)}]")
                    inst_input = input("Enter instance ID (hex, e.g., 0x1C) or Enter to skip: ").strip()
                    if not inst_input:
                        ans = input("i/ip/is/id/ips to ignore, Enter to skip: ").strip()
                        if ans in ("i","ip","is","id","ips"):
                            if ans=="i":   self.ignore.add_rule({"type":"signature","signature":sig})
                            elif ans=="ip": self.ignore.add_rule({"type":"pgn","pgn":f["pgn"]})
                            elif ans=="is": self.ignore.add_rule({"type":"sa","sa":f["sa"]})
                            elif ans=="id": self.ignore.add_rule({"type":"da","da":f["da"]})
                            elif ans=="ips": self.ignore.add_rule({"type":"pgn_sa","pgn":f["pgn"],"sa":f["sa"]})
                            print("  ✓ Ignore rule added.")
                        continue
                    try:
                        inst = int(inst_input, 0)
                    except ValueError:
                        print("  ! Invalid instance ID, skipping")
                        continue
                
                # If action not determined (non-1FEDB PGNs), prompt user
                if action is None:
                    pgn_name = PGN_NAMES.get(f["pgn"]) or self.decoder.name_for(f["pgn"]) or f"PGN {phex(f['pgn'])}"
                    print(f"\n--- {pgn_name} command detected ---")
                    print(f"Instance: 0x{inst:02X}  PGN: {phex(f['pgn'])}  SA: {phex(f['sa'],2)}  data=[{bytes_hex(data)}]")
                    action = input("Enter action name (e.g., ON, OFF, UP, DOWN, LOCK, UNLOCK) or Enter to skip: ").strip().upper()
                    if not action:
                        continue

                ctl_sa = last_controller_for_inst.get(inst)  # may be None if echo not yet seen

                key = f"inst_{inst:02X}"
                have_name = self.cmap.doc.get("lights", {}).get(key, {}).get("name")
                fname = None
                category = None
                compatibility = None
                
                # Check if this instance already exists in rvc_map.json
                doc_v1 = load_rvc_map_json()
                existing_entry = None
                if doc_v1:
                    lights_list = doc_v1.get("lights", [])
                    for light in lights_list:
                        if light.get("instance") == key:
                            existing_entry = light
                            break
                
                if not have_name:
                    pgn_name = PGN_NAMES.get(f["pgn"]) or self.decoder.name_for(f["pgn"]) or f"PGN {phex(f['pgn'])}"
                    print(f"\nDiscovered instance {key} via {action} from panel {phex(f['sa'],2)}; controller={phex(ctl_sa,2) if ctl_sa is not None else '--'}")
                    print(f"PGN: {pgn_name} ({phex(f['pgn'])})")
                    fname = input("Enter friendly name for this instance (e.g., kitchen_overhead), or Enter to skip: ").strip() or None
                    
                    # Prompt for category if this is a new entry or category not set
                    if not existing_entry or not existing_entry.get("category"):
                        # Get all available categories
                        all_categories = get_all_categories_list()
                        print("\nCategory options:")
                        for i, cat in enumerate(all_categories, start=1):
                            default_marker = " (default)" if i == 1 else ""
                            print(f"  [{i}] {cat}{default_marker}")
                        cat_choice = input(f"Select category [1]: ").strip() or "1"
                        try:
                            cat_idx = int(cat_choice) - 1
                            if 0 <= cat_idx < len(all_categories):
                                category = all_categories[cat_idx]
                            else:
                                category = all_categories[0] if all_categories else "light"
                        except ValueError:
                            category = all_categories[0] if all_categories else "light"
                    
                    # Optionally prompt for compatibility info
                    add_compat = input("\nAdd compatibility info (year/model)? (y/N): ").strip().lower()
                    if add_compat == "y":
                        year_range = input("Year range (e.g., 'pre-2013', '2013-2019', '2017+'): ").strip() or None
                        model_input = input("Model names (comma-separated, e.g., 'Entegra Aspire 40SKT'): ").strip()
                        model_range = [m.strip() for m in model_input.split(",") if m.strip()] if model_input else []
                        if year_range or model_range:
                            compatibility = {}
                            if year_range:
                                compatibility["year_range"] = year_range
                            if model_range:
                                compatibility["model_range"] = model_range
                elif existing_entry:
                    # Use existing category and compatibility if entry already exists
                    category = existing_entry.get("category")
                    compatibility = existing_entry.get("compatibility")

                # Canonical upsert to rvc_map_v2.json
                self.cmap.upsert(
                    instance=inst, action=action,
                    panel_sa=f["sa"], controller_sa=ctl_sa,
                    style=style, level=level, friendly_name=fname, payload=data,
                    pgn=f["pgn"]
                )

                # Also save to rvc_map.json in matching structure/format (load on demand)
                try:
                    upsert_rvc_map_light(
                        instance=inst, action=action,
                        panel_sa=f["sa"], controller_sa=ctl_sa,
                        style=style, level=level, friendly_name=fname, payload=data,
                        pgn=f["pgn"], category=category, compatibility=compatibility
                    )
                except Exception:
                    # rvc_map.json not available or error - continue without it
                    pass

                # Optionally store a masked legacy signature only when a new name is provided
                changed_idx = DeltaTracker().delta(f["pgn"], f["sa"], data)  # fresh tracker for masked indices here
                signature = sig_masked(f, data, changed_idx)
                if fname and not legacy.get(signature):
                    legacy.set(signature, f"{fname}:{action}")

                style_str = f" style={style}" if style else ""
                level_str = f" level={level}" if level is not None else ""
                print(f"[LEARN] inst={key} action={action}{style_str}{level_str} panel={phex(f['sa'],2)} ctl={phex(ctl_sa,2) if ctl_sa is not None else '--'}")
                continue

        except KeyboardInterrupt:
            print("\n[i] Autolearn stopped.")

    # ---------- Ignore Manager ----------
    def action_ignore_mgr(self):
        while True:
            print("\n--- Ignore Manager ---")
            print(f"Rules file: {self.ignore.path}  |  count: {len(self.ignore.rules)}")
            print("1) List rules")
            print("2) Add rule (PGN / SA / DA / PGN+SA)")
            print("3) Add rule (Exact signature string)")
            print("4) Remove rule by index")
            print("5) Back")
            c = input("Select> ").strip()
            if c == "1":
                if not self.ignore.rules:
                    print("  (no rules)")
                else:
                    for idx, r in enumerate(self.ignore.list_rules()):
                        print(f"  [{idx}] {r}")
            elif c == "2":
                kind = input("Type (pgn/sa/da/pgn_sa): ").strip().lower()
                try:
                    if kind == "pgn":
                        val = int(input("PGN (e.g., 0x1FEDA): ").strip(), 0)
                        self.ignore.add_rule({"type": "pgn", "pgn": val})
                    elif kind == "sa":
                        val = int(input("SA (e.g., 0x8E): ").strip(), 0)
                        self.ignore.add_rule({"type": "sa", "sa": val})
                    elif kind == "da":
                        val = int(input("DA (e.g., 0xFF): ").strip(), 0)
                        self.ignore.add_rule({"type": "da", "da": val})
                    elif kind == "pgn_sa":
                        vp = int(input("PGN: ").strip(), 0); vs = int(input("SA: ").strip(), 0)
                        self.ignore.add_rule({"type": "pgn_sa", "pgn": vp, "sa": vs})
                    else:
                        print("  ! Unknown type."); continue
                    print("  ✓ Added.")
                except Exception as e:
                    print(f"  ! Failed: {e}")
            elif c == "3":
                sig = input("Paste exact signature (PGN=...|SA=...|DA=...|LEN=...|DATA=...): ").strip()
                if sig:
                    self.ignore.add_rule({"type": "signature", "signature": sig})
                    print("  ✓ Added.")
            elif c == "4":
                try:
                    idx = int(input("Index to remove: ").strip())
                    self.ignore.remove_rule(idx); print("  ✓ Removed.")
                except Exception as e:
                    print(f"  ! Failed: {e}")
            elif c == "5":
                return
            else:
                print("  ! Invalid selection.")

# -------------------- Main --------------------

def main():
    ap = argparse.ArgumentParser(description="RV-C / J1939 Mapper (TP reassembly + Burst + Roles + Discovery + Send Command + Canonical Autolearn + MQTT)")
    ap.add_argument("--channel", default="can0", help="SocketCAN channel (default: can0)")
    ap.add_argument("--mqtt-host", default="localhost", help="MQTT broker host (default: localhost)")
    ap.add_argument("--mqtt-port", type=int, default=1883, help="MQTT broker port (default: 1883)")
    ap.add_argument("--mqtt-enable", action="store_true", help="Enable MQTT publishing on startup")
    args = ap.parse_args()

    app = RvcMapperApp(channel=args.channel, mqtt_host=args.mqtt_host, mqtt_port=args.mqtt_port)
    
    # Enable MQTT if requested
    if args.mqtt_enable:
        if app.mqtt.connect():
            app.mqtt_enabled = True
            print(f"[i] MQTT enabled and connected to {args.mqtt_host}:{args.mqtt_port}")
        else:
            print(f"[!] Failed to connect to MQTT broker {args.mqtt_host}:{args.mqtt_port}")

    # Try to load rvc-spec.yml first, then fall back to rvc_map.yaml
    spec_dir = os.path.dirname(os.path.abspath(__file__))
    yaml_candidates = [
        os.path.join(spec_dir, "rvc-spec.yaml"),
        os.path.join(spec_dir, "rvc-spec.yml"),
        os.path.join(spec_dir, "rvc_map.yaml"),
    ]

    for yaml_path in yaml_candidates:
        if not os.path.exists(yaml_path):
            continue
        try:
            app.decoder.load(yaml_path)
            print(f"[i] Auto-loaded YAML {yaml_path} (PGNs: {len(app.decoder.compiled_decoders)})")
            break
        except Exception as e:
            print(f"[!] Failed to auto-load {yaml_path}: {e}")

    app.menu()

if __name__ == "__main__":
    main()
