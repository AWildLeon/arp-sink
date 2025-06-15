#!/usr/bin/env python3
"""
ARP Daemon - Intercepts ARP requests and responds when no other device replies

This daemon listens for ARP "who-has" requests on a specified network interface
and responds with its own MAC address if no other device responds within a timeout.

Includes HTTP API for monitoring and management.
"""

import argparse
import asyncio
import ipaddress
import json
import logging
import signal
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, Optional, Set, List

from scapy.all import (
    ARP, Ether, get_if_hwaddr, get_if_list, sendp, sniff, srp1
)

# Optional HTTP API dependencies
try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import JSONResponse
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False


@dataclass
class ARPRequest:
    """Represents an ARP request with metadata"""
    target_ip: str
    sender_ip: str
    sender_mac: str
    timestamp: float
    interface: str


@dataclass
class IPStatus:
    """Represents the status of an IP address"""
    ip: str
    status: str  # "claimed", "detected", "unknown"
    mac_address: Optional[str]
    first_seen: float
    last_seen: float
    request_count: int


class ARPDaemon:
    """Main ARP daemon class"""
    
    def __init__(self, interface: str, timeout: float = 0.15, 
                 subnet_filter: Optional[str] = None, log_level: str = "INFO",
                 conflict_check_interval: float = 30.0, api_port: Optional[int] = None):
        self.interface = interface
        self.timeout = timeout
        self.conflict_check_interval = conflict_check_interval
        self.api_port = api_port
        self.subnet_filter = ipaddress.IPv4Network(subnet_filter) if subnet_filter else None
        self.claimed_ips: Set[str] = set()
        self.pending_requests: Dict[str, float] = {}
        self.ip_status: Dict[str, IPStatus] = {}
        self.request_history: List[ARPRequest] = []
        self.max_history = 1000  # Keep last 1000 requests
        self.executor = ThreadPoolExecutor(max_workers=10)
        self.running = False
        self.start_time = time.time()
        
        # Get interface MAC address
        try:
            self.interface_mac = get_if_hwaddr(interface)
        except Exception as e:
            raise ValueError(f"Cannot get MAC address for interface {interface}: {e}")
        
        # Setup logging
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.logger = logging.getLogger(__name__)
        
        # Validate interface
        if interface not in get_if_list():
            raise ValueError(f"Interface {interface} not found. Available: {get_if_list()}")
        
        self.logger.info(f"ARP Daemon initialized on {interface} ({self.interface_mac})")
        if self.subnet_filter:
            self.logger.info(f"Filtering subnet: {self.subnet_filter}")
        self.logger.info(f"Response timeout: {timeout}s")

    def should_handle_ip(self, ip: str) -> bool:
        """Check if we should handle requests for this IP"""
        if self.subnet_filter:
            try:
                return ipaddress.IPv4Address(ip) in self.subnet_filter
            except ipaddress.AddressValueError:
                return False
        return True

    def packet_handler(self, packet):
        """Handle incoming packets (runs in sniff thread)"""
        if not self.running:
            return
            
        # Check if it's an ARP request
        if not (packet.haslayer(ARP) and packet[ARP].op == 1):  # op=1 is "who-has"
            return
        
        arp_layer = packet[ARP]
        target_ip = arp_layer.pdst
        sender_ip = arp_layer.psrc
        sender_mac = arp_layer.hwsrc
        
        # Skip if we shouldn't handle this IP
        if not self.should_handle_ip(target_ip):
            return
        
        # Skip our own requests
        if sender_mac == self.interface_mac:
            return
        
        # Create request object
        request = ARPRequest(
            target_ip=target_ip,
            sender_ip=sender_ip,
            sender_mac=sender_mac,
            timestamp=time.time(),
            interface=self.interface
        )
        
        self.logger.debug(f"[ARP] Request for {target_ip} from {sender_ip} ({sender_mac})")
        
        # Update IP status tracking
        self.update_ip_status(target_ip, sender_ip, sender_mac)
        
        # Add to request history
        self.request_history.append(request)
        if len(self.request_history) > self.max_history:
            self.request_history.pop(0)
        
        # Schedule async handling - improved method
        try:
            # Try to schedule directly if in async context
            if hasattr(self, 'loop') and self.loop and not self.loop.is_closed():
                future = asyncio.run_coroutine_threadsafe(
                    self.handle_arp_request(request),
                    self.loop
                )
                # Don't wait for result to avoid blocking sniff thread
        except Exception as e:
            self.logger.debug(f"[SCHEDULE] Error scheduling handler: {e}")

    async def handle_arp_request(self, request: ARPRequest):
        """Handle ARP request asynchronously"""
        target_ip = request.target_ip
        
        # Check if we're already processing this IP
        if target_ip in self.pending_requests:
            time_diff = time.time() - self.pending_requests[target_ip]
            if time_diff < self.timeout * 2:  # Still in processing window
                self.logger.debug(f"[SKIP] Already processing {target_ip}")
                return
        
        self.pending_requests[target_ip] = time.time()
        
        try:
            # If we already claimed this IP, check if it's still ours
            if target_ip in self.claimed_ips:
                if await self.check_for_existing_response(target_ip):
                    self.logger.warning(f"[CONFLICT] IP {target_ip} now has legitimate owner, releasing claim")
                    self.claimed_ips.discard(target_ip)
                    return
                else:
                    # Still ours, respond immediately
                    await self.send_arp_reply(request)
                    self.logger.debug(f"[MAINTAIN] Maintaining claim on {target_ip}")
                    return
            
            # Wait for potential legitimate response
            self.logger.debug(f"[WAIT] Waiting {self.timeout}s for response to {target_ip}")
            await asyncio.sleep(self.timeout)
            
            # Check if someone else responded during our wait
            if await self.check_for_existing_response(target_ip):
                self.logger.info(f"[DETECTED] Legitimate response for {target_ip}, not claiming")
                return
            
            # No response detected, send our own
            await self.send_arp_reply(request)
            self.claimed_ips.add(target_ip)
            self.logger.info(f"[CLAIM] Claimed {target_ip} (total claimed: {len(self.claimed_ips)})")
            
        except Exception as e:
            self.logger.error(f"[ERROR] Handling request for {target_ip}: {e}")
        finally:
            # Clean up pending request
            self.pending_requests.pop(target_ip, None)

    async def check_for_existing_response(self, target_ip: str) -> bool:
        """Check if there's already a legitimate response for the IP"""
        try:
            # Run ARP probe in thread pool to avoid blocking
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = asyncio.get_event_loop()
                
            result = await loop.run_in_executor(
                self.executor,
                self._arp_probe,
                target_ip
            )
            return result is not None
        except Exception as e:
            self.logger.debug(f"[PROBE] Error probing {target_ip}: {e}")
            return False

    def _arp_probe(self, target_ip: str) -> Optional[str]:
        """Perform ARP probe to check if IP is responding"""
        try:
            # Create ARP request
            arp_request = ARP(pdst=target_ip)
            ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ethernet_frame / arp_request
            
            # Send and wait for response (short timeout)
            response = srp1(packet, iface=self.interface, timeout=0.05, verbose=False)
            
            if response and response.haslayer(ARP) and response[ARP].op == 2:
                response_mac = response[ARP].hwsrc
                self.logger.debug(f"[PROBE] {target_ip} responded with MAC {response_mac}")
                return response_mac
            
            return None
        except Exception as e:
            self.logger.debug(f"[PROBE] Exception probing {target_ip}: {e}")
            return None

    async def send_arp_reply(self, request: ARPRequest):
        """Send ARP reply claiming the IP"""
        try:
            # Create ARP reply
            arp_reply = ARP(
                op=2,  # ARP reply
                hwsrc=self.interface_mac,  # Our MAC
                psrc=request.target_ip,    # IP we're claiming
                hwdst=request.sender_mac,  # Original sender's MAC
                pdst=request.sender_ip     # Original sender's IP
            )
            
            # Create Ethernet frame
            eth_frame = Ether(
                src=self.interface_mac,
                dst=request.sender_mac
            )
            
            packet = eth_frame / arp_reply
            
            # Send packet in thread pool
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = asyncio.get_event_loop()
                
            await loop.run_in_executor(
                self.executor,
                lambda: sendp(packet, iface=self.interface, verbose=False)
            )
            
            self.logger.info(
                f"[REPLY] Sent ARP reply: {request.target_ip} is at {self.interface_mac} "
                f"(to {request.sender_ip})"
            )
            
        except Exception as e:
            self.logger.error(f"[ERROR] Sending ARP reply for {request.target_ip}: {e}")

    async def start(self):
        """Start the daemon"""
        self.running = True
        try:
            # Python 3.7+
            self.loop = asyncio.get_running_loop()
        except AttributeError:
            # Fallback for older Python versions
            self.loop = asyncio.get_event_loop()
        
        # Setup signal handlers
        for sig in [signal.SIGTERM, signal.SIGINT]:
            signal.signal(sig, self._signal_handler)
        
        self.logger.info(f"[START] ARP Daemon starting on {self.interface}")
        
        # Setup and start HTTP API if enabled
        if self.api_port and HAS_FASTAPI:
            self.app = self.setup_api()
            self.logger.info(f"[API] Starting HTTP API on port {self.api_port}")
            
            # Start API server in background task
            api_task = asyncio.create_task(
                self._run_api_server()
            )
        else:
            api_task = None
            if self.api_port and not HAS_FASTAPI:
                self.logger.warning("[API] FastAPI not available, install with: pip install fastapi uvicorn")

        try:
            # Start background tasks - create explicit tasks
            # Use to_thread if available (Python 3.9+), otherwise use executor
            try:
                sniff_task = asyncio.create_task(
                    asyncio.to_thread(self._start_sniffing)
                )
            except AttributeError:
                # Fallback for Python < 3.9
                sniff_task = asyncio.create_task(
                    self.loop.run_in_executor(self.executor, self._start_sniffing)
                )
            
            conflict_check_task = asyncio.create_task(
                self._periodic_conflict_check()
            )
            
            # Collect all tasks
            tasks = [sniff_task, conflict_check_task]
            if api_task:
                tasks.append(api_task)
            
            # Wait for any task to complete
            done, pending = await asyncio.wait(
                tasks, 
                return_when=asyncio.FIRST_COMPLETED
            )
            
            # Cancel remaining tasks
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            
        except KeyboardInterrupt:
            self.logger.info("[STOP] Received keyboard interrupt")
        except Exception as e:
            self.logger.error(f"[ERROR] Daemon error: {e}")
        finally:
            await self.stop()

    async def _run_api_server(self):
        """Run the API server"""
        if not self.app:
            return
            
        config = uvicorn.Config(
            self.app,
            host="0.0.0.0",
            port=self.api_port,
            log_level="warning",  # Reduce uvicorn logging
            access_log=False
        )
        server = uvicorn.Server(config)
        
        try:
            await server.serve()
        except asyncio.CancelledError:
            self.logger.info("[API] API server stopped")
        except Exception as e:
            self.logger.error(f"[API] API server error: {e}")

    def _start_sniffing(self):
        """Start packet sniffing (runs in thread)"""
        try:
            self.logger.info(f"[SNIFF] Started packet capture on {self.interface}")
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                filter="arp",
                store=0,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            self.logger.error(f"[SNIFF] Sniffing error: {e}")

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"[SIGNAL] Received signal {signum}")
        self.running = False

    async def stop(self):
        """Stop the daemon"""
        self.logger.info("[STOP] Stopping ARP Daemon")
        self.running = False
        
        # Wait for pending operations
        if self.pending_requests:
            self.logger.info(f"[STOP] Waiting for {len(self.pending_requests)} pending requests")
            await asyncio.sleep(0.5)
        
        # Shutdown executor
        self.executor.shutdown(wait=True)
        
        # Log statistics
        self.logger.info(f"[STATS] Total IPs claimed: {len(self.claimed_ips)}")
        if self.claimed_ips:
            self.logger.info(f"[STATS] Claimed IPs: {sorted(self.claimed_ips)}")

    async def _periodic_conflict_check(self):
        """Periodically check for conflicts on claimed IPs"""
        while self.running:
            try:
                await asyncio.sleep(self.conflict_check_interval)
                
                if not self.claimed_ips:
                    continue
                
                self.logger.debug(f"[CONFLICT_CHECK] Checking {len(self.claimed_ips)} claimed IPs")
                
                # Check each claimed IP
                conflicts_found = set()
                for ip in list(self.claimed_ips):  # Copy to avoid modification during iteration
                    if await self.check_for_existing_response(ip):
                        self.logger.warning(f"[CONFLICT] IP {ip} now has legitimate owner, releasing")
                        conflicts_found.add(ip)
                
                # Remove conflicted IPs
                self.claimed_ips -= conflicts_found
                
                if conflicts_found:
                    self.logger.info(f"[CONFLICT] Released {len(conflicts_found)} IPs due to conflicts")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"[PERIODIC_CHECK] Error: {e}")

    def send_gratuitous_arp(self, ip: str):
        """Send gratuitous ARP to announce ownership"""
        try:
            # Gratuitous ARP: sender and target are the same
            arp_announce = ARP(
                op=2,  # ARP reply
                hwsrc=self.interface_mac,
                psrc=ip,
                hwdst="ff:ff:ff:ff:ff:ff",  # Broadcast
                pdst=ip
            )
            
            eth_frame = Ether(
                src=self.interface_mac,
                dst="ff:ff:ff:ff:ff:ff"
            )
            
            packet = eth_frame / arp_announce
            sendp(packet, iface=self.interface, verbose=False)
            
            self.logger.debug(f"[GRATUITOUS] Announced ownership of {ip}")
            
        except Exception as e:
            self.logger.error(f"[GRATUITOUS] Error announcing {ip}: {e}")

    def update_ip_status(self, target_ip: str, sender_ip: str, sender_mac: str):
        """Update IP status tracking"""
        current_time = time.time()
        
        # Update target IP status
        if target_ip not in self.ip_status:
            self.ip_status[target_ip] = IPStatus(
                ip=target_ip,
                status="unknown",
                mac_address=None,
                first_seen=current_time,
                last_seen=current_time,
                request_count=1
            )
        else:
            self.ip_status[target_ip].last_seen = current_time
            self.ip_status[target_ip].request_count += 1
        
        # Update sender IP status (we know it exists)
        if sender_ip not in self.ip_status:
            self.ip_status[sender_ip] = IPStatus(
                ip=sender_ip,
                status="detected",
                mac_address=sender_mac,
                first_seen=current_time,
                last_seen=current_time,
                request_count=0
            )
        else:
            self.ip_status[sender_ip].last_seen = current_time
            self.ip_status[sender_ip].mac_address = sender_mac
            if self.ip_status[sender_ip].status == "unknown":
                self.ip_status[sender_ip].status = "detected"

    def get_subnet_scan_results(self) -> Dict[str, Dict]:
        """Get comprehensive subnet information"""
        if not self.subnet_filter:
            return {"error": "No subnet filter configured"}
        
        results = {
            "subnet": str(self.subnet_filter),
            "total_ips": self.subnet_filter.num_addresses - 2,  # Exclude network and broadcast
            "scanned": {},
            "claimed": list(self.claimed_ips),
            "detected": [],
            "unknown": [],
            "statistics": {
                "claimed_count": len(self.claimed_ips),
                "detected_count": 0,
                "unknown_count": 0,
                "total_requests": len(self.request_history)
            }
        }
        
        # Categorize all IPs in subnet
        for ip in self.subnet_filter.hosts():
            ip_str = str(ip)
            
            if ip_str in self.ip_status:
                status = self.ip_status[ip_str]
                results["scanned"][ip_str] = {
                    "status": status.status,
                    "mac_address": status.mac_address,
                    "first_seen": datetime.fromtimestamp(status.first_seen).isoformat(),
                    "last_seen": datetime.fromtimestamp(status.last_seen).isoformat(),
                    "request_count": status.request_count
                }
                
                if status.status == "detected":
                    results["detected"].append(ip_str)
                    results["statistics"]["detected_count"] += 1
                else:
                    results["unknown"].append(ip_str)
                    results["statistics"]["unknown_count"] += 1
            else:
                results["unknown"].append(ip_str)
                results["statistics"]["unknown_count"] += 1
        
        return results

    def setup_api(self) -> Optional[FastAPI]:
        """Setup HTTP API if FastAPI is available"""
        if not HAS_FASTAPI or not self.api_port:
            return None
        
        app = FastAPI(
            title="ARP Daemon API",
            description="Monitor and manage ARP daemon operations",
            version="1.0.0"
        )
        
        @app.get("/")
        async def root():
            return {
                "service": "ARP Daemon",
                "interface": self.interface,
                "status": "running" if self.running else "stopped",
                "uptime_seconds": time.time() - self.start_time,
                "api_endpoints": [
                    "/status", "/claimed", "/detected", "/requests", 
                    "/subnet", "/statistics", "/health"
                ]
            }
        
        @app.get("/status")
        async def get_status():
            return {
                "running": self.running,
                "interface": self.interface,
                "interface_mac": self.interface_mac,
                "subnet_filter": str(self.subnet_filter) if self.subnet_filter else None,
                "timeout": self.timeout,
                "uptime_seconds": time.time() - self.start_time,
                "claimed_ips_count": len(self.claimed_ips),
                "pending_requests": len(self.pending_requests),
                "total_requests_seen": len(self.request_history)
            }
        
        @app.get("/claimed")
        async def get_claimed_ips():
            claimed_details = {}
            for ip in self.claimed_ips:
                if ip in self.ip_status:
                    status = self.ip_status[ip]
                    claimed_details[ip] = {
                        "mac_address": self.interface_mac,
                        "first_seen": datetime.fromtimestamp(status.first_seen).isoformat(),
                        "last_seen": datetime.fromtimestamp(status.last_seen).isoformat(),
                        "request_count": status.request_count
                    }
                else:
                    claimed_details[ip] = {"mac_address": self.interface_mac}
            
            return {
                "claimed_ips": list(self.claimed_ips),
                "count": len(self.claimed_ips),
                "details": claimed_details
            }
        
        @app.get("/detected")
        async def get_detected_ips():
            detected = {
                ip: {
                    "mac_address": status.mac_address,
                    "first_seen": datetime.fromtimestamp(status.first_seen).isoformat(),
                    "last_seen": datetime.fromtimestamp(status.last_seen).isoformat(),
                    "request_count": status.request_count
                }
                for ip, status in self.ip_status.items()
                if status.status == "detected"
            }
            
            return {
                "detected_ips": detected,
                "count": len(detected)
            }
        
        @app.get("/requests")
        async def get_recent_requests(limit: int = 50):
            recent = self.request_history[-limit:] if limit else self.request_history
            return {
                "recent_requests": [
                    {
                        "target_ip": req.target_ip,
                        "sender_ip": req.sender_ip,
                        "sender_mac": req.sender_mac,
                        "timestamp": datetime.fromtimestamp(req.timestamp).isoformat(),
                        "interface": req.interface
                    }
                    for req in recent
                ],
                "count": len(recent),
                "total_seen": len(self.request_history)
            }
        
        @app.get("/subnet")
        async def get_subnet_info():
            return self.get_subnet_scan_results()
        
        @app.get("/statistics")
        async def get_statistics():
            current_time = time.time()
            
            # Calculate request rates
            recent_requests = [
                req for req in self.request_history 
                if current_time - req.timestamp < 3600  # Last hour
            ]
            
            return {
                "uptime_seconds": current_time - self.start_time,
                "total_requests": len(self.request_history),
                "requests_last_hour": len(recent_requests),
                "requests_per_minute": len(recent_requests) / 60.0,
                "claimed_ips": len(self.claimed_ips),
                "detected_ips": len([s for s in self.ip_status.values() if s.status == "detected"]),
                "unknown_ips": len([s for s in self.ip_status.values() if s.status == "unknown"]),
                "pending_requests": len(self.pending_requests),
                "interface": self.interface,
                "subnet": str(self.subnet_filter) if self.subnet_filter else None
            }
        
        @app.get("/health")
        async def health_check():
            return {
                "status": "healthy" if self.running else "stopped",
                "timestamp": datetime.now().isoformat()
            }
        
        @app.post("/release/{ip}")
        async def release_ip(ip: str):
            """Manually release a claimed IP"""
            if ip in self.claimed_ips:
                self.claimed_ips.discard(ip)
                self.logger.info(f"[API] Manually released {ip}")
                return {"message": f"Released {ip}", "success": True}
            else:
                raise HTTPException(status_code=404, detail=f"IP {ip} not claimed")
        
        return app


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="ARP Daemon - Respond to ARP requests when no other device does",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 arp_daemon.py eth0
  sudo python3 arp_daemon.py eth0 --timeout 0.2 --subnet 192.168.1.0/24
  sudo python3 arp_daemon.py wlan0 --log-level DEBUG
        """
    )
    
    parser.add_argument("interface", help="Network interface to listen on")
    parser.add_argument("--timeout", "-t", type=float, default=0.15,
                       help="Timeout in seconds to wait for responses (default: 0.15)")
    parser.add_argument("--conflict-check", "-c", type=float, default=30.0,
                       help="Interval in seconds for conflict checking (default: 30.0)")
    parser.add_argument("--api-port", "-p", type=int,
                       help="Enable HTTP API on specified port (requires: pip install fastapi uvicorn)")
    parser.add_argument("--subnet", "-s", 
                       help="Subnet filter (e.g., 192.168.1.0/24) - only handle IPs in this range")
    parser.add_argument("--log-level", "-l", default="INFO",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                       help="Logging level (default: INFO)")
    
    args = parser.parse_args()
    
    # Check if running as root
    if sys.platform.startswith('linux') and os.geteuid() != 0:
        print("Warning: This program typically requires root privileges for raw socket access.")
        print("Consider running with sudo.")
    
    try:
        # Create and start daemon
        daemon = ARPDaemon(
            interface=args.interface,
            timeout=args.timeout,
            subnet_filter=args.subnet,
            log_level=args.log_level,
            conflict_check_interval=args.conflict_check,
            api_port=args.api_port
        )
        
        # Run daemon
        asyncio.run(daemon.start())
        
    except ValueError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)
    except PermissionError as e:
        print(f"Permission error: {e}", file=sys.stderr)
        print("Try running with sudo for raw socket access.", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    import os
    main()
