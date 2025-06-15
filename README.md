# arp-sink

A small Python daemon that silently **claims unused IPs on your LAN via ARP**, allowing you to serve custom content (like a warning page) when the original host is unreachable or offline.

---

## 🧠 What It Does

* Listens for ARP `who-has` requests on a given interface
* Waits a short time (default: 150ms)
* If no legit device replies → responds with its own MAC address
* Periodically checks if the IP becomes active again
* (Optional) Exposes an HTTP API for monitoring
* You can run a local web server (e.g. `nginx`) to display a “Host Unreachable” page for claimed IPs

**Important:** arp-sink does *not* bind the claimed IPs to any interface. To serve actual content, you must use **NAT (DNAT)** to redirect traffic to a local web server.

---

## 🔧 Example Use Case

Let’s say IP `192.168.1.123` goes offline, but clients still try to reach it:

1. **arp-sink** sees the ARP request
2. No real host replies
3. It responds and claims the IP
4. Traffic destined to `192.168.1.123` hits your machine (via ARP)
5. **iptables/nftables** rule redirects the traffic to a local web service (e.g. on 127.0.0.1:8080)
6. Your server displays a fallback page:

```
📡 The requested host is offline.
You were redirected here by the network.
```

---

## ⚙️ Requirements

* Python 3.7+
* `scapy`
* `fastapi` and `uvicorn` (for the monitoring API)
* a web server (e.g. `nginx`)

```bash
pip install scapy
pip install fastapi uvicorn  # optional
```

---

## 🔥 Real-World Tips

* Use `iptables` or `nftables` to redirect traffic to your fallback service:

```nftables
#!/usr/sbin/nft -f

flush ruleset

table ip nat {
    chain prerouting {
        type nat hook prerouting priority dstnat;

        iif "eth0" tcp dport 80 dnat to 127.0.0.1

        iif "eth0" ip protocol icmp dnat to 127.0.0.1
    }
}

```

* You do *not* need to assign the IP to any interface
* Works well in flat Layer 2 networks without gateway involvement

---

## API Endpoints (if enabled)

* `/status` – Runtime status
* `/claimed` – IPs currently owned
* `/requests` – Recent ARP queries
* `/release/{ip}` – Manually give up an IP

---

## ⚠️ Legal / Ethical Warning

This tool *does hijack ARP queries* — it will trick clients into thinking you are the legitimate destination for an IP.

Use it **only** in environments where you're authorized (lab, testing, honeypots, internal error pages, etc.). **Don't use on production networks you don't own.**

---

## 📄 License

MIT License – no warranties, no guarantees.

---

## TL;DR

> `arp-sink` lets you hijack unclaimed IPs and show a “host unreachable” page.
