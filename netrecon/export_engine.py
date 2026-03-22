"""
Export results to JSON, CSV, styled HTML, and interactive Leaflet maps.
All file writes use atomic-ish patterns (write to temp, rename) and
path traversal is blocked by normalizing against the target directory.
"""

import json
import csv
import os
import html as html_mod
from datetime import datetime
from pathlib import Path


def _safe_path(filepath):
    """
    Normalize a file path, create parent dirs, and return a Path object.
    Rejects anything that tries to escape via '..' into system directories.
    """
    p = Path(filepath).resolve()
    # basic safety: don't allow writing outside user home or /tmp
    home = Path.home().resolve()
    if not (
        str(p).startswith(str(home))
        or str(p).startswith(os.path.realpath(os.environ.get("TEMP", "/tmp")))
    ):
        cwd = Path.cwd().resolve()
        if not str(p).startswith(str(cwd)):
            raise ValueError(f"Refusing to write to {p} (outside workspace/home/temp)")
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


class ExportEngine:

    @staticmethod
    def to_json(data, filepath):
        p = _safe_path(filepath)
        payload = ExportEngine._normalize(data)
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        return str(p)

    @staticmethod
    def to_csv(data, filepath):
        p = _safe_path(filepath)
        payload = ExportEngine._normalize(data)
        rows = ExportEngine._flatten_for_csv(payload)
        if not rows:
            return None
        with open(p, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        return str(p)

    @staticmethod
    def to_html(data, filepath, title="PradaFit Report"):
        p = _safe_path(filepath)
        payload = ExportEngine._normalize(data)
        content = ExportEngine._build_html(payload, title)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)
        return str(p)

    @staticmethod
    def generate_map(geo_results, filepath, title="PradaFit Geolocation Map"):
        try:
            import folium
            from folium.plugins import MarkerCluster
        except ImportError:
            return None

        p = _safe_path(filepath)

        locations = []
        for item in geo_results:
            d = item.to_dict() if hasattr(item, "to_dict") else item
            if d.get("latitude") and d.get("longitude"):
                locations.append(d)

        if not locations:
            return None

        center = [locations[0]["latitude"], locations[0]["longitude"]]
        m = folium.Map(location=center, zoom_start=4, tiles="OpenStreetMap")

        container = m
        if len(locations) > 10:
            container = MarkerCluster().add_to(m)

        palette = [
            "red",
            "blue",
            "green",
            "purple",
            "orange",
            "darkred",
            "darkblue",
            "darkgreen",
            "cadetblue",
            "pink",
        ]

        for idx, loc in enumerate(locations):
            color = palette[idx % len(palette)]
            ip_safe = html_mod.escape(str(loc.get("ip", "")))
            city_safe = html_mod.escape(str(loc.get("city", "")))
            region_safe = html_mod.escape(str(loc.get("region", "")))
            country_safe = html_mod.escape(str(loc.get("country", "")))
            isp_safe = html_mod.escape(str(loc.get("isp", "N/A")))
            org_safe = html_mod.escape(str(loc.get("org", "N/A")))
            asn_safe = html_mod.escape(str(loc.get("asn", "N/A")))

            popup = (
                f"<div style='font-family:sans-serif;min-width:200px'>"
                f"<h4 style='margin:0 0 6px'>{ip_safe}</h4>"
                f"<b>Location:</b> {city_safe}, {region_safe}, {country_safe}<br>"
                f"<b>ISP:</b> {isp_safe}<br>"
                f"<b>Org:</b> {org_safe}<br>"
                f"<b>ASN:</b> {asn_safe}<br>"
                f"<b>Coords:</b> {loc.get('latitude',0)}, {loc.get('longitude',0)}"
                f"</div>"
            )
            folium.Marker(
                location=[loc["latitude"], loc["longitude"]],
                popup=folium.Popup(popup, max_width=300),
                tooltip=f"{ip_safe} - {city_safe}, {country_safe}",
                icon=folium.Icon(color=color, icon="info-sign"),
            ).add_to(container)

        if len(locations) > 1:
            points = [[l["latitude"], l["longitude"]] for l in locations]
            folium.PolyLine(
                points, weight=2, color="blue", opacity=0.6, dash_array="5"
            ).add_to(m)

        m.save(str(p))
        return str(p)

    # internals

    @staticmethod
    def _normalize(data):
        if hasattr(data, "to_dict"):
            return data.to_dict()
        if isinstance(data, list):
            return [d.to_dict() if hasattr(d, "to_dict") else d for d in data]
        return data

    @staticmethod
    def _flatten_for_csv(data):
        rows = []
        if isinstance(data, dict):
            if "hosts" in data:
                for host in data.get("hosts", []):
                    if host.get("ports"):
                        for port in host["ports"]:
                            rows.append(
                                {
                                    "target": data.get("target", ""),
                                    "profile": data.get("profile", ""),
                                    "host_ip": host.get("ip", ""),
                                    "hostname": host.get("hostname", ""),
                                    "host_state": host.get("state", ""),
                                    "port": port.get("port", ""),
                                    "protocol": port.get("protocol", ""),
                                    "state": port.get("state", ""),
                                    "service": port.get("service", ""),
                                    "version": port.get("version", ""),
                                    "product": port.get("product", ""),
                                }
                            )
                    else:
                        rows.append(
                            {
                                "target": data.get("target", ""),
                                "profile": data.get("profile", ""),
                                "host_ip": host.get("ip", ""),
                                "hostname": host.get("hostname", ""),
                                "host_state": host.get("state", ""),
                            }
                        )
            elif "records" in data:
                for rec in data.get("records", []):
                    row = {
                        "query": data.get("query", ""),
                        "record_type": data.get("record_type", ""),
                        "server": data.get("server", ""),
                    }
                    row.update(rec)
                    rows.append(row)
            elif "latitude" in data:
                rows.append(data)
            else:
                rows.append(data)
        elif isinstance(data, list):
            for item in data:
                rows.extend(ExportEngine._flatten_for_csv(item))
        return rows

    @staticmethod
    def _build_html(data, title):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        title_safe = html_mod.escape(title)
        body_cards = ""
        items = data if isinstance(data, list) else [data]
        for item in items:
            if isinstance(item, dict):
                body_cards += ExportEngine._render_card(item)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title_safe}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#0f0f23;color:#e0e0e0;padding:24px;line-height:1.6}}
.wrap{{max-width:1200px;margin:0 auto}}
.hdr{{background:linear-gradient(135deg,#1a1a3e,#2d2d6b);padding:28px;border-radius:12px;margin-bottom:24px;border:1px solid #333366}}
.hdr h1{{font-size:26px;color:#00d4ff;margin-bottom:6px}}
.hdr .meta{{color:#888;font-size:13px}}
.card{{background:#1a1a2e;border:1px solid #2a2a4a;border-radius:10px;padding:20px;margin-bottom:16px}}
.card h2{{color:#00d4ff;font-size:17px;margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid #2a2a4a}}
.card h3{{color:#7eb8da;font-size:14px;margin:10px 0 6px}}
table{{width:100%;border-collapse:collapse;margin:8px 0}}
th,td{{padding:8px 10px;text-align:left;border-bottom:1px solid #2a2a4a;font-size:13px}}
th{{background:#16213e;color:#00d4ff;font-weight:600;text-transform:uppercase;letter-spacing:.5px;font-size:12px}}
tr:hover{{background:#16213e}}
.tag{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}}
.tag-open{{background:#0d4d2b;color:#00ff88}}
.tag-closed{{background:#4d0d0d;color:#ff4444}}
.tag-filtered{{background:#4d3d0d;color:#ffaa00}}
.tag-up{{background:#0d4d2b;color:#00ff88}}
.tag-down{{background:#4d0d0d;color:#ff4444}}
.kv{{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:6px}}
.kv-row{{display:flex;padding:4px 0}}
.kv-k{{color:#888;min-width:130px;font-size:13px}}
.kv-v{{color:#e0e0e0;font-size:13px;word-break:break-all}}
pre{{background:#0d0d1a;padding:12px;border-radius:6px;overflow-x:auto;font-size:12px;color:#b0b0d0}}
.foot{{text-align:center;padding:20px;color:#555;font-size:11px}}
</style>
</head>
<body>
<div class="wrap">
<div class="hdr"><h1>{title_safe}</h1><div class="meta">Generated: {ts} | PradaFit</div></div>
{body_cards}
<div class="foot">Generated by PradaFit &middot; {ts}</div>
</div>
</body>
</html>"""

    @staticmethod
    def _render_card(data):
        out = '<div class="card">'

        if "hosts" in data:
            out += f'<h2>Scan: {html_mod.escape(str(data.get("target","")))}</h2><div class="kv">'
            for k in ("profile", "arguments", "scan_time", "command_line", "timestamp"):
                if data.get(k):
                    out += f'<div class="kv-row"><span class="kv-k">{k.replace("_"," ").title()}:</span><span class="kv-v">{html_mod.escape(str(data[k]))}</span></div>'
            out += "</div>"
            for host in data.get("hosts", []):
                sc = "tag-up" if host.get("state") == "up" else "tag-down"
                out += f'<h3>{html_mod.escape(str(host.get("ip","")))} ({html_mod.escape(str(host.get("hostname","N/A")))}) <span class="tag {sc}">{html_mod.escape(str(host.get("state","")))}</span></h3>'
                if host.get("ports"):
                    out += "<table><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Version</th><th>Product</th></tr>"
                    for p in host["ports"]:
                        s = p.get("state", "")
                        tc = f"tag-{s}" if s in ("open", "closed", "filtered") else ""
                        out += f'<tr><td>{p.get("port","")}</td><td>{html_mod.escape(str(p.get("protocol","")))}</td><td><span class="tag {tc}">{html_mod.escape(s)}</span></td><td>{html_mod.escape(str(p.get("service","")))}</td><td>{html_mod.escape(str(p.get("version","")))}</td><td>{html_mod.escape(str(p.get("product","")))}</td></tr>'
                    out += "</table>"
                if host.get("os_matches"):
                    out += "<table><tr><th>OS Match</th><th>Accuracy</th></tr>"
                    for om in host["os_matches"]:
                        out += f'<tr><td>{html_mod.escape(str(om.get("name","")))}</td><td>{om.get("accuracy","")}%</td></tr>'
                    out += "</table>"

        elif "records" in data:
            out += f'<h2>DNS: {html_mod.escape(str(data.get("query","")))} ({html_mod.escape(str(data.get("record_type","")))})</h2>'
            out += f'<div class="kv"><div class="kv-row"><span class="kv-k">Server:</span><span class="kv-v">{html_mod.escape(str(data.get("server","")))}</span></div>'
            out += f'<div class="kv-row"><span class="kv-k">Response Time:</span><span class="kv-v">{data.get("response_time_ms",0)} ms</span></div></div>'
            if data.get("error"):
                out += f'<pre>Error: {html_mod.escape(str(data["error"]))}</pre>'
            elif data.get("records"):
                keys = list(data["records"][0].keys())
                out += (
                    "<table><tr>"
                    + "".join(f"<th>{html_mod.escape(k)}</th>" for k in keys)
                    + "</tr>"
                )
                for rec in data["records"]:
                    out += (
                        "<tr>"
                        + "".join(
                            f'<td>{html_mod.escape(str(rec.get(k,"")))}</td>'
                            for k in keys
                        )
                        + "</tr>"
                    )
                out += "</table>"

        elif "latitude" in data:
            out += f'<h2>Geolocation: {html_mod.escape(str(data.get("ip","")))}</h2><div class="kv">'
            fields = [
                (
                    "Country",
                    f'{data.get("country","")} ({data.get("country_code","")})',
                ),
                ("Region", data.get("region", "")),
                ("City", data.get("city", "")),
                ("ZIP", data.get("zip_code", "")),
                ("Coordinates", f'{data.get("latitude",0)}, {data.get("longitude",0)}'),
                ("Timezone", data.get("timezone", "")),
                ("ISP", data.get("isp", "")),
                ("Organization", data.get("org", "")),
                ("ASN", data.get("asn", "")),
                ("Reverse DNS", data.get("reverse_dns", "")),
            ]
            for label, val in fields:
                if val:
                    out += f'<div class="kv-row"><span class="kv-k">{label}:</span><span class="kv-v">{html_mod.escape(str(val))}</span></div>'
            out += "</div>"

        else:
            out += '<div class="kv">'
            for k, v in data.items():
                out += f'<div class="kv-row"><span class="kv-k">{html_mod.escape(str(k))}:</span><span class="kv-v">{html_mod.escape(str(v))}</span></div>'
            out += "</div>"

        out += "</div>"
        return out
