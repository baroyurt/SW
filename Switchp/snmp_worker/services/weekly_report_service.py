"""
Weekly report service.
Sends weekly HTML email summaries for:
  - Yavaş Portlar       (slow ports ≤ 100 Mbps that are UP)
  - Up/Down Döngüsü     (flapping ports)
  - Hata / Drop         (ports with in/out errors or discards)
  - VLAN/Alias Uyumsuzluk (VLAN vs alias type mismatch)

The report is sent once per week on the configured day at the configured hour
(default: Monday 08:00 local time).
"""

import logging
import asyncio
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from sqlalchemy import text


# VLAN ID → expected alias type  (kept in sync with PHP pages)
VLAN_TYPE_MAP: Dict[int, str] = {
    30:   'GUEST',
    40:   'VIP',
    50:   'DEVICE',
    70:   'AP',
    80:   'KAMERA',
    110:  'SES',
    120:  'OTOMASYON',
    130:  'IPTV',
    140:  'SANTRAL',
    150:  'JACKPOT',
    254:  'SERVER',
    1500: 'DRGT',
}

STYLE = """
<style>
  body { background:#0a0f1c; color:#c8d5e8; font-family:Arial,Helvetica,sans-serif; }
  h2   { color:#3b82f6; border-bottom:1px solid #1e2d4d; padding-bottom:6px; }
  h3   { color:#8899bb; margin-top:24px; }
  table { width:100%; border-collapse:collapse; margin-bottom:20px; }
  th    { background:#0f1f3a; color:#8899bb; padding:8px 12px; text-align:left; font-size:12px; text-transform:uppercase; }
  td    { padding:7px 12px; border-bottom:1px solid #1e2d4d; font-size:13px; }
  tr:hover td { background:#1a2540; }
  .badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; }
  .badge-up   { background:#064e3b; color:#34d399; }
  .badge-down { background:#450a0a; color:#f87171; }
  .cnt { font-size:24px; font-weight:700; color:#3b82f6; }
  .section { background:#111827; border:1px solid #1e2d4d; border-radius:10px; padding:18px 22px; margin-bottom:24px; }
  .none { color:#6b7280; font-style:italic; padding:12px 0; }
</style>
"""


def _detect_alias_type(alias: str, type_list: List[str]) -> Optional[str]:
    """Mirror of PHP detectAliasType() logic."""
    import re
    alias_upper = alias.strip().upper()
    alias_norm  = re.sub(r'[\s\-_]+', '', alias_upper)

    for t in type_list:
        tu    = t.upper()
        t_norm = re.sub(r'[\s\-_]+', '', tu)

        if alias_upper == tu:
            return t
        if re.match(r'^' + re.escape(tu) + r'[\s\-_:/]', alias_upper):
            return t
        if re.search(r'(?:^|[\s\-_])' + re.escape(tu) + r'(?:$|[\s\-_])', alias_upper):
            return t
        if alias_norm == t_norm:
            return t
        if t_norm and t_norm in alias_norm:
            return t
    return None


class WeeklyReportService:
    """
    Sends a weekly summary email on a configured weekday / hour.

    Args:
        db_manager:    DatabaseManager instance.
        email_service: EmailNotificationService instance (or None).
        weekday:       0=Monday … 6=Sunday  (default 0 = Monday).
        hour:          Hour of day to send report (0-23, default 8).
    """

    def __init__(self, db_manager, email_service, weekday: int = 0, hour: int = 8):
        self.db_manager    = db_manager
        self.email_service = email_service
        self.weekday       = weekday
        self.hour          = hour
        self.logger        = logging.getLogger('snmp_worker.weekly_report')
        self._last_sent: Optional[datetime] = None

    # ──────────────────────────────────────────────────────────────────────────
    # Public interface
    # ──────────────────────────────────────────────────────────────────────────

    def check_and_send(self) -> None:
        """
        Call this once per polling cycle.
        Sends the weekly report when the scheduled window arrives.
        """
        if not (self.email_service and self.email_service.enabled):
            return

        now = datetime.now()

        # Only send on the configured weekday at the configured hour
        if now.weekday() != self.weekday or now.hour != self.hour:
            return

        # Avoid double-send within the same hour window
        if self._last_sent and (now - self._last_sent) < timedelta(hours=1):
            return

        self.logger.info("Sending weekly report email…")
        try:
            self._send_report()
            self._last_sent = now
            self.logger.info("Weekly report sent successfully.")
        except Exception as e:
            self.logger.error(f"Weekly report error: {e}", exc_info=True)

    # ──────────────────────────────────────────────────────────────────────────
    # Report generation
    # ──────────────────────────────────────────────────────────────────────────

    def _send_report(self) -> None:
        with self.db_manager.session_scope() as session:
            slow_ports  = self._query_slow_ports(session)
            flapping    = self._query_flapping(session)
            errors      = self._query_errors(session)
            vlan_alias  = self._query_vlan_alias(session)

        subject  = f"CHAMADA Haftalık Rapor – {datetime.now().strftime('%d.%m.%Y')}"
        html     = self._build_html(slow_ports, flapping, errors, vlan_alias)
        plain    = self._build_plain(slow_ports, flapping, errors, vlan_alias)

        self.email_service.send_email(subject, plain, html)

    # ──────────────────────────────────────────────────────────────────────────
    # DB queries
    # ──────────────────────────────────────────────────────────────────────────

    def _query_slow_ports(self, session) -> List[Dict[str, Any]]:
        """Ports that are UP but link speed ≤ 100 Mbps (same as reports.php)."""
        try:
            result = session.execute(text("""
                SELECT
                    sd.name        AS switch_name,
                    sd.ip_address,
                    psd.port_number,
                    COALESCE(psd.port_alias,'') AS alias,
                    psd.vlan_id,
                    psd.port_speed
                FROM port_status_data psd
                JOIN snmp_devices sd ON sd.id = psd.device_id
                WHERE psd.oper_status = 'up'
                  AND psd.port_speed  IS NOT NULL
                  AND psd.port_speed  > 0
                  AND psd.port_speed  <= 100000000
                ORDER BY psd.port_speed ASC, sd.name, psd.port_number
            """))
            rows = result.fetchall()
            return [dict(r._mapping) for r in rows]
        except Exception as e:
            self.logger.error(f"Slow ports query error: {e}")
            return []

    def _query_flapping(self, session) -> List[Dict[str, Any]]:
        """Ports that flapped ≥3 times in the last 7 days."""
        try:
            result = session.execute(text("""
                SELECT
                    sd.name        AS switch_name,
                    sd.ip_address,
                    pch.port_number,
                    COALESCE(psd.port_alias,'') AS alias,
                    psd.vlan_id,
                    COUNT(*)                    AS change_count,
                    MIN(pch.change_timestamp)   AS first_change,
                    MAX(pch.change_timestamp)   AS last_change
                FROM port_change_history pch
                JOIN snmp_devices sd ON sd.id = pch.device_id
                LEFT JOIN port_status_data psd
                       ON psd.device_id = pch.device_id AND psd.port_number = pch.port_number
                WHERE pch.change_timestamp >= :since
                GROUP BY sd.name, sd.ip_address, pch.port_number, psd.port_alias, psd.vlan_id
                HAVING COUNT(*) >= 3
                ORDER BY COUNT(*) DESC, sd.name, pch.port_number
            """), {'since': datetime.now() - timedelta(days=7)})
            rows = result.fetchall()
            return [dict(r._mapping) for r in rows]
        except Exception as e:
            self.logger.error(f"Flapping query error: {e}")
            return []

    def _query_errors(self, session) -> List[Dict[str, Any]]:
        """Ports with non-zero in/out errors or output discards (= CLI Total output drops)."""
        try:
            result = session.execute(text("""
                SELECT
                    sd.name        AS switch_name,
                    sd.ip_address,
                    psd.port_number,
                    COALESCE(psd.port_alias,'') AS alias,
                    psd.vlan_id,
                    psd.oper_status,
                    COALESCE(psd.in_errors,   0) AS in_errors,
                    COALESCE(psd.out_errors,  0) AS out_errors,
                    COALESCE(psd.out_discards,0) AS out_discards,
                    COALESCE(psd.in_errors,0)+COALESCE(psd.out_errors,0)
                        +COALESCE(psd.out_discards,0) AS total_issues
                FROM port_status_data psd
                JOIN snmp_devices sd ON sd.id = psd.device_id
                WHERE (COALESCE(psd.in_errors,0)   > 0
                    OR COALESCE(psd.out_errors,0)  > 0
                    OR COALESCE(psd.out_discards,0)> 0)
                ORDER BY total_issues DESC, sd.name, psd.port_number
            """))
            rows = result.fetchall()
            return [dict(r._mapping) for r in rows]
        except Exception as e:
            self.logger.error(f"Error/drop query error: {e}")
            return []

    def _query_vlan_alias(self, session) -> List[Dict[str, Any]]:
        """Ports where the alias type does not match the VLAN expected type."""
        try:
            result = session.execute(text("""
                SELECT
                    sd.name        AS switch_name,
                    sd.ip_address  AS switch_ip,
                    psd.port_number,
                    psd.vlan_id,
                    COALESCE(psd.port_alias,'') AS alias,
                    psd.oper_status
                FROM port_status_data psd
                JOIN snmp_devices sd ON sd.id = psd.device_id
                WHERE psd.vlan_id IS NOT NULL
                  AND psd.port_alias IS NOT NULL
                  AND psd.port_alias != ''
                ORDER BY sd.name, psd.port_number
            """))
            rows = result.fetchall()
        except Exception as e:
            self.logger.error(f"VLAN/alias query error: {e}")
            return []

        type_list = list(VLAN_TYPE_MAP.values())
        mismatches = []
        for r in rows:
            row = dict(r._mapping)
            vlan_id = int(row['vlan_id']) if row['vlan_id'] else 0
            if vlan_id not in VLAN_TYPE_MAP:
                continue
            expected = VLAN_TYPE_MAP[vlan_id]
            detected = _detect_alias_type(row['alias'], type_list)
            if detected is None or detected.upper() == expected.upper():
                continue
            row['expected_type'] = expected
            row['detected_type'] = detected
            mismatches.append(row)

        return mismatches

    # ──────────────────────────────────────────────────────────────────────────
    # HTML builder
    # ──────────────────────────────────────────────────────────────────────────

    def _fmt_speed(self, speed: Any) -> str:
        try:
            s = int(speed)
            if s >= 1_000_000_000:
                return f"{s // 1_000_000_000} Gbps"
            return f"{s // 1_000_000} Mbps"
        except (TypeError, ValueError):
            return str(speed)

    def _build_html(self, slow, flapping, errors, vlan_alias) -> str:
        date_str = datetime.now().strftime('%d.%m.%Y')

        def section(title: str, icon: str, count: int, table_html: str) -> str:
            return (
                f'<div class="section">'
                f'<h2>{icon} {title} <span class="cnt">({count})</span></h2>'
                f'{table_html}'
                f'</div>'
            )

        def none_msg() -> str:
            return '<p class="none">Bu hafta sorun bulunmadı.</p>'

        # ── Slow ports ────────────────────────────────────────────────────────
        if slow:
            rows_html = ''.join(
                f'<tr>'
                f'<td>{r["switch_name"]}</td>'
                f'<td>{r["port_number"]}</td>'
                f'<td>{r["alias"] or "—"}</td>'
                f'<td>{r["vlan_id"] or "—"}</td>'
                f'<td>{self._fmt_speed(r["port_speed"])}</td>'
                f'</tr>'
                for r in slow[:100]
            )
            slow_html = (
                '<table><tr>'
                '<th>Switch</th><th>Port</th><th>Alias</th><th>VLAN</th><th>Hız</th>'
                f'</tr>{rows_html}</table>'
            )
        else:
            slow_html = none_msg()

        # ── Flapping ──────────────────────────────────────────────────────────
        if flapping:
            rows_html = ''.join(
                f'<tr>'
                f'<td>{r["switch_name"]}</td>'
                f'<td>{r["port_number"]}</td>'
                f'<td>{r["alias"] or "—"}</td>'
                f'<td>{r["change_count"]}x</td>'
                f'<td>{r["first_change"]}</td>'
                f'<td>{r["last_change"]}</td>'
                f'</tr>'
                for r in flapping[:100]
            )
            flap_html = (
                '<table><tr>'
                '<th>Switch</th><th>Port</th><th>Alias</th>'
                '<th>Değişim</th><th>İlk</th><th>Son</th>'
                f'</tr>{rows_html}</table>'
            )
        else:
            flap_html = none_msg()

        # ── Errors ────────────────────────────────────────────────────────────
        if errors:
            rows_html = ''.join(
                f'<tr>'
                f'<td>{r["switch_name"]}</td>'
                f'<td>{r["port_number"]}</td>'
                f'<td>{r["alias"] or "—"}</td>'
                f'<td>{r["in_errors"]:,}</td>'
                f'<td>{r["out_errors"]:,}</td>'
                f'<td>{r["out_discards"]:,}</td>'
                f'<td><strong>{r["total_issues"]:,}</strong></td>'
                f'</tr>'
                for r in errors[:100]
            )
            err_html = (
                '<table><tr>'
                '<th>Switch</th><th>Port</th><th>Alias</th>'
                '<th>↓ Hata</th><th>↑ Hata</th><th>Output Drop</th><th>Toplam</th>'
                f'</tr>{rows_html}</table>'
            )
        else:
            err_html = none_msg()

        # ── VLAN/Alias ────────────────────────────────────────────────────────
        if vlan_alias:
            rows_html = ''.join(
                f'<tr>'
                f'<td>{r["switch_name"]}</td>'
                f'<td>{r["port_number"]}</td>'
                f'<td>{r["vlan_id"]}</td>'
                f'<td>{r["expected_type"]}</td>'
                f'<td>{r["detected_type"]}</td>'
                f'<td>{r["alias"]}</td>'
                f'</tr>'
                for r in vlan_alias[:100]
            )
            vac_html = (
                '<table><tr>'
                '<th>Switch</th><th>Port</th><th>VLAN</th>'
                '<th>Beklenen</th><th>Algılanan</th><th>Alias</th>'
                f'</tr>{rows_html}</table>'
            )
        else:
            vac_html = none_msg()

        body = (
            f'<p style="color:#8899bb;margin-bottom:20px;">Haftalık özet raporu — {date_str}</p>'
            + section('Yavaş Portlar',          '🐢', len(slow),      slow_html)
            + section('Up/Down Döngüsü',         '🔄', len(flapping),  flap_html)
            + section('Hata / Drop',              '⚠️', len(errors),    err_html)
            + section('VLAN/Alias Uyumsuzluk',   '🏷️', len(vlan_alias), vac_html)
        )

        return (
            f'<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8">{STYLE}</head>'
            f'<body>{body}</body></html>'
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Plain-text builder
    # ──────────────────────────────────────────────────────────────────────────

    def _build_plain(self, slow, flapping, errors, vlan_alias) -> str:
        date_str = datetime.now().strftime('%d.%m.%Y')
        lines = [f"CHAMADA Haftalık Rapor – {date_str}", "=" * 60, ""]

        def section(title: str, rows: list, fmt) -> None:
            lines.append(f"── {title} ({len(rows)}) ──")
            if not rows:
                lines.append("  Bu hafta sorun bulunmadı.")
            else:
                for r in rows[:50]:
                    lines.append("  " + fmt(r))
            lines.append("")

        section("Yavaş Portlar", slow,
                lambda r: f"{r['switch_name']} Port {r['port_number']} – {self._fmt_speed(r['port_speed'])} – {r['alias'] or '—'}")

        section("Up/Down Döngüsü", flapping,
                lambda r: f"{r['switch_name']} Port {r['port_number']} – {r['change_count']}x – {r['alias'] or '—'}")

        section("Hata / Drop", errors,
                lambda r: f"{r['switch_name']} Port {r['port_number']} – Toplam {r['total_issues']:,} – {r['alias'] or '—'}")

        section("VLAN/Alias Uyumsuzluk", vlan_alias,
                lambda r: f"{r['switch_name']} Port {r['port_number']} – VLAN {r['vlan_id']} Beklenen:{r['expected_type']} Algılanan:{r['detected_type']}")

        return "\n".join(lines)
