"""
Notifications utility for Reconcli toolkit
Supports Slack and Discord webhooks for scan result notifications
"""

import json
import time
import httpx
import click
from datetime import datetime
from typing import Dict, List, Optional, Any


class NotificationManager:
    """Manages notifications to various platforms (Slack, Discord)"""

    def __init__(
        self,
        slack_webhook: Optional[str] = None,
        discord_webhook: Optional[str] = None,
        verbose: bool = False,
    ):
        self.slack_webhook = slack_webhook
        self.discord_webhook = discord_webhook
        self.verbose = verbose

    def send_vhost_results(
        self, domain: str, target_ip: str, results: List[Dict], scan_metadata: Dict
    ) -> bool:
        """Send VHOST scan results to configured notification channels"""
        success = True

        if self.slack_webhook:
            success &= self._send_slack_vhost_notification(
                domain, target_ip, results, scan_metadata
            )

        if self.discord_webhook:
            success &= self._send_discord_vhost_notification(
                domain, target_ip, results, scan_metadata
            )

        return success

    def send_takeover_results(self, results: List[Dict], scan_metadata: Dict) -> bool:
        """Send subdomain takeover scan results to configured notification channels"""
        success = True

        if self.slack_webhook:
            success &= self._send_slack_takeover_notification(results, scan_metadata)

        if self.discord_webhook:
            success &= self._send_discord_takeover_notification(results, scan_metadata)

        return success

    def send_url_results(self, results: List[Dict], scan_metadata: Dict) -> bool:
        """Send URL discovery scan results to configured notification channels"""
        success = True

        if self.slack_webhook:
            success &= self._send_slack_url_notification(results, scan_metadata)

        if self.discord_webhook:
            success &= self._send_discord_url_notification(results, scan_metadata)

        return success

    def send_dns_results(self, results: List[Dict], scan_metadata: Dict) -> bool:
        """Send DNS resolution scan results to configured notification channels"""
        success = True

        if self.slack_webhook:
            success &= self._send_slack_dns_notification(results, scan_metadata)

        if self.discord_webhook:
            success &= self._send_discord_dns_notification(results, scan_metadata)

        return success

    def send_whoisfreaks_results(
        self, results: List[Dict], scan_metadata: Dict
    ) -> bool:
        """Send WhoisFreaks scan results to configured notification channels"""
        success = True

        if self.slack_webhook:
            success &= self._send_slack_whoisfreaks_notification(results, scan_metadata)

        if self.discord_webhook:
            success &= self._send_discord_whoisfreaks_notification(
                results, scan_metadata
            )

        return success

    def _send_slack_vhost_notification(
        self, domain: str, target_ip: str, results: List[Dict], metadata: Dict
    ) -> bool:
        """Send VHOST results to Slack"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Create summary
            status_counts = {}
            for result in results:
                status = result.get("status", "unknown")
                status_counts[status] = status_counts.get(status, 0) + 1

            # Build Slack message
            if results:
                color = (
                    "good"
                    if any(r.get("status") == 200 for r in results)
                    else "warning"
                )
                title = f"🎯 VHOST Discovery: {len(results)} hosts found for {domain}"

                fields = [
                    {"title": "Domain", "value": f"`{domain}`", "short": True},
                    {"title": "Target IP", "value": f"`{target_ip}`", "short": True},
                    {
                        "title": "Engine",
                        "value": f"`{metadata.get('engine', 'unknown')}`",
                        "short": True,
                    },
                    {
                        "title": "Total Results",
                        "value": f"`{len(results)}`",
                        "short": True,
                    },
                ]

                # Add status breakdown
                if status_counts:
                    status_text = ", ".join(
                        [
                            f"{status}: {count}"
                            for status, count in status_counts.items()
                        ]
                    )
                    fields.append(
                        {
                            "title": "Status Breakdown",
                            "value": f"`{status_text}`",
                            "short": False,
                        }
                    )

                # Add top results
                if len(results) <= 10:
                    hosts_text = "\n".join(
                        [
                            f"• `{r['host']}` ({r.get('status', 'unknown')})"
                            for r in results[:10]
                        ]
                    )
                else:
                    hosts_text = "\n".join(
                        [
                            f"• `{r['host']}` ({r.get('status', 'unknown')})"
                            for r in results[:10]
                        ]
                    )
                    hosts_text += f"\n... and {len(results) - 10} more"

                fields.append(
                    {"title": "Discovered Hosts", "value": hosts_text, "short": False}
                )
            else:
                color = "danger"
                title = f"❌ VHOST Discovery: No hosts found for {domain}"
                fields = [
                    {"title": "Domain", "value": f"`{domain}`", "short": True},
                    {"title": "Target IP", "value": f"`{target_ip}`", "short": True},
                    {
                        "title": "Engine",
                        "value": f"`{metadata.get('engine', 'unknown')}`",
                        "short": True,
                    },
                    {
                        "title": "Status",
                        "value": "No virtual hosts discovered",
                        "short": False,
                    },
                ]

            payload = {
                "attachments": [
                    {
                        "color": color,
                        "title": title,
                        "fields": fields,
                        "footer": "Reconcli VHOST Scanner",
                        "ts": int(datetime.now().timestamp()),
                    }
                ]
            }

            response = httpx.post(self.slack_webhook, json=payload, timeout=10)
            response.raise_for_status()

            if self.verbose:
                click.echo("📱 Slack notification sent successfully")
            return True

        except Exception as e:
            if self.verbose:
                click.echo(f"❌ Failed to send Slack notification: {e}")
            return False

    def _send_discord_vhost_notification(
        self, domain: str, target_ip: str, results: List[Dict], metadata: Dict
    ) -> bool:
        """Send VHOST results to Discord"""
        try:
            timestamp = datetime.now().isoformat()

            # Create summary
            status_counts = {}
            for result in results:
                status = result.get("status", "unknown")
                status_counts[status] = status_counts.get(status, 0) + 1

            # Build Discord embed
            if results:
                color = (
                    0x00FF00
                    if any(r.get("status") == 200 for r in results)
                    else 0xFF9900
                )  # Green or orange
                title = f"🎯 VHOST Discovery Results"
                description = f"Found {len(results)} virtual hosts for **{domain}**"

                fields = [
                    {"name": "Domain", "value": f"`{domain}`", "inline": True},
                    {"name": "Target IP", "value": f"`{target_ip}`", "inline": True},
                    {
                        "name": "Engine",
                        "value": f"`{metadata.get('engine', 'unknown')}`",
                        "inline": True,
                    },
                ]

                # Add status breakdown
                if status_counts:
                    status_text = ", ".join(
                        [
                            f"{status}: {count}"
                            for status, count in status_counts.items()
                        ]
                    )
                    fields.append(
                        {
                            "name": "Status Breakdown",
                            "value": f"`{status_text}`",
                            "inline": False,
                        }
                    )

                # Add top results
                if len(results) <= 10:
                    hosts_text = "\n".join(
                        [
                            f"• `{r['host']}` ({r.get('status', 'unknown')})"
                            for r in results[:10]
                        ]
                    )
                else:
                    hosts_text = "\n".join(
                        [
                            f"• `{r['host']}` ({r.get('status', 'unknown')})"
                            for r in results[:10]
                        ]
                    )
                    hosts_text += f"\n... and {len(results) - 10} more"

                fields.append(
                    {"name": "Discovered Hosts", "value": hosts_text, "inline": False}
                )
            else:
                color = 0xFF0000  # Red
                title = f"❌ VHOST Discovery Results"
                description = f"No virtual hosts found for **{domain}**"
                fields = [
                    {"name": "Domain", "value": f"`{domain}`", "inline": True},
                    {"name": "Target IP", "value": f"`{target_ip}`", "inline": True},
                    {
                        "name": "Engine",
                        "value": f"`{metadata.get('engine', 'unknown')}`",
                        "inline": True,
                    },
                    {
                        "name": "Status",
                        "value": "No virtual hosts discovered",
                        "inline": False,
                    },
                ]

            embed = {
                "title": title,
                "description": description,
                "color": color,
                "fields": fields,
                "footer": {"text": "Reconcli VHOST Scanner"},
                "timestamp": timestamp,
            }

            payload = {"embeds": [embed]}

            response = httpx.post(self.discord_webhook, json=payload, timeout=10)
            response.raise_for_status()

            if self.verbose:
                click.echo("📱 Discord notification sent successfully")
            return True

        except Exception as e:
            if self.verbose:
                click.echo(f"❌ Failed to send Discord notification: {e}")
            return False

    def _send_slack_takeover_notification(
        self, results: List[Dict], metadata: Dict
    ) -> bool:
        """Send takeover results to Slack"""
        try:
            # Build Slack message for takeover results
            if results:
                color = "danger"  # Red for potential security issues
                title = (
                    f"🚨 Subdomain Takeover: {len(results)} vulnerable subdomains found"
                )

                fields = [
                    {
                        "title": "Total Vulnerable",
                        "value": f"`{len(results)}`",
                        "short": True,
                    },
                    {
                        "title": "Tool Used",
                        "value": f"`{metadata.get('tool', 'unknown')}`",
                        "short": True,
                    },
                ]

                # Add vulnerable subdomains
                if len(results) <= 10:
                    subdomains_text = "\n".join(
                        [
                            f"• `{r.get('subdomain', r.get('url', 'unknown'))}`"
                            for r in results[:10]
                        ]
                    )
                else:
                    subdomains_text = "\n".join(
                        [
                            f"• `{r.get('subdomain', r.get('url', 'unknown'))}`"
                            for r in results[:10]
                        ]
                    )
                    subdomains_text += f"\n... and {len(results) - 10} more"

                fields.append(
                    {
                        "title": "Vulnerable Subdomains",
                        "value": subdomains_text,
                        "short": False,
                    }
                )
            else:
                color = "good"
                title = f"✅ Subdomain Takeover: No vulnerabilities found"
                fields = [
                    {
                        "title": "Tool Used",
                        "value": f"`{metadata.get('tool', 'unknown')}`",
                        "short": True,
                    },
                    {
                        "title": "Status",
                        "value": "No vulnerable subdomains detected",
                        "short": False,
                    },
                ]

            payload = {
                "attachments": [
                    {
                        "color": color,
                        "title": title,
                        "fields": fields,
                        "footer": "Reconcli Takeover Scanner",
                        "ts": int(datetime.now().timestamp()),
                    }
                ]
            }

            response = httpx.post(self.slack_webhook, json=payload, timeout=10)
            response.raise_for_status()

            if self.verbose:
                click.echo("📱 Slack notification sent successfully")
            return True

        except Exception as e:
            if self.verbose:
                click.echo(f"❌ Failed to send Slack notification: {e}")
            return False

    def _send_discord_takeover_notification(
        self, results: List[Dict], metadata: Dict
    ) -> bool:
        """Send takeover results to Discord"""
        try:
            timestamp = datetime.now().isoformat()

            # Build Discord embed for takeover results
            if results:
                color = 0xFF0000  # Red for potential security issues
                title = f"🚨 Subdomain Takeover Results"
                description = f"Found {len(results)} potentially vulnerable subdomains"

                fields = [
                    {
                        "name": "Total Vulnerable",
                        "value": f"`{len(results)}`",
                        "inline": True,
                    },
                    {
                        "name": "Tool Used",
                        "value": f"`{metadata.get('tool', 'unknown')}`",
                        "inline": True,
                    },
                ]

                # Add vulnerable subdomains
                if len(results) <= 10:
                    subdomains_text = "\n".join(
                        [
                            f"• `{r.get('subdomain', r.get('url', 'unknown'))}`"
                            for r in results[:10]
                        ]
                    )
                else:
                    subdomains_text = "\n".join(
                        [
                            f"• `{r.get('subdomain', r.get('url', 'unknown'))}`"
                            for r in results[:10]
                        ]
                    )
                    subdomains_text += f"\n... and {len(results) - 10} more"

                fields.append(
                    {
                        "name": "Vulnerable Subdomains",
                        "value": subdomains_text,
                        "inline": False,
                    }
                )
            else:
                color = 0x00FF00  # Green
                title = f"✅ Subdomain Takeover Results"
                description = f"No vulnerable subdomains detected"
                fields = [
                    {
                        "name": "Tool Used",
                        "value": f"`{metadata.get('tool', 'unknown')}`",
                        "inline": True,
                    },
                    {
                        "name": "Status",
                        "value": "No vulnerabilities found",
                        "inline": False,
                    },
                ]

            embed = {
                "title": title,
                "description": description,
                "color": color,
                "fields": fields,
                "footer": {"text": "Reconcli Takeover Scanner"},
                "timestamp": timestamp,
            }

            payload = {"embeds": [embed]}

            response = httpx.post(self.discord_webhook, json=payload, timeout=10)
            response.raise_for_status()

            if self.verbose:
                click.echo("📱 Discord notification sent successfully")
            return True

        except Exception as e:
            if self.verbose:
                click.echo(f"❌ Failed to send Discord notification: {e}")
            return False

    def _send_slack_url_notification(self, results: List[Dict], metadata: Dict) -> bool:
        """Send URL discovery results to Slack"""
        if not self.slack_webhook:
            return False

        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Build Slack message for URL discovery results
            total_urls = metadata.get("total_urls_found", len(results))
            domains_processed = metadata.get("domains_processed", 1)
            tools_used = metadata.get("tools_used", [])

            color = "good" if total_urls > 0 else "warning"
            title = f"🔗 URL Discovery: {total_urls} URLs found"

            fields = [
                {"title": "Total URLs", "value": f"`{total_urls}`", "short": True},
                {
                    "title": "Domains Processed",
                    "value": f"`{domains_processed}`",
                    "short": True,
                },
                {
                    "title": "Tools Used",
                    "value": f"`{', '.join(tools_used) if tools_used else 'None'}`",
                    "short": False,
                },
            ]

            # Add sample URLs if available
            if results and len(results) > 0:
                sample_urls = []
                for result in results[:5]:  # Show first 5 URLs
                    if isinstance(result, dict):
                        url = result.get("url", str(result))
                    else:
                        url = str(result)
                    sample_urls.append(f"• `{url}`")

                if sample_urls:
                    fields.append(
                        {
                            "title": "Sample URLs",
                            "value": "\n".join(sample_urls)
                            + (
                                f"\n... and {total_urls - len(sample_urls)} more"
                                if total_urls > 5
                                else ""
                            ),
                            "short": False,
                        }
                    )

            attachment = {
                "color": color,
                "title": title,
                "fields": fields,
                "footer": "Reconcli URL Discovery",
                "ts": int(datetime.now().timestamp()),
            }

            payload = {"attachments": [attachment]}

            response = httpx.post(self.slack_webhook, json=payload, timeout=10)
            response.raise_for_status()

            if self.verbose:
                click.echo("📱 Slack notification sent successfully")
            return True

        except Exception as e:
            if self.verbose:
                click.echo(f"❌ Failed to send Slack notification: {e}")
            return False

    def _send_discord_url_notification(
        self, results: List[Dict], metadata: Dict
    ) -> bool:
        """Send URL discovery results to Discord"""
        if not self.discord_webhook:
            return False

        try:
            timestamp = datetime.now().isoformat()

            # Build Discord embed for URL discovery results
            total_urls = metadata.get("total_urls_found", len(results))
            domains_processed = metadata.get("domains_processed", 1)
            tools_used = metadata.get("tools_used", [])

            color = (
                0x00FF00 if total_urls > 0 else 0xFFAA00
            )  # Green if URLs found, amber if none
            title = f"🔗 URL Discovery Complete"
            description = (
                f"Found {total_urls} URLs across {domains_processed} domain(s)"
            )

            fields = [
                {
                    "name": "Total URLs",
                    "value": f"`{total_urls}`",
                    "inline": True,
                },
                {
                    "name": "Domains Processed",
                    "value": f"`{domains_processed}`",
                    "inline": True,
                },
                {
                    "name": "Tools Used",
                    "value": f"`{', '.join(tools_used) if tools_used else 'None'}`",
                    "inline": False,
                },
            ]

            # Add sample URLs if available
            if results and len(results) > 0:
                sample_urls = []
                for result in results[:5]:  # Show first 5 URLs
                    if isinstance(result, dict):
                        url = result.get("url", str(result))
                    else:
                        url = str(result)
                    sample_urls.append(f"• `{url}`")

                if sample_urls:
                    fields.append(
                        {
                            "name": "Sample URLs",
                            "value": "\n".join(sample_urls)
                            + (
                                f"\n... and {total_urls - len(sample_urls)} more"
                                if total_urls > 5
                                else ""
                            ),
                            "inline": False,
                        }
                    )

            embed = {
                "title": title,
                "description": description,
                "color": color,
                "fields": fields,
                "footer": {"text": "Reconcli URL Discovery"},
                "timestamp": timestamp,
            }

            payload = {"embeds": [embed]}

            response = httpx.post(self.discord_webhook, json=payload, timeout=10)
            response.raise_for_status()

            if self.verbose:
                click.echo("📱 Discord notification sent successfully")
            return True

        except Exception as e:
            if self.verbose:
                click.echo(f"❌ Failed to send Discord notification: {e}")
            return False

    def _send_slack_dns_notification(self, results: List[Dict], metadata: Dict) -> bool:
        """Send DNS resolution results to Slack"""
        if not self.slack_webhook:
            return False

        try:
            # Build Slack message for DNS resolution results
            total_subdomains = metadata.get("total_subdomains", len(results))
            resolved_count = metadata.get("resolved_count", 0)
            resolution_rate = metadata.get("resolution_rate", 0)
            top_tags = metadata.get("top_tags", {})

            color = "good" if resolved_count > 0 else "warning"
            title = f"🔍 DNS Resolution: {resolved_count}/{total_subdomains} subdomains resolved"

            fields = [
                {
                    "title": "Total Subdomains",
                    "value": f"`{total_subdomains}`",
                    "short": True,
                },
                {
                    "title": "Successfully Resolved",
                    "value": f"`{resolved_count}`",
                    "short": True,
                },
                {
                    "title": "Resolution Rate",
                    "value": f"`{resolution_rate}%`",
                    "short": True,
                },
                {
                    "title": "Scan Duration",
                    "value": f"`{metadata.get('scan_duration', 'unknown')}`",
                    "short": True,
                },
            ]

            # Add top tags if available
            if top_tags:
                tags_text = "\n".join(
                    [f"• {tag}: {count}" for tag, count in list(top_tags.items())[:5]]
                )
                fields.append(
                    {
                        "title": "Top Classifications",
                        "value": tags_text,
                        "short": False,
                    }
                )

            # Add sample resolved subdomains
            if results:
                resolved_samples = [
                    r for r in results[:5] if r.get("ip") != "unresolved"
                ]
                if resolved_samples:
                    samples_text = "\n".join(
                        [
                            f"• `{r['subdomain']}` → {r['ip']}"
                            + (f" ({', '.join(r['tags'])})" if r.get("tags") else "")
                            for r in resolved_samples
                        ]
                    )
                    fields.append(
                        {
                            "title": "Sample Results",
                            "value": samples_text,
                            "short": False,
                        }
                    )

            attachment = {
                "color": color,
                "title": title,
                "fields": fields,
                "footer": "Reconcli DNS Scanner",
                "ts": int(datetime.now().timestamp()),
            }

            payload = {"attachments": [attachment]}

            response = httpx.post(self.slack_webhook, json=payload, timeout=10)
            response.raise_for_status()

            if self.verbose:
                click.echo("📱 Slack notification sent successfully")
            return True

        except Exception as e:
            if self.verbose:
                click.echo(f"❌ Failed to send Slack notification: {e}")
            return False

    def _send_discord_dns_notification(
        self, results: List[Dict], metadata: Dict
    ) -> bool:
        """Send DNS resolution results to Discord"""
        if not self.discord_webhook:
            return False

        try:
            timestamp = datetime.now().isoformat()

            # Build Discord embed for DNS resolution results
            total_subdomains = metadata.get("total_subdomains", len(results))
            resolved_count = metadata.get("resolved_count", 0)
            resolution_rate = metadata.get("resolution_rate", 0)
            top_tags = metadata.get("top_tags", {})

            color = (
                0x00FF00 if resolved_count > 0 else 0xFFAA00
            )  # Green if resolved, amber if none
            title = f"🔍 DNS Resolution Complete"
            description = f"Resolved {resolved_count}/{total_subdomains} subdomains ({resolution_rate}%)"

            fields = [
                {
                    "name": "Total Subdomains",
                    "value": f"`{total_subdomains}`",
                    "inline": True,
                },
                {
                    "name": "Successfully Resolved",
                    "value": f"`{resolved_count}`",
                    "inline": True,
                },
                {
                    "name": "Resolution Rate",
                    "value": f"`{resolution_rate}%`",
                    "inline": True,
                },
                {
                    "name": "Scan Duration",
                    "value": f"`{metadata.get('scan_duration', 'unknown')}`",
                    "inline": True,
                },
            ]

            # Add top tags if available
            if top_tags:
                tags_text = "\n".join(
                    [f"• {tag}: {count}" for tag, count in list(top_tags.items())[:5]]
                )
                fields.append(
                    {
                        "name": "Top Classifications",
                        "value": tags_text,
                        "inline": False,
                    }
                )

            # Add sample resolved subdomains
            if results:
                resolved_samples = [
                    r for r in results[:5] if r.get("ip") != "unresolved"
                ]
                if resolved_samples:
                    samples_text = "\n".join(
                        [
                            f"• `{r['subdomain']}` → {r['ip']}"
                            + (f" ({', '.join(r['tags'])})" if r.get("tags") else "")
                            for r in resolved_samples
                        ]
                    )
                    fields.append(
                        {
                            "name": "Sample Results",
                            "value": samples_text,
                            "inline": False,
                        }
                    )

            embed = {
                "title": title,
                "description": description,
                "color": color,
                "fields": fields,
                "footer": {"text": "Reconcli DNS Scanner"},
                "timestamp": timestamp,
            }

            payload = {"embeds": [embed]}

            response = httpx.post(self.discord_webhook, json=payload, timeout=10)
            response.raise_for_status()

            if self.verbose:
                click.echo("📱 Discord notification sent successfully")
            return True

        except Exception as e:
            if self.verbose:
                click.echo(f"❌ Failed to send Discord notification: {e}")
            return False

    def _send_slack_whoisfreaks_notification(
        self, results: List[Dict], metadata: Dict
    ) -> bool:
        """Send WhoisFreaks results to Slack"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Calculate statistics
            total_domains = metadata.get("total_domains", len(results))
            success_count = metadata.get("success_count", 0)
            failed_count = metadata.get("failed_count", 0)

            # Risk statistics
            risk_dist = metadata.get("risk_distribution", {})
            high_risk = risk_dist.get("HIGH", 0)
            medium_risk = risk_dist.get("MEDIUM", 0)

            # Expiring domains
            expiring_domains = metadata.get("expiring_domains", 0)

            # Build Slack message
            if success_count > 0:
                color = (
                    "danger"
                    if high_risk > 0
                    else (
                        "warning" if medium_risk > 0 or expiring_domains > 0 else "good"
                    )
                )
                title = f"🔍 WhoisFreaks Analysis: {success_count}/{total_domains} domains analyzed"

                # Risk summary
                risk_summary = []
                if high_risk > 0:
                    risk_summary.append(f"🚨 {high_risk} HIGH risk")
                if medium_risk > 0:
                    risk_summary.append(f"⚠️ {medium_risk} MEDIUM risk")
                if expiring_domains > 0:
                    risk_summary.append(f"⏰ {expiring_domains} expiring soon")

                risk_text = (
                    " | ".join(risk_summary)
                    if risk_summary
                    else "✅ No significant risks found"
                )

            else:
                color = "warning"
                title = f"🔍 WhoisFreaks Analysis: No domains successfully analyzed"
                risk_text = "No data to analyze"

            fields = [
                {
                    "title": "📊 Analysis Summary",
                    "value": f"Total Domains: {total_domains}\n"
                    f"Successful: {success_count}\n"
                    f"Failed: {failed_count}\n"
                    f"Success Rate: {metadata.get('success_rate', 0)}%",
                    "short": True,
                },
                {
                    "title": "🚨 Risk Assessment",
                    "value": risk_text,
                    "short": True,
                },
                {
                    "title": "⏱️ Scan Details",
                    "value": f"Duration: {metadata.get('scan_duration', 'unknown')}\n"
                    f"Timestamp: {metadata.get('timestamp', 'unknown')}\n"
                    f"Tool: {metadata.get('tool', 'whoisfreakscli')}",
                    "short": True,
                },
            ]

            # Add sample domain details for successful results
            successful_results = [r for r in results if r.get("status") == "success"]
            if successful_results:
                for result in successful_results[:5]:  # Limit to first 5 results
                    whois_data = result.get("whois_data", {})
                    domain = result.get("domain", "unknown")
                    registrar = whois_data.get(
                        "registrar", whois_data.get("registrarName", "unknown")
                    )
                    expiry = whois_data.get(
                        "expiration_date", whois_data.get("expiresDate", "unknown")
                    )

                    # Risk info
                    risk_info = result.get("risk_analysis", {})
                    risk_level = risk_info.get("risk_level", "NONE")
                    risk_score = risk_info.get("risk_score", 0)

                    # Expiry warning
                    expiry_info = result.get("expiring_soon", {})
                    expiry_warning = ""
                    if expiry_info:
                        days = expiry_info.get("days_until_expiry", 0)
                        expiry_warning = f"\n⏰ Expires in {days} days!"

                    fields.append(
                        {
                            "title": f"📍 {domain}",
                            "value": f"Registrar: {registrar}\n"
                            f"Expires: {expiry}\n"
                            f"Risk: {risk_level} ({risk_score}){expiry_warning}",
                            "short": False,
                        }
                    )

            attachment = {
                "fallback": title,
                "color": color,
                "title": title,
                "fields": fields,
                "footer": "ReconCLI WhoisFreaks Analysis",
                "ts": int(time.time()),
            }

            payload = {"attachments": [attachment]}

            response = httpx.post(self.slack_webhook, json=payload, timeout=10)
            response.raise_for_status()

            if self.verbose:
                click.echo("✅ Slack notification sent successfully")
            return True

        except Exception as e:
            if self.verbose:
                click.echo(f"❌ Failed to send Slack notification: {e}")
            return False

    def _send_discord_whoisfreaks_notification(
        self, results: List[Dict], metadata: Dict
    ) -> bool:
        """Send WhoisFreaks results to Discord"""
        try:
            timestamp = datetime.now().isoformat()

            # Calculate statistics
            total_domains = metadata.get("total_domains", len(results))
            success_count = metadata.get("success_count", 0)
            failed_count = metadata.get("failed_count", 0)

            # Risk statistics
            risk_dist = metadata.get("risk_distribution", {})
            high_risk = risk_dist.get("HIGH", 0)
            medium_risk = risk_dist.get("MEDIUM", 0)

            # Expiring domains
            expiring_domains = metadata.get("expiring_domains", 0)

            # Build Discord embed
            if success_count > 0:
                color = (
                    0xFF0000
                    if high_risk > 0
                    else (
                        0xFFA500
                        if medium_risk > 0 or expiring_domains > 0
                        else 0x00FF00
                    )
                )
                title = f"🔍 WhoisFreaks Analysis Complete"
                description = (
                    f"**{success_count}/{total_domains}** domains analyzed successfully"
                )

                # Risk summary
                risk_summary = []
                if high_risk > 0:
                    risk_summary.append(f"🚨 **{high_risk}** HIGH risk")
                if medium_risk > 0:
                    risk_summary.append(f"⚠️ **{medium_risk}** MEDIUM risk")
                if expiring_domains > 0:
                    risk_summary.append(f"⏰ **{expiring_domains}** expiring soon")

                if risk_summary:
                    description += f"\n\n**Security Alerts:**\n" + "\n".join(
                        risk_summary
                    )
                else:
                    description += f"\n\n✅ **No significant risks detected**"

            else:
                color = 0xFFA500
                title = f"🔍 WhoisFreaks Analysis"
                description = "No domains were successfully analyzed"

            embed = {
                "title": title,
                "description": description,
                "color": color,
                "timestamp": timestamp,
                "fields": [
                    {
                        "name": "📊 Analysis Summary",
                        "value": f"```\nTotal Domains:  {total_domains}\n"
                        f"Successful:     {success_count}\n"
                        f"Failed:         {failed_count}\n"
                        f"Success Rate:   {metadata.get('success_rate', 0)}%\n"
                        f"Duration:       {metadata.get('scan_duration', 'unknown')}```",
                        "inline": True,
                    }
                ],
                "footer": {
                    "text": f"ReconCLI WhoisFreaks • {metadata.get('tool', 'whoisfreakscli')}"
                },
            }

            # Add sample results
            successful_results = [r for r in results if r.get("status") == "success"]
            if successful_results and len(successful_results) > 0:
                sample_results = []
                for result in successful_results[:5]:  # Limit to first 5
                    whois_data = result.get("whois_data", {})
                    domain = result.get("domain", "unknown")
                    registrar = whois_data.get(
                        "registrar", whois_data.get("registrarName", "unknown")
                    )

                    # Risk info
                    risk_info = result.get("risk_analysis", {})
                    risk_level = risk_info.get("risk_level", "NONE")

                    # Expiry warning
                    expiry_info = result.get("expiring_soon", {})
                    warning = ""
                    if expiry_info:
                        days = expiry_info.get("days_until_expiry", 0)
                        warning = f" ⏰ Expires in {days} days"

                    sample_results.append(
                        f"• **{domain}** | {registrar} | Risk: {risk_level}{warning}"
                    )

                if sample_results:
                    embed["fields"].append(
                        {
                            "name": f"📋 Sample Results ({len(sample_results)}/{len(successful_results)})",
                            "value": "\n".join(sample_results),
                            "inline": False,
                        }
                    )

            payload = {"embeds": [embed]}

            response = httpx.post(self.discord_webhook, json=payload, timeout=10)
            response.raise_for_status()

            if self.verbose:
                click.echo("✅ Discord notification sent successfully")
            return True

        except Exception as e:
            if self.verbose:
                click.echo(f"❌ Failed to send Discord notification: {e}")
            return False


def send_notification(notification_type: str, **kwargs) -> bool:
    """
    Convenience function to send notifications

    Args:
        notification_type: Type of notification ('vhost', 'takeover')
        **kwargs: Arguments for the specific notification type
    """
    slack_webhook = kwargs.get("slack_webhook")
    discord_webhook = kwargs.get("discord_webhook")
    verbose = kwargs.get("verbose", False)

    if not slack_webhook and not discord_webhook:
        if verbose:
            click.echo("⚠️  No notification webhooks configured")
        return True

    notifier = NotificationManager(slack_webhook, discord_webhook, verbose)

    if notification_type == "vhost":
        return notifier.send_vhost_results(
            kwargs["domain"],
            kwargs["target_ip"],
            kwargs["results"],
            kwargs["scan_metadata"],
        )
    elif notification_type == "takeover":
        return notifier.send_takeover_results(
            kwargs["results"], kwargs["scan_metadata"]
        )
    elif notification_type == "url":
        return notifier.send_url_results(kwargs["results"], kwargs["scan_metadata"])
    elif notification_type == "dns":
        return notifier.send_dns_results(kwargs["results"], kwargs["scan_metadata"])
    elif notification_type == "whoisfreaks":
        return notifier.send_whoisfreaks_results(
            kwargs["results"], kwargs["scan_metadata"]
        )
    else:
        if verbose:
            click.echo(f"❌ Unknown notification type: {notification_type}")
        return False
