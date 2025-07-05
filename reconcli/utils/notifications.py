"""
Notifications utility for Reconcli toolkit
Supports Slack and Discord webhooks for scan result notifications
"""

import json
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
    else:
        if verbose:
            click.echo(f"❌ Unknown notification type: {notification_type}")
        return False
