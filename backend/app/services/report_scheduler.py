"""
AEGIS Report Scheduler
Background task that auto-generates PDF reports on a weekly/monthly schedule.
Saves reports to disk and optionally emails them.

Integration:
    To start the scheduler, add to your main.py lifespan:

        from app.services.report_scheduler import report_scheduler

        @asynccontextmanager
        async def lifespan(app: FastAPI):
            # ... existing startup code ...
            report_scheduler.start()
            logger.info("Report scheduler started")

            yield

            # ... existing shutdown code ...
            report_scheduler.stop()

    The scheduler reads its config from the reports API module's in-memory
    _schedule_config. If no schedule is configured, defaults apply:
      - Weekly reports: every Monday at 06:00 UTC
      - Monthly reports: 1st of each month at 06:00 UTC
"""

import asyncio
import logging
import os
import smtplib
from datetime import datetime, timedelta
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

from app.config import settings
from app.database import async_session
from app.services.report_generator import pdf_report_generator

logger = logging.getLogger("aegis.report_scheduler")

# Default output directory for saved reports
REPORTS_DIR = Path(os.getenv("AEGIS_REPORTS_DIR", "/tmp/aegis_reports"))


def _get_schedule_config():
    """Import schedule config from the API module (avoids circular import at module level)."""
    try:
        from app.api.reports import _schedule_config, ScheduleConfig
        return _schedule_config or ScheduleConfig()
    except ImportError:
        return None


class ReportScheduler:
    """Background asyncio task that generates reports on a cron-like schedule."""

    def __init__(self):
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._last_weekly: Optional[datetime] = None
        self._last_monthly: Optional[datetime] = None

    def start(self):
        """Start the scheduler background task."""
        if self._running:
            logger.warning("Report scheduler is already running")
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("Report scheduler started")

    def stop(self):
        """Stop the scheduler."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
        logger.info("Report scheduler stopped")

    async def _loop(self):
        """Main scheduler loop. Checks every 60 seconds if a report is due."""
        # Ensure reports directory exists
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

        while self._running:
            try:
                await self._tick()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(f"Report scheduler error: {e}")

            # Sleep 60 seconds between checks
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                break

    async def _tick(self):
        """Check if any reports are due and generate them."""
        config = _get_schedule_config()
        if config is None:
            return

        now = datetime.utcnow()

        # Weekly check
        if config.weekly_enabled and self._is_weekly_due(now, config):
            await self._generate_and_save("weekly", config)
            self._last_weekly = now

        # Monthly check
        if config.monthly_enabled and self._is_monthly_due(now, config):
            await self._generate_and_save("monthly", config)
            self._last_monthly = now

    def _is_weekly_due(self, now: datetime, config) -> bool:
        """Check if the weekly report should run now."""
        # config.weekly_day: 0=Monday ... 6=Sunday
        if now.weekday() != config.weekly_day:
            return False
        if now.hour != config.weekly_hour:
            return False
        # Only trigger once per hour window
        if self._last_weekly and (now - self._last_weekly) < timedelta(hours=1):
            return False
        return True

    def _is_monthly_due(self, now: datetime, config) -> bool:
        """Check if the monthly report should run now."""
        if now.day != config.monthly_day:
            return False
        if now.hour != config.monthly_hour:
            return False
        if self._last_monthly and (now - self._last_monthly) < timedelta(hours=1):
            return False
        return True

    async def _generate_and_save(self, report_type: str, config):
        """Generate a report, save to disk, and optionally email it."""
        logger.info(f"Scheduled {report_type} report generation starting...")

        async with async_session() as db:
            # Get all clients (for multi-tenant, generate one per client)
            from app.models.client import Client
            from sqlalchemy import select

            result = await db.execute(select(Client))
            clients = result.scalars().all()

            for client in clients:
                try:
                    if report_type == "weekly":
                        pdf_bytes = await pdf_report_generator.generate_weekly_report(
                            client.id, db
                        )
                    else:
                        pdf_bytes = await pdf_report_generator.generate_monthly_report(
                            client.id, db
                        )

                    # Save to disk
                    now_str = datetime.utcnow().strftime("%Y%m%d_%H%M")
                    filename = f"aegis_{report_type}_{client.slug}_{now_str}.pdf"
                    filepath = REPORTS_DIR / filename

                    if config.save_to_disk:
                        filepath.write_bytes(pdf_bytes)
                        logger.info(f"Report saved: {filepath} ({len(pdf_bytes)} bytes)")

                    # Track in history
                    try:
                        from app.api.reports import _record_history
                        _record_history(report_type, filename, len(pdf_bytes))
                    except ImportError:
                        pass

                    # Email if configured
                    if config.email_recipients:
                        await self._send_email(
                            recipients=config.email_recipients,
                            subject=f"AEGIS {report_type.title()} Report - {client.name}",
                            filename=filename,
                            pdf_bytes=pdf_bytes,
                        )

                    logger.info(
                        f"Scheduled {report_type} report completed for client "
                        f"'{client.name}' ({len(pdf_bytes)} bytes)"
                    )

                except Exception as e:
                    logger.exception(
                        f"Failed to generate scheduled {report_type} report "
                        f"for client '{client.name}': {e}"
                    )

    async def _send_email(
        self,
        recipients: list[str],
        subject: str,
        filename: str,
        pdf_bytes: bytes,
    ):
        """Send the PDF report via email using SMTP settings from config."""
        if not settings.SMTP_HOST or not settings.SMTP_USER:
            logger.warning("SMTP not configured, skipping email delivery")
            return

        try:
            msg = MIMEMultipart()
            msg["From"] = settings.SMTP_USER
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = subject

            body = MIMEText(
                f"Please find attached the {subject}.\n\n"
                "This report was automatically generated by AEGIS Defense Platform.\n"
                "Do not reply to this email.",
                "plain",
            )
            msg.attach(body)

            attachment = MIMEApplication(pdf_bytes, _subtype="pdf")
            attachment.add_header(
                "Content-Disposition", "attachment", filename=filename
            )
            msg.attach(attachment)

            # Run SMTP in executor to avoid blocking the event loop
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._smtp_send, msg, recipients)

            logger.info(f"Report emailed to {recipients}")

        except Exception as e:
            logger.exception(f"Failed to send report email: {e}")

    def _smtp_send(self, msg: MIMEMultipart, recipients: list[str]):
        """Synchronous SMTP send (runs in thread executor)."""
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASS)
            server.send_message(msg, to_addrs=recipients)


# Singleton
report_scheduler = ReportScheduler()
