from django.conf import settings
from django.db import models


class Scan(models.Model):
    """One scan of one website, owned by one user."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="scans"
    )
    target_url = models.URLField(max_length=500)
    final_url = models.URLField(max_length=500, blank=True)  # after redirects
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PENDING)
    score = models.PositiveSmallIntegerField(null=True, blank=True)  # 0-100
    grade = models.CharField(max_length=1, blank=True)  # A-F
    error_message = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["user", "-created_at"])]

    def __str__(self):
        return f"{self.target_url} ({self.grade or self.status})"


class Finding(models.Model):
    """The result of one security check inside a scan (passed or failed)."""

    class Severity(models.TextChoices):
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"
        INFO = "info", "Info"

    class Category(models.TextChoices):
        TRANSPORT = "transport", "Transport security (HTTPS)"
        CERTIFICATE = "certificate", "SSL/TLS certificate"
        HEADERS = "headers", "Security headers"
        COOKIES = "cookies", "Cookie security"
        DISCLOSURE = "disclosure", "Information disclosure"

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="findings")
    category = models.CharField(max_length=20, choices=Category.choices)
    check_name = models.CharField(max_length=100)
    severity = models.CharField(max_length=10, choices=Severity.choices)
    passed = models.BooleanField()
    description = models.TextField()
    recommendation = models.TextField(blank=True)
    compliance_ref = models.CharField(max_length=200, blank=True)  # OWASP / PCI DSS

    class Meta:
        ordering = ["passed", "id"]  # failed checks first

    def __str__(self):
        return f"[{'PASS' if self.passed else 'FAIL'}] {self.check_name}"
