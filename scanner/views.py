import logging

from django.db.models import Count, Q
from django.utils import timezone
from rest_framework import generics, mixins, permissions, status, viewsets
from rest_framework.decorators import action, api_view, permission_classes, throttle_classes
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle

from .models import Finding, Scan
from .serializers import (
    RegisterSerializer,
    ScanCreateSerializer,
    ScanDetailSerializer,
    ScanListSerializer,
)
from .services.engine import ScanError, run_scan
from .services.ssrf import UnsafeTargetError

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


class ScanCreateRateThrottle(UserRateThrottle):
    """Each user may start only N scans per hour (SCAN_RATE_LIMIT, default 10/hour)."""
    scope = "scan_create"


@api_view(["GET"])
@permission_classes([permissions.AllowAny])
@throttle_classes([])
def health(request):
    return Response({"status": "ok"})


class RegisterView(generics.CreateAPIView):
    """POST /api/auth/register/ - create an account."""
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]


class ScanViewSet(
    mixins.CreateModelMixin,
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):
    """
    POST   /api/scans/              start a scan          {"target_url": "example.com"}
    GET    /api/scans/              list my scans
    GET    /api/scans/{id}/         scan details + all findings
    GET    /api/scans/{id}/report/  compliance summary
    DELETE /api/scans/{id}/         delete a scan
    """

    def get_queryset(self):
        # Users only ever see THEIR OWN scans. Another user's scan id returns 404,
        # which prevents IDOR (Insecure Direct Object Reference).
        return (
            Scan.objects.filter(user=self.request.user)
            .annotate(failed_checks=Count("findings", filter=Q(findings__passed=False)))
            .prefetch_related("findings")
            .order_by("-created_at")
        )

    def get_serializer_class(self):
        if self.action == "create":
            return ScanCreateSerializer
        if self.action == "list":
            return ScanListSerializer
        return ScanDetailSerializer

    def get_throttles(self):
        if self.action == "create":
            return [ScanCreateRateThrottle()]
        return super().get_throttles()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        scan = Scan.objects.create(
            user=request.user, target_url=serializer.validated_data["target_url"]
        )
        try:
            result = run_scan(scan.target_url)
        except (ScanError, UnsafeTargetError) as exc:
            scan.status = Scan.Status.FAILED
            scan.error_message = str(exc)[:255]
        except Exception:
            # Never show internal errors to the user - log them instead.
            logger.exception("Unexpected error while scanning %s", scan.target_url)
            scan.status = Scan.Status.FAILED
            scan.error_message = "Internal error while scanning."
        else:
            Finding.objects.bulk_create([Finding(scan=scan, **f) for f in result.findings])
            scan.status = Scan.Status.COMPLETED
            scan.final_url = result.final_url[:500]
            scan.score = result.score
            scan.grade = result.grade
        scan.completed_at = timezone.now()
        scan.save()

        scan = self.get_queryset().get(pk=scan.pk)
        data = ScanDetailSerializer(scan, context=self.get_serializer_context()).data
        # dict(...) so the browsable API shows the simple "target_url" form again
        return Response(dict(data), status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["get"])
    def report(self, request, pk=None):
        """A short compliance-style summary of one scan."""
        scan = self.get_object()
        findings = list(scan.findings.all())
        failed = sorted(
            (f for f in findings if not f.passed), key=lambda f: SEVERITY_ORDER[f.severity]
        )

        gaps = {}
        for finding in failed:
            for control in filter(None, (c.strip() for c in finding.compliance_ref.split(";"))):
                gaps.setdefault(control, []).append(finding.check_name)

        return Response({
            "scan_id": scan.id,
            "target_url": scan.target_url,
            "scanned_at": scan.created_at,
            "status": scan.status,
            "grade": scan.grade,
            "score": scan.score,
            "summary": {
                "total_checks": len(findings),
                "passed": len(findings) - len(failed),
                "failed": len(failed),
                "failed_by_severity": {
                    sev: sum(1 for f in failed if f.severity == sev)
                    for sev in ("high", "medium", "low")
                },
            },
            "compliance_gaps": [
                {"control": control, "failed_checks": checks}
                for control, checks in sorted(gaps.items())
            ],
            "recommendations": [
                {"check": f.check_name, "severity": f.severity, "fix": f.recommendation}
                for f in failed
            ],
        })
