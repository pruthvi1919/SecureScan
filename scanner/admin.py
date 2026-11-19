from django.contrib import admin

from .models import Finding, Scan


class FindingInline(admin.TabularInline):
    model = Finding
    extra = 0
    fields = ("check_name", "severity", "passed", "compliance_ref")
    readonly_fields = fields


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ("id", "target_url", "user", "status", "grade", "score", "created_at")
    list_filter = ("status", "grade")
    search_fields = ("target_url", "user__username")
    inlines = [FindingInline]


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ("check_name", "scan", "severity", "passed")
    list_filter = ("severity", "passed", "category")
