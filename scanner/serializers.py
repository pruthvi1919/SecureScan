from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from .models import Finding, Scan
from .services.ssrf import UnsafeTargetError, validate_target


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, style={"input_type": "password"})

    class Meta:
        model = User
        fields = ("id", "username", "email", "password")

    def validate_password(self, value):
        # Django's validators: min length, not too common, not all numbers, ...
        try:
            validate_password(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(list(exc.messages))
        return value

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)  # stores a password HASH


class FindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Finding
        fields = (
            "id", "category", "check_name", "severity", "passed",
            "description", "recommendation", "compliance_ref",
        )


class ScanCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = ("target_url",)

    def to_internal_value(self, data):
        # Let users type "example.com" - assume https:// if no scheme is given.
        url = str(data.get("target_url", "")).strip()
        if url and "://" not in url:
            url = "https://" + url
        return super().to_internal_value({"target_url": url})

    def validate_target_url(self, value):
        try:
            validate_target(value)  # SSRF check before we touch the network
        except UnsafeTargetError as exc:
            raise serializers.ValidationError(str(exc))
        return value


class ScanListSerializer(serializers.ModelSerializer):
    failed_checks = serializers.IntegerField(read_only=True)

    class Meta:
        model = Scan
        fields = ("id", "target_url", "status", "score", "grade", "failed_checks", "created_at")
        # Output only - users can never set their own score/grade/status
        # (prevents "mass assignment").
        read_only_fields = fields


class ScanDetailSerializer(ScanListSerializer):
    findings = FindingSerializer(many=True, read_only=True)

    class Meta(ScanListSerializer.Meta):
        fields = ScanListSerializer.Meta.fields + (
            "final_url", "error_message", "completed_at", "findings",
        )
        read_only_fields = fields
