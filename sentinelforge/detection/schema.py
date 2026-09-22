"""Detection rule schema validation for SentinelForge.

Defines the Pydantic schema for Detection-as-Code YAML rule files
as specified in ARCHITECTURE.md §7.
"""
from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic.types import UUID4


class TestCaseSchema(BaseModel):
    """Test case for a detection rule."""
    description: str = Field(..., min_length=1, max_length=500)
    telemetry: dict[str, Any] = Field(..., description="Test telemetry event")
    expected: bool = Field(..., description="Expected detection result (true=match, false=noop)")

    __test__ = False  # Prevent pytest from collecting this as a test class
    model_config = {"arbitrary_types_allowed": True}


class DetectionRuleSchema(BaseModel):
    """Validated detection rule schema matching ARCHITECTURE.md §7.

    This is the input contract for detection rule YAML files.
    """
    __test__ = False  # Prevent pytest from collecting this as a test class
    model_config = {"arbitrary_types_allowed": True}

    # Required fields
    id: str = Field(..., min_length=1, max_length=100, description="Unique rule identifier")
    name: str = Field(..., min_length=1, max_length=255, description="Human-readable rule name")
    severity: str = Field(..., description="Rule severity: low, medium, high, critical")
    enabled: bool = Field(..., description="Whether the rule is active")
    version: str = Field(..., min_length=1, max_length=50, description="Rule version (semantic)")
    query: str = Field(..., min_length=1, description="Detection query (SQL/Elastic DSL-like)")

    # Optional fields
    description: Optional[str] = Field(None, max_length=2000, description="Rule description")
    author: Optional[str] = Field(None, max_length=100, description="Rule author")
    tags: Optional[list[str]] = Field(None, max_length=50, description="Rule tags")
    attck_techniques: Optional[list[str]] = Field(None, max_length=50, description="MITRE ATT&CK technique IDs")
    test_cases: Optional[list[TestCaseSchema]] = Field(None, max_length=20, description="Validation test cases")

    @field_validator("id", "name", "query")
    @classmethod
    def validate_non_empty_string(cls, v: str) -> str:
        """Ensure required strings are not just whitespace."""
        if not v or not v.strip():
            raise ValueError("must not be empty or whitespace")
        return v.strip()

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        """Validate severity is one of the allowed values."""
        allowed = {"low", "medium", "high", "critical"}
        v_lower = v.lower().strip()
        if v_lower not in allowed:
            raise ValueError(f"severity must be one of: {', '.join(sorted(allowed))}")
        return v_lower

    @field_validator("version")
    @classmethod
    def validate_version_format(cls, v: str) -> str:
        """Basic semantic version format validation."""
        v = v.strip()
        # Basic semver pattern: major.minor.patch with optional prerelease/build
        import re
        if not re.match(r'^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?(?:\+[a-zA-Z0-9.-]+)?$', v):
            raise ValueError("version must be semantic version format (e.g., 1.0.0)")
        return v

    @field_validator("attck_techniques")
    @classmethod
    def validate_attck_techniques(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        """Validate ATT&CK technique ID format (TXXXX or TXXXX.XXX)."""
        if v is None:
            return v
        import re
        for tech in v:
            if not re.match(r'^T\d{4}(?:\.\d{3})?$', tech):
                raise ValueError(f"invalid ATT&CK technique ID format: {tech} (expected TXXXX or TXXXX.XXX)")
        return v

    @model_validator(mode="after")
    def validate_test_cases(self) -> "DetectionRuleSchema":
        """Ensure test_cases have valid structure if provided."""
        if self.test_cases is not None:
            for i, tc in enumerate(self.test_cases):
                if tc.telemetry is None:
                    raise ValueError(f"test_cases[{i}].telemetry is required")
                if not isinstance(tc.expected, bool):
                    raise ValueError(f"test_cases[{i}].expected must be boolean")
        return self