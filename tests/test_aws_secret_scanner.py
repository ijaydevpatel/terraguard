"""TG-P14: secrets and state left in AWS. Fake clients, so no account is needed."""

from __future__ import annotations

import io

from terraguard.aws_secret_scanner import scan_s3_objects, scan_ssm_parameters
from terraguard.policy_engine import load_controls


class _Pages:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **_):
        return iter(self._pages)


class FakeS3:
    def __init__(self, objects: dict[str, bytes], *, deny: bool = False):
        self.objects, self.deny, self.reads = objects, deny, []

    def get_paginator(self, _name):
        if self.deny:
            raise PermissionError("AccessDenied")
        contents = [{"Key": k, "Size": len(v)} for k, v in self.objects.items()]
        return _Pages([{"Contents": contents}])

    def get_object(self, Bucket, Key):  # noqa: N803 - boto3's argument names
        self.reads.append(Key)
        return {"Body": io.BytesIO(self.objects[Key])}


class FakeSSM:
    def __init__(self, parameters, *, deny: bool = False):
        self.parameters, self.deny = parameters, deny

    def get_paginator(self, _name):
        if self.deny:
            raise PermissionError("AccessDenied")
        return _Pages([{"Parameters": self.parameters}])


def fake_key() -> str:
    return "AKIA" + "IOSFODNN7" + "EXAMPLE"


def test_state_file_outside_the_backend_is_found():
    s3 = FakeS3({"backup/terraform.tfstate": b"{}", "notes.txt": b"nothing here"})
    findings = scan_s3_objects(s3, "app-artifacts", state_bucket="team-state")
    assert [f.detail for f in findings] == [
        "Terraform state or plan stored outside the state backend"
    ]
    assert findings[0].control_id == "TG-P14"


def test_state_in_the_backend_is_expected_and_not_read():
    s3 = FakeS3({"baseline/terraform.tfstate": b'{"password": "x"}'})
    assert scan_s3_objects(s3, "team-state", state_bucket="team-state") == []
    assert s3.reads == []


def test_key_and_password_in_objects_are_found_and_never_echoed():
    planted = "Pr0d" + "DbPass!"
    s3 = FakeS3(
        {
            "config/app.env": f"AWS_ACCESS_KEY_ID={fake_key()}\n".encode(),
            "config/db.yaml": f"db_password: {planted}\n".encode(),
        }
    )
    findings = scan_s3_objects(s3, "app-config")
    details = " ".join(f.detail for f in findings)
    assert "AWS access key id found in an S3 object" in details
    assert "sensitive key 'db_password'" in details
    assert fake_key() not in details and planted not in details


def test_logs_and_compressed_objects_are_skipped():
    s3 = FakeS3({"AWSLogs/1/trail.json.gz": b"\x1f\x8b", "x.zip": b"PK"})
    assert scan_s3_objects(s3, "trail-logs") == []
    assert s3.reads == []


def test_a_bucket_that_cannot_be_listed_is_indeterminate_not_clean():
    findings = scan_s3_objects(FakeS3({}, deny=True), "locked")
    assert len(findings) == 1 and findings[0].raw["indeterminate"]


def test_plaintext_ssm_parameter_named_like_a_secret_is_found():
    ssm = FakeSSM(
        [
            {"Name": "/app/db_password", "Type": "String"},
            {"Name": "/app/api_key", "Type": "SecureString"},
            {"Name": "/app/region", "Type": "String"},
        ]
    )
    findings = scan_ssm_parameters(ssm)
    assert [f.resource_address for f in findings] == ["ssm:/app/db_password"]


def test_ssm_without_permission_is_indeterminate():
    findings = scan_ssm_parameters(FakeSSM([], deny=True))
    assert len(findings) == 1 and findings[0].raw["indeterminate"]


def test_extension_control_stays_out_of_the_experiment_catalogue():
    """TG-P14 must not change the 13-control assessment behind every recorded result."""
    experiment = load_controls("policies", include_optional=True)
    assert "TG-P14" not in {c.id for c in experiment}
    assert len(experiment) == 13
    assert [c.id for c in load_controls("policies", only_extension=True)] == ["TG-P14"]
