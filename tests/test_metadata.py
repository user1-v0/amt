import hashlib
import zipfile
from pathlib import Path
from xml.etree.ElementTree import ParseError

import pytest

from tools.metadata import file_identity, parse_manifest_xml, resolve_class_name, signature_fingerprints, split_label

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app"
    android:versionName="1.2.3"
    android:versionCode="4">
  <uses-permission android:name="android.permission.SEND_SMS"/>
  <application android:name=".App" android:label="@string/app_name">
    <activity android:name=".Main" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
      </intent-filter>
    </activity>
    <service android:name="com.example.app.Worker" android:exported="false"/>
    <receiver android:name=".Boot">
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED"/>
      </intent-filter>
    </receiver>
    <provider android:name=".Store" android:exported="false"/>
  </application>
</manifest>
"""


def test_file_identity_hashes_bytes(tmp_path: Path):
    sample = tmp_path / "sample.apk"
    sample.write_bytes(b"abc")
    identity = file_identity(sample)
    assert identity.name == "sample.apk"
    assert identity.size == 3
    assert identity.md5 == hashlib.md5(b"abc").hexdigest()
    assert identity.sha1 == hashlib.sha1(b"abc").hexdigest()
    assert identity.sha256 == hashlib.sha256(b"abc").hexdigest()


def test_parse_manifest_resolves_classes_and_keeps_resource_label():
    facts = parse_manifest_xml(MANIFEST)
    assert facts.package == "com.example.app"
    assert facts.version_name == "1.2.3"
    assert facts.version_code == "4"
    assert facts.app_label is None
    assert facts.app_label_ref == "@string/app_name"
    assert facts.application_class == "com.example.app.App"
    assert facts.permissions == ["android.permission.SEND_SMS"]
    kinds = {component.name: component for component in facts.components}
    assert kinds["com.example.app.Main"].exported is True
    assert kinds["com.example.app.Main"].actions == ["android.intent.action.MAIN"]
    assert kinds["com.example.app.Worker"].kind == "service"
    assert kinds["com.example.app.Worker"].exported is False
    assert kinds["com.example.app.Boot"].exported is None
    assert kinds["com.example.app.Store"].kind == "provider"


def test_literal_label_and_relative_class():
    label, ref = split_label("Demo App")
    assert label == "Demo App"
    assert ref is None
    assert resolve_class_name("MainActivity", "com.example.app") == "com.example.app.MainActivity"
    assert resolve_class_name(".ui.Main", "com.example.app") == "com.example.app.ui.Main"


def test_oversized_manifest_is_rejected():
    with pytest.raises((ValueError, ParseError)):
        parse_manifest_xml("x" * 2_000_001)


def test_signature_fingerprint_hashes_the_cert(tmp_path: Path):
    apk = tmp_path / "app.apk"
    body = b"certificate-bytes"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("META-INF/CERT.RSA", body)
        archive.writestr("classes.dex", b"dex")
    found = signature_fingerprints(apk)
    assert len(found) == 1
    assert found[0].name == "META-INF/CERT.RSA"
    assert found[0].sha256 == hashlib.sha256(body).hexdigest()
