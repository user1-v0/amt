from schemas import (
    Component,
    Evidence,
    FileIdentity,
    Finding,
    NativeLib,
    Report,
    SampleFacts,
    Verdict,
    Verification,
    enforce_verdict,
    report_from_dict,
)
from tools.native_decompiler import SoMember, rank_symbols, select_native
from utils.limits import select_names, truncate


def _facts() -> SampleFacts:
    identity = FileIdentity("app.apk", 3, "m", "s1", "s256")
    return SampleFacts(
        original=identity,
        container="apk",
        base_apk="app.apk",
        members=[],
        apks=[identity],
        package="com.example.app",
        version_name="1",
        version_code="1",
        app_label=None,
        app_label_ref="@string/app_name",
        application_class="com.example.app.App",
        permissions=["android.permission.INTERNET"],
        components=[Component("activity", "com.example.app.Main", True, ["MAIN"])],
        native_libs=[
            NativeLib("app.apk", "arm64-v8a", "libdemo.so", "native/arm64-v8a/libdemo.so", 4, "ok")
        ],
    )


def test_report_round_trip():
    report = Report(
        facts=_facts(),
        hypotheses=[
            Finding("f1", "sends sms", [Evidence("dex/Main.java", "Main", "sendSms")], "medium")
        ],
        verification=[Verification("f1", "supported", "dex/Main.java contains sendSms")],
        verdict=Verdict("malicious", "sms", "high", "Hidden SMS behavior.", ["f1"], True, "trojan"),
        artifact_paths=["manifest.xml"],
        errors=[],
    )
    restored = report_from_dict(report.to_dict())
    assert restored.facts.package == "com.example.app"
    assert restored.hypotheses[0].evidence[0].quote == "sendSms"
    assert restored.verdict is not None
    assert restored.verdict.family == "sms"
    assert restored.verdict.malicious is True


def test_enforce_verdict_drops_unsupported_malware_label():
    forced, note = enforce_verdict(
        Verdict("trojan", "spyware", "high", "Looks hostile.", ["f1"]),
        [],
    )
    assert forced.verdict == "inconclusive"
    assert forced.malware_type == "clean"
    assert forced.family == "unknown"
    assert forced.malicious is False
    assert forced.supporting_finding_ids == []
    assert note is not None

    kept, clean_note = enforce_verdict(
        Verdict("malicious", "sms", "high", "Hidden SMS behavior.", ["f1", "f9"], True, "trojan"),
        ["f1"],
        [Verification("f1", "supported", "dex/Sms.java")],
        [Finding("f1", "the app calls sendTextMessage", [], "high")],
    )
    assert kept.supporting_finding_ids == ["f1"]
    assert kept.verdict == "malicious"
    assert kept.malware_type == "trojan"
    assert kept.family == "sms"
    assert kept.malicious is True
    assert clean_note is None

    medium, medium_note = enforce_verdict(
        Verdict("malicious", "spyware", "medium", "Hidden collection.", ["f1"], True, "trojan"),
        ["f1"],
        [Verification("f1", "supported", "dex/Spy.java")],
        [Finding("f1", "exfiltrates contacts to a remote server", [], "medium")],
    )
    assert medium.verdict == "malicious"
    assert medium.malware_type == "trojan"
    assert medium.family == "spyware"
    assert medium.confidence == "medium"
    assert medium.malicious is True
    assert medium_note is None

    relabeled, _note = enforce_verdict(
        Verdict("pup", "none", "low", "Aggressive ads.", ["f1"]),
        ["f1"],
        [Verification("f1", "supported", "dex/Ads.java")],
        [Finding("f1", "shows aggressive advertising", [], "low")],
    )
    assert relabeled.verdict == "malicious"
    assert relabeled.malware_type == "pup"
    assert relabeled.family == "adware"
    assert relabeled.malicious is True

    capped, _note = enforce_verdict(
        Verdict("malicious", "adware", "high", "Sure ads.", ["f1"], True, "pup"),
        ["f1"],
        [Verification("f1", "supported", "dex/Ads.java")],
        [Finding("f1", "shows aggressive advertising", [], "low")],
    )
    assert capped.confidence == "low"
    assert capped.malware_type == "pup"


def test_supported_finding_is_a_malicious_pup():
    unsure, note = enforce_verdict(
        Verdict("clean", "none", "low", "Nothing obvious.", []),
        ["f1"],
        [Verification("f1", "supported", "dex/Main.java")],
        [Finding("f1", "ordinary startup", [], "low")],
    )
    assert unsure.verdict == "malicious"
    assert unsure.malware_type == "pup"
    assert unsure.malicious is True
    assert note is not None

    unresolved, unresolved_note = enforce_verdict(
        Verdict("clean", "none", "high", "Looks ordinary.", []),
        [],
        [Verification("f1", "insufficient", "could not open the class")],
    )
    assert unresolved.verdict == "inconclusive"
    assert unresolved.malware_type == "clean"
    assert unresolved.family == "unknown"
    assert unresolved.malicious is False
    assert unresolved_note is not None

    cleared, cleared_note = enforce_verdict(
        Verdict("clean", "none", "high", "Rejected claims were ordinary.", []),
        [],
        [Verification("f1", "unsupported", "the quote is absent")],
    )
    assert cleared.verdict == "clean"
    assert cleared.malware_type == "clean"
    assert cleared.family == "none"
    assert cleared.malicious is False
    assert cleared_note is None


def test_family_comes_from_behavior_not_a_denied_word():
    from schemas import infer_category

    spyware, _note = enforce_verdict(
        Verdict("inconclusive", "adware", "low", "Unwanted behavior.", ["f1"], False, "pup"),
        ["f1"],
        [Verification("f1", "supported", "dex/Listener.java")],
        [Finding("f1", "exfiltrates notifications over a socket", [], "high")],
    )
    assert spyware.verdict == "malicious"
    assert spyware.malware_type == "trojan"
    assert spyware.family == "spyware"
    assert spyware.confidence == "high"
    assert spyware.malicious is True

    denied, _note = enforce_verdict(
        Verdict(
            "pup",
            "unknown",
            "medium",
            "None of these behaviors shows credential collection, so this is not a banker.",
            ["f1"],
        ),
        ["f1"],
        [Verification("f1", "supported", "dex/Update.java")],
        [Finding("f1", "downloads an APK into the public Downloads directory", [], "medium")],
    )
    assert denied.verdict == "malicious"
    assert denied.malware_type == "pup"
    assert denied.family == "dropper"
    assert denied.malicious is True
    assert denied.summary.startswith("Label malicious, type pup, family dropper.")
    assert infer_category("shows aggressive advertising") == "adware"


def test_label_follows_the_behavior_that_was_shown():
    hidden, _note = enforce_verdict(
        Verdict("pup", "adware", "low", "Verdict: pup, type adware, family adware.", ["f1"]),
        ["f1"],
        [Verification("f1", "supported", "dex/App.java")],
        [Finding("f1", "The Application class is heavily obfuscated. The excerpt shows no payload loading.", [], "low")],
    )
    assert hidden.verdict == "inconclusive"
    assert hidden.malware_type == "trojan"
    assert hidden.family == "unknown"
    assert hidden.malicious is False

    packer, _note = enforce_verdict(
        Verdict("pup", "adware", "low", "Packed.", ["f1"]),
        ["f1"],
        [Verification("f1", "supported", "dex/App.java")],
        [Finding(
            "f1",
            "Application class is a Jiagu packer stub. It loads the real application class from the hidden payload.",
            [],
            "medium",
        )],
    )
    assert packer.verdict == "malicious"
    assert packer.malware_type == "trojan"
    assert packer.family == "dropper"
    assert packer.confidence == "medium"

    unconfirmed, _note = enforce_verdict(
        Verdict("pup", "adware", "medium", "Maybe a crack.", ["f1"]),
        ["f1"],
        [Verification("f1", "supported", "dex/App.java")],
        [Finding("f1", "The class can spoof the APK signature. I did not confirm what it hooks.", [], "medium")],
    )
    assert unconfirmed.verdict == "inconclusive"
    assert unconfirmed.malware_type == "trojan"
    assert unconfirmed.malicious is False

    updater, _note = enforce_verdict(
        Verdict("inconclusive", "unknown", "medium", "Verdict: pup, type unknown, family unknown. Self update.", ["f1"], False, "pup"),
        ["f1"],
        [Verification("f1", "supported", "dex/Update.java")],
        [Finding("f1", "The app has an in-app updater. It downloads an APK into the public Downloads directory.", [], "medium")],
    )
    assert updater.verdict == "malicious"
    assert updater.malware_type == "pup"
    assert updater.family == "dropper"
    assert updater.summary.startswith("Label malicious, type pup, family dropper.")


def test_select_native_prefers_arm64_and_skips_other_abis():
    def member(abi: str, soname: str) -> SoMember:
        return SoMember("a.apk", "a.apk", f"lib/{abi}/{soname}", abi, soname, 10)

    chosen = select_native(
        [
            member("x86_64", "liba.so"),
            member("arm64-v8a", "liba.so"),
            member("x86", "libonlyx86.so"),
        ]
    )
    assert [(item.soname, item.abi) for item in chosen] == [("liba.so", "arm64-v8a")]

    fallback = select_native([member("x86_64", "liba.so")])
    assert fallback[0].abi == "x86_64"


def test_rank_symbols_puts_jni_first_and_caps():
    exports = [{"name": f"exp{index}", "vaddr": index} for index in range(40)]
    exports.append({"name": "JNI_OnLoad", "vaddr": 99})
    functions = [{"name": "sym.Java_com_example_App_start", "offset": 7}]
    ranked = rank_symbols(exports, functions)
    assert len(ranked) == 30
    assert ranked[0]["name"] == "JNI_OnLoad"
    assert ranked[1]["name"] == "sym.Java_com_example_App_start"


def test_truncate_and_select_names():
    text, truncated = truncate("abcdef", 3)
    assert truncated is True
    assert text.startswith("abc")
    assert select_names(["A", "A", "", "B", "C"], 2) == ["A", "B"]
