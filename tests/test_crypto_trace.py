import base64

from tools.crypto_trace import render_crypto_report, trace_source


def test_base64_literal_in_the_same_method_is_decoded():
    blob = base64.b64encode(b"http://example.test/payload.dex").decode("ascii")
    source = f"""
public class Loader {{
  public void load() {{
    String blob = "{blob}";
    byte[] raw = Base64.decode(blob, 0);
  }}
}}
"""
    hits = trace_source("dex/Loader.java", source)
    assert len(hits) == 1
    assert hits[0].via == "base64"
    assert hits[0].kind == "text"
    assert "http://example.test/payload.dex" in hits[0].detail
    assert "Base64.decode" in hits[0].quote
    assert "via=base64" in render_crypto_report(hits)


def test_xor_uses_the_literal_key_in_the_method():
    source = """
void decode() {
  byte[] data = new byte[]{68, 69, 88, 42, 0, 0, 0, 0};
  for (int i = 0; i < data.length; i++) data[i] ^= 0x20;
}
"""
    hits = trace_source("dex/Decoder.java", source)
    assert hits[0].via == "static-xor"
    assert hits[0].kind == "dex"


def test_cipher_without_a_static_key_is_not_decoded():
    source = """
void protect(byte[] incoming) {
  Cipher cipher = Cipher.getInstance(incoming[0] == 0 ? "A" : "B");
  cipher.init(Cipher.DECRYPT_MODE, incomingKey);
}
"""
    hits = trace_source("dex/Guard.java", source)
    assert hits[0].via == "cipher"
    assert hits[0].kind == ""
    assert hits[0].size == 0
