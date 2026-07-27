package decrypt

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestDecryptAlreadyPlainWxapkg(t *testing.T) {
	// 构造最小明文 wxapkg 头: firstMark=0xBE ... lastMark=0xED
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, byte(0xBE))
	_ = binary.Write(buf, binary.BigEndian, uint32(0))
	_ = binary.Write(buf, binary.BigEndian, uint32(0))
	_ = binary.Write(buf, binary.BigEndian, uint32(0))
	_ = binary.Write(buf, binary.BigEndian, byte(0xED))
	buf.WriteString("payload")

	dir := t.TempDir()
	path := filepath.Join(dir, "plain.wxapkg")
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	out, err := DecryptWxapkg(path, "wx1234567890ab")
	if err != nil {
		t.Fatalf("DecryptWxapkg: %v", err)
	}
	if !bytes.Equal(out, buf.Bytes()) {
		t.Fatal("plain package should pass through")
	}
}

func TestDecryptInvalidHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.wxapkg")
	if err := os.WriteFile(path, []byte("not-a-wxapkg"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptWxapkg(path, "wx1234567890ab"); err == nil {
		t.Fatal("expected invalid format error")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	// 明文前 14 字节模拟 header + 数据
	plain := make([]byte, 2048)
	plain[0] = 0xBE
	plain[13] = 0xED
	copy(plain[14:], []byte("hello-gwxapkg-roundtrip-data"))

	appID := "wxabcdef012345"
	enc, err := EncryptWxapkg(plain, appID)
	if err != nil {
		t.Fatalf("EncryptWxapkg: %v", err)
	}
	if string(enc[:6]) != fileHeader {
		t.Fatalf("missing V1MMWX header")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "enc.wxapkg")
	if err := os.WriteFile(path, enc, 0644); err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptWxapkg(path, appID)
	if err != nil {
		t.Fatalf("DecryptWxapkg: %v", err)
	}
	// 解密后前 1023 字节来自 AES，最后可能有 padding 差异；校验有效载荷片段
	if !bytes.Contains(dec, []byte("hello-gwxapkg-roundtrip-data")) {
		t.Fatalf("round-trip payload missing, dec[:64]=%q", dec[:min(64, len(dec))])
	}
}
