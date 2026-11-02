package main

// Audit-grade export of readable PUBLIC PKCS#11 objects.
// No private/secret key value extraction and no token writes.

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type dumpFile struct {
	Path   string `json:"path"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
	Source string `json:"source"`
}

type dumpIntegrity struct {
	Schema       string     `json:"schema"`
	GeneratedUTC string     `json:"generated_utc"`
	Files        []dumpFile `json:"files"`
}

type dumpCompatibility struct {
	Format                       string   `json:"format"`
	CryptoProCSPFileContainer    bool     `json:"cryptopro_csp_file_container"`
	CanSignWithoutToken          bool     `json:"can_sign_without_token"`
	PrivateKeyCount              int      `json:"private_key_count"`
	PrivateKeyValuesExported     int      `json:"private_key_values_exported"`
	PrivateKeyExportRestrictions []string `json:"private_key_export_restrictions"`
	Note                         string   `json:"note"`
}

func upperSHA(v []byte) string {
	h := sha256.Sum256(v)
	return strings.ToUpper(hex.EncodeToString(h[:]))
}
func pemCertificate(data []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	b.WriteString("-----BEGIN CERTIFICATE-----\n")
	for len(b64) > 64 {
		b.WriteString(b64[:64])
		b.WriteByte('\n')
		b64 = b64[64:]
	}
	if b64 != "" {
		b.WriteString(b64)
		b.WriteByte('\n')
	}
	b.WriteString("-----END CERTIFICATE-----\n")
	return []byte(b.String())
}

func writeEnhancedDumpZIP(path string, report *scanReport) error {
	if report == nil {
		return fmt.Errorf("не выполнено сканирование")
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".rutoken-dump-*.zip")
	if err != nil {
		return err
	}
	tmpName := temp.Name()
	defer os.Remove(tmpName)
	zw := zip.NewWriter(temp)
	integrity := dumpIntegrity{Schema: "rutoken-inspector-integrity-v1", GeneratedUTC: time.Now().UTC().Format(time.RFC3339), Files: []dumpFile{}}
	put := func(name, source string, v []byte, track bool) error {
		f, er := zw.Create(name)
		if er != nil {
			return er
		}
		if _, er = f.Write(v); er != nil {
			return er
		}
		if track {
			integrity.Files = append(integrity.Files, dumpFile{Path: name, Size: len(v), SHA256: upperSHA(v), Source: source})
		}
		return nil
	}
	fail := func(e error) error { _ = zw.Close(); _ = temp.Close(); return e }
	meta, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fail(err)
	}
	if err = put("manifest.json", "scan-report", meta, true); err != nil {
		return fail(err)
	}
	compat := dumpCompatibility{Format: "PKCS#11 public logical snapshot (NOT CryptoPro container)", CryptoProCSPFileContainer: false, CanSignWithoutToken: false, PrivateKeyValuesExported: 0, PrivateKeyExportRestrictions: []string{}, Note: "Archive does NOT contain a signing private key. Copying or renaming files cannot create an independent CryptoPro signing container."}
	for i, o := range report.Objects {
		detail, er := json.MarshalIndent(o, "", "  ")
		if er != nil {
			return fail(er)
		}
		if er = put(fmt.Sprintf("objects/%03d_attributes.json", i), fmt.Sprintf("object[%d]-metadata", i), detail, true); er != nil {
			return fail(er)
		}
		if o.Class == "Закрытый ключ" || o.Class == "Секретный ключ" {
			compat.PrivateKeyCount++
			compat.PrivateKeyExportRestrictions = append(compat.PrivateKeyExportRestrictions, fmt.Sprintf("object[%d]: extractable=%v; never_extractable=%v; sensitive=%v", i, o.Attributes["CKA_EXTRACTABLE"], o.Attributes["CKA_NEVER_EXTRACTABLE"], o.Attributes["CKA_SENSITIVE"]))
			continue
		}
		// Certificates are normally public but respect explicit CKA_PRIVATE=true.
		if o.Attributes["CKA_PRIVATE"] == true {
			continue
		}
		if o.Class == "Сертификат" && len(o.Cert) > 0 {
			if len(o.Cert) != o.CertLength || upperSHA(o.Cert) != o.CertSHA256 {
				return fail(fmt.Errorf("сертификат %d: несовпадение длины или SHA256", i))
			}
			if er = put(fmt.Sprintf("public/%03d_certificate.cer", i), "CKA_VALUE of public X.509 certificate", o.Cert, true); er != nil {
				return fail(er)
			}
			if er = put(fmt.Sprintf("public/%03d_certificate.pem", i), "PEM encoding of public certificate", pemCertificate(o.Cert), true); er != nil {
				return fail(er)
			}
		}
		if (o.Class == "Открытый ключ" || o.Class == "Объект данных") && o.DataRead == "ok" {
			if len(o.PublicData) != o.DataLength || upperSHA(o.PublicData) != o.DataSHA256 {
				return fail(fmt.Errorf("публичный объект %d: несовпадение длины или SHA256", i))
			}
			if len(o.PublicData) > 1024*1024 {
				return fail(fmt.Errorf("публичный объект %d превышает предел 1 МБ", i))
			}
			kind := "data"
			if o.Class == "Открытый ключ" {
				kind = "public_key"
			}
			if er = put(fmt.Sprintf("public/%03d_%s.bin", i, kind), "public PKCS#11 CKA_VALUE", o.PublicData, true); er != nil {
				return fail(er)
			}
		}
	}
	b, err := json.MarshalIndent(compat, "", "  ")
	if err != nil {
		return fail(err)
	}
	if err = put("compatibility.json", "compatibility-statement", b, true); err != nil {
		return fail(err)
	}
	readme := `Rutoken Inspector 3 v0.9 — расширенный логический дамп (только чтение)

manifest.json           Модель, слот, успешность C_Login, объекты и атрибуты.
objects/*.json          Доступные атрибуты каждого объекта (без секретных значений).
public/*.cer, *.pem     Доступные публичные X.509 сертификаты.
public/*.bin            Значения публичных объектов PKCS#11.
integrity.json          Контрольные суммы SHA-256 и точные размеры выгруженных файлов.
compatibility.json      Статус совместимости с контейнерами КриптоПро CSP.

Этот ZIP не содержит CKA_VALUE закрытого/секретного ключа и НЕ является
контейнером КриптоПро. Он не воспроизводит файловую систему токена
и не позволяет подписывать без оригинального аппаратного ключа.
PIN, содержимое закрытого ключа и пароли в архив не записываются.
`
	if err = put("README.txt", "documentation", []byte(readme), true); err != nil {
		return fail(err)
	}
	ib, err := json.MarshalIndent(integrity, "", "  ")
	if err != nil {
		return fail(err)
	}
	if err = put("integrity.json", "file-integrity", ib, false); err != nil {
		return fail(err)
	}
	if err = zw.Close(); err != nil {
		_ = temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	if err = verifyEnhancedZIP(tmpName, integrity); err != nil {
		return err
	}
	// Never delete a prior archive before successfully replacing it.
	// On Windows, use a new filename if the destination is currently locked.
	return os.Rename(tmpName, path)
}

func verifyEnhancedZIP(path string, metadata dumpIntegrity) error {
	z, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer z.Close()
	byName := make(map[string]*zip.File, len(z.File))
	for _, f := range z.File {
		if _, exists := byName[f.Name]; exists {
			return fmt.Errorf("дублированный путь %q", f.Name)
		}
		byName[f.Name] = f
	}
	for _, item := range metadata.Files {
		f, ok := byName[item.Path]
		if !ok {
			return fmt.Errorf("архив неполон: нет %s", item.Path)
		}
		r, er := f.Open()
		if er != nil {
			return er
		}
		data, er := io.ReadAll(io.LimitReader(r, 12*1024*1024))
		_ = r.Close()
		if er != nil {
			return er
		}
		if len(data) != item.Size || upperSHA(data) != item.SHA256 {
			return fmt.Errorf("контрольная сумма или размер %s не совпадает", item.Path)
		}
	}
	if _, ok := byName["integrity.json"]; !ok {
		return fmt.Errorf("отсутствует integrity.json")
	}
	return nil
}