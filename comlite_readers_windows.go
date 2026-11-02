//go:build windows

package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Read-only Rutoken COM Lite device discovery. This never requests a PIN,
// authenticates, selects filesystem objects, or reads container data.
// Each bitness runs in a separate cscript.exe process with a strict timeout.
const comReadersScript = `WScript.Echo("SCAN_START");
var context = null;
function code(e) {
  var n = (e && typeof e.number == "number") ? (e.number >>> 0) : 0;
  return ("00000000" + n.toString(16)).slice(-8).toUpperCase();
}
function enc(v) {
  try { return encodeURIComponent(String(v)); } catch (e) { return "unavailable"; }
}
try {
  context = new ActiveXObject("rtCOMLite.rtContext");
  WScript.Echo("COM_READY");
  context.Acquire();
  WScript.Echo("ACQUIRE_OK");
  var variant = context.EnumReaders();
  var names = (variant == null) ? [] : (new VBArray(variant)).toArray();
  WScript.Echo("COUNT:" + names.length);
  var limit = Math.min(names.length, 12);
  for (var i=0; i<limit; ++i) {
    var name = String(names[i]);
    WScript.Echo("READER:" + i + ":" + enc(name));
    var reader = null;
    try {
      reader = context.OpenReader(name, 2, 2500);
      WScript.Echo("OPEN_OK:" + i);
      try { WScript.Echo("MODEL:" + i + ":" + enc(reader.ModelName)); }
      catch (e) { WScript.Echo("MODEL_ERROR:" + i + ":" + code(e)); }
      try { WScript.Echo("VERSION:" + i + ":" + enc(reader.Version)); }
      catch (e) { WScript.Echo("VERSION_ERROR:" + i + ":" + code(e)); }
    } catch (e) {
      WScript.Echo("OPEN_ERROR:" + i + ":" + code(e));
    } finally {
      if (reader != null) {
        try { context.CloseReader(reader, 0); WScript.Echo("CLOSE_OK:" + i); }
        catch (e) { WScript.Echo("CLOSE_ERROR:" + i + ":" + code(e)); }
      }
    }
  }
  if (names.length > limit) WScript.Echo("TRUNCATED:" + (names.length-limit));
  WScript.Echo("SCAN_FINISHED");
} catch (e) {
  WScript.Echo("SCAN_ERROR:" + code(e));
} finally {
  if (context != null) {
    try { context.Free(); WScript.Echo("FREE_OK"); }
    catch (e) { WScript.Echo("FREE_ERROR:" + code(e)); }
  }
}
`

const comReadersTimeout = 20 * time.Second

func findCOMReaders(arch string) string {
	if arch != "32" && arch != "64" {
		return "Недопустимая разрядность"
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	folder := "System32"
	if arch == "32" {
		folder = "SysWOW64"
	}
	host := filepath.Join(root, folder, "cscript.exe")
	st, err := os.Stat(host)
	if err != nil || st.IsDir() {
		return "Windows Script Host отсутствует"
	}
	tmp, err := os.CreateTemp("", "ri-com-readers-*.js")
	if err != nil {
		return "Не удалось создать временный сценарий"
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = tmp.WriteString(comReadersScript); err != nil {
		tmp.Close()
		return "Ошибка записи сценария"
	}
	if err = tmp.Close(); err != nil {
		return "Ошибка подготовки сценария"
	}
	ctx, cancel := context.WithTimeout(context.Background(), comReadersTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, host, comProbeHostArgs(name)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	raw, execErr := cmd.CombinedOutput()
	return formatCOMReaderResult(raw, execErr, ctx.Err() != nil)
}

func formatCOMReaderResult(raw []byte, execErr error, timedOut bool) string {
	// JScript emits only ASCII markers and URL-encoded Unicode device labels.
	// Never show uncontrolled output from the script host or drivers.
	txt := string(raw)
	var result strings.Builder
	var count int = -1
	lines := strings.Split(strings.ReplaceAll(txt, "\r", ""), "\n")
	started, ready, acquired, finished := false, false, false, false
	readers := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch line {
		case "SCAN_START":
			started = true
		case "COM_READY":
			ready = true
		case "ACQUIRE_OK":
			acquired = true
		case "SCAN_FINISHED":
			finished = true
		}
		if strings.HasPrefix(line, "COUNT:") {
			n, err := strconv.Atoi(strings.TrimPrefix(line, "COUNT:"))
			if err == nil && n >= 0 && n <= 1000 {
				count = n
			}
		}
		for _, kind := range []string{"READER", "MODEL", "VERSION"} {
			prefix := kind + ":"
			if !strings.HasPrefix(line, prefix) {
				continue
			}
			rest := strings.TrimPrefix(line, prefix)
			sep := strings.IndexByte(rest, ':')
			if sep < 1 {
				continue
			}
			idx, err := strconv.Atoi(rest[:sep])
			if err != nil || idx < 0 || idx >= 12 {
				continue
			}
			value := rest[sep+1:]
			if len(value) > 1024 {
				continue
			}
			decoded, err := url.PathUnescape(value)
			if err != nil {
				continue
			}
			decoded = strings.Map(func(r rune) rune {
				if r == '\r' || r == '\n' || r < 32 {
					return -1
				}
				return r
			}, decoded)
			if len([]rune(decoded)) > 160 {
				decoded = string([]rune(decoded)[:160]) + "…"
			}
			if kind == "READER" {
				result.WriteString(fmt.Sprintf("  %d. Считыватель: %s\r\n", idx+1, decoded))
				readers++
			}
			if kind == "MODEL" {
				result.WriteString("     Модель: " + decoded + "\r\n")
			}
			if kind == "VERSION" {
				result.WriteString("     Версия: " + decoded + "\r\n")
			}
		}
		for _, kind := range []string{"SCAN_ERROR", "OPEN_ERROR", "MODEL_ERROR", "VERSION_ERROR", "CLOSE_ERROR", "FREE_ERROR"} {
			if !strings.HasPrefix(line, kind+":") {
				continue
			}
			parts := strings.Split(line, ":")
			h := parts[len(parts)-1]
			if len(h) == 8 && isHexHRESULT(h) {
				result.WriteString("  " + kind + " (HRESULT 0x" + h + ")\r\n")
			}
		}
		if strings.HasPrefix(line, "TRUNCATED:") {
			result.WriteString("  Часть считывателей не показана (лимит: 12).\r\n")
		}
	}
	if count >= 0 {
		result.WriteString(fmt.Sprintf("Считывателей по COM: %d. Отображено: %d.\r\n", count, readers))
	}
	if timedOut {
		stage := "Windows Script Host"
		if ready {
			stage = "COM Lite (Acquire / EnumReaders / OpenReader / завершение)"
		}
		return "Тайм-аут (20 с) на этапе: " + stage + ".\r\n" + result.String()
	}
	if execErr != nil && !ready {
		return "Не удалось запустить JScript или COM: " + execErr.Error()
	}
	if !started {
		return "Нет подтверждения запуска JScript (статус неизвестен)"
	}
	if !ready {
		return "COM Lite не создан.\r\n" + result.String()
	}
	if !acquired {
		return "COM Lite создан, но Acquire не завершён успешно.\r\n" + result.String()
	}
	if !finished {
		return "Операция прервана до окончания перечисления.\r\n" + result.String()
	}
	if count == 0 {
		return "COM Lite работает. Подключённых считывателей не найдено.\r\n"
	}
	return "COM Lite работает. Обнаружение завершено.\r\n" + result.String()
}

func isHexHRESULT(s string) bool {
	if len(s) != 8 {
		return false
	}
	for _, ch := range s {
		if !((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F')) {
			return false
		}
	}
	return true
}

func auditCOMReaders() string {
	var b strings.Builder
	b.WriteString("РУТОКЕН ЧЕРЕЗ COM LITE — ЧТЕНИЕ ТОЛЬКО СВЕДЕНИЙ ОБ УСТРОЙСТВЕ\r\n")
	b.WriteString("Используются Acquire, EnumReaders, OpenReader (SHARED), ModelName и Version.\r\n")
	b.WriteString("PIN, файлы и закрытые ключи не запрашиваются. Запрос записи не выполняется.\r\n")
	b.WriteString("Результаты 32- и 64-битных проверок могут различаться.\r\n\r\n")
	for _, arch := range []string{"32", "64"} {
		start := time.Now()
		b.WriteString(arch + "-bit:\r\n" + findCOMReaders(arch))
		b.WriteString(fmt.Sprintf("Проверка: %.1f с\r\n\r\n", time.Since(start).Seconds()))
	}
	b.WriteString("Важно: обнаружение Рутокена не означает разрешение на копирование контейнера.\r\n")
	return b.String()
}