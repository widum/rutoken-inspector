//go:build windows

package main

import (
	"fmt"
	"strings"
)

// auditDeviceAndCSP is read-only: it asks Rutoken COM Lite for reader labels,
// then asks CryptoPro CSP to enumerate public container identifiers.
// It does NOT read token files or keys, authenticate, or change HDIMAGE.
func auditDeviceAndCSP() string {
	var b strings.Builder
	b.WriteString("СВЕРКА РУТОКЕНА И КРИПТОПРО — ТОЛЬКО ЧТЕНИЕ\r\n")
	b.WriteString("COM Lite определяет физический считыватель; КриптоПро перечисляет имена контейнеров.\r\n")
	b.WriteString("PIN не нужен. Содержимое закрытых ключей не читается.\r\n\r\n")
	b.WriteString("РУТОКЕН ЧЕРЕЗ COM LITE\r\n")
	for _, arch := range []string{"32", "64"} {
		b.WriteString(arch + "-bit: " + findCOMReaders(arch) + "\r\n")
	}
	b.WriteString("\r\nКРИПТОПРО CSP 5 — ИМЕНА КОНТЕЙНЕРОВ\r\n")
	names, diagnostic, errText := enumerateCSPContainers()
	if errText != "" {
		b.WriteString("Ошибка перечисления: " + errText + "\r\n")
	} else {
		ordered, inventory := summarizeCSPInventory(names)
		b.WriteString(inventory + "\r\n\r\n")
		for i, name := range ordered {
			b.WriteString(fmt.Sprintf("%d. %s\r\n", i+1, name))
		}
		if len(ordered) == 0 {
			b.WriteString("Контейнеров не найдено.\r\n")
		}
	}
	if diagnostic != "" && errText != "" {
		b.WriteString("Дополнительные данные CSP: " + diagnostic + "\r\n")
	}
	b.WriteString("\r\nОГРАНИЧЕНИЯ СВЕРКИ\r\n")
	b.WriteString("Совпадение названий считывателей или имён контейнеров не доказывает совпадение закрытых ключей.\r\n")
	b.WriteString("Проверять работоспособность локальной подписи необходимо отдельно, без физического носителя.\r\n")
	b.WriteString("Новая файловая копия в HDIMAGE этой проверкой НЕ создаётся.\r\n")
	return b.String()
}