package main

import (
	"fmt"
	"sort"
	"strings"
)

type cspContainerRef struct {
	reader, name     string
	isLocal, isToken bool
}

func splitCSPFQCN(fqcn string) cspContainerRef {
	s := strings.TrimPrefix(strings.TrimSpace(fqcn), `\\.\`)
	pieces := strings.SplitN(s, `\`, 2)
	if len(pieces) < 2 {
		return cspContainerRef{}
	}
	r := cspContainerRef{reader: pieces[0], name: pieces[1]}
	r.isLocal = strings.EqualFold(r.reader, "HDIMAGE")
	reader := strings.ToLower(r.reader)
	r.isToken = strings.Contains(reader, "rutoken") || strings.Contains(reader, "rutok") || strings.Contains(reader, "scard") || strings.Contains(reader, "token")
	return r
}

func matchingHDIMAGE(tokenFQCN string, all []string) string {
	target := splitCSPFQCN(tokenFQCN)
	if !target.isToken || target.name == "" {
		return ""
	}
	for _, fqcn := range all {
		ref := splitCSPFQCN(fqcn)
		if ref.isLocal && strings.EqualFold(ref.name, target.name) {
			return fqcn
		}
	}
	return ""
}

// Summarizes only reader paths and identifiers returned by CryptoPro. It never
// claims a local container contains the same private key as one on a token.
func summarizeCSPInventory(names []string) ([]string, string) {
	result := append([]string(nil), names...)
	sort.SliceStable(result, func(i, j int) bool {
		rank := func(s string) int {
			r := splitCSPFQCN(s)
			if r.isToken {
				return 0
			}
			if r.isLocal {
				return 2
			}
			return 1
		}
		return rank(result[i]) < rank(result[j])
	})
	local, token, other := 0, 0, 0
	var matches []string
	for _, fqcn := range result {
		ref := splitCSPFQCN(fqcn)
		switch {
		case ref.isToken:
			token++
		case ref.isLocal:
			local++
		default:
			other++
		}
		if ref.isToken {
			if h := matchingHDIMAGE(fqcn, result); h != "" {
				matches = append(matches, fmt.Sprintf("%s  ↔  %s", fqcn, h))
			}
		}
	}
	summary := fmt.Sprintf("Обнаруженные CSP-контейнеры: на токенных считывателях — %d, HDIMAGE — %d, прочие — %d.", token, local, other)
	if len(matches) > 0 {
		summary += "\r\n\r\nСОВПАДАЮЩИЕ ИМЕНА КОНТЕЙНЕРОВ:\r\n" + strings.Join(matches, "\r\n") +
			"\r\nВНИМАНИЕ: одинаковые имена НЕ доказывают совпадение закрытых ключей. " +
			"Для НОВОГО переноса программа создаст отдельное уникальное имя, не изменяя уже работающий HDIMAGE."
	}
	summary += "\r\n\r\nСписок отображается со считывателями Рутокен впереди. " +
		"Расположение контейнера на считывателе не устанавливает автоматически, какой физической модели он принадлежит."
	return result, summary
}