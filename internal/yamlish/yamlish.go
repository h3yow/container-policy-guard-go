// Package yamlish 是一个极简 YAML 子集解析器。
//
// 仓库运行环境可能离线，无法依赖 gopkg.in/yaml.v3，因此策略、清单与
// 公钥库文件支持 JSON 原生解析；对 YAML 则用本包解析其常用子集：
// 缩进映射、块序列（- item）、标量、行内流序列 [a, b]、注释与引号。
// 解析结果为 map[string]any / []any，再经 JSON 回填到目标结构体。
package yamlish

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type rawLine struct {
	indent int
	dash   bool   // 该行是一个 "- " 序列项起始
	text   string // "- " 之后的内容（dash=true 时），或 "key: value" 原文
	lineNo int
}

// Unmarshal 解析 YAML 子集或 JSON 到 v。
func Unmarshal(data []byte, v any) error {
	s := strings.TrimSpace(string(data))
	if s == "" {
		return fmt.Errorf("yamlish: empty document")
	}
	// 原生 JSON 直接走标准库。
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		return json.Unmarshal(data, v)
	}
	lines, err := preprocess(string(data))
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		return fmt.Errorf("yamlish: empty document")
	}
	node, ni, err := parseNodes(lines, 0)
	if err != nil {
		return err
	}
	if ni < len(lines) {
		return fmt.Errorf("yamlish: line %d: malformed indentation or unexpected content (%q)",
			lines[ni].lineNo, lines[ni].text)
	}
	buf, err := json.Marshal(node)
	if err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}

func preprocess(src string) ([]rawLine, error) {
	var out []rawLine
	for i, full := range strings.Split(src, "\n") {
		line := stripComment(full)
		if strings.TrimSpace(line) == "" {
			continue
		}
		// 不允许 tab 缩进。
		indent := 0
		for indent < len(line) && line[indent] == ' ' {
			indent++
		}
		content := line[indent:]
		if strings.HasPrefix(content, "\t") {
			return nil, fmt.Errorf("yamlish: line %d: tab indentation is not supported", i+1)
		}
		if strings.HasPrefix(content, "- ") || content == "-" {
			rest := ""
			if content != "-" {
				rest = strings.TrimSpace(content[1:])
			}
			out = append(out, rawLine{indent: indent, dash: true, text: rest, lineNo: i + 1})
		} else {
			out = append(out, rawLine{indent: indent, text: content, lineNo: i + 1})
		}
	}
	return out, nil
}

func stripComment(line string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				// 注释前必须是行首或空白。
				if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
					return line[:i]
				}
			}
		}
	}
	return strings.TrimRight(line, " \t\r")
}

// parseNodes 解析 lines[start:] 中缩进 >= lines[start].indent 的整块。
func parseNodes(lines []rawLine, start int) (any, int, error) {
	if lines[start].dash {
		return parseSeq(lines, start, lines[start].indent)
	}
	return parseMap(lines, start, lines[start].indent)
}

func parseSeq(lines []rawLine, start, indent int) (any, int, error) {
	seq := []any{}
	i := start
	for i < len(lines) {
		ln := lines[i]
		if ln.indent < indent || !ln.dash {
			break
		}
		if ln.indent > indent {
			return nil, i, fmt.Errorf("yamlish: line %d: unexpected indentation", ln.lineNo)
		}
		if ln.text == "" {
			// "-" 后接嵌套块。
			if i+1 < len(lines) && lines[i+1].indent > indent {
				child, ni, err := parseNodes(lines, i+1)
				if err != nil {
					return nil, i, err
				}
				seq = append(seq, child)
				i = ni
				continue
			}
			seq = append(seq, nil)
			i++
			continue
		}
		// "- <rest>"：rest 与后续同属该项的更深行合并成子片段解析。
		// 虚拟行缩进对齐到续行的实际缩进，使 "- key: value" 与下一行对齐键同级。
		j := i + 1
		childIndent := indent + 2
		if j < len(lines) && lines[j].indent > indent {
			childIndent = lines[j].indent
		}
		virtual := rawLine{indent: childIndent, text: ln.text, lineNo: ln.lineNo}
		item := []rawLine{virtual}
		for j < len(lines) && lines[j].indent > indent {
			if lines[j].indent < childIndent {
				return nil, i, fmt.Errorf("yamlish: line %d: bad indentation for sequence item content",
					lines[j].lineNo)
			}
			item = append(item, lines[j])
			j++
		}
		child, _, err := parseNodes(item, 0)
		if err != nil {
			return nil, i, err
		}
		seq = append(seq, child)
		i = j
	}
	return seq, i, nil
}

func parseMap(lines []rawLine, start, indent int) (any, int, error) {
	m := map[string]any{}
	i := start
	for i < len(lines) {
		ln := lines[i]
		if ln.dash || ln.indent < indent {
			break
		}
		if ln.indent > indent {
			return nil, i, fmt.Errorf("yamlish: line %d: unexpected indentation", ln.lineNo)
		}
		key, rest, err := splitKey(ln.text)
		if err != nil {
			return nil, i, fmt.Errorf("yamlish: line %d: %w", ln.lineNo, err)
		}
		i++
		if strings.TrimSpace(rest) != "" {
			if v, ni, ok, err := parseBlockScalar(lines, i, indent, rest); ok {
				if err != nil {
					return nil, i, fmt.Errorf("yamlish: line %d: %w", ln.lineNo, err)
				}
				m[key] = v
				i = ni
				continue
			}
			val, err := parseScalar(rest)
			if err != nil {
				return nil, i, fmt.Errorf("yamlish: line %d: %w", ln.lineNo, err)
			}
			m[key] = val
			continue
		}
		// 值为空：看是否有更深的嵌套块。
		if i < len(lines) && lines[i].indent > indent {
			child, ni, err := parseNodes(lines, i)
			if err != nil {
				return nil, i, err
			}
			m[key] = child
			i = ni
		} else {
			m[key] = nil
		}
	}
	return m, i, nil
}

// parseBlockScalar 尝试把 rest（如 "|"、">-"）解析为块标量头。
// 块内容从 lines[i] 开始，返回（值, 下一行索引, 是否块标量, 错误）。
func parseBlockScalar(lines []rawLine, i, parentIndent int, rest string) (any, int, bool, error) {
	rest = strings.TrimSpace(rest)
	if rest == "" || (rest[0] != '|' && rest[0] != '>') {
		return nil, i, false, nil
	}
	literal := rest[0] == '|'
	chomp := byte(0) // 0 clip, '-' strip, '+' keep
	explicitIndent := -1
	for _, c := range rest[1:] {
		switch c {
		case '-':
			chomp = '-'
		case '+':
			chomp = '+'
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			explicitIndent = int(c - '0')
		case ' ':
		default:
			return nil, i, true, fmt.Errorf("invalid block scalar header %q", rest)
		}
	}
	// 收集所有缩进更深的连续行。
	type blkLine struct {
		text   string
		indent int
	}
	var block []blkLine
	contentIndent := -1
	j := i
	for j < len(lines) && lines[j].indent > parentIndent {
		if lines[j].dash {
			return nil, j, true, fmt.Errorf("sequence item inside block scalar")
		}
		if contentIndent < 0 && strings.TrimSpace(lines[j].text) != "" {
			contentIndent = lines[j].indent
		}
		block = append(block, blkLine{lines[j].text, lines[j].indent})
		j++
	}
	if explicitIndent > 0 {
		contentIndent = parentIndent + explicitIndent
	}
	raw := make([]string, len(block))
	if contentIndent < 0 {
		// 空块标量。
		return "", j, true, nil
	}
	for k, bl := range block {
		extra := bl.indent - contentIndent
		if extra > 0 {
			raw[k] = bl.text[extra:]
		} else {
			raw[k] = bl.text
		}
	}
	var value string
	if literal {
		value = strings.Join(raw, "\n")
	} else {
		// 折叠：连续非空行用空格连接，空行保留换行。
		var b strings.Builder
		for k, line := range raw {
			if k > 0 {
				if line == "" || raw[k-1] == "" {
					b.WriteByte('\n')
				} else {
					b.WriteByte(' ')
				}
			}
			b.WriteString(line)
		}
		value = b.String()
	}
	switch chomp {
	case '-':
		value = strings.TrimRight(value, "\n")
	case '+':
		// 保留所有尾部换行（已在 block 中）。
	default:
		value = strings.TrimRight(value, "\n") + "\n"
	}
	return value, j, true, nil
}

func splitKey(text string) (string, string, error) {
	// 在第一个未被引号包裹的冒号（后接空格或行尾）处切分。
	inSingle, inDouble := false, false
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case ':':
			if !inSingle && !inDouble && (i+1 == len(text) || text[i+1] == ' ') {
				key := unquote(strings.TrimSpace(text[:i]))
				return key, strings.TrimSpace(text[i+1:]), nil
			}
		}
	}
	return "", "", fmt.Errorf("expected 'key: value', got %q", text)
}

func parseScalar(s string) (any, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") {
		if !strings.HasSuffix(s, "]") {
			return nil, fmt.Errorf("unterminated flow sequence %q", s)
		}
		inner := strings.TrimSpace(s[1 : len(s)-1])
		if inner == "" {
			return []any{}, nil
		}
		parts, err := splitFlow(inner)
		if err != nil {
			return nil, err
		}
		out := make([]any, 0, len(parts))
		for _, p := range parts {
			v, err := parseScalar(p)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	if s == "null" || s == "~" {
		return nil, nil
	}
	if s == "true" {
		return true, nil
	}
	if s == "false" {
		return false, nil
	}
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') {
		return unquote(s), nil
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	return s, nil
}

func splitFlow(s string) ([]string, error) {
	var parts []string
	depth := 0
	inSingle, inDouble := false, false
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '[', '{':
			if !inSingle && !inDouble {
				depth++
			}
		case ']', '}':
			if !inSingle && !inDouble {
				depth--
			}
		case ',':
			if !inSingle && !inDouble && depth == 0 {
				parts = append(parts, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	if depth != 0 || inSingle || inDouble {
		return nil, fmt.Errorf("unbalanced flow sequence %q", s)
	}
	parts = append(parts, strings.TrimSpace(s[start:]))
	return parts, nil
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if v, err := strconv.Unquote(s); err == nil {
			return v
		}
		return s[1 : len(s)-1]
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	return s
}
