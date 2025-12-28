package main

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/xuri/excelize/v2"
	"golang.org/x/crypto/ssh"
)

// Simple program ported from the Python script to Go.
// Features:
// - Prompt for username/password/enable(secret)
// - Accept one or more hosts
// - Ping-check, SSH into device, disable paging, get 'show cdp neighbors detail'
// - Parse neighbors, optionally update interface descriptions
// - Save neighbor data to Excel and generate a simple draw.io-compatible XML

func pingReachable(ip string) bool {
	cmd := exec.Command("ping", "-c", "1", ip)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "1 packets transmitted, 1 received")
}

func sshConnect(host, user, pass string) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}
	return ssh.Dial("tcp", host+":22", config)
}

func readUntilPrompt(r *bufio.Reader, timeout time.Duration) (string, string, error) {
	// read with timeout until we detect a prompt ending with > or #
	var buf bytes.Buffer
	promptRe := regexp.MustCompile(`[\r\n]([\w\-\.]+[>#])\s*$`)
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return buf.String(), "", fmt.Errorf("read timeout")
		}
		r.SetReadDeadline(deadline)
		line, err := r.ReadString('\n')
		if err != nil {
			// small sleep and continue
			time.Sleep(100 * time.Millisecond)
			continue
		}
		buf.WriteString(line)
		if matches := promptRe.FindStringSubmatch(buf.String()); len(matches) >= 2 {
			return buf.String(), matches[1], nil
		}
	}
}

func runInteractiveCommand(client *ssh.Client, commands []string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	stdin, _ := sess.StdinPipe()
	stdout, _ := sess.StdoutPipe()
	// request pty for interactive behaviour
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echo
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}
	if err := sess.RequestPty("vt100", 80, 40, modes); err != nil {
		return "", err
	}
	if err := sess.Shell(); err != nil {
		return "", err
	}
	reader := bufio.NewReader(stdout)
	// clear initial banner/prompt
	_, _, _ = readUntilPrompt(reader, 3*time.Second)
	var outBuf strings.Builder
	for _, cmd := range commands {
		fmt.Fprintln(stdin, cmd)
		out, _, err := readUntilPrompt(reader, 8*time.Second)
		if err != nil {
			// still append what we have
			outBuf.WriteString(out)
			return outBuf.String(), err
		}
		outBuf.WriteString(out)
	}
	// exit shell
	fmt.Fprintln(stdin, "exit")
	return outBuf.String(), nil
}

func parseCDP(output string) [][]string {
	// Regex similar to python: Device ID: ... \n ... Interface: local, Port ID (outgoing port): remote\n
	re := regexp.MustCompile(`Device ID:\s*(.+?)\n[\s\S]*?Interface:\s*(.+?),\s+Port ID \(outgoing port\):\s*(.+?)\n`)
	matches := re.FindAllStringSubmatch(output, -1)
	var rows [][]string
	for _, m := range matches {
		if len(m) >= 4 {
			device := strings.TrimSpace(m[1])
			local := strings.TrimSpace(m[2])
			remote := strings.TrimSpace(m[3])
			rows = append(rows, []string{device, local, remote})
		}
	}
	return rows
}

// parseLLDP attempts to extract neighbor rows from LLDP output for NX-OS.
// Best-effort; may need tweaks for specific NX-OS versions.
func parseLLDP(output string) [][]string {
	re := regexp.MustCompile(`(?m)System Name:\s*(.+?)\n[\s\S]*?Local Intf:\s*(.+?)\n[\s\S]*?Port id:\s*(.+?)\n`)
	matches := re.FindAllStringSubmatch(output, -1)
	var rows [][]string
	if len(matches) > 0 {
		for _, m := range matches {
			if len(m) >= 4 {
				device := strings.TrimSpace(m[1])
				local := strings.TrimSpace(m[2])
				remote := strings.TrimSpace(m[3])
				rows = append(rows, []string{device, local, remote})
			}
		}
		return rows
	}
	// fallback to CDP-style parsing if LLDP blocks not found
	return parseCDP(output)
}

func convertInterfaceName(iface string) string {
	replacements := []struct{ pat, rep string }{
		{"^GigabitEthernet", "Gi"},
		{"^FastEthernet", "Fa"},
		{"^TenGigabitEthernet", "Te"},
		{"^TwentyFiveGigE", "Tw"},
		{"^FortyGigE", "Fo"},
		{"^HundredGigE", "Hu"},
		{"^Serial", "Se"},
		{"^Port-channel", "Po"},
		{"^Vlan", "Vl"},
		{"^Loopback", "Lo"},
	}
	for _, r := range replacements {
		rex := regexp.MustCompile(r.pat)
		if rex.MatchString(iface) {
			return rex.ReplaceAllString(iface, r.rep)
		}
	}
	return iface
}

func saveExcel(rows [][]string, filename string) error {
	f := excelize.NewFile()
	index := f.NewSheet("Sheet1")
	f.SetCellValue("Sheet1", "A1", "Hostname-A")
	f.SetCellValue("Sheet1", "B1", "Interface-A")
	f.SetCellValue("Sheet1", "C1", "Interface-B")
	f.SetCellValue("Sheet1", "D1", "Hostname-B")
	for i, r := range rows {
		row := i + 2
		f.SetCellValue("Sheet1", fmt.Sprintf("A%d", row), r[0])
		f.SetCellValue("Sheet1", fmt.Sprintf("B%d", row), r[1])
		f.SetCellValue("Sheet1", fmt.Sprintf("C%d", row), r[2])
		f.SetCellValue("Sheet1", fmt.Sprintf("D%d", row), r[3])
	}
	f.SetActiveSheet(index)
	return f.SaveAs(filename)
}

// Minimal draw.io XML generation structures
type MXCell struct {
	XMLName  xml.Name `xml:"mxCell"`
	ID       string   `xml:"id,attr,omitempty"`
	Value    string   `xml:"value,attr,omitempty"`
	Style    string   `xml:"style,attr,omitempty"`
	Vertex   string   `xml:"vertex,attr,omitempty"`
	Parent   string   `xml:"parent,attr,omitempty"`
	Edge     string   `xml:"edge,attr,omitempty"`
	Source   string   `xml:"source,attr,omitempty"`
	Target   string   `xml:"target,attr,omitempty"`
	Geometry *struct {
		XMLName xml.Name `xml:"mxGeometry"`
		X       string   `xml:"x,attr,omitempty"`
		Y       string   `xml:"y,attr,omitempty"`
		Width   string   `xml:"width,attr,omitempty"`
		Height  string   `xml:"height,attr,omitempty"`
		As      string   `xml:"as,attr,omitempty"`
	} `xml:"mxGeometry,omitempty"`
}

func generateDrawioXML(rows [][]string, outFile string) error {
	// create simple node ids
	unique := map[string]string{}
	xpos, ypos := 100, 100
	var cells []MXCell
	idCounter := 1
	for _, r := range rows {
		a := r[0]
		ia := r[1]
		ib := r[2]
		b := r[3]
		if _, ok := unique[a]; !ok {
			unique[a] = fmt.Sprintf("id%d", idCounter)
			idCounter++
			cells = append(cells, MXCell{ID: unique[a], Value: a, Style: "shape=ellipse;", Vertex: "1", Parent: "1", Geometry: &struct {
				xml.Name `xml:"mxGeometry"`
				X        string `xml:"x,attr,omitempty"`
				Y        string `xml:"y,attr,omitempty"`
				Width    string `xml:"width,attr,omitempty"`
				Height   string `xml:"height,attr,omitempty"`
				As       string `xml:"as,attr,omitempty"`
			}{X: fmt.Sprint(xpos), Y: fmt.Sprint(ypos), Width: "80", Height: "80", As: "geometry"}})
			xpos += 120
		}
		if _, ok := unique[b]; !ok {
			unique[b] = fmt.Sprintf("id%d", idCounter)
			idCounter++
			cells = append(cells, MXCell{ID: unique[b], Value: b, Style: "shape=ellipse;", Vertex: "1", Parent: "1", Geometry: &struct {
				xml.Name `xml:"mxGeometry"`
				X        string `xml:"x,attr,omitempty"`
				Y        string `xml:"y,attr,omitempty"`
				Width    string `xml:"width,attr,omitempty"`
				Height   string `xml:"height,attr,omitempty"`
				As       string `xml:"as,attr,omitempty"`
			}{X: fmt.Sprint(xpos), Y: fmt.Sprint(ypos), Width: "80", Height: "80", As: "geometry"}})
			xpos += 120
		}
		edgeID := fmt.Sprintf("id%d", idCounter)
		idCounter++
		cells = append(cells, MXCell{ID: edgeID, Value: fmt.Sprintf("%s to %s", ia, ib), Edge: "1", Source: unique[a], Target: unique[b], Parent: "1", Geometry: &struct {
			xml.Name `xml:"mxGeometry"`
			X        string `xml:"x,attr,omitempty"`
			Y        string `xml:"y,attr,omitempty"`
			Width    string `xml:"width,attr,omitempty"`
			Height   string `xml:"height,attr,omitempty"`
			As       string `xml:"as,attr,omitempty"`
		}{As: "geometry"}})
	}
	// Build xml manually
	var b strings.Builder
	b.WriteString(`<mxfile><diagram><mxGraphModel><root><mxCell id="0"/><mxCell id="1" parent="0"/>`)
	for _, c := range cells {
		// very simple serialization
		if c.Edge == "1" {
			b.WriteString(fmt.Sprintf(`<mxCell id="%s" value="%s" edge="1" source="%s" target="%s" parent="1"><mxGeometry relative="1" as="geometry"/></mxCell>`, c.ID, xmlEscape(c.Value), c.Source, c.Target))
		} else {
			b.WriteString(fmt.Sprintf(`<mxCell id="%s" value="%s" style="%s" vertex="1" parent="1"><mxGeometry x="%s" y="%s" width="80" height="80" as="geometry"/></mxCell>`, c.ID, xmlEscape(c.Value), c.Style, c.Geometry.X, c.Geometry.Y))
		}
	}
	b.WriteString(`</root></mxGraphModel></diagram></mxfile>`)
	return os.WriteFile(outFile, []byte(b.String()), 0644)
}

func xmlEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "&", "&amp;"), "<", "&lt;")
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Do you want to update interface descriptions? (y/n): ")
	updateDesc, _ := reader.ReadString('\n')
	updateDesc = strings.TrimSpace(strings.ToLower(updateDesc))

	fmt.Print("Enter username: ")
	user, _ := reader.ReadString('\n')
	user = strings.TrimSpace(user)
	fmt.Print("Enter password: ")
	pass, _ := reader.ReadString('\n')
	pass = strings.TrimSpace(pass)
	fmt.Print("Enter enable password (press Enter if none): ")
	secret, _ := reader.ReadString('\n')
	secret = strings.TrimSpace(secret)

	fmt.Print("Enter device IP addresses (comma separated): ")
	hostLine, _ := reader.ReadString('\n')
	hostLine = strings.TrimSpace(hostLine)
	hosts := strings.Split(hostLine, ",")

	var neighborData [][]string
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if pingReachable(h) {
			fmt.Printf("Device with IP %s is reachable by ping.\n", h)
		} else {
			fmt.Printf("Device with IP %s is unreachable by ping; attempting SSH access...\n", h)
		}
		client, err := sshConnect(h, user, pass)
		if err != nil {
			fmt.Printf("SSH connect error to %s: %v\n", h, err)
			continue
		}
		defer client.Close()
		// detect device type by running 'show version'
		verOut, _ := runInteractiveCommand(client, []string{"show version"})
		lo := strings.ToLower(verOut)
		devType := "ios"
		if strings.Contains(lo, "nx-os") || strings.Contains(lo, "nexus") || strings.Contains(lo, "nxos") {
			devType = "nxos"
			fmt.Printf("Detected NX-OS on %s\n", h)
		}

		// If enable required, enter enable before running neighbor commands
		if secret != "" {
			_, _ = runInteractiveCommand(client, []string{"enable", secret})
		}

		// disable paging and run appropriate neighbor command for device type
		var cmds []string
		if devType == "nxos" {
			// run both LLDP and CDP; prefer CDP results if present
			cmds = []string{"terminal width 511", "terminal length 0", "show cdp neighbors detail", "show lldp neighbors detail"}
		} else {
			cmds = []string{"terminal width 511", "terminal length 0", "show cdp neighbors detail"}
		}
		out, err := runInteractiveCommand(client, cmds)
		if err != nil {
			fmt.Printf("Error running commands on %s: %v\n", h, err)
		}
		// Prefer CDP parsing first, fall back to LLDP when no CDP neighbors found
		rows := parseCDP(out)
		if len(rows) == 0 {
			rows = parseLLDP(out)
		}
		for _, r := range rows {
			// r = [remote-hostname, local-interface, remote-interface]
			localHost := h // use the target IP/host as the local identifier
			localIface := convertInterfaceName(r[1])
			remoteIface := convertInterfaceName(r[2])
			remoteHost := strings.TrimSpace(r[0])
			neighborData = append(neighborData, []string{localHost, localIface, remoteIface, remoteHost})
		}
	}
	excelFile := "cdp_neighbors_auto.xlsx"
	err := saveExcel(neighborData, excelFile)
	if err != nil {
		fmt.Printf("Failed to write Excel: %v\n", err)
	} else {
		fmt.Printf("Saved neighbors to %s\n", excelFile)
	}
	// Drawio xml
	_ = generateDrawioXML(neighborData, "network_topology_filtered.xml")
	fmt.Println("Generated network_topology_filtered.xml")
}
