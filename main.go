package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
)

type object = map[string]json.RawMessage
type statRecord struct {
	Total int64 `json:"total"`
	Last  int64 `json:"last"`
}
type app struct {
	mu                                     sync.Mutex
	collectMu                              sync.Mutex
	config, xray, api, statsFile, password string
	publicHost                             string
	restartService                         string
	sessions                               map[string]time.Time
	stats                                  map[string]statRecord
	rates                                  map[string]int64
	statsErr                               string
	updated                                time.Time
}
type client struct {
	Email, Credential, Up, Down    string
	Online, Flow, RateUp, RateDown string
	Index                          int
}
type inbound struct {
	Index                                                                 int
	Protocol                                                              string
	Port                                                                  any
	Clients                                                               []client
	Target, ServerNames, ShortIDs, TLSServerName, CertFile, KeyFile, ALPN string
}
type page struct {
	Token, Error, Notice, Updated string
	CanRestart                    bool
	Inbounds                      []inbound
}

func random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func uuid() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	s := hex.EncodeToString(b)
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}
func str(v json.RawMessage) string  { var s string; _ = json.Unmarshal(v, &s); return s }
func put(o object, k string, v any) { b, _ := json.Marshal(v); o[k] = b }
func readConfig(path string) (object, []object, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, nil, e
	}
	var root object
	if e = json.Unmarshal(b, &root); e != nil {
		return nil, nil, e
	}
	var ins []object
	if e = json.Unmarshal(root["inbounds"], &ins); e != nil {
		return nil, nil, e
	}
	return root, ins, nil
}
func clients(in object) (object, []object, error) {
	var s object
	if e := json.Unmarshal(in["settings"], &s); e != nil {
		return nil, nil, e
	}
	var cs []object
	if b, ok := s["clients"]; ok {
		if e := json.Unmarshal(b, &cs); e != nil {
			return nil, nil, e
		}
	}
	return s, cs, nil
}
func atomicWrite(path string, b []byte) error {
	dir := filepath.Dir(path)
	f, e := os.CreateTemp(dir, ".mini-xui-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(name, path)
}
func (a *app) saveConfig(root object, ins []object) error {
	put(root, "inbounds", ins)
	b, e := json.MarshalIndent(root, "", "  ")
	if e != nil {
		return e
	}
	b = append(b, '\n')
	dir := filepath.Dir(a.config)
	f, e := os.CreateTemp(dir, ".mini-xui-check-*.json")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	cmd := exec.Command(a.xray, "run", "-test", "-config", name)
	out, e := cmd.CombinedOutput()
	if e != nil {
		return fmt.Errorf("Xray 配置验证失败: %s", strings.TrimSpace(string(out)))
	}
	old, e := os.ReadFile(a.config)
	if e != nil {
		return e
	}
	if e = atomicWrite(a.config+".bak", old); e != nil {
		return e
	}
	return atomicWrite(a.config, b)
}
func (a *app) logged(r *http.Request) string {
	c, e := r.Cookie("mini_session")
	if e != nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	until, ok := a.sessions[c.Value]
	if !ok || time.Now().After(until) {
		delete(a.sessions, c.Value)
		return ""
	}
	return c.Value
}
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	failed := false
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if e := r.ParseForm(); e != nil {
			http.Error(w, "bad request", 400)
			return
		}
		x := sha256.Sum256([]byte(r.FormValue("password")))
		y := sha256.Sum256([]byte(a.password))
		if subtle.ConstantTimeCompare(x[:], y[:]) == 1 {
			s := random(32)
			a.mu.Lock()
			a.sessions[s] = time.Now().Add(12 * time.Hour)
			a.mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "mini_session", Value: s, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		time.Sleep(time.Second)
		failed = true
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = loginHTML.Execute(w, struct{ Failed bool }{failed})
}
func (a *app) index(w http.ResponseWriter, r *http.Request) {
	token := a.logged(r)
	if token == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "method not allowed", 405)
		return
	}
	online, onlineErr := a.onlineUsers()
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ins, e := readConfig(a.config)
	p := page{Token: token, Notice: r.URL.Query().Get("notice"), CanRestart: a.restartService != ""}
	if e != nil {
		p.Error = e.Error()
	} else {
		for i, in := range ins {
			proto := str(in["protocol"])
			if proto != "vless" && proto != "hysteria" {
				continue
			}
			item := inbound{Index: i, Protocol: proto}
			_ = json.Unmarshal(in["port"], &item.Port)
			var stream object
			_ = json.Unmarshal(in["streamSettings"], &stream)
			if proto == "vless" {
				var reality object
				_ = json.Unmarshal(stream["realitySettings"], &reality)
				item.Target = str(reality["target"])
				var names, ids []string
				_ = json.Unmarshal(reality["serverNames"], &names)
				_ = json.Unmarshal(reality["shortIds"], &ids)
				item.ServerNames = strings.Join(names, ",")
				item.ShortIDs = strings.Join(ids, ",")
			} else {
				var tls object
				_ = json.Unmarshal(stream["tlsSettings"], &tls)
				item.TLSServerName = str(tls["serverName"])
				var certs []object
				_ = json.Unmarshal(tls["certificates"], &certs)
				if len(certs) > 0 {
					item.CertFile = str(certs[0]["certificateFile"])
					item.KeyFile = str(certs[0]["keyFile"])
				}
				var alpn []string
				_ = json.Unmarshal(tls["alpn"], &alpn)
				item.ALPN = strings.Join(alpn, ",")
			}
			_, cs, err := clients(in)
			if err != nil {
				p.Error = err.Error()
				break
			}
			for j, c := range cs {
				email := str(c["email"])
				key := "id"
				if proto == "hysteria" {
					key = "auth"
				}
				status := "离线"
				if onlineErr != nil {
					status = "不可用"
				} else if online[email] {
					status = "活跃"
				}
				item.Clients = append(item.Clients, client{Email: email, Credential: str(c[key]), Flow: str(c["flow"]), Online: status, RateUp: rate(a.rates, "user>>>"+email+">>>traffic>>>uplink"), RateDown: rate(a.rates, "user>>>"+email+">>>traffic>>>downlink"), Index: j, Up: formatBytes(a.stats["user>>>"+email+">>>traffic>>>uplink"].Total), Down: formatBytes(a.stats["user>>>"+email+">>>traffic>>>downlink"].Total)})
			}
			p.Inbounds = append(p.Inbounds, item)
		}
	}
	if a.statsErr != "" {
		p.Updated = "统计不可用：" + a.statsErr
	} else if !a.updated.IsZero() {
		p.Updated = "最近采集：" + a.updated.Format("2006-01-02 15:04:05")
	} else {
		p.Updated = "正在等待首次采集"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = indexHTML.Execute(w, p)
}
func formatBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	f := float64(n)
	for _, u := range []string{"KiB", "MiB", "GiB", "TiB"} {
		f /= 1024
		if f < 1024 || u == "TiB" {
			return fmt.Sprintf("%.2f %s", f, u)
		}
	}
	return ""
}
func (a *app) change(w http.ResponseWriter, r *http.Request) {
	token := a.logged(r)
	if token == "" {
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if e := r.ParseForm(); e != nil {
		http.Error(w, "bad request", 400)
		return
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(r.FormValue("token"))) != 1 {
		http.Error(w, "forbidden", 403)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	root, ins, e := readConfig(a.config)
	idx, err := strconv.Atoi(r.FormValue("inbound"))
	if e != nil || err != nil || idx < 0 || idx >= len(ins) {
		http.Error(w, "无效配置或入站", 400)
		return
	}
	in := ins[idx]
	proto := str(in["protocol"])
	if proto != "vless" && proto != "hysteria" {
		http.Error(w, "不支持此协议", 400)
		return
	}
	settings, cs, e := clients(in)
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	switch r.FormValue("action") {
	case "settings":
		if e = updateInbound(in, proto, r.Form); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		var port int
		_ = json.Unmarshal(in["port"], &port)
		for n, other := range ins {
			if n == idx {
				continue
			}
			otherProto := str(other["protocol"])
			if (proto == "vless" && otherProto == "hysteria") || (proto == "hysteria" && otherProto != "hysteria") {
				continue
			}
			var otherPort int
			_ = json.Unmarshal(other["port"], &otherPort)
			if port == otherPort {
				http.Error(w, "端口与另一入站冲突", 400)
				return
			}
		}
		ins[idx] = in
		if e = a.saveConfig(root, ins); e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		http.Redirect(w, r, "/?notice=协议配置已保存并验证，请确认端口和防火墙后重启 Xray", http.StatusSeeOther)
		return
	case "add":
		email := strings.TrimSpace(r.FormValue("email"))
		if email == "" || len(email) > 128 || strings.Contains(email, ">>>") || strings.ContainsAny(email, "\r\n") {
			http.Error(w, "用户标识无效", 400)
			return
		}
		for _, in2 := range ins {
			_, existing, err := clients(in2)
			if err != nil {
				continue
			}
			for _, c := range existing {
				if str(c["email"]) == email {
					http.Error(w, "用户标识已存在，统计要求全局唯一", 400)
					return
				}
			}
		}
		credential := strings.TrimSpace(r.FormValue("credential"))
		c := object{}
		put(c, "email", email)
		if proto == "vless" {
			if credential == "" {
				credential = uuid()
			}
			put(c, "id", credential)
			if r.FormValue("vision") == "on" {
				put(c, "flow", "xtls-rprx-vision")
			}
		} else {
			if credential == "" {
				credential = random(24)
			}
			put(c, "auth", credential)
		}
		cs = append(cs, c)
	case "edit":
		n, err := strconv.Atoi(r.FormValue("client"))
		if err != nil || n < 0 || n >= len(cs) {
			http.Error(w, "无效用户", 400)
			return
		}
		credential := strings.TrimSpace(r.FormValue("credential"))
		if credential == "" {
			http.Error(w, "凭据不能为空", 400)
			return
		}
		if proto == "vless" {
			put(cs[n], "id", credential)
			if r.FormValue("vision") == "on" {
				put(cs[n], "flow", "xtls-rprx-vision")
			} else {
				delete(cs[n], "flow")
			}
		} else {
			put(cs[n], "auth", credential)
		}
	case "delete":
		n, err := strconv.Atoi(r.FormValue("client"))
		if err != nil || n < 0 || n >= len(cs) {
			http.Error(w, "无效用户", 400)
			return
		}
		cs = append(cs[:n], cs[n+1:]...)
	default:
		http.Error(w, "无效操作", 400)
		return
	}
	put(settings, "clients", cs)
	put(in, "settings", settings)
	ins[idx] = in
	if e = a.saveConfig(root, ins); e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	http.Redirect(w, r, "/?notice="+"配置已保存并验证，请重启 Xray 后生效", http.StatusSeeOther)
}
func (a *app) collect() {
	a.collectMu.Lock()
	defer a.collectMu.Unlock()
	a.collectUnlocked()
}
func (a *app) collectUnlocked() {
	cmd := exec.Command(a.xray, "api", "statsquery", "--server="+a.api, "-pattern", "user>>>")
	b, e := cmd.Output()
	var res struct {
		Stat []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
		} `json:"stat"`
	}
	if e == nil {
		e = json.Unmarshal(b, &res)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if e != nil {
		a.statsErr = e.Error()
		return
	}
	if a.rates == nil {
		a.rates = map[string]int64{}
	}
	elapsed := time.Since(a.updated).Seconds()
	for _, s := range res.Stat {
		if !strings.HasSuffix(s.Name, ">>>traffic>>>uplink") && !strings.HasSuffix(s.Name, ">>>traffic>>>downlink") {
			continue
		}
		var v int64
		if json.Unmarshal(s.Value, &v) != nil {
			var t string
			if json.Unmarshal(s.Value, &t) != nil {
				continue
			}
			v, _ = strconv.ParseInt(t, 10, 64)
		}
		old := a.stats[s.Name]
		delta := v - old.Last
		if delta < 0 {
			delta = v
		}
		if !a.updated.IsZero() && elapsed > 0 {
			a.rates[s.Name] = int64(float64(delta) / elapsed)
		}
		old.Total += delta
		old.Last = v
		a.stats[s.Name] = old
	}
	data, e := json.MarshalIndent(a.stats, "", "  ")
	if e == nil {
		e = atomicWrite(a.statsFile, data)
	}
	if e != nil {
		a.statsErr = e.Error()
		return
	}
	a.statsErr = ""
	a.updated = time.Now()
}
func main() {
	cfg := flag.String("config", "./config.json", "Xray 配置路径")
	xr := flag.String("xray", "xray", "Xray 可执行文件路径")
	api := flag.String("api", "127.0.0.1:62789", "Xray Stats API 地址")
	listen := flag.String("listen", "127.0.0.1:8080", "面板监听地址（仅限回环地址）")
	stats := flag.String("stats", "./traffic.json", "流量统计文件")
	interval := flag.Duration("interval", 30*time.Second, "统计采集间隔")
	publicHost := flag.String("public-host", "", "分享链接使用的公网 IP 或域名")
	restartService := flag.String("restart-service", "", "允许重启的 systemd 服务名，留空禁用")
	flag.Parse()
	if *restartService != "" && *restartService != "mini-xui-xray.service" {
		log.Fatal("仅允许操作 mini-xui-xray.service")
	}
	host, _, e := net.SplitHostPort(*listen)
	if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("面板必须绑定回环 IP，例如 127.0.0.1:8080")
	}
	password := os.Getenv("MINI_XUI_PASSWORD")
	if len(password) < 8 {
		log.Fatal("请通过 MINI_XUI_PASSWORD 设置至少 8 字符的面板密码")
	}
	if *interval < time.Second {
		log.Fatal("采集间隔至少为 1 秒")
	}
	if _, _, e = readConfig(*cfg); e != nil {
		log.Fatal(e)
	}
	if _, e = exec.LookPath(*xr); e != nil {
		log.Fatal(e)
	}
	a := &app{config: *cfg, xray: *xr, api: *api, statsFile: *stats, password: password, publicHost: *publicHost, restartService: *restartService, sessions: map[string]time.Time{}, stats: map[string]statRecord{}}
	if b, e := os.ReadFile(*stats); e == nil {
		if e = json.Unmarshal(b, &a.stats); e != nil {
			log.Fatal("统计文件无效：", e)
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		log.Fatal(e)
	}
	go func() {
		a.collect()
		t := time.NewTicker(*interval)
		defer t.Stop()
		for range t.C {
			a.collect()
		}
	}()
	mux := http.NewServeMux()
	mux.HandleFunc("/login", a.login)
	mux.HandleFunc("/", a.index)
	mux.HandleFunc("/change", a.change)
	mux.HandleFunc("/share", a.share)
	mux.HandleFunc("/restart", a.restart)
	server := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("面板监听 http://%s", *listen)
	log.Fatal(server.ListenAndServe())
}

func (a *app) onlineUsers() (map[string]bool, error) {
	b, e := exec.Command(a.xray, "api", "statsgetallonlineusers", "--server="+a.api, "-timeout=2").Output()
	if e != nil {
		return nil, e
	}
	var r struct {
		Users []string `json:"users"`
	}
	if e = json.Unmarshal(b, &r); e != nil {
		return nil, e
	}
	m := map[string]bool{}
	for _, u := range r.Users {
		m[u] = true
		if strings.HasPrefix(u, "user>>>") {
			m[strings.TrimSuffix(strings.TrimPrefix(u, "user>>>"), ">>>online")] = true
		}
	}
	return m, nil
}
func (a *app) share(w http.ResponseWriter, r *http.Request) {
	if a.logged(r) == "" {
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "method not allowed", 405)
		return
	}
	i, e := strconv.Atoi(r.URL.Query().Get("inbound"))
	if e != nil {
		http.Error(w, "invalid inbound", 400)
		return
	}
	j, e := strconv.Atoi(r.URL.Query().Get("client"))
	if e != nil {
		http.Error(w, "invalid client", 400)
		return
	}
	a.mu.Lock()
	_, ins, e := readConfig(a.config)
	if e != nil || i < 0 || i >= len(ins) {
		a.mu.Unlock()
		http.Error(w, "invalid inbound", 400)
		return
	}
	in := ins[i]
	_, cs, e := clients(in)
	if e != nil || j < 0 || j >= len(cs) {
		a.mu.Unlock()
		http.Error(w, "invalid client", 400)
		return
	}
	link, e := shareLink(a.publicHost, in, cs[j])
	a.mu.Unlock()
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	img, e := qrcode.Encode(link, qrcode.Medium, 320)
	if e != nil {
		http.Error(w, "二维码生成失败", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	_ = shareHTML.Execute(w, struct{ Link, Image string }{link, base64.StdEncoding.EncodeToString(img)})
}
func shareLink(host string, in, client object) (string, error) {
	if host == "" {
		return "", errors.New("请通过 -public-host 设置公网 IP 或域名")
	}
	var port int
	if e := json.Unmarshal(in["port"], &port); e != nil || port < 1 || port > 65535 {
		return "", errors.New("无效端口")
	}
	var stream object
	if e := json.Unmarshal(in["streamSettings"], &stream); e != nil {
		return "", e
	}
	proto := str(in["protocol"])
	q := url.Values{}
	u := url.URL{Host: net.JoinHostPort(host, strconv.Itoa(port)), Fragment: str(client["email"])}
	switch proto {
	case "vless":
		if str(stream["security"]) != "reality" {
			return "", errors.New("目前分享仅支持 VLESS + Reality")
		}
		var reality object
		if e := json.Unmarshal(stream["realitySettings"], &reality); e != nil {
			return "", e
		}
		if len(reality["mldsa65Seed"]) > 0 && str(reality["mldsa65Seed"]) != "" {
			return "", errors.New("暂不支持后量子 Reality 分享链接")
		}
		key, e := base64.RawURLEncoding.DecodeString(str(reality["privateKey"]))
		if e != nil {
			return "", errors.New("Reality 私钥无效")
		}
		priv, e := ecdh.X25519().NewPrivateKey(key)
		if e != nil {
			return "", e
		}
		var names, shorts []string
		_ = json.Unmarshal(reality["serverNames"], &names)
		_ = json.Unmarshal(reality["shortIds"], &shorts)
		if len(names) == 0 || len(shorts) == 0 {
			return "", errors.New("Reality 缺少 serverNames 或 shortIds")
		}
		u.Scheme = "vless"
		u.User = url.User(str(client["id"]))
		q.Set("encryption", "none")
		q.Set("security", "reality")
		network := str(stream["network"])
		if network == "raw" {
			network = "tcp"
		}
		q.Set("type", network)
		q.Set("sni", names[0])
		q.Set("fp", "chrome")
		q.Set("pbk", base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()))
		q.Set("sid", shorts[0])
		if flow := str(client["flow"]); flow != "" {
			q.Set("flow", flow)
		}
	case "hysteria":
		if str(stream["security"]) != "tls" {
			return "", errors.New("目前分享仅支持 Hysteria + TLS")
		}
		u.Scheme = "hysteria2"
		u.User = url.User(str(client["auth"]))
		var tls object
		_ = json.Unmarshal(stream["tlsSettings"], &tls)
		if sni := str(tls["serverName"]); sni != "" {
			q.Set("sni", sni)
		}
		var alpn []string
		_ = json.Unmarshal(tls["alpn"], &alpn)
		if len(alpn) > 0 {
			q.Set("alpn", strings.Join(alpn, ","))
		}
	default:
		return "", errors.New("不支持此协议")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func rate(m map[string]int64, k string) string {
	v, ok := m[k]
	if !ok {
		return "—"
	}
	return formatBytes(v) + "/s"
}

// updateInbound changes only explicitly managed protocol fields.
func updateInbound(in object, proto string, form url.Values) error {
	port, e := strconv.Atoi(form.Get("port"))
	if e != nil || port < 1 || port > 65535 {
		return errors.New("端口必须在 1 到 65535 之间")
	}
	var stream object
	if e = json.Unmarshal(in["streamSettings"], &stream); e != nil || stream == nil {
		return errors.New("入站缺少传输配置")
	}
	switch proto {
	case "vless":
		if str(stream["security"]) != "reality" {
			return errors.New("此入站不是 Reality，不能用此表单编辑")
		}
		var r object
		if e = json.Unmarshal(stream["realitySettings"], &r); e != nil || r == nil {
			return errors.New("缺少 Reality 配置")
		}
		target := strings.TrimSpace(form.Get("target"))
		if target == "" {
			return errors.New("Reality 目标地址不能为空")
		}
		names := strings.Split(form.Get("serverNames"), ",")
		for i := range names {
			names[i] = strings.TrimSpace(names[i])
			if names[i] == "" {
				return errors.New("服务名称不能为空")
			}
		}
		ids := strings.Split(form.Get("shortIds"), ",")
		for i := range ids {
			ids[i] = strings.TrimSpace(ids[i])
			if len(ids[i]) > 16 || len(ids[i])%2 != 0 {
				return errors.New("Short ID 必须是长度不超过 16 的偶数位十六进制")
			}
			if _, e = hex.DecodeString(ids[i]); e != nil {
				return errors.New("Short ID 必须是十六进制")
			}
		}
		put(r, "target", target)
		put(r, "serverNames", names)
		put(r, "shortIds", ids)
		if key := strings.TrimSpace(form.Get("privateKey")); key != "" {
			b, e := base64.RawURLEncoding.DecodeString(key)
			if e != nil {
				return errors.New("Reality 私钥格式无效")
			}
			if _, e = ecdh.X25519().NewPrivateKey(b); e != nil {
				return errors.New("Reality 私钥长度无效")
			}
			put(r, "privateKey", key)
		}
		put(stream, "realitySettings", r)
	case "hysteria":
		if str(stream["security"]) != "tls" {
			return errors.New("此入站不是 TLS，不能用此表单编辑")
		}
		var t object
		if e = json.Unmarshal(stream["tlsSettings"], &t); e != nil || t == nil {
			return errors.New("缺少 TLS 配置")
		}
		cert, key := strings.TrimSpace(form.Get("certFile")), strings.TrimSpace(form.Get("keyFile"))
		if cert == "" || key == "" {
			return errors.New("证书及私钥路径不能为空")
		}
		var certs []object
		if e = json.Unmarshal(t["certificates"], &certs); e != nil || len(certs) == 0 {
			return errors.New("缺少可编辑的证书")
		}
		put(certs[0], "certificateFile", cert)
		put(certs[0], "keyFile", key)
		put(t, "certificates", certs)
		put(t, "serverName", strings.TrimSpace(form.Get("tlsServerName")))
		alpn := []string{}
		if text := strings.TrimSpace(form.Get("alpn")); text != "" {
			for _, v := range strings.Split(text, ",") {
				v = strings.TrimSpace(v)
				if v == "" {
					return errors.New("ALPN 格式无效")
				}
				alpn = append(alpn, v)
			}
		}
		put(t, "alpn", alpn)
		put(stream, "tlsSettings", t)
	default:
		return errors.New("不支持此协议")
	}
	put(in, "port", port)
	put(in, "streamSettings", stream)
	return nil
}

// restart applies an already saved configuration to the explicitly selected service.
func (a *app) restart(w http.ResponseWriter, r *http.Request) {
	token := a.logged(r)
	if token == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(r.FormValue("token"))) != 1 {
		http.Error(w, "forbidden", 403)
		return
	}
	if a.restartService != "mini-xui-xray.service" {
		http.Error(w, "此面板未启用重启服务", 403)
		return
	}
	// Collect first to reduce gaps when Xray's in-memory counters reset.
	a.collectMu.Lock()
	defer a.collectMu.Unlock()
	a.collectUnlocked()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.statsErr != "" {
		http.Error(w, "流量采集失败，未重启："+a.statsErr, 500)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, a.xray, "run", "-test", "-config", a.config).CombinedOutput()
	if err != nil {
		http.Error(w, "配置验证失败，未重启："+strings.TrimSpace(string(out)), 500)
		return
	}
	out, err = exec.CommandContext(ctx, "systemctl", "restart", a.restartService).CombinedOutput()
	if err != nil {
		http.Error(w, "重启失败，请检查 Xray 服务状态："+strings.TrimSpace(string(out)), 500)
		return
	}
	out, err = exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", a.restartService).CombinedOutput()
	if err != nil {
		http.Error(w, "Xray 重启后未正常运行，请检查服务状态："+strings.TrimSpace(string(out)), 500)
		return
	}
	for name, record := range a.stats {
		record.Last = 0
		a.stats[name] = record
	}
	b, err := json.MarshalIndent(a.stats, "", "  ")
	if err == nil {
		err = atomicWrite(a.statsFile, b)
	}
	if err != nil {
		http.Error(w, "Xray 已重启，但流量状态保存失败："+err.Error(), 500)
		return
	}
	a.updated = time.Time{}
	a.rates = map[string]int64{}
	http.Redirect(w, r, "/?notice=配置已应用，Xray 已重启", http.StatusSeeOther)
}
