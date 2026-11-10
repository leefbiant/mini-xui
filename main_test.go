package main

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testApp(t *testing.T) *app {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	xray := filepath.Join(dir, "xray")
	data := `{"other":{"keep":true},"inbounds":[{"protocol":"vless","port":443,"settings":{"clients":[{"email":"old","id":"original","flow":"keep"}],"decryption":"none"}},{"protocol":"hysteria","port":8446,"settings":{"clients":[],"version":2}},{"protocol":"tunnel","settings":{}}]}`
	if err := os.WriteFile(cfg, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(xray, []byte("#!/bin/sh\nif [ \"$1\" = api ]; then printf '%s' '{\"stat\":[{\"name\":\"user>>>old>>>traffic>>>uplink\",\"value\":\"123\"}]}'; fi\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return &app{config: cfg, xray: xray, statsFile: filepath.Join(dir, "stats.json"), api: "127.0.0.1:1", sessions: map[string]time.Time{"session": time.Now().Add(time.Hour)}, stats: map[string]statRecord{}}
}
func post(t *testing.T, a *app, v url.Values) *httptest.ResponseRecorder {
	t.Helper()
	v.Set("token", "session")
	r := httptest.NewRequest("POST", "/change", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Cookie", "mini_session=session")
	w := httptest.NewRecorder()
	a.change(w, r)
	return w
}
func TestAddPreservesConfigurationAndBackup(t *testing.T) {
	a := testApp(t)
	w := post(t, a, url.Values{"action": {"add"}, "inbound": {"1"}, "email": {"new"}, "credential": {"secret"}})
	if w.Code != 303 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	root, ins, e := readConfig(a.config)
	if e != nil {
		t.Fatal(e)
	}
	if string(root["other"]) == "" || len(ins) != 3 {
		t.Fatal("unrelated configuration lost")
	}
	_, cs, e := clients(ins[1])
	if e != nil || len(cs) != 1 || str(cs[0]["auth"]) != "secret" {
		t.Fatalf("bad client: %v %v", cs, e)
	}
	if _, e = os.Stat(a.config + ".bak"); e != nil {
		t.Fatal(e)
	}
}
func TestValidationFailureDoesNotChangeConfig(t *testing.T) {
	a := testApp(t)
	before, _ := os.ReadFile(a.config)
	if e := os.WriteFile(a.xray, []byte("#!/bin/sh\nexit 1\n"), 0700); e != nil {
		t.Fatal(e)
	}
	w := post(t, a, url.Values{"action": {"add"}, "inbound": {"0"}, "email": {"new"}})
	after, _ := os.ReadFile(a.config)
	if w.Code != 500 || string(before) != string(after) {
		t.Fatal("invalid config was not rejected")
	}
}
func TestStatsPersistsWithoutDoubleCounting(t *testing.T) {
	a := testApp(t)
	a.collect()
	a.collect()
	var data map[string]statRecord
	b, e := os.ReadFile(a.statsFile)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &data); e != nil {
		t.Fatal(e)
	}
	if got := data["user>>>old>>>traffic>>>uplink"].Total; got != 123 {
		t.Fatalf("got %d", got)
	}
}

func TestShareLinkRealityAndHysteria(t *testing.T) {
	var v object
	if err := json.Unmarshal([]byte(`{"protocol":"vless","port":1443,"streamSettings":{"network":"raw","security":"reality","realitySettings":{"privateKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","serverNames":["example.org"],"shortIds":["abcd"]}}}`), &v); err != nil {
		t.Fatal(err)
	}
	c := object{}
	put(c, "email", "phone")
	put(c, "id", "00000000-0000-4000-8000-000000000000")
	link, err := shareLink("203.0.113.1", v, c)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "vless" || u.Host != "203.0.113.1:1443" || u.Query().Get("pbk") == "" || u.Query().Get("sni") != "example.org" || u.Query().Get("type") != "tcp" {
		t.Fatalf("invalid VLESS link %v", err)
	}
	var h object
	if err = json.Unmarshal([]byte(`{"protocol":"hysteria","port":18446,"streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.org","alpn":["h3"]}}}`), &h); err != nil {
		t.Fatal(err)
	}
	put(c, "auth", "a/b@c")
	link, err = shareLink("203.0.113.1", h, c)
	if err != nil {
		t.Fatal(err)
	}
	u, err = url.Parse(link)
	if err != nil || u.Scheme != "hysteria2" || u.User.Username() != "a/b@c" || u.Query().Get("sni") != "example.org" {
		t.Fatal("invalid Hysteria link")
	}
}
func TestShareRequiresLogin(t *testing.T) {
	a := testApp(t)
	w := httptest.NewRecorder()
	a.share(w, httptest.NewRequest("GET", "/share?inbound=0&client=0", nil))
	if w.Code != 401 {
		t.Fatalf("got %d", w.Code)
	}
}

func TestProtocolSettingsPreserveOtherFields(t *testing.T) {
	var in object
	if e := json.Unmarshal([]byte(`{"port":443,"protocol":"vless","streamSettings":{"security":"reality","network":"raw","realitySettings":{"target":"old:443","serverNames":["old"],"shortIds":["abcd"],"privateKey":"original","xver":0}}}`), &in); e != nil {
		t.Fatal(e)
	}
	form := url.Values{"port": {"1443"}, "target": {"new:443"}, "serverNames": {"one.example,two.example"}, "shortIds": {"abcd,ef"}}
	if e := updateInbound(in, "vless", form); e != nil {
		t.Fatal(e)
	}
	var stream, reality object
	_ = json.Unmarshal(in["streamSettings"], &stream)
	_ = json.Unmarshal(stream["realitySettings"], &reality)
	if string(in["port"]) != "1443" || str(reality["target"]) != "new:443" || str(reality["privateKey"]) != "original" || string(reality["xver"]) != "0" {
		t.Fatal("config was not preserved")
	}
	form.Set("shortIds", "xyz")
	if updateInbound(in, "vless", form) == nil {
		t.Fatal("invalid short id accepted")
	}
}
func TestProtocolTLSSettingsPreserveCertificateMetadata(t *testing.T) {
	var in object
	_ = json.Unmarshal([]byte(`{"port":8446,"streamSettings":{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/old","keyFile":"/key","usage":"encipherment"}]}}}`), &in)
	f := url.Values{"port": {"18446"}, "certFile": {"/new-cert"}, "keyFile": {"/new-key"}, "tlsServerName": {"example.com"}, "alpn": {"h3"}}
	if e := updateInbound(in, "hysteria", f); e != nil {
		t.Fatal(e)
	}
	var stream, tls object
	var certs []object
	_ = json.Unmarshal(in["streamSettings"], &stream)
	_ = json.Unmarshal(stream["tlsSettings"], &tls)
	_ = json.Unmarshal(tls["certificates"], &certs)
	if str(certs[0]["usage"]) != "encipherment" || str(certs[0]["certificateFile"]) != "/new-cert" {
		t.Fatal("certificate metadata lost")
	}
}

func TestRestartAuthorizesAndPersistsCounters(t *testing.T) {
	a := testApp(t)
	a.restartService = "mini-xui-xray.service"
	systemctl := filepath.Join(filepath.Dir(a.config), "systemctl")
	if e := os.WriteFile(systemctl, []byte("#!/bin/sh\nexit 0\n"), 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("PATH", filepath.Dir(a.config)+string(os.PathListSeparator)+os.Getenv("PATH"))
	r := httptest.NewRequest("POST", "/restart", strings.NewReader("token=session"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Cookie", "mini_session=session")
	w := httptest.NewRecorder()
	a.restart(w, r)
	if w.Code != 303 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	v := a.stats["user>>>old>>>traffic>>>uplink"]
	if v.Total != 123 || v.Last != 0 {
		t.Fatalf("bad counter after restart: %+v", v)
	}
}
func TestRestartRequiresSessionAndToken(t *testing.T) {
	a := testApp(t)
	a.restartService = "mini-xui-xray.service"
	r := httptest.NewRequest("POST", "/restart", strings.NewReader("token=wrong"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Cookie", "mini_session=session")
	w := httptest.NewRecorder()
	a.restart(w, r)
	if w.Code != 403 {
		t.Fatalf("got %d", w.Code)
	}
}

func TestDashboardShowsCorrectApplyInstructions(t *testing.T) {
	a := testApp(t)
	dashboard := func() string {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Cookie", "mini_session=session")
		w := httptest.NewRecorder()
		a.index(w, r)
		if w.Code != 200 {
			t.Fatalf("status: %d", w.Code)
		}
		return w.Body.String()
	}
	body := dashboard()
	if !strings.Contains(body, "手动重启 Xray") || strings.Contains(body, `action="/restart"`) {
		t.Fatal("manual restart instructions missing")
	}
	a.restartService = "mini-xui-xray.service"
	body = dashboard()
	if !strings.Contains(body, `action="/restart"`) || !strings.Contains(body, "重启并应用配置") {
		t.Fatal("restart controls missing")
	}
}
