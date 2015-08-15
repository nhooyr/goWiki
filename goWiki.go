package main

import (
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"golang.org/x/crypto/ocsp"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

type Page struct {
	Title string
	Body  template.HTML
}

func (p *Page) save() error {
	return ioutil.WriteFile("data/" + p.Title, []byte(p.Body), 0644)
}

func loadPage(title string) (*Page, error) {
	body, err := ioutil.ReadFile("data/" + title)
	if err != nil {
		return nil, err
	}
	return &Page{Title: title, Body: template.HTML(body)}, nil
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/front", http.StatusFound)
}

func newHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/edit/"+r.FormValue("title"), http.StatusFound)
}

var linkRegExp = regexp.MustCompile(`\[[a-zA-Z0-9.\-_~!$&'()*+,;=:@ ]+\]`)

func viewHandler(w http.ResponseWriter, r *http.Request, title string) {
	p, err := loadPage(title)
	if err != nil {
		http.Redirect(w, r, "/edit/"+title, http.StatusFound)
		return
	}
	if p.Body == "" {
		p.Body = "Empty"
	}
	p.Body = template.HTML(linkRegExp.ReplaceAllFunc([]byte(template.HTMLEscaper(p.Body)), func(link []byte) []byte {
		sLink := string(link)
		return []byte("<a href=\"/view/" + sLink[1:len(sLink)-1] + "\">" + sLink[1:len(sLink)-1] + "</a>")
	}))
	renderTemplate(w, "view", p)
}

func editHandler(w http.ResponseWriter, r *http.Request, title string) {
	p, err := loadPage(title)
	if err != nil {
		p = &Page{Title: title}
	}
	renderTemplate(w, "edit", p)
}

func saveHandler(w http.ResponseWriter, r *http.Request, title string) {
	if title != r.FormValue("title") {
		os.Rename("data/"+title, "data/"+r.FormValue("title"))
	}
	p := &Page{Title: r.FormValue("title"), Body: template.HTML(r.FormValue("body"))}
	err := p.save()
	if err != nil {
		http.Error(w, err.Error() + "; likely a invalid name (/ not allowed in names)", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/view/"+p.Title, http.StatusFound)
}

var templates = template.Must(template.ParseFiles("tmpl/front.html", "tmpl/edit.html", "tmpl/view.html"))

func renderTemplate(w http.ResponseWriter, tmpl string, p *Page) {
	err := templates.ExecuteTemplate(w, tmpl+".html", p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func delHandler(w http.ResponseWriter, r *http.Request, title string) {
	os.Remove("data/" + title)
	http.Redirect(w, r, "/front", http.StatusSeeOther)
}

var validPath = regexp.MustCompile(`^\/(edit|save|view|del)\/([a-zA-Z0-9.\-_~!$&'()*+,;=:@ ]+)$`)

func titleHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m := validPath.FindStringSubmatch(r.URL.Path)
		if m == nil {
			http.Error(w, "Invalid Name", http.StatusInternalServerError)
			return
		}
		fn(w, r, m[2])
	}
}

func frontHandler(w http.ResponseWriter, r *http.Request) {
	type LeList struct {
		ListItems template.HTML
	}
	htmlList := LeList{}
	files, err := ioutil.ReadDir("data")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	if len(files) > 0 {
		for i := 0; i < len(files); i++ {
			leName := files[i].Name()[:len(files[i].Name())]
			htmlList.ListItems = htmlList.ListItems + template.HTML("<li><a href=\"/view/"+leName+"\">"+leName+"</a></li><br/>")
		}
	} else {
		htmlList.ListItems = template.HTML("<li>No pages</li>")
	}
	err = templates.ExecuteTemplate(w, "front.html", htmlList)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

const (
	DOMAIN = "www.aubble.com"
	HTTPS_PORT = ":443"
	HTTP_PORT = ":80"
	KEY = "key.pem"
	CERT = "cert.pem"
	ISSUER = "issuer.pem"
	TIMEOUT = 30
)

type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}

type gzipResponseWriter struct {
	gzipWriter io.Writer
	http.ResponseWriter
	sniffDone  bool
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	if !w.sniffDone && w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", http.DetectContentType(b))
		w.sniffDone = true
	}
	return w.gzipWriter.Write(b)
}

func newGzipHandleFunc(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Accept-Encoding")
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			handler(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		handler(&gzipResponseWriter{gzipWriter: gz, ResponseWriter: w}, r)
	}
}

func newLoggingHandleFunc(handler func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=15552000; includeSubDomains; preload")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Server", "Jesus")
		if r.Host == DOMAIN[4:] {
			log.Println("redirecting", r.RemoteAddr, "to web domain", DOMAIN+HTTPS_PORT+r.URL.String())
			http.Redirect(w, r, "https://"+DOMAIN+HTTPS_PORT+r.URL.String(), http.StatusMovedPermanently)
			return
		}
		log.Println(r.URL.String() + " : " + r.RemoteAddr + " : " + r.Host)
		handler(w, r)
	})
}

func main() {
	http.HandleFunc("/", newLoggingHandleFunc(rootHandler))
	http.HandleFunc("/new", newLoggingHandleFunc(newHandler))
	http.HandleFunc("/view/", newLoggingHandleFunc(newGzipHandleFunc(titleHandler(viewHandler))))
	http.HandleFunc("/edit/", newLoggingHandleFunc(newGzipHandleFunc(titleHandler(editHandler))))
	http.HandleFunc("/save/", newLoggingHandleFunc(titleHandler(saveHandler)))
	http.HandleFunc("/del/", newLoggingHandleFunc(titleHandler(delHandler)))
	http.HandleFunc("/front", newLoggingHandleFunc(newGzipHandleFunc(frontHandler)))
	log.SetPrefix("goWiki: ")
	log.Println("listening... on port", HTTPS_PORT)
	go func() {
		for {
			err := func() error {
				cert, err := tls.LoadX509KeyPair(CERT, KEY)
				if err != nil {
					return err
				}
				if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
					return err
				}
				if cert.Leaf.OCSPServer != nil {
					issuerRAW, err := ioutil.ReadFile(ISSUER)
					if err != nil {
						return err
					}
					var issuer *x509.Certificate
					for {
						var issuerPEM *pem.Block
						issuerPEM, issuerRAW = pem.Decode(issuerRAW)
						if issuerPEM == nil {
							break
						}
						if issuerPEM.Type == "CERTIFICATE" {
							issuer, err = x509.ParseCertificate(issuerPEM.Bytes)
							if err != nil {
								return err
							}
						}
					}
					if issuer == nil {
						return err
					}
					req, err := ocsp.CreateRequest(cert.Leaf, issuer, nil)
					if err != nil {
						return err
					}
					var resp *http.Response
					for i := 0; i < len(cert.Leaf.OCSPServer); i++ {
						httpReq, err := http.NewRequest("GET", cert.Leaf.OCSPServer[i]+"/"+base64.StdEncoding.EncodeToString(req), nil)
						httpReq.Header.Add("Content-Language", "application/ocsp-request")
						httpReq.Header.Add("Accept", "application/ocsp-response")
						resp, err = http.DefaultClient.Do(httpReq)
						if err == nil {
							break
						}
						if i == len(cert.Leaf.OCSPServer){
							break
						}
						continue
					}
					if cert.OCSPStaple, err = ioutil.ReadAll(resp.Body); err != nil {
						return err
					}
					resp.Body.Close()
				}
				//TODO this ocsp in a goroutine and TLSConfig.GetCertificate
				TLSConfig := new(tls.Config)
				TLSConfig.Certificates = []tls.Certificate{cert}
				TLSConfig.BuildNameToCertificate()
				TLSConfig.CipherSuites = []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
					tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}
				TLSConfig.PreferServerCipherSuites = true
				TLSConfig.MinVersion = tls.VersionTLS11
				//MaxVersion needed because of bug with TLS_FALLBACK_SCSV gonna be fixed in go 1.5
				TLSConfig.MaxVersion = tls.VersionTLS12
				TLSConfig.NextProtos = []string{"http/1.1"}
				ln, err := net.Listen("tcp", HTTPS_PORT)
				if err != nil {
					return err
				}
				tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, TLSConfig)
				return new(http.Server).Serve(tlsListener)
			}()
			if err != nil {
				log.Println(err)
			}
		}
		time.Sleep(time.Second * TIMEOUT)
	}()
	for {
		log.Println("redirecting from port", HTTP_PORT, "to", HTTPS_PORT)
		err := http.ListenAndServe(HTTP_PORT, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Strict-Transport-Security", "max-age=15552000; includeSubDomains; preload")
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			log.Println("redirecting http", r.RemoteAddr, "to https", DOMAIN+HTTPS_PORT+r.URL.String())
			http.Redirect(w, r, "https://"+DOMAIN+HTTPS_PORT+r.URL.String(), http.StatusMovedPermanently)
		}))
		if err != nil {
			log.Println(err)
		}
		time.Sleep(time.Second * TIMEOUT)
	}
}

//todo when go 1.5 release, http2, take off maxversion in tlsconfig, and add session ticket rotation, and update OCSP response