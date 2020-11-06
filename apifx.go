package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	debug "net/http/pprof"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/ratelimit"
)

type config struct {
	Open    bool
	GoodIps []string
	GoodUri []string
	RateIps map[string]int
	Redirs map[string]string
}

var (
	listenAddr  string
	listenAddr2 string
	listenAddr3 string
	cfgDump     string
	cfg         = &config{
		Open: false,
	}
	stats   chan (string)
	verbose bool
	rl      map[string]ratelimit.Limiter

	HealthRegistry *prometheus.Registry
	AccessMetric   = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "access_total",
			Help: "Total amount of requests checked",
		},
		[]string{"access"},
	)
	DenyMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "deny_total",
			Help: "Total amount of requests denied",
		},
		[]string{"deny"},
	)
)

var lock = &sync.Mutex{}

func init() {
	stats = make(chan string)
	cfg.RateIps = make(map[string]int)
	cfg.Redirs = make(map[string]string)
	rl = make(map[string]ratelimit.Limiter)
	//create a registry
	HealthRegistry = prometheus.NewRegistry()
	HealthRegistry.MustRegister(AccessMetric)
	HealthRegistry.MustRegister(DenyMetric)
	//sample of header based redir
	//cfg.Redirs["X-Mauro"]="www.example.com"
}

func main() {
	flag.StringVar(&listenAddr, "listen-nginx", "/tmp/apifx.sock", "Listen address/socket for Nginx")
	flag.StringVar(&listenAddr2, "listen-api", ":5001", "Listen address for mgmt API")
	flag.StringVar(&listenAddr3, "listen-prom", ":5002", "Listen address for mgmt API")
	flag.StringVar(&cfgDump, "config-dump", "/tmp/cfg.dump", "Path for the configuration dump")
	flag.BoolVar(&verbose, "verbose", true, "increase verbosity")
	flag.Parse()
	logger := log.New(os.Stdout, "apifx: ", log.LstdFlags)
	Load(cfgDump, cfg)
	if cfg.GoodUri == nil {
		parseSwagger()
	}
	setupRateLimits()
	if verbose {
		log.Printf("Verbose on")
	}
	go func() {
		unixListener, err := net.Listen("unix",listenAddr)
		if err != nil {
			panic(err)
		}

		server := &http.Server{
			Addr:         listenAddr,
			Handler:      routes(),
			ErrorLog:     logger,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  15 * time.Second,
		}
		logger.Println("Server is ready to handle requests from NGINX at", listenAddr)

		if err := server.Serve(unixListener); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Could not listen on %s: %v\n", listenAddr, err)
		}
	}()
	go func() {
		serverBackend := &http.Server{
			Addr:         listenAddr2,
			Handler:      routesBackend(),
			ErrorLog:     logger,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  15 * time.Second,
		}
		logger.Println("Server is ready to handle requests for mgmt API at", listenAddr2)

		if err := serverBackend.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Could not listen on %s: %v\n", listenAddr, err)
		}
	}()

	go func() {
		logger.Println("Starting http server to serve metrics at port ", listenAddr3)

		server := http.NewServeMux()
		server.Handle("/metrics", promhttp.HandlerFor(HealthRegistry, promhttp.HandlerOpts{}))

		http.ListenAndServe(listenAddr3, server)
	}()

	go process_stats()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		lock.Lock()
		cfgCopy := cfg
		lock.Unlock()
		//log.Printf("")
		Save(cfgDump, cfgCopy)
	}
}

// Setup endpoints for Nginx
func routes() *http.ServeMux {
	router := http.NewServeMux()
	router.HandleFunc("/auth", authHandler)
	return router
}

// Setup backend endpoints
func routesBackend() *http.ServeMux {
	routerBackend := http.NewServeMux()
	routerBackend.HandleFunc("/open", openHandler)
	routerBackend.HandleFunc("/addgoodip", addGoodHandler)
	routerBackend.HandleFunc("/addlimitip", addLimitHandler)
	routerBackend.HandleFunc("/delip", delHandler)
	routerBackend.HandleFunc("/showcfg", showHandler)
	routerBackend.HandleFunc("/newswagger", swagHandler)
	routerBackend.HandleFunc("/debug/pprof/", debug.Index)
	return routerBackend
}

// Communicate with Nginx
func authHandler(w http.ResponseWriter, r *http.Request) {
	validated := false
	ip := r.Header.Get("IP")
	method := r.Header.Get("METHOD")
	uri := r.Header.Get("URI")
	url := method + " " + uri
	//body, err := ioutil.ReadAll(r.Body)
	stats <- url + " " + ip
	if verbose {
		log.Printf("Request from: %s, uri: %s", ip, url)
	}
	lock.Lock()
	cfgCopy := cfg
	lock.Unlock()
	if cfgCopy.Open {
		w.WriteHeader(http.StatusOK)
		log.Printf("Replied 200")
		return
	}
	//we check the SRC IP
	for _, goodIp := range cfgCopy.GoodIps {
		if ip == goodIp {
			validated = true
			break
		}
	}
	if !validated {
		// we check the ratelimiting
		for k, _ := range cfgCopy.RateIps {
			if k == ip {
				rl[k].Take()
				validated = true
				break
			}
		}
	}

	if !validated {
		w.WriteHeader(http.StatusForbidden)
		log.Printf("Replied 403")
		DenyInc(ip)
		return
	}

	validated = false
	for _, goodUri := range cfgCopy.GoodUri {
		if url == goodUri {
			validated = true
			break
		}
	}
	// look for specific header redir
	for header, redirection := range cfgCopy.Redirs {
		for h,v := range r.Header {
			log.Printf("examining %s:%s",h,v[0])
			if  h == header {
				log.Printf("found! %s", redirection)
				w.WriteHeader(http.StatusFound)
				//http.Redirect(w,r,redirection, http.StatusFound)
				return
			}
		}
	}
	if !validated {
		w.WriteHeader(http.StatusForbidden)
		log.Printf("Replied 403")
		DenyInc(ip)
		return
	}

	// finally we reply to Nginx with a 200
	w.WriteHeader(http.StatusOK)
	log.Printf("Replied 200")
}

func setupRateLimits() {
	lock.Lock()
	cfgCopy := cfg
	lock.Unlock()
	for ip, limit := range cfgCopy.RateIps {
		log.Printf("setting limit of %d for %s\n", limit, ip)
		rl[ip] = ratelimit.New(limit)
	}
}

// flick the open switch
func openHandler(w http.ResponseWriter, r *http.Request) {
	lock.Lock()
	if cfg.Open {
		cfg.Open = false
	} else {
		cfg.Open = true
	}
	lock.Unlock()
	log.Printf("open is %v", cfg.Open)
	w.WriteHeader(http.StatusOK)
}

func addGoodHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	ipinfo := query.Get("ip")
	IP := net.ParseIP(ipinfo)
	if IP != nil {
		lock.Lock()
		cfg.GoodIps = AppendIfMissing(cfg.GoodIps, ipinfo)
		msg := ipinfo + " added"
		lock.Unlock()
		log.Println(msg)
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNotAcceptable)
		log.Printf("invalid IP %s", ipinfo[0])
	}
}

func addLimitHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	ipinfo := strings.Split(query.Get("ip"), ",")
	IP := net.ParseIP(ipinfo[0])
	// extract the rate limiting value
	rate := 0
	if ipinfo[1] != "-1" {
		rate, _ = strconv.Atoi(ipinfo[1])
	}
	if IP != nil {
		lock.Lock()
		msg := ipinfo[0] + " added"
		if rate != 0 {
			cfg.RateIps[ipinfo[0]] = rate
			msg = msg + " with rate limit of " + ipinfo[1]
		}
		lock.Unlock()
		log.Println(msg)
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNotAcceptable)
		log.Printf("invalid IP %s", ipinfo[0])
	}
	setupRateLimits()
}

func showHandler(w http.ResponseWriter, r *http.Request) {
	lock.Lock()
	cfgCopy := cfg
	lock.Unlock()
	fmt.Fprintf(w, "Running config:\n %v\n", cfgCopy)
}

func delHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	ipDelete := query.Get("ip")
	lock.Lock()
	cfgCopy := cfg
	lock.Unlock()
	slice := cfgCopy.GoodIps
	pos := -1
	for x, ip := range cfgCopy.GoodIps {
		if ip == ipDelete {
			pos = x
			break
		}
	}
	if pos >= 0 {
		copy(slice[pos:], slice[pos+1:])
		cfg.GoodIps = slice[:len(slice)-1]
	}

	//in case is in RateIps
	delete(cfg.RateIps, ipDelete)

	log.Printf("%s removed", ipDelete)
	w.WriteHeader(http.StatusOK)
}

func swagHandler(w http.ResponseWriter, r *http.Request) {
	parseSwagger()
	fmt.Fprintf(w, "OK\n")
}

func Save(path string, v interface{}) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, bytes.NewReader(r))
	return err
}

func Load(path string, v interface{}) error {
	lock.Lock()
	defer lock.Unlock()
	f, err := ioutil.ReadFile(path)
	if err != nil {
		log.Printf("Config dump not found on disk")
	} else {
		log.Printf("Config loaded from disk")
	}
	return json.Unmarshal(f, v)
}

func process_stats() {
	for {
		data := <-stats
		info := strings.Split(data, " ")
		AccessInc("total")
		AccessInc(info[0])
		if len(info) > 1 {
			AccessInc(info[1])
		}
		if len(info) > 2 {
			AccessInc(info[2])
		}
	}
}

func AccessInc(info string) {
	AccessMetric.With(prometheus.Labels{"access": info}).Inc()
}

func DenyInc(info string) {
	DenyMetric.With(prometheus.Labels{"deny": info}).Inc()
}

func fetchSwagger() (swagger []byte) {
	res, err := http.Get("https://xxx.com/docs/swagger.json")
	if err != nil {
		log.Println(err)
	} else {
		swagger, err = ioutil.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			log.Println(err)
		}
	}
	// failover
	swagger, err = ioutil.ReadFile("/tmp/swagger.json")
	if err != nil {
		log.Println(err)
	}
	return swagger
}

func parseSwagger() {
	var validUrls []string
	var uniqueUrls []string
	//var validparms map[string]string
	data := fetchSwagger()
	if data == nil {
		return
	}
	// Declared an empty interface of type Array
	var results map[string]interface{}

	// Unmarshal or Decode the JSON to the interface.
	json.Unmarshal([]byte(data), &results)
	uri := ""
	address := results["paths"].(map[string]interface{})
	for k, _ := range address {
		dirs := strings.Split(k, "/")
		for method, _ := range address[k].(map[string]interface{}) {
			uri = strings.ToUpper(method) + " /" + dirs[1]
			validUrls = append(validUrls, uri)
			//for p,_ := range results[k][method].(map[string]interface{}){
			//	fmt.Println("---"+p)
			//}
		}
	}

	//fmt.Println(validUrls)
	for _, v := range validUrls {
		uniqueUrls = AppendIfMissing(uniqueUrls, v)
	}
	fmt.Println(uniqueUrls)
	lock.Lock()
	cfg.GoodUri = uniqueUrls
	lock.Unlock()
}

func AppendIfMissing(slice []string, i string) []string {
	for _, ele := range slice {
		if ele == i {
			return slice
		}
	}
	return append(slice, i)
}

/*
// to implement network checks
func (s *Server) whitelisted(client string) (good bool) {
	good = false
	clientip := strings.Split(client, ":")
	dnsclient := net.ParseIP(clientip[0])
	for _, networks := range s.conf.Allowed {
		_, subnet, _ := net.ParseCIDR(networks)
		if subnet.Contains(dnsclient) {
			good = true
			break
		}
	}
	return good
}
*/
