// This file is part of firebut.
// Copyright 2019 Darell Tan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the README.

package main

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gopkg.in/cheggaaa/pb.v1"

	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// Compression level used when uploading to Firebase
	compressionLevel = gzip.BestCompression

	// format for progress bar
	pbFormat = "[=- ]"

	configFilename = ".firebut"
)

// Out-of-band URL for OAuth2 authentication
const OAuthOOBUrl = "urn:ietf:wg:oauth:2.0:oob"

var config = &Config{}

// global flags
var (
	verbose = flag.Bool("v", false, "produce more verbose output")
)

type Config struct {
	SiteName    string
	CachedToken *oauth2.Token
}

func (c *Config) Read(fname string) error {
	f, err := os.Open(fname)
	if err != nil {
		return err
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	err = dec.Decode(c)
	return err
}

func (c *Config) Write(fname string) error {
	f, err := os.OpenFile(fname, os.O_CREATE|os.O_WRONLY, 0700)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	return enc.Encode(c)
}

func getQueryParam(url *url.URL, key string) string {
	v, found := url.Query()[key]
	if found && len(v) > 0 {
		return v[0]
	}
	return ""
}

func rand64() uint64 {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		panic("unable to generate random number")
	}
	var n uint64
	n = uint64(b[0])<<0 |
		uint64(b[1])<<8 |
		uint64(b[2])<<16 |
		uint64(b[3])<<24 |
		uint64(b[4])<<32 |
		uint64(b[5])<<40 |
		uint64(b[6])<<48 |
		uint64(b[7])<<56
	return n
}

// Performs the OAuth2 authorization flow.
// If you wish to use OOB method, set conf.RedirectURL to OAuthOOBUrl.
func authorize(conf *oauth2.Config) (*oauth2.Token, error) {
	cookie := fmt.Sprintf("%x", rand64())

	ch := make(chan string)

	var svr *http.Server
	if conf.RedirectURL != OAuthOOBUrl {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, fmt.Errorf("unable to create a local listening socket: %+v", err)
		}

		port := listener.Addr().(*net.TCPAddr).Port
		cbUrl := "/oauth"

		// construct callback URL
		conf.RedirectURL = fmt.Sprintf("http://localhost:%d%s", port, cbUrl)

		handler := func(resp http.ResponseWriter, req *http.Request) {
			var msg, title string
			if req.Method == "GET" && strings.HasPrefix(req.URL.Path, cbUrl) {
				// verify returned parameters
				if getQueryParam(req.URL, "state") != cookie {
					msg = "OAuth state doesn't match"
				} else {
					code := getQueryParam(req.URL, "code")
					if code != "" {
						ch <- code
						title, msg = "Done!", "You may now close this window/tab"
					} else {
						msg = "Invalid parameters"
					}
				}

				if title == "" {
					title = "Error"
				}

				fmt.Fprintf(resp, "<h1>%s</h1><p>%s</p>", title, msg)
			}
		}

		svr = &http.Server{Handler: http.HandlerFunc(handler)}

		if *verbose {
			fmt.Printf("waiting for OAuth2 callback on %+v\n", listener.Addr())
		}

		go func() {
			svr.Serve(listener)
			close(ch)
		}()
	}

	url := conf.AuthCodeURL(cookie)
	fmt.Printf("visit the URL to authorize:\n%v\n", url)

	if conf.RedirectURL == OAuthOOBUrl {
		go func() {
			code := ""
			fmt.Printf("enter code: ")
			fmt.Scanln(&code)
			ch <- code
			close(ch)
		}()
	}

	oauthCode := <-ch // wait for code

	// shutdown http server if necessary
	if svr != nil {
		svr.Shutdown(context.Background())
	}

	// wait till whatever input method closes
	<-ch

	if oauthCode == "" {
		return nil, fmt.Errorf("no code was entered")
	}

	token, err := conf.Exchange(oauth2.NoContext, oauthCode)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// Hashes a directory, returning a filepath->hash map.
// This just calls hashFiles() after walking the specified root directory.
// File paths will be relative to the specified basedir and using forward
// slashes instead of the OS separator.
func hashDirectory(basedir string) (map[string]string, error) {
	files := make([]string, 0)
	err := filepath.Walk(basedir, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !f.Mode().IsRegular() {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}

	hashes, err := hashFiles(files)
	if err != nil {
		return nil, err
	}

	hashesMap := make(map[string]string)
	for i, h := range hashes {
		p, err := filepath.Rel(basedir, files[i])
		if err != nil {
			p = files[i]
		}
		p = filepath.ToSlash(p)
		hashesMap[p] = h
	}

	return hashesMap, nil
}

type DiffStatus rune

const (
	DiffNew      DiffStatus = '+'
	DiffModified            = 'M'
	DiffDeleted             = '-'
	DiffNoChange            = ' '
)

// Compares files locally to what is on the server.
// Returns a map of file paths and its corresponding status.
func diffToServer(localFiles map[string]string, serverFiles []VersionFile) map[string]DiffStatus {
	diffMap := make(map[string]DiffStatus)
	for _, remoteFile := range serverFiles {
		p := remoteFile.Path[1:]

		var status DiffStatus
		localHash, localExists := localFiles[p]
		if localExists {
			if localHash == remoteFile.Hash {
				status = DiffNoChange
			} else {
				status = DiffModified
			}
		} else {
			status = DiffDeleted
		}

		diffMap[p] = status
	}

	// now look for files in the local map to see which ones are new
	for localFile, _ := range localFiles {
		if _, remoteExists := diffMap[localFile]; !remoteExists {
			diffMap[localFile] = DiffNew
		}
	}

	return diffMap
}

// Gets the next argument and returns the remaining args.
// If there are no more args, `rest` will never be nil but instead an empty
// slice.
func nextArg(args []string) (arg string, rest []string) {
	l := len(args)
	if l == 0 {
		arg = ""
		rest = args[0:]
	} else {
		arg = args[0]
		rest = args[1:]
	}
	return
}

// Parses action-specific flags.
// Pass in the command-line (after the action verb) and it will return the
// remainder of the command-line after parsing flags.
func parseActionFlags(flagSet *flag.FlagSet, commandLine []string) []string {
	flagSet.Usage = func() {
		usage := `
Usage: %s [global flags...] %s [action flags...]

where action flags are:
`

		fmt.Fprintf(flag.CommandLine.Output(), usage, os.Args[0], flagSet.Name())
		flagSet.PrintDefaults()
	}
	flagSet.Parse(commandLine)
	return flagSet.Args()
}

func main() {
	flag.Usage = func() {
		usage := `
Usage: %s [-v | global flags...] <action> [action flags...]
		
where <action> is one of the following:
    login     - logs into Firebase
    upload    - uploads (deploy) files to Firebase Hosting
    diff      - performs a diff of local files to current release

Use "%[1]s <action> -help" for usage of that action, 
for example, "%[1]s upload -help"

The following global flags, placed before <action>, are supported:

`
		fmt.Fprintf(flag.CommandLine.Output(), usage, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	actionFlags := map[string]*flag.FlagSet{
		"login":  flag.NewFlagSet("login", flag.ExitOnError),
		"upload": flag.NewFlagSet("upload", flag.ExitOnError),

		// specify actions here, without action-specific flags
		"diff":     nil,
		"releases": nil,
	}

	args := flag.Args()

	// check for recognized actions against the map
	action, args := nextArg(args)
	flagSet, actionFound := actionFlags[action]
	if !actionFound {
		fmt.Printf("unknown action %q\n", action)
		flag.Usage()
		os.Exit(2)
	}

	err := config.Read(configFilename)
	if err != nil && !os.IsNotExist(err) {
		fmt.Printf("cannot read config file: %+v\n", err)
		return
	}

	if config.SiteName == "" && action != "login" {
		fmt.Println("use login first")
		os.Exit(1)
	}

	conf := &oauth2.Config{
		ClientID:     "701427408010-kfoluqkdcfnnc2tj8akgae8lah1eco6h.apps.googleusercontent.com",
		ClientSecret: "Tx1c3vGyFub6d4thCvSTlEcb",

		RedirectURL: "",
		Endpoint:    google.Endpoint,
		Scopes: []string{
			FirebaseHostingScope,
			FirebaseScope,
			CloudPlatformScope,
		},
	}

	// "login" action is handled here
	if action == "login" {
		useOob := flagSet.Bool("oob", false, "use out-of-band code entry for OAuth")
		args = parseActionFlags(flagSet, args)

		var siteName string
		siteName, args = nextArg(args)
		if siteName == "" {
			fmt.Println("need to specify site-name")
			os.Exit(1)
		} else {
			config.SiteName = siteName
		}

		if *useOob {
			conf.RedirectURL = OAuthOOBUrl
		}
	}

	if config.CachedToken == nil {
		token, err := authorize(conf)
		if err != nil {
			fmt.Printf("cant authorize. %v\n", err)
			return
		}

		//fmt.Printf("token = %v\n", token)

		if token != nil {
			config.CachedToken = token
		}
	}

	// write config file if not empty
	defer func() {
		// XXX need a better way to check for non-empty config
		if config.SiteName != "" || config.CachedToken != nil {
			config.Write(configFilename)
		}
	}()

	// FIXME: not sure why first req after authorization says
	// "token expired and refresh token is not set"
	// it's very obviously set from the print above
	client := conf.Client(oauth2.NoContext, config.CachedToken)

	// TODO read public path from firebase.json
	uploadDir := "public"
	if _, err := os.Stat(uploadDir); os.IsNotExist(err) {
		fmt.Printf("public directory does not exist: %q\n", uploadDir)
		os.Exit(1)
	}

	h := HostingClient(client, config.SiteName)

	switch action {
	case "diff":
		if err := doDiff(h, uploadDir); err != nil {
			fmt.Println("unable to do diff:", err)
			os.Exit(1)
		}

	case "releases":
		releases, err := h.Releases()
		if err != nil {
			return
		}
		fmt.Println("releases:")
		for _, r := range releases {
			fmt.Printf("%+v\n", r)
		}

	case "upload":
		message := flagSet.String("message", "", "message for this release")
		args = parseActionFlags(flagSet, args)

		version, err := doUploadVersion(h, uploadDir)
		if err != nil {
			fmt.Println("cannot upload new version:", err)
			os.Exit(1)
		}
		if *verbose {
			fmt.Printf("finalized version: %+v\n", version)
		}
		release, err := h.ReleaseVersion(version.Name, *message)
		if err != nil {
			fmt.Println("cannot release version:", err)
			os.Exit(1)
		}
		if *verbose {
			fmt.Printf("release: %+v\n", release)
		}
		fmt.Printf("version %s released\n", release.Name)
	}
}

func doUploadVersion(h *Hosting, uploadDir string) (Version, error) {
	var emptyVer Version

	localFiles, err := hashDirectory(uploadDir)
	if err != nil {
		return emptyVer, err
	}

	newVersion, err := h.NewVersion()
	if err != nil {
		return emptyVer, err
	}

	if *verbose {
		fmt.Printf("new version: %+v\n", newVersion)
	}

	requiredUploads, uploadUrl, err := h.PopulateFiles(newVersion.Name, localFiles)
	if err != nil {
		return emptyVer, err
	}

	err = uploadFiles(h, uploadUrl, requiredUploads, uploadDir, localFiles)
	if err != nil {
		return emptyVer, err
	}

	finalizedVer, err := h.FinalizeVersion(newVersion.Name)
	if err != nil {
		return emptyVer, err
	}

	return finalizedVer, nil
}

func uploadFiles(h *Hosting, baseurl string, requiredUploads []string, basedir string, localFiles map[string]string) error {
	// invert the filename->hash map
	hashesMap := make(map[string]string)
	for fname, hash := range localFiles {
		hashesMap[hash] = fname
	}

	// check that all files required files can be found
	for _, hash := range requiredUploads {
		if _, found := hashesMap[hash]; !found {
			return fmt.Errorf("cant find file with hash %s", hash)
		}
	}

	for _, hash := range requiredUploads {
		localFile := basedir + "/" + hashesMap[hash]
		f, bar, err := openFileWithProgress(localFile)
		if err != nil {
			bar.Finish()
			return err
		}

		zr, err := addGzipper(f)
		if err != nil {
			bar.Finish()
			f.Close()
			return err
		}

		err = h.UploadFile(baseurl, hash, zr)
		f.Close()
		zr.Close()
		bar.Finish()

		if err != nil {
			return err
		}
	}
	return nil
}

func doDiff(h *Hosting, uploadDir string) error {
	localFiles, err := hashDirectory(uploadDir)
	if err != nil {
		return err
	}

	releases, err := h.Releases()
	if err != nil {
		return err
	}

	releasedVer := releases[0].Version.Name
	remoteFiles, err := h.VersionFiles(releasedVer)
	if err != nil {
		return err
	}

	diff := diffToServer(localFiles, remoteFiles)

	var fnames []string
	for f := range diff {
		fnames = append(fnames, f)
	}
	sort.Strings(fnames)

	for _, f := range fnames {
		status := diff[f]

		// show hash in verbose mode
		hash := ""
		if *verbose {
			var found bool
			if hash, found = localFiles[f]; !found {
				hash = "-"
			}
			hash = "\t" + hash
		}

		if status != DiffNoChange || *verbose {
			fmt.Printf("%c %s%s\n", status, f, hash)
		}
	}

	return nil
}

// Gzips and returns the hashes for specified files.
// This is how Firebase handles Hosting file uploads.
// Hashes are lowercase hex strings
func hashFiles(filenames []string) ([]string, error) {
	hashes := make([]string, 0, len(filenames))

	hasher := sha256.New()
	zw, err := gzip.NewWriterLevel(hasher, compressionLevel)
	if err != nil {
		return nil, err
	}

	for _, fname := range filenames {
		f, err := os.Open(fname)
		if err != nil {
			return nil, err
		}

		_, err = io.Copy(zw, f)
		if err != nil {
			return nil, err
		}

		f.Close()
		zw.Close()

		hash := hasher.Sum(nil)
		hashes = append(hashes, hex.EncodeToString(hash))

		hasher.Reset()
		zw.Reset(hasher)
	}

	return hashes, nil
}

// Opens a file with a progress bar.
// pb starts as soon as function returns.
// Closing the pb will close the underlying file as well.
func openFileWithProgress(name string) (io.ReadCloser, *pb.ProgressBar, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}

	bar := pb.New64(fi.Size()).SetUnits(pb.U_BYTES).Format(pbFormat)
	bar.Prefix(name)
	defer bar.Start()

	return bar.NewProxyReader(f), bar, nil
}

// Adds a gzip writer that takes data from src and returns another Reader
// (io.PipeReader to be exact) from which the gzipped data can be read.
// A new goroutine is spawned to handle the data copying from src Reader to
// output Reader.
// Any errors during copying will be propagated into the reader.
// The returned PipeReader should be closed by the caller when finished.
func addGzipper(src io.ReadCloser) (*io.PipeReader, error) {
	r, w := io.Pipe()

	zw, err := gzip.NewWriterLevel(w, compressionLevel)
	if err != nil {
		return nil, err
	}

	go func() {
		defer src.Close()
		defer w.Close()

		_, err = io.Copy(zw, src)
		if err != nil {
			r.CloseWithError(err)
			return
		}

		zw.Close()
	}()

	return r, nil
}
