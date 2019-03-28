// This file is part of firebut.
// Copyright 2019 Darell Tan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the README.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// OAuth scope for Firebase Hosting
const (
	FirebaseHostingScope = "https://www.googleapis.com/auth/firebase.hosting"
	FirebaseScope        = "https://www.googleapis.com/auth/firebase"

	CloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
)

const ServiceUrl = "https://firebasehosting.googleapis.com/v1beta1"

const (
	debugRequests = false
)

type Hosting struct {
	c       *http.Client
	baseUrl string
	site    string
}

func HostingClient(c *http.Client, siteId string) *Hosting {
	return &Hosting{
		c:       c,
		site:    siteId,
		baseUrl: ServiceUrl,
	}
}

type ActingUser struct {
	Email    string
	ImageUrl string
}

type Version struct {
	Name         string
	Labels       map[string]string
	FileCount    int64 `json:",string"`
	VersionBytes int64 `json:",string"`

	CreateTime, FinalizeTime, DeleteTime string
	CreateUser, FinalizeUser, DeleteUser *ActingUser
}

type VersionFile struct {
	Path   string
	Hash   string
	Status string
}

type Release struct {
	Name    string
	Version Version
	Message string
}

// Performs a request.
// Generally, all the API parameters are either in the URL query string, or
// encoded in the POST body as JSON. Data is returned via a JSON-encoded body
// as well.
func (h *Hosting) httpReq(method, url string, reqData, respData interface{}) error {
	var body io.Reader
	if reqData != nil {
		reqJson, err := json.Marshal(reqData)
		if err != nil {
			return err
		}

		body = bytes.NewReader(reqJson)
	}

	// prefix URL with the service base URL
	url = h.baseUrl + "/" + url

	if debugRequests {
		fmt.Printf("%s %s\n", method, url)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return err
	}

	if reqData != nil {
		req.Header.Set("Content-Type", "text/json")
	}

	resp, err := h.c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body = resp.Body
	if debugRequests {
		body = io.TeeReader(resp.Body, os.Stdout)
	}

	if resp.StatusCode != http.StatusOK {
		// in case there was an error, print out the body
		if debugRequests {
			io.Copy(os.Stdout, resp.Body)
		}
		return fmt.Errorf("request returned %s", resp.Status)
	}

	dec := json.NewDecoder(body)
	err = dec.Decode(respData)
	if err != nil {
		return err
	}

	return nil
}

// Accepts a full versionName (sites/$site/versions/$id) or just the version ID
// and returns a full versionName
func (h *Hosting) versionId(versionIdOrName string) string {
	versionId := versionIdOrName
	if !strings.ContainsRune(versionIdOrName, '/') {
		versionId = "sites/" + h.site + "/versions/" + versionIdOrName
	}
	return versionId
}

func (h *Hosting) Releases() ([]Release, error) {
	var r struct {
		Releases []Release
	}
	err := h.httpReq("GET", "sites/"+h.site+"/releases", nil, &r)
	return r.Releases, err
}

func (h *Hosting) ReleaseVersion(versionName string, message string) (Release, error) {
	var r Release
	releaseParams := struct {
		Message string `json:"message,omitempty"`
	}{message}

	err := h.httpReq("POST", "sites/"+h.site+"/releases?version_name="+h.versionId(versionName), releaseParams, &r)
	return r, err
}

func (h *Hosting) VersionFiles(versionName string) ([]VersionFile, error) {
	var f struct {
		Files []VersionFile
	}
	err := h.httpReq("GET", h.versionId(versionName)+"/files", nil, &f)
	return f.Files, err
}

func (h *Hosting) NewVersion() (Version, error) {
	var v Version
	err := h.httpReq("POST", "sites/"+h.site+"/versions", nil, &v)
	return v, err
}

// Populates a version with the specified files.
// The path that is contained in fileHashes should be relative to the web root.
// In fact, they should all be preceeded by a slash, but this function will
// prepend that for you if required.
func (h *Hosting) PopulateFiles(versionName string, fileHashes map[string]string) ([]string, string, error) {
	// make sure that the paths begin with a slash
	for fname, hash := range fileHashes {
		if fname[0] != '/' {
			fileHashes["/"+fname] = hash
			delete(fileHashes, fname)
		}
	}

	files := struct {
		Files map[string]string `json:"files"`
	}{fileHashes}

	var hh struct {
		UploadRequiredHashes []string
		UploadUrl            string
	}

	err := h.httpReq("POST", h.versionId(versionName)+":populateFiles", files, &hh)
	if err != nil {
		return nil, "", err
	}

	return hh.UploadRequiredHashes, hh.UploadUrl, nil
}

func (h *Hosting) FinalizeVersion(versionName string) (Version, error) {
	var updatedVer Version
	patchStatus := struct {
		Status string `json:"status"`
	}{"FINALIZED"}
	err := h.httpReq("PATCH", h.versionId(versionName), patchStatus, &updatedVer)
	return updatedVer, err
}

func (h *Hosting) UploadFile(baseUrl, hash string, src io.ReadCloser) error {
	resp, err := h.c.Post(baseUrl+"/"+hash, "application/octet-stream", src)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %s", resp.Status)
	}

	return nil
}
