package utils

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
)

var HasuraEndpoint = os.Getenv("HASURA_GRAPHQL_URL")     // e.g. http://localhost:8080/v1/graphql
var HasuraAdminSecret = os.Getenv("HASURA_ADMIN_SECRET") // optional if you use admin secret

func HasuraRequest(query string, variables map[string]any) (map[string]any, error) {
	body := map[string]any{
		"query":     query,
		"variables": variables,
	}

	jsonData, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", HasuraEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if HasuraAdminSecret != "" {
		req.Header.Set("x-hasura-admin-secret", HasuraAdminSecret)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	return result, err
}
