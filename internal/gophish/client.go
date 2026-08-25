package gophish

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

type Campaign struct {
	ID          int        `json:"id"`
	Name        string     `json:"name"`
	Status      string     `json:"status"`
	LureURL     string     `json:"lure_url"`
	Phishlet    string     `json:"phishlet"`
	CreatedAt   time.Time  `json:"created_at"`
	LaunchedAt  *time.Time `json:"launched_at,omitempty"`
}

type CampaignResults struct {
	CampaignID  int     `json:"campaign_id"`
	TotalSent   int     `json:"total_sent"`
	Opened      int     `json:"opened"`
	Clicked     int     `json:"clicked"`
	Credentials int     `json:"credentials"`
	Sessions    int     `json:"sessions"`
	OpenRate    float64 `json:"open_rate"`
	ClickRate   float64 `json:"click_rate"`
	CredRate    float64 `json:"cred_rate"`
}

type SendEmailRequest struct {
	TemplateID  int      `json:"template_id"`
	GroupID     int      `json:"group_id"`
	URL         string   `json:"url"`
	FromAddress string   `json:"from_address"`
}

type Template struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Subject  string `json:"subject"`
	HTML     string `json:"html"`
}

type Group struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Members []struct {
		Email     string `json:"email"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	} `json:"members"`
}

func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) request(method, path string, body interface{}) ([]byte, error) {
	url := fmt.Sprintf("%s/api%s", c.baseURL, path)
	
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal body: %w", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}
	
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()
	
	return io.ReadAll(resp.Body)
}

func (c *Client) TestConnection() error {
	_, err := c.request("GET", "/campaigns?results=0", nil)
	return err
}

func (c *Client) CreateCampaign(name string, templateID, groupID int, url string) (*Campaign, error) {
	body := map[string]interface{}{
		"name":        name,
		"template_id": templateID,
		"group_id":    groupID,
		"url":         url,
	}
	
	data, err := c.request("POST", "/campaigns", body)
	if err != nil {
		return nil, err
	}
	
	var campaign Campaign
	if err := json.Unmarshal(data, &campaign); err != nil {
		return nil, err
	}
	
	return &campaign, nil
}

func (c *Client) LaunchCampaign(campaignID int) error {
	_, err := c.request("POST", fmt.Sprintf("/campaigns/%d/launch", campaignID), nil)
	return err
}

func (c *Client) GetCampaignResults(campaignID int) (*CampaignResults, error) {
	data, err := c.request("GET", fmt.Sprintf("/campaigns/%d", campaignID), nil)
	if err != nil {
		return nil, err
	}
	
	var results CampaignResults
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, err
	}
	
	return &results, nil
}

func (c *Client) ListCampaigns() ([]Campaign, error) {
	data, err := c.request("GET", "/campaigns", nil)
	if err != nil {
		return nil, err
	}
	
	var campaigns []Campaign
	if err := json.Unmarshal(data, &campaigns); err != nil {
		return nil, err
	}
	
	return campaigns, nil
}

func (c *Client) ListTemplates() ([]Template, error) {
	data, err := c.request("GET", "/templates", nil)
	if err != nil {
		return nil, err
	}
	
	var templates []Template
	if err := json.Unmarshal(data, &templates); err != nil {
		return nil, err
	}
	
	return templates, nil
}

func (c *Client) ListGroups() ([]Group, error) {
	data, err := c.request("GET", "/groups", nil)
	if err != nil {
		return nil, err
	}
	
	var groups []Group
	if err := json.Unmarshal(data, &groups); err != nil {
		return nil, err
	}
	
	return groups, nil
}
