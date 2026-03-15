package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	maxFeedbackLength = 1000
	captchaTTL        = 10 * time.Minute
	feedbackFile      = "data/feedback.json"
	listenAddr        = ":8080"
	defaultAdminUser  = "admin"
	defaultAdminPass  = "changeme"
)

var (
	htmlTagRe    = regexp.MustCompile(`<[^>]*>`)
	hmacSecret   []byte
	feedbackMu   sync.Mutex
	templates    *template.Template
	adminUser    string
	adminPass    string
)

type PageData struct {
	CaptchaQuestion string
	CaptchaToken    string
	Success         bool
	Error           string
	Year            int
}

type ReadFeedbackData struct {
	Entries []FeedbackEntry
	Count   int
	Year    int
}

type FeedbackEntry struct {
	ID        string `json:"id"`
	Text      string `json:"text"`
	Timestamp string `json:"timestamp"`
}

func main() {
	hmacSecret = generateSecret()

	adminUser = os.Getenv("ADMIN_USER")
	if adminUser == "" {
		adminUser = defaultAdminUser
	}
	adminPass = os.Getenv("ADMIN_PASSWORD")
	if adminPass == "" {
		adminPass = defaultAdminPass
		log.Println("WARNING: Using default admin password. Set ADMIN_PASSWORD environment variable for production.")
	}

	var err error
	templates, err = template.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}

	if err := ensureFeedbackFile(); err != nil {
		log.Fatalf("Failed to initialize feedback file: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/privacy", handlePrivacy)
	mux.HandleFunc("/feedback", handleFeedback)
	mux.HandleFunc("/readfeedback", handleReadFeedback)

	log.Printf("Starting server on %s", listenAddr)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func generateSecret() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("Failed to generate secret: %v", err)
	}
	return b
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	question, token := generateCaptcha()
	data := PageData{
		CaptchaQuestion: question,
		CaptchaToken:    token,
		Year:            time.Now().Year(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "index.html", data); err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func handlePrivacy(w http.ResponseWriter, r *http.Request) {
	data := PageData{Year: time.Now().Year()}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "privacy.html", data); err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func handleFeedback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/#feedback", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		renderIndex(w, "", "Invalid form submission.")
		return
	}

	// Honeypot check — hidden field should be empty
	if r.FormValue("website") != "" {
		renderIndex(w, "", "Invalid submission.")
		return
	}

	text := r.FormValue("feedback")
	captchaAnswer := r.FormValue("captcha_answer")
	captchaToken := r.FormValue("captcha_token")

	// Validate CAPTCHA
	if !verifyCaptcha(captchaToken, captchaAnswer) {
		renderIndex(w, text, "Incorrect CAPTCHA answer. Please try again.")
		return
	}

	// Sanitize and validate text
	text = sanitizeText(text)
	if len(strings.TrimSpace(text)) == 0 {
		renderIndex(w, "", "Please enter some feedback text.")
		return
	}
	if len(text) > maxFeedbackLength {
		text = text[:maxFeedbackLength]
	}

	entry := FeedbackEntry{
		ID:        generateID(),
		Text:      text,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	if err := saveFeedback(entry); err != nil {
		log.Printf("Failed to save feedback: %v", err)
		renderIndex(w, text, "Failed to save feedback. Please try again later.")
		return
	}

	question, token := generateCaptcha()
	data := PageData{
		CaptchaQuestion: question,
		CaptchaToken:    token,
		Success:         true,
		Year:            time.Now().Year(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templates.ExecuteTemplate(w, "index.html", data)
}

func renderIndex(w http.ResponseWriter, preservedText string, errMsg string) {
	question, token := generateCaptcha()
	data := PageData{
		CaptchaQuestion: question,
		CaptchaToken:    token,
		Error:           errMsg,
		Year:            time.Now().Year(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templates.ExecuteTemplate(w, "index.html", data)
}

func handleReadFeedback(w http.ResponseWriter, r *http.Request) {
	if !checkBasicAuth(r) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Admin Area"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	feedbackMu.Lock()
	data, err := os.ReadFile(feedbackFile)
	feedbackMu.Unlock()
	if err != nil {
		http.Error(w, "Failed to read feedback", http.StatusInternalServerError)
		return
	}

	var entries []FeedbackEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		http.Error(w, "Failed to parse feedback", http.StatusInternalServerError)
		return
	}

	// Reverse order so newest is first
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}

	pageData := ReadFeedbackData{
		Entries: entries,
		Count:   len(entries),
		Year:    time.Now().Year(),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := templates.ExecuteTemplate(w, "readfeedback.html", pageData); err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func checkBasicAuth(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	userMatch := hmac.Equal([]byte(user), []byte(adminUser))
	passMatch := hmac.Equal([]byte(pass), []byte(adminPass))
	return userMatch && passMatch
}

// CAPTCHA: simple math problem with HMAC-signed token
func generateCaptcha() (string, string) {
	a := randomInt(1, 20)
	b := randomInt(1, 20)
	answer := a + b
	question := fmt.Sprintf("What is %d + %d?", a, b)

	expiry := time.Now().Add(captchaTTL).Unix()
	payload := fmt.Sprintf("%d|%d", answer, expiry)

	mac := hmac.New(sha256.New, hmacSecret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	token := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s|%s", payload, sig)))
	return question, token
}

func verifyCaptcha(token, answer string) bool {
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return false
	}

	parts := strings.SplitN(string(decoded), "|", 3)
	if len(parts) != 3 {
		return false
	}

	expectedAnswer, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}

	expiry, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false
	}

	if time.Now().Unix() > expiry {
		return false
	}

	// Verify HMAC
	payload := fmt.Sprintf("%d|%d", expectedAnswer, expiry)
	mac := hmac.New(sha256.New, hmacSecret)
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	if parts[2] != expectedSig {
		return false
	}

	userAnswer, err := strconv.Atoi(strings.TrimSpace(answer))
	if err != nil {
		return false
	}

	return userAnswer == expectedAnswer
}

func sanitizeText(input string) string {
	// Strip HTML tags
	text := htmlTagRe.ReplaceAllString(input, "")

	// Remove control characters except newline and tab
	var b strings.Builder
	for _, r := range text {
		if r == '\n' || r == '\t' || (unicode.IsPrint(r) && !unicode.IsControl(r)) {
			b.WriteRune(r)
		}
	}
	text = b.String()

	// Collapse excessive newlines
	multiNewline := regexp.MustCompile(`\n{3,}`)
	text = multiNewline.ReplaceAllString(text, "\n\n")

	return strings.TrimSpace(text)
}

func ensureFeedbackFile() error {
	if _, err := os.Stat(feedbackFile); os.IsNotExist(err) {
		return os.WriteFile(feedbackFile, []byte("[]"), 0644)
	}
	return nil
}

func saveFeedback(entry FeedbackEntry) error {
	feedbackMu.Lock()
	defer feedbackMu.Unlock()

	data, err := os.ReadFile(feedbackFile)
	if err != nil {
		return err
	}

	var entries []FeedbackEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}

	entries = append(entries, entry)

	updated, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(feedbackFile, updated, 0644)
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func randomInt(min, max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	return int(n.Int64()) + min
}
