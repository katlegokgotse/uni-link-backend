package main

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Configuration constants
const (
	MinPasswordLength = 8
	JWTSecret         = "your-secret-key-here" // In production, use environment variable
	TokenExpiration   = 24 * time.Hour
)

var (
	db  *gorm.DB
	err error
)

// User model with input validation
type User struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Username  string    `json:"username" gorm:"unique;not null"`
	Password  string    `json:"password" gorm:"not null"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Student model with input validation
type Student struct {
	ID            uint      `json:"id" gorm:"primaryKey"`
	UserID        uint      `json:"user_id" gorm:"not null"`
	Name          string    `json:"name" gorm:"not null"`
	DateOfBirth   time.Time `json:"date_of_birth" gorm:"not null"`
	ContactNumber string    `json:"contact_number" gorm:"not null"`
	Email         string    `json:"email" gorm:"unique;not null"`
	Address       string    `json:"address" gorm:"not null"`
	Marks         float64   `json:"marks" gorm:"not null"`
	GPA           float64   `json:"gpa" gorm:"not null"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// LoginRequest represents the login request body
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// RegisterRequest represents the registration request body
type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// Claims represents JWT claims
type Claims struct {
	UserID uint `json:"user_id"`
	jwt.StandardClaims
}

func init() {
	// Use environment variables in production
	dsn := "user=dbunilink_user password=7Is1S6y4pYXJuGNG26xNMy02gstj04wI dbname=dbunilink host=dpg-cuq59mtsvqrc73f7dnog-a.oregon-postgres.render.com port=5432 sslmode=require TimeZone=UTC"

	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("failed to connect to database:", err)
	}

	// Auto-migrate the schema
	err = db.AutoMigrate(&User{}, &Student{})
	if err != nil {
		log.Fatal("failed to migrate database:", err)
	}
}

func main() {
	r := gin.Default()

	// Add security headers middleware
	r.Use(securityHeaders())

	// Rate limiting middleware could be added here

	// Public routes
	r.GET("/", documentation)
	r.POST("/register", register)
	r.POST("/login", login)

	// Protected routes
	authorized := r.Group("/")
	authorized.Use(authMiddleware())
	{
		authorized.POST("/students/register", addStudent)
		authorized.GET("/students/:id", getStudent)
	}

	r.Run(":5000")
}

// Security headers middleware
func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Next()
	}
}

// JWT Authentication middleware
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Remove "Bearer " prefix if present
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(JWTSecret), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("userID", claims.UserID)
		c.Next()
	}
}

// Input validation functions
func validatePassword(password string) error {
	if len(password) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	// Add more password requirements as needed
	return nil
}

func validateEmail(email string) error {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}
func documentation(c *gin.Context) {
	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>UniLink API Documentation</title>
	</head>
	<body>
		<h1>Welcome to the Student Management API</h1>
		<h2>Endpoints</h2>
		<ul>
			<li><strong>POST /register</strong> - Register a new user</li>
			<li><strong>POST /login</strong> - Login and get a JWT token</li>
			<li><strong>POST /students/register</strong> - Register a new student (requires authentication)</li>
			<li><strong>GET /students/:id</strong> - Get student details by ID (requires authentication)</li>
		</ul>
		<h2>Notes</h2>
		<ul>
			<li>All protected routes require a valid JWT token in the Authorization header.</li>
			<li>JWT token can be obtained by logging in via the /login endpoint.</li>
		</ul>
	</body>
	</html>
	`
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}

// User registration handler with improved validation
func register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Validate password
	if err := validatePassword(req.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if user already exists
	var existingUser User
	if err := db.Where("username = ?", req.Username).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process registration"})
		return
	}

	user := User{
		Username: req.Username,
		Password: string(hashedPassword),
	}

	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully"})
}

// User login handler with JWT token generation
func login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var user User
	if err := db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate JWT token
	expirationTime := time.Now().Add(TokenExpiration)
	claims := &Claims{
		UserID: user.ID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(JWTSecret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Logged in successfully",
		"token":   tokenString,
	})
}

// Add student handler with improved validation
func addStudent(c *gin.Context) {
	userID, _ := c.Get("userID")

	var student Student
	if err := c.ShouldBindJSON(&student); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Validate email
	if err := validateEmail(student.Email); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate other fields
	if student.GPA < 0 || student.GPA > 4.0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid GPA"})
		return
	}

	if student.Marks < 0 || student.Marks > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid marks"})
		return
	}

	student.UserID = userID.(uint)

	if err := db.Create(&student).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create student"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Student registered successfully",
		"student": student,
	})
}

// Get student handler
func getStudent(c *gin.Context) {
	userID, _ := c.Get("userID")
	studentID := c.Param("id")

	var student Student
	if err := db.Where("id = ? AND user_id = ?", studentID, userID).First(&student).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Student not found"})
		return
	}

	c.JSON(http.StatusOK, student)
}
