package main

import (
	"log"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/logger"
	"github.com/gin-contrib/secure"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/middleware/gin"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	db       *gorm.DB
	err      error
	validate *validator.Validate
	jwtKey   []byte
)

type User struct {
	ID       uint   `json:"id"`
	Username string `json:"username" validate:"required,min=3,max=50"`
	Password string `json:"password" validate:"required,min=8"`
}

type Student struct {
	ID            uint      `json:"id"`
	UserID        uint      `json:"user_id"`
	Name          string    `json:"name" validate:"required"`
	DateOfBirth   time.Time `json:"date_of_birth" validate:"required"`
	ContactNumber string    `json:"contact_number" validate:"required"`
	Email         string    `json:"email" validate:"required,email"`
	Address       string    `json:"address" validate:"required"`
	Marks         float64   `json:"marks" validate:"required"`
	GPA           float64   `json:"gpa" validate:"required"`
}

func init() {
	// Load environment variables
	dsn := os.Getenv("DATABASE_URL")
	jwtKey = []byte(os.Getenv("JWT_SECRET"))

	// Initialize database connection
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Initialize validator
	validate = validator.New()
}

func main() {
	r := gin.Default()

	// Middleware
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"}, // Replace with your frontend URL
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	r.Use(secure.New(secure.Config{
		FrameDeny:             true,
		ContentTypeNosniff:    true,
		BrowserXssFilter:      true,
		ContentSecurityPolicy: "default-src 'self'",
	}))

	r.Use(logger.SetLogger())

	// Rate limiting
	rate, err := limiter.NewRateFromFormatted("10-M") // 10 requests per minute
	if err != nil {
		log.Fatal("Failed to configure rate limiter:", err)
	}
	store := memory.NewStore()
	limiterInstance := limiter.New(store, rate)
	rateLimiterMiddleware := ginmw.NewMiddleware(limiterInstance)
	r.Use(rateLimiterMiddleware)

	// Routes
	r.POST("/register", register)
	r.POST("/login", login)
	r.POST("/students/register", authMiddleware(), addStudent)

	// Start the server with HTTPS
	r.RunTLS(":5000", "cert.pem", "key.pem") // Replace with your SSL certificate and key
}

// User registration handler
func register(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(400, gin.H{"message": "Invalid input"})
		return
	}

	// Validate input
	if err := validate.Struct(user); err != nil {
		c.JSON(400, gin.H{"message": "Validation failed", "errors": err.Error()})
		return
	}

	// Check if user already exists
	var existingUser User
	if err := db.Where("username = ?", user.Username).First(&existingUser).Error; err == nil {
		c.JSON(400, gin.H{"message": "Username already exists"})
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(500, gin.H{"message": "Failed to hash password"})
		return
	}

	// Create new user in the database
	user.Password = string(hashedPassword)
	if err := db.Create(&user).Error; err != nil {
		c.JSON(500, gin.H{"message": "Failed to create user"})
		return
	}

	c.JSON(201, gin.H{"message": "User created successfully"})
}

// User login handler
func login(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(400, gin.H{"message": "Invalid input"})
		return
	}

	// Validate input
	if err := validate.Struct(user); err != nil {
		c.JSON(400, gin.H{"message": "Validation failed", "errors": err.Error()})
		return
	}

	// Check if user exists
	var existingUser User
	if err := db.Where("username = ?", user.Username).First(&existingUser).Error; err != nil {
		c.JSON(404, gin.H{"message": "User not found"})
		return
	}

	// Compare password with stored hash
	if err := bcrypt.CompareHashAndPassword([]byte(existingUser.Password), []byte(user.Password)); err != nil {
		c.JSON(401, gin.H{"message": "Invalid credentials"})
		return
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": existingUser.Username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // Token expires in 24 hours
	})

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(500, gin.H{"message": "Failed to generate token"})
		return
	}

	c.JSON(200, gin.H{"token": tokenString})
}

// Add student handler
func addStudent(c *gin.Context) {
	var student Student
	if err := c.ShouldBindJSON(&student); err != nil {
		c.JSON(400, gin.H{"message": "Invalid input"})
		return
	}

	// Validate input
	if err := validate.Struct(student); err != nil {
		c.JSON(400, gin.H{"message": "Validation failed", "errors": err.Error()})
		return
	}

	// Create new student in the database
	if err := db.Create(&student).Error; err != nil {
		c.JSON(500, gin.H{"message": "Failed to create student"})
		return
	}

	c.JSON(201, gin.H{"message": "Student registered successfully", "student": student})
}

// Middleware for JWT authentication
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(401, gin.H{"message": "Authorization token required"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(401, gin.H{"message": "Invalid or expired token"})
			c.Abort()
			return
		}

		c.Next()
	}
}
