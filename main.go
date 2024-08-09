package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/messaging"
	"github.com/gin-gonic/gin"
	"google.golang.org/api/option"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
	"github.com/joho/godotenv"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var dbpsql *gorm.DB
var dbmysql *gorm.DB
var err error

var messagingClient *messaging.Client

var redisClient *redis.Client
var ctx = context.Background()

type User struct {
	Useraddress    string `json:"useraddress"`
	Profilepicture []byte `json:"profilepicture"` // Use BYTEA for image data
	Filename       string `json:"filename"`
	Filetype       string `json:"filetype"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      gorm.DeletedAt `gorm:"index"`
}

type ERC20 struct {
	Useraddress     string `json:"useraddress"`
	Contractaddress string `json:"contractaddress"`
	Function        string `json:"function"`
	Blockhash       string `json:"blockhash"`
	Blocknumber     string `json:"blocknumber"`
	Transactionhash string `json:"transactionhash"`
	Status          string `json:"status"`
}

type ERC721 struct {
	Useraddress     string `json:"useraddress"`
	Contractaddress string `json:"contractaddress"`
	Function        string `json:"function"`
	Blockhash       string `json:"blockhash"`
	Blocknumber     string `json:"blocknumber"`
	Transactionhash string `json:"transactionhash"`
	Status          string `json:"status"`
}

type FCMToken struct {
	Token string `json:"token"`
}

// NotificationPayload represents the structure of the notification
type NotificationPayload struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

func init() {
	dsnpsql := "host=" + os.Getenv("DB_HOST") + " user=" + os.Getenv("PSQL_USER") + " password=" + os.Getenv("DB_PASS") + " dbname=testmemehunter" + os.Getenv("DB_NAME") + " port=5432"
	dbpsql, err = gorm.Open(postgres.Open(dsnpsql), &gorm.Config{})

	dsnmysql := os.Getenv("MYSQL_USER") + ":" + os.Getenv("DB_PASS") + "@tcp(" + os.Getenv("DB_HOST") + ":3306)/" + os.Getenv("DB_NAME") + "?charset=utf8mb4&parseTime=True&loc=Local"
	dbmysql, err = gorm.Open(mysql.Open(dsnmysql), &gorm.Config{})

	if err != nil {
		panic("failed to connect to database")
	}

	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379" // default to localhost if no environment variable is set
	}

	redisClient = redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})

	// Initialize Firebase Admin SDK
	ctx := context.Background()
	sa := option.WithCredentialsFile("config/serviceAccountKey.json")

	app, err := firebase.NewApp(ctx, nil, sa)
	if err != nil {
		log.Fatalf("Error initializing app: %v", err)
	}

	messagingClient, err = app.Messaging(ctx)
	if err != nil {
		log.Fatalf("Error getting Messaging client: %v", err)
	}

}

func generateToken(useraddress string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"useraddress": useraddress,
		"exp":         time.Now().Add(time.Hour * 24).Unix(),
	})
	tokenString, err := token.SignedString([]byte("secret"))
	return tokenString, err
}

func loginUser(c *gin.Context) {
	var credentials struct {
		Useraddress string `json:"useraddress"`
	}
	if err := c.ShouldBindJSON(&credentials); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var user User
	if err := dbpsql.Where("useraddress = ?", credentials.Useraddress).First(&user).Error; err != nil {
		user := User{
			Useraddress: c.PostForm("useraddress"),
		}

		if err := dbpsql.Create(&user).Error; err != nil {
			log.Printf("Error saving user data to database: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save user data"})
			return
		}

	}

	token, err := generateToken(credentials.Useraddress)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	err = redisClient.Set(ctx, "token:"+token, credentials.Useraddress, 24*time.Hour).Err()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte("secret"), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func logoutUser(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	err := redisClient.Del(ctx, "token:"+tokenString).Err()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to invalidate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Token invalidated successfully"})
}

func createFCMToken(c *gin.Context) {
	var fcmtoken FCMToken
	if err := c.ShouldBindJSON(&fcmtoken); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := dbpsql.Create(&fcmtoken).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "token saved"})
}

func sendPushNotification(c *gin.Context) {
	var payload NotificationPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var tokens []FCMToken
	if err := dbpsql.Find(&tokens).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var registrationTokens []string
	for _, token := range tokens {
		registrationTokens = append(registrationTokens, token.Token)
	}

	message := &messaging.MulticastMessage{
		Notification: &messaging.Notification{
			Title: payload.Title,
			Body:  payload.Body,
		},
		Tokens: registrationTokens,
	}

	response, err := messagingClient.SendMulticast(context.Background(), message)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success_count": response.SuccessCount,
		"failure_count": response.FailureCount,
	})
}

func main() {

	r := gin.Default()

	r.POST("/login", loginUser)
	r.POST("/logout", logoutUser)
	r.POST("/save-fcm-token", createFCMToken)
	r.POST("/send-notification", sendPushNotification)

	r.POST("/erc20trxlog", createErc20TrxLog)
	r.POST("/erc721trxlog", createErc721TrxLog)
	r.GET("/erc20/:useraddress", getErc20Transaction)
	r.GET("/erc721/:useraddress", getErc721Transaction)

	authorized := r.Group("/")
	authorized.Use(AuthMiddleware())
	{
		authorized.POST("/user", createProfile)
		authorized.GET("/user/:useraddress", getProfile)
		authorized.PUT("/userupdate/:useraddress", updateProfile)
	}

	r.Run(":3001")
}

func createProfile(c *gin.Context) {
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		log.Printf("Error reading file from form: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read file"})
		return
	}
	defer file.Close()

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		log.Printf("Error reading file content: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file content"})
		return
	}

	user := User{
		Useraddress:    c.PostForm("useraddress"),
		Filename:       c.PostForm("filename"),
		Filetype:       c.PostForm("filetype"),
		Profilepicture: fileBytes,
	}

	if err := dbpsql.Create(&user).Error; err != nil {
		log.Printf("Error saving user data to database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save user data"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "File uploaded successfully"})

}

func getProfile(c *gin.Context) {
	userID := c.Param("useraddress")

	var user User
	if err := dbpsql.Where("useraddress = ?", userID).First(&user).Error; err != nil {
		log.Printf("Error retrieving user: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if len(user.Profilepicture) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "No image found for this user"})
		return
	}

	// Set the appropriate content type based on filetype
	c.Data(http.StatusOK, user.Filetype, user.Profilepicture)
}

func updateProfile(c *gin.Context) {
	userID := c.Param("useraddress")

	file, _, err := c.Request.FormFile("file")
	if err != nil {
		log.Printf("Error reading file from form: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read file"})
		return
	}
	defer file.Close()

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		log.Printf("Error reading file content: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file content"})
		return
	}

	var user User
	if err := dbpsql.Where("useraddress = ?", userID).First(&user).Error; err != nil {
		log.Printf("Error retrieving user: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	user.Profilepicture = fileBytes
	user.Filename = c.PostForm("filename")
	user.Filetype = c.PostForm("filetype")

	if err := dbpsql.Where("useraddress = ?", userID).Save(&user).Error; err != nil {
		log.Printf("Error updating user data: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user data", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "Image updated successfully"})
}

func getErc20Transaction(c *gin.Context) {

	useraddress := c.Param("useraddress")
	var erc20 []ERC20
	query := dbmysql.Model(&ERC20{}).Where("useraddress = ?", useraddress)

	if err := query.Find(&erc20).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, erc20)
}

func getErc721Transaction(c *gin.Context) {
	useraddress := c.Param("useraddress")
	var erc721 []ERC721
	query := dbmysql.Model(&ERC721{}).Where("useraddress = ?", useraddress)

	if err := query.Find(&erc721).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, erc721)
}

func createErc20TrxLog(c *gin.Context) {
	var logdata ERC20

	if err := c.ShouldBindJSON(&logdata); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := dbmysql.Model(&ERC20{}).Create(&logdata)

	if err := query.Find(&logdata).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, "ERC20 Transaction Log Created")
}

func createErc721TrxLog(c *gin.Context) {
	var logdata ERC721

	if err := c.ShouldBindJSON(&logdata); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := dbmysql.Model(&ERC721{}).Create(&logdata)

	if err := query.Find(&logdata).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, "ERC721 Transaction Log Created")
}
