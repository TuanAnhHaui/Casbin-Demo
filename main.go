package main

import (
	"casbin-golang/controller"
	"casbin-golang/middleware"
	"casbin-golang/repository"
	"fmt"
	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"log"
	"os"
)

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatalln("Error loading .env file")
	}

	dbConStr := os.Getenv("DBConnectionStr")

	db, err := gorm.Open(mysql.Open(dbConStr), &gorm.Config{})
	if err != nil {
		log.Fatalln(err)
	}

	db = db.Debug()

	if err := SetupRoutes(db); err != nil {
		log.Fatalln(err)
	}

}

//SetupRoutes : all the routes are defined here
func SetupRoutes(db *gorm.DB) error {
	httpRouter := gin.Default()

	// Initialize  casbin adapter
	adapter, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize casbin adapter: %v", err))
	}

	// Load model configuration file and policy store adapter
	enforcer, err := casbin.NewEnforcer("config/rbac_model.conf", adapter)
	if err != nil {
		panic(fmt.Sprintf("failed to create casbin enforcer: %v", err))
	}

	//add policy
	if hasPolicy := enforcer.HasPolicy("admin", "report", "read"); !hasPolicy {
		enforcer.AddPolicy("admin", "report", "read")
	}
	if hasPolicy := enforcer.HasPolicy("admin", "report", "write"); !hasPolicy {
		enforcer.AddPolicy("admin", "report", "write")
	}
	if hasPolicy := enforcer.HasPolicy("user", "report", "read"); !hasPolicy {
		enforcer.AddPolicy("user", "report", "read")
	}

	userRepository := repository.NewUserRepository(db)

	if err := userRepository.Migrate(); err != nil {
		log.Fatal("User migrate err", err)
	}

	userController := controller.NewUserController(userRepository)

	apiRoutes := httpRouter.Group("/api")

	{
		apiRoutes.POST("/register", userController.AddUser(enforcer))
		apiRoutes.POST("/login", userController.SignInUser)
	}

	userProtectedRoutes := apiRoutes.Group("/users", middleware.AuthorizeJWT())
	{
		userProtectedRoutes.GET("/", middleware.Authorize("report", "read", enforcer), userController.GetAllUser)
		userProtectedRoutes.GET("/:user", middleware.Authorize("report", "read", enforcer), userController.GetUser)
		userProtectedRoutes.PUT("/:user", middleware.Authorize("report", "write", enforcer), userController.UpdateUser)
		userProtectedRoutes.DELETE("/:user", middleware.Authorize("report", "write", enforcer), userController.DeleteUser)
	}

	return httpRouter.Run()

}
